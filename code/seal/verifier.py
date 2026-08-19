"""
Standalone verifier.

Given an artifact, confirm integrity and report what was bound. Depends on the
standard library and `cryptography` only, and imports nothing from any capture
mechanism, because an examiner running this years later will not have the
producing system.

The verifier exists before the capture mechanism deliberately. What a verifier
can report without overclaiming is what an artifact must actually contain, and
the field that matters most is `timestamp_replicable`. KC2 states that the
mechanism
fails if it does nothing a third-party-timestamped bundle of the same local
files could not do. That is not a matter of opinion. It is computable from the
artifact, and this module computes it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .artifact import (
    GENESIS,
    Entry,
    EntryKind,
    RederivationRecipe,
    WitnessMode,
    chain_identity,
    load_artifact,
    signing_payload,
)
from .anchor import Anchoring, BeaconResolver, resolve_bounds
from .assignment import Disclosure
from .assignment import assess as assess_disclosure
from .checkpoint import load as cp_load
from .checkpoint import signature_valid as cp_signature_valid
from .checkpoint import signer_pem as cp_signer_pem
from .primitives import PrimitiveKind, Pinning, canonical_bytes
from .retention import Holding, Provenance
from .retention import assess as assess_holding
from .retention import conflicts as retention_conflicts


class BindingLevel(Enum):
    """
    What the artifact establishes about the relation between action and evidence.

    Ordered weakest to strongest. The ordering is the point: co-occurrence is
    not binding, and the gap between them is the one element of the framework
    that better records management does not cure. It sits outside the matrix
    of six primitives on three properties, because a relation among
    constituents is not the same kind of object as a constituent.
    """

    BUNDLED = 0
    PRECEDENCE = 1
    WITNESSED = 2
    REDERIVABLE = 3
    REDERIVED = 4


class Completeness(Enum):
    """
    Whether anything outside the artifact vouches for how long the chain is.

    UNCHECKED is the honest default. Without a checkpoint from another party,
    an artifact showing
    three entries and an artifact truncated from five to three are the same
    document, and no amount of verification distinguishes them.
    """

    UNCHECKED = "unchecked"
    CONSISTENT = "consistent"
    SHORT = "short"
    MISMATCHED = "mismatched"
    UNUSABLE = "unusable"


class Coverage(Enum):
    """Whether the workfile binding makes omission of a run detectable."""

    CONTIGUOUS = "contiguous"
    SUBSET = "subset"
    ABSENT = "absent"


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    bears_on: Optional[str] = None


@dataclass
class VerificationReport:
    chain_intact: bool = False
    signatures_valid: bool = False
    key_trusted: Optional[bool] = None
    binding_level: BindingLevel = BindingLevel.BUNDLED
    coverage: Coverage = Coverage.ABSENT
    completeness: Completeness = Completeness.UNCHECKED
    disclosure: Disclosure = Disclosure.UNCHECKED
    assignment_id: Optional[str] = None
    chains_withheld: int = 0
    anchoring: Anchoring = Anchoring.UNANCHORED
    anchor_interval_ns: Optional[int] = None
    timestamp_replicable: bool = True
    input_provenance: Provenance = Provenance.UNSOURCED
    input_holding: Holding = Holding.UNDETERMINED
    primitives_present: dict[str, bool] = field(default_factory=dict)
    primitives_pinned: dict[str, str] = field(default_factory=dict)
    primitives_reachable: dict[str, bool] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def trustworthy(self) -> bool:
        """
        The only field a caller should read to decide whether to rely on this.

        `signatures_valid` on its own means the artifact is internally
        consistent, which a forger achieves by signing everything with their
        own key. It was the obvious field to check and the wrong one, so the
        composite exists to make the mistake harder. Trust requires an intact
        chain, valid signatures, and a key the caller recognised, and the last
        of those is None unless `trusted_keys` was supplied.
        """
        return bool(self.chain_intact and self.signatures_valid
                    and self.key_trusted is True)

    @property
    def kc2_fires(self) -> bool:
        """
        KC2 as written: the mechanism fails if it does nothing a
        third-party-timestamped bundle of the same local files could not do.

        Two RFC-3161 timestamps over two local files establish that one existed
        before the other, which reaches PRECEDENCE, so anything at or below
        PRECEDENCE is replicable by a commodity timestamping service.

        Re-derivation is subtler and the subtlety decides the product. If every
        input can be retained locally, then the same folder can be timestamped
        locally and re-run locally, and re-derivation is replicable too. What a
        local timestamp cannot do is resolve an input the holder is not
        permitted to keep.

        Whether the operator can hold the input is a fact about the tool's
        documented workflow rather than a field in this document, so it arrives
        through `retention_determinations` and is reported as
        `input_provenance`. See `retention.py` for why the artifact's own
        retention field is not that fact.
        """
        return self.timestamp_replicable

    def summary(self) -> str:
        lines = [
            f"TRUSTWORTHY          {self.trustworthy}",
            f"chain_intact         {self.chain_intact}",
            f"signatures_valid     {self.signatures_valid}",
            f"key_trusted          {self.key_trusted}",
            f"binding_level        {self.binding_level.name}",
            f"coverage             {self.coverage.name}",
            f"completeness         {self.completeness.name}",
            f"disclosure           {self.disclosure.name}",
            f"anchoring            {self.anchoring.name}",
            f"input_provenance     {self.input_provenance.name}",
            f"input_holding        {self.input_holding.name}",
            f"timestamp_replicable {self.timestamp_replicable}",
            f"KC2 fires            {self.kc2_fires}",
        ]
        for f in self.findings:
            bears = f" [{f.bears_on}]" if f.bears_on else ""
            lines.append(f"  - {f.code}{bears}: {f.detail}")
        return "\n".join(lines)


def _verify_signature(entry: Entry) -> bool:
    payload = signing_payload(
        entry.kind, entry.seq, entry.prev_hash, entry.body, entry.ts_ns
    )
    raw = canonical_bytes(payload)
    if hashlib.sha256(raw).hexdigest() != entry.block_hash:
        return False
    try:
        pub = serialization.load_pem_public_key(entry.public_key.encode("ascii"))
        pub.verify(bytes.fromhex(entry.signature), raw, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def _verify(
    artifact: dict[str, Any],
    trusted_keys: Optional[Iterable[str]] = None,
    rederive: Optional[Callable[[dict[str, Any]], Optional[str]]] = None,
    checkpoint: Optional[dict[str, Any]] = None,
    assignment_checkpoint: Optional[dict[str, Any]] = None,
    time_anchors: Optional[Iterable[dict[str, Any]]] = None,
    beacon_resolver: Optional[BeaconResolver] = None,
    trusted_authorities: Optional[Iterable[str]] = None,
    retention_determinations: Optional[Iterable[dict[str, Any]]] = None,
) -> VerificationReport:
    """
    Verify an artifact and report what it establishes.

    `trusted_keys` carries PEM public keys the caller considers authoritative.
    Omitting it leaves `key_trusted` as None, which is not a pass. An artifact
    carrying its own public key proves internal consistency and nothing about
    who produced it, since anyone can sign anything with a key they generated.
    Resolving identity to a licensed appraiser is outside this module.

    `rederive` is how an examiner actually performs the re-derivation. It takes
    a recipe and returns the digest of the output it produced, or None if the
    pinned version could no longer be executed. Without it the verifier reports
    REDERIVABLE at best, because a recipe that has not been run is a claim.
    That gap is the liveness dependency: this artifact is not self-contained
    the way a signature is, and it degrades if the partner stops serving the
    pinned version.

    `retention_determinations` carries signed readings of what a tool's
    documented workflow does with the raw input, one per tool and pinned
    version. Omitting it leaves every run unsourced, which fires KC2, because
    the artifact cannot answer a question about its own author's position.
    """
    report = VerificationReport()
    entries = load_artifact(artifact)
    _check_completeness(artifact, entries, checkpoint, report)
    _check_assignment(artifact, entries, assignment_checkpoint, report)
    _check_anchoring(entries, time_anchors, beacon_resolver,
                     trusted_authorities, report)

    if not entries:
        report.findings.append(Finding("empty_artifact", "No entries present."))
        return report

    # Chain integrity: contiguous sequence, prev_hash linkage from genesis.
    intact = True
    expected_prev = GENESIS
    for i, e in enumerate(entries):
        if e.seq != i:
            intact = False
            report.findings.append(
                Finding("sequence_gap", f"Entry at index {i} carries seq {e.seq}.",
                        "omission detectable only on a contiguous chain")
            )
        if i > 0 and e.ts_ns < entries[i - 1].ts_ns:
            report.findings.append(
                Finding(
                    "timestamp_regression",
                    f"Entry seq {e.seq} carries a timestamp earlier than its "
                    "predecessor. Clock values are signed but the chain has no "
                    "external anchor, so ordering rests on sequence alone.",
                    "no external time anchor",
                )
            )
        if e.prev_hash != expected_prev:
            intact = False
            report.findings.append(
                Finding("chain_break", f"Entry seq {e.seq} does not link to its predecessor.")
            )
        if e.kind is EntryKind.ASSIGNMENT_ANCHOR and i != 0:
            intact = False
            report.findings.append(
                Finding(
                    "anchor_out_of_position",
                    f"An assignment anchor appears at seq {e.seq}. A chain "
                    "names one assignment, fixed before anything is sealed "
                    "into it, so a second anchor is an attempt to re-declare "
                    "the assignment part way through.",
                    "assignment custody",
                )
            )
        expected_prev = e.block_hash
    report.chain_intact = intact

    # Signatures.
    bad = [e.seq for e in entries if not _verify_signature(e)]
    report.signatures_valid = not bad
    if bad:
        report.findings.append(
            Finding("bad_signature", f"Signature or block hash failed at seq {bad}.")
        )

    # Key identity is a separate question from signature validity.
    if trusted_keys is not None:
        trusted = {k.strip() for k in trusted_keys}
        report.key_trusted = all(e.public_key.strip() in trusted for e in entries)
        if not report.key_trusted:
            report.findings.append(
                Finding("untrusted_key", "One or more entries signed by an unrecognized key.")
            )
    else:
        report.findings.append(
            Finding(
                "key_identity_unchecked",
                "No trusted key set supplied. Signature validity does not "
                "establish who produced the artifact.",
            )
        )

    runs = [e for e in entries if e.kind is EntryKind.RUN_SEAL]
    commitments = {e.block_hash: e for e in entries
                   if e.kind is EntryKind.EVIDENCE_COMMITMENT}
    bindings = [e for e in entries if e.kind is EntryKind.WORKFILE_BINDING]

    if not runs:
        report.findings.append(Finding("no_runs", "Artifact seals no analysis."))
        return report

    # Primitives, per the three properties. Reported over the last run.
    # Worst case across every run rather than whichever happened to be last.
    # Reporting only runs[-1] let a dirty run hide behind a clean one sealed
    # after it, including the retention read that decides KC2 above.
    def _worst(kind: PrimitiveKind) -> dict[str, Any]:
        recs = [(r.body.get("primitives", {}) or {}).get(kind.value) or {}
                for r in runs]
        absent = [r for r in recs if not r.get("commitment")]
        if absent:
            return absent[0]
        floating = [r for r in recs
                    if r.get("pinning") == Pinning.FLOATING.value]
        if floating:
            return floating[0]
        unreachable = [r for r in recs
                       if r.get("holder") not in ("appraiser", "custodian")]
        return unreachable[0] if unreachable else recs[0]

    for kind in PrimitiveKind:
        rec = _worst(kind)
        present = bool(rec and rec.get("commitment"))
        report.primitives_present[kind.value] = present
        report.primitives_pinned[kind.value] = (
            rec.get("pinning") if rec else Pinning.ABSENT.value
        )
        report.primitives_reachable[kind.value] = bool(
            rec and rec.get("holder") in ("appraiser", "custodian")
        )
        if not present:
            report.findings.append(
                Finding("primitive_absent", f"{kind.value} carries no commitment.",
                        "existence")
            )
        elif rec.get("pinning") == Pinning.FLOATING.value:
            report.findings.append(
                Finding(
                    "primitive_floating",
                    f"{kind.value} points at a live surface and resolves to present state.",
                    "pinning",
                )
            )

    # Binding level, taken as the weakest across all sealed runs.
    level = BindingLevel.REDERIVED
    for run in runs:
        level = min(level, _run_binding_level(run, commitments, report, rederive),
                    key=lambda x: x.value)
    report.binding_level = level

    # Whether a commodity timestamping service could have produced the same
    # evidentiary force. See BindingLevel and kc2_fires for the reasoning.
    if level.value <= BindingLevel.PRECEDENCE.value:
        report.timestamp_replicable = True
        report.findings.append(
            Finding(
                "kc2_fires",
                f"Artifact reaches {level.name}. Two independent timestamps over "
                "local files reach PRECEDENCE, so nothing here exceeds a "
                "commodity timestamping service.",
                "KC2",
            )
        )
    elif level in (BindingLevel.REDERIVABLE, BindingLevel.REDERIVED):
        # Re-derivation only escapes the timestamp if the input cannot be held
        # locally. A locally retainable input set can be timestamped and re-run
        # without a custodian.
        #
        # This used to read `primitives.evidence.retention` out of the run
        # body. That field records what the artifact carries, meaning bytes or
        # a commitment, which is a different fact from whether the operator can
        # hold the raw input, and only the second decides KC2. Reading one and
        # calling it the other let nine characters in a field the sealer writes
        # clear a kill condition, which is the defect `witness_mode` already
        # demonstrates elsewhere in this function.
        #
        # Fails closed and reads across every run, not just the last. A run
        # whose tool is unsourced makes the whole artifact replicable, so an
        # artifact recording less cannot grade better.
        holdings = [assess_holding(r, entries, retention_determinations)
                    for r in runs]
        cleared = [h for h in holdings if h.clears_kc2]
        report.timestamp_replicable = len(cleared) != len(holdings)

        worst = next((h for h in holdings if not h.clears_kc2), holdings[0])
        report.input_provenance = worst.provenance
        report.input_holding = worst.holding

        for h in holdings:
            for detail in h.findings:
                report.findings.append(
                    Finding(f"input_{h.provenance.value}", detail, "KC2")
                )
        if report.timestamp_replicable:
            report.findings.append(
                Finding(
                    "kc2_fires",
                    f"Artifact reaches {level.name}, and nothing outside it "
                    "establishes that the operator cannot hold the raw input. "
                    "Where the input can be held, the same folder can be "
                    "timestamped and re-run locally, so re-derivation adds "
                    "nothing a commodity service could not.",
                    "KC2",
                )
            )
    else:
        report.timestamp_replicable = False

    for detail in retention_conflicts(retention_determinations or ()):
        report.findings.append(Finding("retention_contested", detail, "KC2"))

    # Coverage, which is design question three.
    #
    # This check previously looked only at entries earlier than the binding,
    # which let an appraiser certify a clean run and then keep working. Runs
    # sealed after the last binding are the obvious way to cherry-pick, so the
    # window is the whole chain.
    if not bindings:
        report.coverage = Coverage.ABSENT
        report.findings.append(
            Finding("no_workfile_binding", "No Layer 2 binding at certification.",
                    "design question three")
        )
    else:
        stray = sorted({b.body.get("assignment_id") for b in bindings}
                       - {report.assignment_id})
        if report.assignment_id is not None and stray:
            report.findings.append(
                Finding(
                    "binding_assignment_mismatch",
                    f"A workfile binding certifies assignment {stray} while "
                    f"the chain is anchored to {report.assignment_id}. The "
                    "assignment is fixed at open and cannot be changed by the "
                    "entry written last.",
                    "assignment custody",
                )
            )

        binding = bindings[-1]
        covered = set(binding.body.get("covered_seqs", []))
        expected = {e.seq for e in entries if e.seq < binding.seq}
        present = {e.seq for e in entries}
        head_ok = binding.body.get("chain_head") == entries[binding.seq - 1].block_hash

        # Runs sealed after the last binding are outside every binding.
        after = [e.seq for e in runs if e.seq > binding.seq]

        omitted = sorted(expected - covered)
        phantom = sorted(covered - present)

        if covered == expected and head_ok and not after:
            report.coverage = Coverage.CONTIGUOUS
        else:
            report.coverage = Coverage.SUBSET
            if omitted:
                report.findings.append(
                    Finding(
                        "selective_binding",
                        f"Binding names a subset of the chain. Omitted: {omitted}. "
                        "A run can be excluded without detection.",
                        "design question three",
                    )
                )
            if after:
                report.findings.append(
                    Finding(
                        "runs_after_certification",
                        f"Runs at {after} were sealed after the last binding and "
                        "are covered by no binding at all. Certifying early and "
                        "continuing to work defeats the completeness property.",
                        "KC3",
                    )
                )
            if phantom:
                report.findings.append(
                    Finding(
                        "binding_names_missing_entries",
                        f"Binding claims entries {phantom} that are not in the "
                        "artifact. The chain has been truncated or the binding "
                        "was written against a different chain.",
                        "KC3",
                    )
                )
            if not (omitted or phantom or after or not head_ok):
                report.findings.append(
                    Finding(
                        "binding_covers_unexpected_seqs",
                        f"Binding covers {sorted(covered)} where {sorted(expected)} "
                        "was expected. Coverage is degraded with no more "
                        "specific cause identified.",
                        "design question three",
                    )
                )
            if not head_ok:
                report.findings.append(
                    Finding(
                        "binding_head_mismatch",
                        "The binding names a chain head that is not the entry "
                        "preceding it.",
                        "KC3",
                    )
                )

    return report


def _check_completeness(
    artifact: dict[str, Any],
    entries: list[Entry],
    checkpoint: Optional[dict[str, Any]],
    report: VerificationReport,
) -> None:
    """
    Compare the artifact against somebody else's statement of its length.

    This is the only check in the package whose input the sealer did not write.
    Everything else reads fields from the artifact, which is why the cold
    review concluded that KC2 was being transcribed rather than computed.
    """
    if checkpoint is None:
        report.completeness = Completeness.UNCHECKED
        report.findings.append(
            Finding(
                "no_checkpoint",
                "No checkpoint supplied. Truncation is undetectable without "
                "one: an artifact of three entries and an artifact cut from "
                "five to three are the same document.",
                "completeness",
            )
        )
        return

    if not cp_signature_valid(checkpoint):
        report.completeness = Completeness.UNUSABLE
        report.findings.append(
            Finding("checkpoint_signature_invalid",
                    "The checkpoint does not verify against its own key.",
                    "completeness")
        )
        return

    # A checkpoint signed by the sealer is the sealer vouching for themselves,
    # which is the situation the checkpoint exists to escape.
    signer = (cp_signer_pem(checkpoint) or "").strip()
    if any(signer == e.public_key.strip() for e in entries):
        report.completeness = Completeness.UNUSABLE
        report.findings.append(
            Finding(
                "checkpoint_self_issued",
                "The checkpoint is signed by the same key that signed the "
                "chain, so it adds nothing the artifact did not already claim.",
                "completeness",
            )
        )
        return

    cp, _, _ = cp_load(checkpoint)
    head = entries[-1].block_hash if entries else GENESIS

    if cp.entry_count > len(entries):
        report.completeness = Completeness.SHORT
        report.findings.append(
            Finding(
                "artifact_truncated",
                f"The checkpoint records {cp.entry_count} entries and the "
                f"artifact carries {len(entries)}. "
                f"{cp.entry_count - len(entries)} were not disclosed.",
                "completeness",
            )
        )
    elif cp.chain_head != head or cp.entry_count < len(entries):
        report.completeness = Completeness.MISMATCHED
        report.findings.append(
            Finding(
                "checkpoint_describes_another_chain",
                "The checkpoint names a head or a length this artifact does "
                "not have. It may belong to a different chain for the same "
                "assignment.",
                "completeness",
            )
        )
    else:
        report.completeness = Completeness.CONSISTENT


def _check_assignment(
    artifact: dict[str, Any],
    entries: list[Entry],
    assignment_checkpoint: Optional[dict[str, Any]],
    report: VerificationReport,
) -> None:
    """
    Whether anything outside this chain says how many chains the assignment has.

    A per-chain checkpoint is honest about the chain it names and silent about
    every other, so five chains under one assignment each verify perfectly and
    each carry a true checkpoint. Counting siblings is a question only the party
    holding all of them can answer, which is why the input here is the
    custodian's and not the sealer's.
    """
    ident = chain_identity(entries)
    report.assignment_id = ident[0] if ident else None

    result = assess_disclosure([artifact], assignment_checkpoint)
    report.disclosure = result.state
    report.chains_withheld = len(result.withheld)

    code = {
        Disclosure.UNANCHORED: "chain_names_no_assignment",
        Disclosure.UNCHECKED: "no_assignment_checkpoint",
        Disclosure.UNUSABLE: "assignment_checkpoint_unusable",
        Disclosure.FOREIGN: "chain_not_in_assignment",
        Disclosure.PARTIAL: "sibling_chains_withheld",
    }.get(result.state)
    if code:
        for detail in result.findings:
            report.findings.append(Finding(code, detail, "assignment custody"))


def _run_binding_level(
    run: Entry,
    commitments: dict[str, Entry],
    report: VerificationReport,
    rederive: Optional[Callable[[dict[str, Any]], Optional[str]]] = None,
) -> BindingLevel:
    """Classify one run seal. Strongest claim the evidence actually supports."""
    body = run.body
    mode = body.get("witness_mode")
    ref = body.get("evidence_commitment_hash")

    if ref is None:
        report.findings.append(
            Finding(
                "no_evidence_commitment",
                f"Run {body.get('run_id')} names no prior evidence commitment. "
                "Nothing fixes the inputs ahead of the output.",
                "KC1",
            )
        )
        return BindingLevel.BUNDLED

    committed = commitments.get(ref)
    if committed is None:
        report.findings.append(
            Finding("dangling_commitment",
                    f"Run {body.get('run_id')} names an evidence commitment not in the chain.")
        )
        return BindingLevel.BUNDLED

    if committed.seq >= run.seq:
        report.findings.append(
            Finding(
                "commitment_not_prior",
                f"Evidence commitment at seq {committed.seq} does not precede run "
                f"at seq {run.seq}. Inputs were fixed after the output existed.",
                "KC1",
            )
        )
        return BindingLevel.BUNDLED

    if mode == WitnessMode.REDERIVABLE.value:
        recipe = body.get("rederivation_recipe")

        # A recipe must be tied to the two things the artifact claims, or
        # re-derivation proves only that the recipe is self-consistent.
        # Without both checks the verifier compares the recipe against itself,
        # which is KC2 stated.
        if RederivationRecipe.is_complete(recipe):
            action = (body.get("primitives", {})
                          .get(PrimitiveKind.ACTION.value, {})
                          .get("commitment"))
            if recipe.get("output_digest") != action:
                report.findings.append(
                    Finding(
                        "recipe_output_not_the_action",
                        f"Run {body.get('run_id')} carries a recipe whose "
                        "output_digest is not the Action this artifact seals. "
                        "Re-deriving it would reproduce some number, but not "
                        "the one claimed.",
                        "KC2",
                    )
                )
                return BindingLevel.PRECEDENCE
            if recipe.get("input_ref") != ref:
                report.findings.append(
                    Finding(
                        "recipe_input_not_the_evidence",
                        f"Run {body.get('run_id')} carries a recipe whose "
                        "input_ref is not the evidence commitment the run "
                        "names. Re-derivation would run on something else.",
                        "KC2",
                    )
                )
                return BindingLevel.PRECEDENCE

        if not RederivationRecipe.is_complete(recipe):
            missing = [f for f in RederivationRecipe.REQUIRED
                       if not (recipe or {}).get(f)]
            report.findings.append(
                Finding(
                    "incomplete_recipe",
                    f"Run {body.get('run_id')} claims re-derivability but the "
                    f"recipe is missing {missing}. A recipe a stranger cannot "
                    "execute is a claim, not a proof.",
                    "KC2",
                )
            )
            return BindingLevel.PRECEDENCE
        if rederive is None:
            report.findings.append(
                Finding(
                    "not_rederived",
                    f"Run {body.get('run_id')} carries a complete recipe that was "
                    "not executed. Supply a rederive callback to reach REDERIVED.",
                    "KC2",
                )
            )
            return BindingLevel.REDERIVABLE
        # The callback used to receive the whole recipe including
        # output_digest, which is the answer it is being asked to produce.
        # Passing the target to the oracle under test is the wrong shape
        # regardless of who runs it.
        produced = rederive({k: v for k, v in recipe.items()
                             if k != "output_digest"})
        if produced is None:
            report.findings.append(
                Finding(
                    "rederivation_unavailable",
                    f"Run {body.get('run_id')} could not be re-executed. The "
                    "pinned version is no longer servable, so the evidentiary "
                    "claim has decayed to its recipe.",
                    "liveness",
                )
            )
            return BindingLevel.REDERIVABLE
        if produced != recipe.get("output_digest"):
            report.findings.append(
                Finding(
                    "rederivation_mismatch",
                    f"Run {body.get('run_id')} re-executed to a different output "
                    f"than the sealed one. Expected {recipe.get('output_digest')}, "
                    f"produced {produced}.",
                    "KC2",
                )
            )
            return BindingLevel.PRECEDENCE
        return BindingLevel.REDERIVED

    if mode == WitnessMode.INDEPENDENT.value:
        # Granting WITNESSED here would be the cheapest route to clearing KC2
        # in the whole package: nine characters in a field the sealer writes,
        # with no recipe and no
        # re-derivation. Nothing in this artifact can carry evidence that an
        # outside party observed anything, because there is no second
        # signature and no external anchor. Until one exists the declaration
        # is a claim, and claims do not clear kill conditions.
        report.findings.append(
            Finding(
                "witness_self_declared",
                f"Run {body.get('run_id')} declares an independent witness. "
                "The artifact carries no second signature and no external "
                "anchor, so nothing distinguishes this from self-attestation.",
                "KC2",
            )
        )
    return BindingLevel.PRECEDENCE


__all__ = ["BindingLevel", "Completeness", "Coverage", "Finding",
           "VerificationReport", "verify"]


def _check_anchoring(
    entries: list[Entry],
    time_anchors: Optional[Iterable[dict[str, Any]]],
    beacon_resolver: Optional[BeaconResolver],
    trusted_authorities: Optional[Iterable[str]],
    report: VerificationReport,
) -> None:
    """
    Whether anything outside the chain constrains when it was written.

    `ts_ns` is signed and monotonic and is still a number the sealer chose, so
    a chain assembled today with last year's timestamps verifies. Two different
    facts are needed and they come from different places. A recognised
    authority bounds the chain from above. A committed unpredictable value
    bounds it from below, and the lower side is the one KC1 is about, which is
    why UPPER_ONLY is reported as its own state rather than counted as
    anchored.
    """
    result = resolve_bounds(
        entries,
        beacon_resolver=beacon_resolver,
        time_anchors=time_anchors,
        trusted_authorities=trusted_authorities,
    )
    report.anchoring = result.state
    report.anchor_interval_ns = result.interval_ns

    code = {
        Anchoring.INCONSISTENT: "instant_outside_anchor",
        Anchoring.UNANCHORED: "no_time_anchor",
        Anchoring.UPPER_ONLY: "backdating_unconstrained",
        Anchoring.LOWER_ONLY: "no_upper_time_bound",
        Anchoring.BOUNDED: "time_anchor_advisory",
    }[result.state]
    for detail in result.findings:
        report.findings.append(Finding(code, detail, "KC1"))


def verify(
    artifact: dict[str, Any],
    trusted_keys: Optional[Iterable[str]] = None,
    rederive: Optional[Callable[[dict[str, Any]], Optional[str]]] = None,
    checkpoint: Optional[dict[str, Any]] = None,
    assignment_checkpoint: Optional[dict[str, Any]] = None,
    time_anchors: Optional[Iterable[dict[str, Any]]] = None,
    beacon_resolver: Optional[BeaconResolver] = None,
    trusted_authorities: Optional[Iterable[str]] = None,
    retention_determinations: Optional[Iterable[dict[str, Any]]] = None,
) -> VerificationReport:
    """
    Fail-closed wrapper around the verification pass.

    Ten single-field mutations make a naive verifier raise instead of
    rejecting: a binding seq past the end of the
    chain, a null signature, a string where a recipe was expected, an unknown
    entry kind, an Ed25519 key where a P-256 key was expected. A crash is not a
    false clean, but the intended reader is an examiner running this years
    later against an artifact supplied by the opposing party, and any caller
    who wraps this in try/except and treats failure as inconclusive converts
    every one of them into a pass. So malformed input returns an untrustworthy
    report with a finding, and never propagates.
    """
    try:
        return _verify(artifact, trusted_keys=trusted_keys,
                       rederive=rederive, checkpoint=checkpoint,
                       assignment_checkpoint=assignment_checkpoint,
                       time_anchors=time_anchors,
                       beacon_resolver=beacon_resolver,
                       trusted_authorities=trusted_authorities,
                       retention_determinations=retention_determinations)
    except Exception as exc:  # noqa: BLE001 - hostile input is the whole point
        report = VerificationReport()
        report.findings.append(
            Finding(
                "malformed_artifact",
                f"Verification could not complete: {type(exc).__name__}: {exc}. "
                "The artifact is rejected rather than reported inconclusive.",
                "fail closed",
            )
        )
        return report
