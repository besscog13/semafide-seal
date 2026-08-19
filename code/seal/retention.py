"""
Whether the operator holds the raw input, determined by somebody who is not
the operator.

THE DEFECT THIS CLOSES. KC2 asks whether the mechanism does anything a
third-party-timestamped bundle of the same local files could not do.
Re-derivation escapes that only where the input cannot be kept by the party who
has to prove something, because a folder that can be held can be timestamped
and re-run without a custodian. So the whole clearance rests on one fact:
does the raw input land on the operator's machine.

The verifier used to answer that by reading `primitives.evidence.retention` out
of the run body. That field is real and it is not the answer. It records what
the artifact carries, meaning bytes or a commitment, which is the sealer's own
business and which the sealer is the right party to declare. Whether the
operator can hold the input is a fact about the tool's documented workflow, it
is constant across every run that tool produces, and the sealer has an interest
in the answer. Reading one and calling it the other is the same class of error
as reading `witness_mode` and calling it a witness.

WHAT A DETERMINATION IS. A signed statement naming a tool and a pinned version,
what the reading found, where it was read, and a digest of the source as read.
Vendor documentation changes, so a determination that cites a page without
fixing its content decays into an assertion about a moving target.

WHAT IT IS NOT. This is provenance rather than proof. Nothing here establishes
that the reading was correct, and nothing can: no cryptographic construction
verifies that somebody read a manual accurately. What the verifier computes is
whether a reading was recorded, by a key that is not the sealer's, against a
source a later reader can go and check. That is the same standing a checkpoint
has. The trust does not disappear, it moves to the determiner, which is the
point.

FAILS CLOSED. Absent, unusable, self-issued, mismatched, and undetermined all
resolve the same way: the input is treated as locally retainable and KC2 fires.
An artifact recording less about its inputs must never grade better on the
condition that turns on its inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .artifact import Entry, RederivationRecipe
from .primitives import canonical_bytes


class Holding(Enum):
    """
    What the tool's documented workflow does with the raw input.

    OPERATOR_HOLDS is the finding the tool export audit returned. Bradford
    documents Redstone as: export a CSV, TXT or TSV of the chosen comparables
    from the MLS, save it on your computer, then import it. The rows are in the
    operator's hands before the tool runs, so the same folder can be timestamped
    locally and re-run later, and re-derivation buys nothing.

    OPERATOR_CANNOT_HOLD is the condition that would create a seat: the input is
    resolved inside the partner's service and never lands anywhere the operator
    can keep it.

    UNDETERMINED is what an honest reading returns when the documentation does
    not say. It is recorded rather than guessed, and it resolves against
    clearance exactly as OPERATOR_HOLDS does.
    """

    OPERATOR_HOLDS = "operator_holds"
    OPERATOR_CANNOT_HOLD = "operator_cannot_hold"
    UNDETERMINED = "undetermined"


class Provenance(Enum):
    """Where the retention answer for a run came from."""

    UNSOURCED = "unsourced"
    UNUSABLE = "unusable"
    SELF_ISSUED = "self_issued"
    MISMATCHED = "mismatched"
    SOURCED = "sourced"


@dataclass(frozen=True)
class RetentionDetermination:
    """
    One reading of one tool at one pinned version.

    `version` is exact and never a range, for the reason `RederivationRecipe`
    pins exactly: a range does not identify what was read. A workflow is usually
    stable across versions and saying so is a claim beyond the reading, so a
    determination speaks for the version named and no other.

    `source` cites where the workflow was read. `source_digest` fixes the text
    as it stood, so a later reader can tell whether the page has moved since.
    `determined_by` names the party who read it, which is the field the verifier
    checks against the chain key.
    """

    tool: str
    version: str
    holding: Holding
    source: str
    source_digest: str
    read_as_of: str
    determined_by: str

    REQUIRED = ("tool", "version", "holding", "source", "source_digest",
                "read_as_of", "determined_by")

    def signing_payload(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "holding": self.holding.value,
            "source": self.source,
            "source_digest": self.source_digest,
            "read_as_of": self.read_as_of,
            "determined_by": self.determined_by,
        }

    def to_payload(self, signature: str, public_key: str) -> dict[str, Any]:
        d = self.signing_payload()
        d["signature"] = signature
        d["public_key"] = public_key
        return d


def issue(
    determination: RetentionDetermination,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    """
    Sign a determination.

    Stateless on purpose, and the contrast with `checkpoint.Issuer` is worth
    stating. A checkpoint issuer must remember, because two checkpoints of the
    same size over different chains are an equivocation the mechanism has to
    refuse. A determination carries no such risk. Two readings of one tool at
    one version that disagree are not an equivocation to be prevented, they are
    a disagreement a reader should see, and `conflicts` surfaces it rather than
    suppressing it.

    The key must not be the one that signed the chain. Nothing here enforces
    that, which is why the verifier refuses a determination sharing the
    artifact's key rather than trusting the determiner to have used another.
    """
    raw = canonical_bytes(determination.signing_payload())
    sig = private_key.sign(raw, ec.ECDSA(hashes.SHA256())).hex()
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return determination.to_payload(sig, pub)


def load(doc: dict[str, Any]) -> tuple[RetentionDetermination, str, str]:
    """Read a transported determination. No verification here."""
    return (
        RetentionDetermination(
            tool=doc["tool"],
            version=doc["version"],
            holding=Holding(doc["holding"]),
            source=doc["source"],
            source_digest=doc["source_digest"],
            read_as_of=doc["read_as_of"],
            determined_by=doc["determined_by"],
        ),
        doc["signature"],
        doc["public_key"],
    )


def signature_valid(doc: dict[str, Any]) -> bool:
    try:
        det, sig, pem = load(doc)
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        pub.verify(bytes.fromhex(sig),
                   canonical_bytes(det.signing_payload()),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - hostile input is expected here
        return False


def signer_pem(doc: dict[str, Any]) -> Optional[str]:
    try:
        return doc["public_key"]
    except Exception:  # noqa: BLE001
        return None


@dataclass
class HoldingReport:
    """What the determinations establish about one run."""

    provenance: Provenance = Provenance.UNSOURCED
    holding: Holding = Holding.UNDETERMINED
    findings: list[str] = field(default_factory=list)

    @property
    def clears_kc2(self) -> bool:
        """
        The only combination under which re-derivation exceeds a local
        timestamp. Every other path through `assess` leaves this false.
        """
        return (self.provenance is Provenance.SOURCED
                and self.holding is Holding.OPERATOR_CANNOT_HOLD)


def conflicts(determinations: Iterable[dict[str, Any]]) -> list[str]:
    """
    Readings of one tool and version that disagree with each other.

    Reported rather than resolved. Two parties who read the same documentation
    and reached different answers is information about the reading, and picking
    a winner here would hide it.
    """
    seen: dict[tuple[str, str], set[str]] = {}
    for doc in determinations or ():
        if not signature_valid(doc):
            continue
        det, _, _ = load(doc)
        seen.setdefault((det.tool, det.version), set()).add(det.holding.value)
    return [
        f"tool {tool} at version {version} has conflicting determinations: "
        f"{sorted(values)}"
        for (tool, version), values in sorted(seen.items())
        if len(values) > 1
    ]


def assess(
    run: Entry,
    entries: list[Entry],
    determinations: Optional[Iterable[dict[str, Any]]],
) -> HoldingReport:
    """
    Resolve the holding question for one run.

    The tool and version come from the re-derivation recipe rather than from
    the Evaluator primitive, because the primitive carries a commitment and a
    commitment does not say what it commits to. Only runs carrying a complete
    recipe reach this, since anything weaker is capped at PRECEDENCE and KC2
    fires without consulting retention at all.
    """
    report = HoldingReport()
    recipe = run.body.get("rederivation_recipe")
    if not RederivationRecipe.is_complete(recipe):
        report.findings.append(
            "The run carries no complete recipe, so no tool and version "
            "identify what would have to be read.")
        return report

    tool, version = recipe.get("tool"), recipe.get("version")
    chain_keys = {e.public_key.strip() for e in entries}
    matched = []

    for doc in determinations or ():
        if not isinstance(doc, dict):
            continue
        if doc.get("tool") != tool or doc.get("version") != version:
            continue
        matched.append(doc)

    if not matched:
        report.findings.append(
            f"No retention determination covers {tool} at version {version}. "
            "The artifact's own retention field records what this document "
            "carries, not whether the operator can hold the input, so nothing "
            "here answers the question KC2 turns on.")
        return report

    usable = []
    for doc in matched:
        if not signature_valid(doc):
            report.provenance = Provenance.UNUSABLE
            report.findings.append(
                f"A determination for {tool} at version {version} does not "
                "verify against its own key.")
            continue
        if (signer_pem(doc) or "").strip() in chain_keys:
            report.provenance = Provenance.SELF_ISSUED
            report.findings.append(
                f"A determination for {tool} at version {version} is signed by "
                "the same key that signed the chain. The sealer reading the "
                "sealer's own tool documentation is the sealer vouching for "
                "itself on the point at issue.")
            continue
        usable.append(doc)

    if not usable:
        return report

    holdings = {Holding(d["holding"]) for d in usable}
    if len(holdings) > 1:
        report.provenance = Provenance.MISMATCHED
        report.findings.append(
            f"Determinations for {tool} at version {version} disagree: "
            f"{sorted(h.value for h in holdings)}. A contested reading does "
            "not clear a kill condition.")
        return report

    report.provenance = Provenance.SOURCED
    report.holding = holdings.pop()
    det, _, _ = load(usable[0])

    if report.holding is Holding.OPERATOR_HOLDS:
        report.findings.append(
            f"{det.determined_by} determined that {tool} at version {version} "
            f"starts from a file the operator already holds, read at "
            f"{det.source}. The same folder can be timestamped locally and "
            "re-run without a custodian.")
    elif report.holding is Holding.UNDETERMINED:
        report.findings.append(
            f"{det.determined_by} read {det.source} and could not determine "
            f"whether {tool} at version {version} puts the raw input in the "
            "operator's hands. An unresolved reading resolves against "
            "clearance.")
    return report


__all__ = [
    "Holding",
    "HoldingReport",
    "Provenance",
    "RetentionDetermination",
    "assess",
    "conflicts",
    "issue",
    "load",
    "signature_valid",
    "signer_pem",
]
