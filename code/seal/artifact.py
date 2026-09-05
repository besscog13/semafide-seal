"""
Artifact schema: the two layers, and the chain that carries them.

Layer 1 seals each run at execution. Layer 2 binds the sealed runs at
certification. The two moments stay separate.

The chain carries four entry kinds. An assignment anchor opens the chain and
names the assignment every later entry belongs to. An evidence commitment fixes
the input set. A run seal records the analysis and names the commitment it
consumed. A workfile binding closes the assignment at certification. Ordering
across those kinds is what makes precedence checkable, and precedence is the
weakest property that rules out choosing evidence after seeing the output.

Without the anchor the assignment is named only in the binding, at the end,
which means no run is committed to an assignment at the moment it is sealed and
a chain can be relabelled afterwards. Declaring the assignment at open rather
than asserting it at certification is the same discipline as the two moments:
a fact is fixed when it is true, not when it becomes convenient. Note what this does not do. It stops a chain being moved
between assignments. It does nothing about five chains under one assignment,
because no field inside one chain can count its siblings.

This module writes and reads artifacts. It does not capture anything. Where a
witness sits, and whether capture can be made complete without breaking the
appraiser's workflow, is KC3 and remains open.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .primitives import (
    PrimitiveKind,
    PrimitiveRecord,
    canonical_bytes,
    commit,
)

GENESIS = "0" * 64


class EntryKind(Enum):
    ASSIGNMENT_ANCHOR = "assignment_anchor"
    EVIDENCE_COMMITMENT = "evidence_commitment"
    RUN_SEAL = "run_seal"
    WORKFILE_BINDING = "workfile_binding"


class WitnessMode(Enum):
    """
    Who observed the capture, and therefore what the seal can be said to attest.

    SELF_ATTESTED means the interested party asserts that the sealed bundle
    represents what the software queried. A third-party timestamping service
    reaches exactly this level, which is why it does not clear KC2.

    INDEPENDENT means a custodian outside the appraiser's control observed the
    capture. Whether this is achievable across the real tool environment is
    KC3.

    REDERIVABLE means the artifact carries a deterministic recipe and a
    verifier can re-execute the analysis and reproduce the output. Binding is
    then proven rather than asserted.
    """

    SELF_ATTESTED = "self_attested"
    INDEPENDENT = "independent"
    REDERIVABLE = "rederivable"


@dataclass(frozen=True)
class WitnessAttestation:
    """An outside witness's statement about one observed execution.

    A signature over an arbitrary supplied bundle is not this attestation.  The
    signed statement must explicitly say that the witness observed the
    execution relation and bind the run, committed evidence, and sealed action.
    The verifier also requires the signing key to be independently trusted.
    """

    witness: str
    public_key: str
    signature: str
    capture_ref: str
    statement: str = "observed_execution"

    def to_body(self) -> dict[str, Any]:
        return {
            "witness": self.witness,
            "public_key": self.public_key,
            "signature": self.signature,
            "capture_ref": self.capture_ref,
            "statement": self.statement,
        }


@dataclass(frozen=True)
class Entry:
    """
    One sealed chain entry.

    `seq` and `prev_hash` together make omission detectable: a verifier walking
    a contiguous chain from genesis notices a missing sequence number, whereas
    a verifier handed an arbitrary set of signed blobs cannot.
    """

    kind: EntryKind
    seq: int
    prev_hash: str
    body: dict[str, Any]
    ts_ns: int
    block_hash: str
    signature: str
    public_key: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "body": self.body,
            "ts_ns": self.ts_ns,
            "block_hash": self.block_hash,
            "signature": self.signature,
            "public_key": self.public_key,
        }

    @staticmethod
    def from_payload(d: dict[str, Any]) -> "Entry":
        return Entry(
            kind=EntryKind(d["kind"]),
            seq=d["seq"],
            prev_hash=d["prev_hash"],
            body=d["body"],
            ts_ns=d["ts_ns"],
            block_hash=d["block_hash"],
            signature=d["signature"],
            public_key=d["public_key"],
        )


def signing_payload(kind: EntryKind, seq: int, prev_hash: str,
                    body: dict[str, Any], ts_ns: int) -> dict[str, Any]:
    """The exact object that gets hashed and signed. Kept in one place so the
    writer and the verifier cannot drift."""
    return {
        "kind": kind.value,
        "seq": seq,
        "prev_hash": prev_hash,
        "body": body,
        "ts_ns": ts_ns,
    }


@dataclass(frozen=True)
class AssignmentAnchor:
    """
    Entry zero. Names the assignment before anything is sealed into it.

    Every later entry links back to this through `prev_hash`, so each run is
    committed to an assignment at the moment it is sealed rather than at
    certification. Without it the assignment appears only in the binding, which
    is written last by the party with the most reason to choose it.

    `chain_label` disambiguates chains a party legitimately opens under one
    assignment. It is a convenience for whoever operates the sealer and carries
    no evidentiary weight, since it is a string the sealer writes.

    `beacon` commits to a published value that could not have been predicted
    before it was issued, which is what bounds the chain from below. It sits in
    the anchor rather than in each entry because every later entry links
    forward from here, so a bound on when the chain was opened bounds all of
    them. See `anchor.py` for why the lower side is the one that matters and
    why a timestamp authority cannot supply it.
    """

    assignment_id: str
    chain_label: str = ""
    beacon: Optional[dict[str, Any]] = None

    def to_body(self) -> dict[str, Any]:
        return {"assignment_id": self.assignment_id,
                "chain_label": self.chain_label,
                "beacon": self.beacon}


class SealChain:
    """
    Append-only chain of sealed entries.

    The signing core is canonical JSON, SHA-256 block hash, prev_hash
    chaining, and ECDSA over SECP256R1, implemented here so this package
    depends on nothing outside `cryptography` and the standard library.

    Timestamps come from the caller. Chain order is carried by `seq` and
    `prev_hash`, not by clock values, so a wrong clock degrades the evidence
    without breaking the structure.
    """

    def __init__(self, assignment_id: str,
                 private_key: Optional[ec.EllipticCurvePrivateKey] = None,
                 opened_ns: int = 0, chain_label: str = "",
                 beacon: Optional[dict[str, Any]] = None):
        self._sk = private_key or ec.generate_private_key(ec.SECP256R1())
        self._pub_pem = (
            self._sk.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
        self._entries: list[Entry] = []
        self._assignment_id = assignment_id
        self._lock = threading.Lock()
        self.append(
            EntryKind.ASSIGNMENT_ANCHOR,
            AssignmentAnchor(assignment_id, chain_label, beacon).to_body(),
            opened_ns,
        )

    @property
    def public_key_pem(self) -> str:
        return self._pub_pem

    @property
    def assignment_id(self) -> str:
        return self._assignment_id

    @property
    def chain_id(self) -> str:
        """
        This chain's identity, which is the block hash of its anchor.

        Derived rather than chosen, so a sealer cannot give two chains one
        identity or one chain two. It is the name a custodian enumerating an
        assignment's chains refers to.
        """
        return self._entries[0].block_hash

    @property
    def head(self) -> str:
        return self._entries[-1].block_hash if self._entries else GENESIS

    @property
    def entries(self) -> list[Entry]:
        return list(self._entries)

    def append(self, kind: EntryKind, body: dict[str, Any], ts_ns: int) -> Entry:
        """
        Seal one entry onto the chain.

        Reading `seq` and `prev_hash`, signing over them, and appending the
        result are one locked step. Two concurrent callers computing `seq`
        and `prev` before either appends would both sign an entry claiming
        the same sequence number and the same predecessor: two different
        entries, both validly signed, both asserting they are position N
        extending the same prior entry. That is not a missing entry, which
        the verifier is built to notice; it is two entries occupying one
        position, which breaks the linkage this whole chain exists to
        provide. Existing callers in `capture/` already hold a coarser lock
        around every `append`, so this is a second, independent guard for any
        caller that constructs a `SealChain` directly.
        """
        with self._lock:
            seq = len(self._entries)
            prev = self.head
            payload = signing_payload(kind, seq, prev, body, ts_ns)
            raw = canonical_bytes(payload)
            block_hash = hashlib.sha256(raw).hexdigest()
            sig = self._sk.sign(raw, ec.ECDSA(hashes.SHA256())).hex()

            entry = Entry(
                kind=kind,
                seq=seq,
                prev_hash=prev,
                body=body,
                ts_ns=ts_ns,
                block_hash=block_hash,
                signature=sig,
                public_key=self._pub_pem,
            )
            self._entries.append(entry)
            return entry


@dataclass(frozen=True)
class EvidenceCommitment:
    """
    Layer 1, first move. Fixes the input set before the analysis runs.

    `row_root` is a Merkle root over the ordered row hashes, so a later
    challenge can prove membership without the artifact retaining the rows.
    Whether retention is permitted at all is a licensing question and is open.
    """

    commitment_id: str
    row_root: str
    row_count: int
    source: str
    as_of: str
    query_descriptor: dict[str, Any] = field(default_factory=dict)

    def to_body(self) -> dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "row_root": self.row_root,
            "row_count": self.row_count,
            "source": self.source,
            "as_of": self.as_of,
            "query_descriptor": self.query_descriptor,
        }


@dataclass(frozen=True)
class RederivationRecipe:
    """
    What a third party needs to re-execute the analysis and compare.

    Re-derivation is the only mechanism this product targets for the
    evidentiary bar. A recipe a stranger cannot execute is a claim rather
    than a proof, so every field here is required and the verifier treats a
    partial recipe as absent.

    `version` must be an exact pinned version and never a range, because a
    range does not identify what ran. `service_window` records how long the
    partner has committed to keeping that version executable, which is the
    liveness dependency this mechanism carries and which a signature does
    not.

    KNOWN DEFECT. These fields pin the tool and say nothing about the machine
    it runs on, the numerical libraries, or the linked BLAS. A partner who
    keeps one version servable for a decade and moves the hardware underneath
    it has honoured every commitment this schema asks for, and the re-run can
    still produce a different digest. `verifier` then reports
    `rederivation_mismatch` and drops the artifact to PRECEDENCE, which reads
    as the partner having altered the analysis when nothing about the analysis
    changed. Note the direction: this manufactures a false accusation rather
    than a false clearance, so it fails loudly against the honest partner and
    not quietly in favour of a dishonest one.

    Not fixed here. The fix is an environment manifest beside the recipe, and
    it waits on the determinism question being put to a vendor engineer,
    because that answer decides whether an environment can be pinned tightly
    enough to matter.
    """

    endpoint: str
    tool: str
    version: str
    invocation: dict[str, Any]
    input_ref: str
    output_digest: str
    service_window: str

    REQUIRED = (
        "endpoint", "tool", "version", "invocation",
        "input_ref", "output_digest", "service_window",
    )

    def to_body(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "tool": self.tool,
            "version": self.version,
            "invocation": self.invocation,
            "input_ref": self.input_ref,
            "output_digest": self.output_digest,
            "service_window": self.service_window,
        }

    @staticmethod
    def is_complete(d: Optional[dict[str, Any]]) -> bool:
        if not d:
            return False
        return all(d.get(f) for f in RederivationRecipe.REQUIRED)


@dataclass(frozen=True)
class RunSeal:
    """
    Layer 1, second move. The analysis, with all six primitives recorded.

    `evidence_commitment_hash` names the block hash of the evidence entry this
    run consumed. A run that names no prior commitment can only ever reach the
    weakest binding level, because nothing fixes the inputs ahead of the output.
    """

    run_id: str
    primitives: dict[PrimitiveKind, PrimitiveRecord]
    evidence_commitment_hash: Optional[str]
    witness_mode: WitnessMode
    rederivation_recipe: Optional[dict[str, Any]] = None
    witness_attestation: Optional[dict[str, Any]] = None

    def to_body(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "primitives": {
                k.value: v.to_payload() for k, v in sorted(
                    self.primitives.items(), key=lambda kv: kv[0].value
                )
            },
            "evidence_commitment_hash": self.evidence_commitment_hash,
            "witness_mode": self.witness_mode.value,
            "rederivation_recipe": self.rederivation_recipe,
            "witness_attestation": self.witness_attestation,
        }


@dataclass(frozen=True)
class WorkfileBinding:
    """
    Layer 2. Binds the assignment at certification.

    `chain_head` names the head at the moment of certification and
    `covered_seqs` names the entries claimed. A binding that names the head of
    a contiguous chain makes omission detectable. A binding that names an
    arbitrary subset does not, which is design question three.
    """

    assignment_id: str
    chain_head: str
    covered_seqs: list[int]
    certification_ref: str
    effective_date: str

    def to_body(self) -> dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "chain_head": self.chain_head,
            "covered_seqs": sorted(self.covered_seqs),
            "certification_ref": self.certification_ref,
            "effective_date": self.effective_date,
        }


def export_artifact(chain: SealChain) -> dict[str, Any]:
    """Serialize a chain to a transportable artifact."""
    return {
        "schema": "semafide.seal.v0",
        "entries": [e.to_payload() for e in chain.entries],
    }


def chain_identity(entries: list[Entry]) -> Optional[tuple[str, str]]:
    """
    The assignment and chain identity an artifact carries, or None.

    Returns None when entry zero is not an anchor, which is either a chain
    written against an older schema or one whose anchor was stripped. Both are the
    same thing to an examiner: a chain that names no assignment, and therefore
    one that no assignment-level statement can be checked against.
    """
    if not entries or entries[0].kind is not EntryKind.ASSIGNMENT_ANCHOR:
        return None
    aid = entries[0].body.get("assignment_id")
    if not isinstance(aid, str) or not aid:
        return None
    return aid, entries[0].block_hash


def load_artifact(doc: dict[str, Any]) -> list[Entry]:
    """Read a transported artifact back into entries. No verification here."""
    return [Entry.from_payload(e) for e in doc.get("entries", [])]


__all__ = [
    "GENESIS",
    "EntryKind",
    "WitnessMode",
    "WitnessAttestation",
    "Entry",
    "AssignmentAnchor",
    "SealChain",
    "chain_identity",
    "EvidenceCommitment",
    "RederivationRecipe",
    "RunSeal",
    "WorkfileBinding",
    "signing_payload",
    "export_artifact",
    "load_artifact",
    "commit",
]
