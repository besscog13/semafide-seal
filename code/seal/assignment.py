"""
Assignment-level custody: how many chains an assignment holds.

The anchor in `artifact.py` stops a chain being moved between assignments. It
does nothing about the harder attack: seal five analyses in five separate
chains under one assignment and disclose the one you like. Every chain links from genesis. Every signature
verifies. Every per-chain checkpoint is honest, because each chain really is
the length its checkpoint says. The examiner is handed one of five and has no
way to learn that four exist.

This is the truncation finding one dimension over, and it has the same shape.
Truncation hides entries inside a chain. Sibling chains hide whole chains inside
an assignment. Both are claims about what is absent, and no field added to a
self-contained document establishes one, because the party choosing what ships
also chooses what to omit. A per-chain checkpoint cannot close it either: it
speaks for the chain it names and says nothing about any other.

So the fix is the same move made one level out. `checkpoint.py` is a statement
by somebody else about how long one chain is. This is a statement by somebody
else about which chains an assignment contains. An examiner holding one compares
the chains they were given against the chains that exist, and the difference is
the number of analyses somebody chose not to hand over.

WHAT THIS DOES NOT SOLVE, and it is the honest half. The statement is only as
complete as what the custodian received. A run sealed to a chain that was never
submitted is invisible to this and to everything else in the package, because
nothing here observes the appraiser's machine. That is capture completeness,
which is KC3, and it is open. What is closed is the disclosure side: given that
the custodian saw the work, the party under examination can no longer choose
which parts of it the examiner learns about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .artifact import Entry, chain_identity, load_artifact
from .primitives import canonical_bytes


@dataclass(frozen=True)
class ChainRef:
    """One chain as the custodian saw it."""

    chain_id: str
    head: str
    entry_count: int

    def to_payload(self) -> dict[str, Any]:
        return {"chain_id": self.chain_id, "head": self.head,
                "entry_count": self.entry_count}


@dataclass(frozen=True)
class AssignmentCheckpoint:
    """
    A signed statement of every chain an assignment holds.

    The chain list is what a per-chain checkpoint cannot carry. Sorted by
    `chain_id` on the way into the signature, so the same set of chains signs
    identically whatever order the custodian happened to hold them in and a
    reordered list is not a different statement.

    `issuer` and `observed_ns` belong to the custodian. As with the per-chain
    checkpoint, nothing in this module can enforce that the signing key is not
    the sealer's, which is why `assess` refuses a checkpoint sharing a key with
    the artifacts rather than trusting the issuer to have used another.
    """

    assignment_id: str
    chains: tuple[ChainRef, ...]
    observed_ns: int
    issuer: str

    def signing_payload(self) -> dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "chains": [c.to_payload() for c in
                       sorted(self.chains, key=lambda c: c.chain_id)],
            "observed_ns": self.observed_ns,
            "issuer": self.issuer,
        }


class AssignmentRefusal(Exception):
    """Raised when an issuer will not sign. The reason is the finding."""


@dataclass
class Issuer:
    """
    A stateful assignment-checkpoint issuer.

    The same defect the per-chain checkpoint had, one level out. A stateless
    signer can be asked twice for one assignment and will happily sign a
    five-chain statement and then a three-chain statement, and a sealer
    produces whichever one suits. An assignment only ever gains chains, so
    dropping a chain that was previously listed is the move to refuse.

    Sizes are allowed to grow, since a chain that was open when the first
    statement was made is longer when the second is. Shrinking is not: a chain
    the custodian previously recorded at ten entries cannot later be recorded at
    six without the custodian having discarded something.
    """

    name: str
    key: ec.EllipticCurvePrivateKey
    _last: dict[str, AssignmentCheckpoint] = field(default_factory=dict)

    def issue(self, checkpoint: AssignmentCheckpoint) -> dict[str, Any]:
        prior = self._last.get(checkpoint.assignment_id)
        if prior is not None:
            now = {c.chain_id: c for c in checkpoint.chains}
            dropped = sorted({c.chain_id for c in prior.chains} - set(now))
            if dropped:
                raise AssignmentRefusal(
                    f"{len(dropped)} chain or chains previously recorded under "
                    f"assignment {checkpoint.assignment_id} are absent from "
                    "this statement")
            for old in prior.chains:
                if now[old.chain_id].entry_count < old.entry_count:
                    raise AssignmentRefusal(
                        f"chain {old.chain_id[:12]} shrank from "
                        f"{old.entry_count} to "
                        f"{now[old.chain_id].entry_count} entries")
        signed = issue(checkpoint, self.key)
        self._last[checkpoint.assignment_id] = checkpoint
        return signed


def issue(checkpoint: AssignmentCheckpoint,
          private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """
    Sign an assignment checkpoint with no memory of what was signed before.

    The primitive rather than the mechanism. A custodian must use `Issuer`, for
    the reason recorded there and in `checkpoint.Issuer`. The key must not be
    the sealer's.
    """
    raw = canonical_bytes(checkpoint.signing_payload())
    d = checkpoint.signing_payload()
    d["signature"] = private_key.sign(raw, ec.ECDSA(hashes.SHA256())).hex()
    d["public_key"] = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return d


def load(doc: dict[str, Any]) -> AssignmentCheckpoint:
    """Read a transported assignment checkpoint. No verification here."""
    return AssignmentCheckpoint(
        assignment_id=doc["assignment_id"],
        chains=tuple(ChainRef(c["chain_id"], c["head"], c["entry_count"])
                     for c in doc["chains"]),
        observed_ns=doc["observed_ns"],
        issuer=doc["issuer"],
    )


def signature_valid(doc: dict[str, Any]) -> bool:
    try:
        cp = load(doc)
        pub = serialization.load_pem_public_key(
            doc["public_key"].encode("ascii"))
        pub.verify(bytes.fromhex(doc["signature"]),
                   canonical_bytes(cp.signing_payload()),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - hostile input is expected
        return False


class Disclosure(Enum):
    """
    What the artifacts handed over amount to, against the assignment.

    UNCHECKED is the honest default. Without a statement of which chains
    exist, one chain and one of five chains are the same document.
    """

    UNCHECKED = "unchecked"
    UNANCHORED = "unanchored"
    WHOLE = "whole"
    PARTIAL = "partial"
    FOREIGN = "foreign"
    UNUSABLE = "unusable"


@dataclass
class DisclosureReport:
    state: Disclosure = Disclosure.UNCHECKED
    expected: int = 0
    disclosed: int = 0
    withheld: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()

    @property
    def whole(self) -> bool:
        return self.state is Disclosure.WHOLE


def assess(artifacts: Iterable[dict[str, Any]],
           checkpoint: Optional[dict[str, Any]]) -> DisclosureReport:
    """
    Compare what was disclosed against what the assignment holds.

    Takes the artifacts an examiner was actually given, which is one document
    in the ordinary case and several where a party discloses more than one
    chain. Anything the checkpoint lists and the disclosure does not is a
    withheld chain, and the count is the finding.
    """
    docs = list(artifacts or [])
    entries_per_doc: list[list[Entry]] = []
    for d in docs:
        try:
            entries_per_doc.append(load_artifact(d))
        except Exception:  # noqa: BLE001
            entries_per_doc.append([])

    identities = [chain_identity(e) for e in entries_per_doc]
    if any(i is None for i in identities):
        return DisclosureReport(
            state=Disclosure.UNANCHORED,
            findings=("An artifact carries no assignment anchor, so it names "
                      "no assignment and no assignment-level statement can be "
                      "checked against it.",),
        )

    if checkpoint is None:
        return DisclosureReport(
            state=Disclosure.UNCHECKED,
            disclosed=len(docs),
            findings=("No assignment checkpoint supplied. Sibling chains are "
                      "undetectable without one: one chain and one chain out "
                      "of five are the same document.",),
        )

    if not signature_valid(checkpoint):
        return DisclosureReport(
            state=Disclosure.UNUSABLE,
            findings=("The assignment checkpoint does not verify against its "
                      "own key.",),
        )

    signer = (checkpoint.get("public_key") or "").strip()
    if any(signer == e.public_key.strip()
           for entries in entries_per_doc for e in entries):
        return DisclosureReport(
            state=Disclosure.UNUSABLE,
            findings=("The assignment checkpoint is signed by a key that also "
                      "signed a chain, so the party under examination is "
                      "counting its own chains.",),
        )

    cp = load(checkpoint)
    findings: list[str] = []

    wrong_assignment = sorted({aid for aid, _ in identities
                               if aid != cp.assignment_id})
    if wrong_assignment:
        findings.append(
            f"Artifacts anchored to {wrong_assignment} were offered against a "
            f"checkpoint for assignment {cp.assignment_id}.")

    expected = {c.chain_id: c for c in cp.chains}
    seen: dict[str, list[Entry]] = {}
    for (_, cid), entries in zip(identities, entries_per_doc):
        seen[cid] = entries

    foreign = sorted(set(seen) - set(expected))
    withheld = sorted(set(expected) - set(seen))

    # A chain that was produced but cut short is a partial disclosure too, and
    # it degrades the state rather than only raising a finding. WHOLE has to
    # mean the disclosure is whole, or a caller reading one field gets a pass
    # on a truncated hand-over, which is the mistake `signatures_valid` made.
    short = []
    for cid, entries in seen.items():
        ref = expected.get(cid)
        if ref is None:
            continue
        if ref.entry_count > len(entries):
            short.append(cid)
            findings.append(
                f"Chain {cid[:12]} was recorded with {ref.entry_count} entries "
                f"and {len(entries)} were disclosed.")
        elif ref.head != (entries[-1].block_hash if entries else ""):
            short.append(cid)
            findings.append(
                f"Chain {cid[:12]} does not end where the custodian recorded "
                "it ending.")

    report = DisclosureReport(
        expected=len(expected),
        disclosed=len(seen),
        withheld=tuple(withheld),
    )

    if foreign or wrong_assignment:
        report.state = Disclosure.FOREIGN
        if foreign:
            findings.append(
                f"{len(foreign)} disclosed chain or chains are not recorded "
                "under this assignment at all.")
    elif withheld or short:
        report.state = Disclosure.PARTIAL
        if withheld:
            findings.append(
                f"The assignment holds {len(expected)} chains and {len(seen)} "
                f"were disclosed. {len(withheld)} were not handed over. Sealing "
                "five analyses in five chains and producing one is the attack "
                "this check exists for.")
    else:
        report.state = Disclosure.WHOLE

    report.findings = tuple(findings)
    return report


__all__ = [
    "AssignmentRefusal",
    "ChainRef",
    "AssignmentCheckpoint",
    "Disclosure",
    "DisclosureReport",
    "Issuer",
    "assess",
    "issue",
    "load",
    "signature_valid",
]
