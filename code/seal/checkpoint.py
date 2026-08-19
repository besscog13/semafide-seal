"""
Checkpoints: the one thing in this package the sealer does not author.

A verifier that decides KC2 by reading fields the sealer wrote is transcribing
a claim rather than computing one, and truncation after the last binding is
undetectable from inside the document. Both have the same root. An artifact is
a self-contained document, and completeness is a claim about what is not in it. No field added
to a document can establish that the document is whole, because the party who
chooses which fields ship also chooses which to omit.

That is a category limit, not a schema gap, and it is worth being blunt about a
tempting non-solution. RFC 3161 timestamping every entry does not close it. A
timestamp proves a document existed at a time; it says nothing about documents
you never showed anyone. Seal five runs, anchor all five perfectly, hand over
three. Every one verifies.

What closes it is a statement made by somebody else about how long the chain
is. A Checkpoint is that statement: assignment, entry count, chain head, signed
by a key that is not the sealer's. An examiner holding a checkpoint can detect
a short chain, because the count and the head disagree with what they were
given.

Where checkpoints come from is deliberately not decided here. A custodian
holding the log is the obvious source and would also close the sibling-chain
hole, since five chains under one assignment are visible to whoever holds them.
Anchoring the checkpoint itself externally, RFC 3161 or a transparency log, is
what would make the custodian accountable in turn. Both are business decisions
about what Semafide is, not engineering ones, and neither is settled. This
module encodes only the shape of the statement and what a verifier does with
one.

The trust does not disappear. It moves to whoever signs the checkpoint, which
is the point: the appraiser can no longer be the only source of the record they
are being examined on.

WHAT THIS IS, IN THE VOCABULARY THAT ALREADY EXISTS. A checkpoint here is a
signed tree head, and the signature that makes it worth anything is a witness
cosignature, both specified at c2sp.org as `tlog-checkpoint` and
`tlog-cosignature`, with `tlog-witness` giving the protocol for obtaining one. The specification states the defining property
directly: a cosignature asserts that the consistent tree head with the largest
size the cosigner has observed for that log has the given root hash, and a
witness verifies a checkpoint against its previously recorded state before
signing.

The word `Checkpoint` and the word `witness` are both already the field's words
for these exact roles. Use the specifications rather than reimplementing them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .primitives import canonical_bytes


@dataclass(frozen=True)
class Checkpoint:
    """
    A signed statement about the state of one assignment's chain.

    `entry_count` is what makes truncation visible: an artifact carrying fewer
    entries than a checkpoint asserts is short, and the shortfall is the number
    of runs somebody chose not to disclose.

    `chain_head` pins which chain, so a sealer cannot answer a checkpoint for
    assignment A with a different chain that happens to be the right length.

    `observed_ns` is the checkpoint issuer's clock, not the sealer's. It is the
    first timestamp in this package that the party under examination did not
    choose.
    """

    assignment_id: str
    entry_count: int
    chain_head: str
    observed_ns: int
    issuer: str

    def signing_payload(self) -> dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "entry_count": self.entry_count,
            "chain_head": self.chain_head,
            "observed_ns": self.observed_ns,
            "issuer": self.issuer,
        }

    def to_payload(self, signature: str, public_key: str) -> dict[str, Any]:
        d = self.signing_payload()
        d["signature"] = signature
        d["public_key"] = public_key
        return d


class CheckpointRefusal(Exception):
    """Raised when an issuer will not sign. The reason is the finding."""


@dataclass
class Issuer:
    """
    A stateful checkpoint issuer, which is what a checkpoint always needed.

    The defect this closes. A stateless `issue` signs whatever it is handed,
    so a custodian can sign a checkpoint over chain A at size five and
    another over chain B at size five, both for one assignment, and both
    verify. A sealer holding two chains produces the one it prefers together
    with the checkpoint that matches it, and `completeness` reports CONSISTENT
    because the chain really is the length its checkpoint names.

    A signature over a count is not the property wanted. The property is that
    the issuer has never signed anything inconsistent with this, and that
    requires the issuer to remember. `witness.Witness` enforces the same
    discipline one level up, over tree heads.

    This is the witness cosignature role in the C2SP transparency log
    specifications, which state it directly: a cosignature asserts that the
    consistent tree head with the largest size the cosigner has observed for
    that log has the given root hash. `tlog-witness` requires the witness to
    verify a checkpoint against its previously recorded state before signing.
    That is this class, and the specification is the thing to adopt rather than
    the thing to reimplement.

    Note the cost of doing it over a hash chain. Establishing that this chain
    extends what was signed before means walking the entries, which is linear.
    A Merkle tree answers the same question with a proof logarithmic in the
    size, which is why transparency logs are trees and not chains, and it is an
    argument for moving the seal chain into a log rather than an argument for
    keeping this.
    """

    name: str
    key: ec.EllipticCurvePrivateKey
    _last: dict[str, Checkpoint] = field(default_factory=dict)

    def issue(self, checkpoint: Checkpoint,
              entries: Optional[list] = None) -> dict[str, Any]:
        """
        Sign a checkpoint, or refuse.

        Refuses rather than returning a failure value, for the reason
        `Witness.cosign` does: a caller who ignores a return code produces the
        rubber stamp this exists to prevent.
        """
        prior = self._last.get(checkpoint.assignment_id)
        if prior is not None:
            if (checkpoint.entry_count == prior.entry_count
                    and checkpoint.chain_head != prior.chain_head):
                raise CheckpointRefusal(
                    f"already signed a different chain at size "
                    f"{prior.entry_count} for assignment "
                    f"{checkpoint.assignment_id}; this is an equivocation")
            if checkpoint.entry_count < prior.entry_count:
                raise CheckpointRefusal(
                    f"assignment {checkpoint.assignment_id} shrank from "
                    f"{prior.entry_count} to {checkpoint.entry_count}")
            if checkpoint.entry_count > prior.entry_count:
                if not _extends(entries, prior, checkpoint):
                    raise CheckpointRefusal(
                        "the chain offered is not an extension of the one last "
                        "signed for this assignment")

        signed = issue(checkpoint, self.key)
        self._last[checkpoint.assignment_id] = checkpoint
        return signed


def _extends(entries: Optional[list], prior: Checkpoint,
             now: Checkpoint) -> bool:
    """
    Whether `entries` is a chain that contains `prior` unchanged.

    Linear in the chain length, because a hash chain carries no shorter proof.
    An issuer given no entries cannot establish this and must refuse, since
    assuming an extension is the whole failure being corrected.
    """
    if not entries or len(entries) != now.entry_count:
        return False
    if entries[-1].block_hash != now.chain_head:
        return False
    if not 0 < prior.entry_count <= len(entries):
        return False
    if entries[prior.entry_count - 1].block_hash != prior.chain_head:
        return False
    expected_prev = entries[0].prev_hash
    for e in entries:
        if e.prev_hash != expected_prev:
            return False
        expected_prev = e.block_hash
    return True


def issue(
    checkpoint: Checkpoint,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    """
    Sign a checkpoint with no memory of what was signed before.

    This is the primitive rather than the mechanism, and a custodian must not
    call it directly. Signing statelessly is the bug `Issuer` exists to close:
    two chains of one size under one assignment can both be signed and both
    verify. Kept because `Issuer` needs it and because a test fixture wants a
    checkpoint without a custodian.

    The key must not be the one that signed the chain. Nothing here can enforce
    that, which is why the verifier refuses a checkpoint sharing the artifact's
    key rather than trusting the issuer to have used a different one.
    """
    raw = canonical_bytes(checkpoint.signing_payload())
    sig = private_key.sign(raw, ec.ECDSA(hashes.SHA256())).hex()
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return checkpoint.to_payload(sig, pub)


def load(doc: dict[str, Any]) -> tuple[Checkpoint, str, str]:
    """Read a transported checkpoint. No verification here."""
    return (
        Checkpoint(
            assignment_id=doc["assignment_id"],
            entry_count=doc["entry_count"],
            chain_head=doc["chain_head"],
            observed_ns=doc["observed_ns"],
            issuer=doc["issuer"],
        ),
        doc["signature"],
        doc["public_key"],
    )


def signature_valid(doc: dict[str, Any]) -> bool:
    try:
        cp, sig, pem = load(doc)
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        pub.verify(bytes.fromhex(sig),
                   canonical_bytes(cp.signing_payload()),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - hostile input is expected here
        return False


def signer_pem(doc: dict[str, Any]) -> Optional[str]:
    try:
        return doc["public_key"]
    except Exception:  # noqa: BLE001
        return None
