"""
Chain statements: the one thing in this package the sealer does not author.

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
is. A ChainStatement is that statement: assignment, entry count, chain head, signed
by a key that is not the sealer's. An examiner holding one can detect
a short chain, because the count and the head disagree with what they were
given.

Where these statements come from is deliberately not decided here. A custodian
holding the log is the obvious source and would also close the sibling-chain
hole, since five chains under one assignment are visible to whoever holds them.
Anchoring the statement itself externally, RFC 3161 or a transparency log, is
what would make the custodian accountable in turn. Both are business decisions
about what Semafide is, not engineering ones, and neither is settled. This
module encodes only the shape of the statement and what a verifier does with
one.

The trust does not disappear. It moves to whoever signs the statement, which
is the point: the appraiser can no longer be the only source of the record they
are being examined on.

WHAT THIS IS NOT, IN THE VOCABULARY THAT ALREADY EXISTS. The c2sp.org
specifications name a signed tree head `tlog-checkpoint`, and the signature
that makes it worth anything a witness cosignature, `tlog-cosignature`, with
`tlog-witness` giving the protocol for obtaining one. `log.py`'s `TreeHead`
and `witness.py`'s `Witness` implement those roles at the scope the
specification means: one log, named by `log_id`, that can hold every chain a
custodian has ever recorded. This module's statement is scoped to one
assignment's chain, not the log. A chain reading whole against this statement
says nothing about whether the log holding it is, which is the sibling-chain
hole this docstring's own opening names.

This class used to be named `Checkpoint`, on the belief that it was the
log-scoped object at a smaller size. It is not. It answers a different
question at a different layer, and it was renamed to `ChainStatement` rather
than kept alongside a word the specification already means something else
by. The spec's own vocabulary stays with `TreeHead`, where it was already
earned.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .primitives import canonical_bytes


@dataclass(frozen=True)
class ChainStatement:
    """
    A signed statement about the state of one assignment's chain.

    `entry_count` is what makes truncation visible: an artifact carrying fewer
    entries than this statement asserts is short, and the shortfall is the
    number of runs somebody chose not to disclose.

    `chain_head` pins which chain, so a sealer cannot answer this statement for
    assignment A with a different chain that happens to be the right length.

    `observed_ns` is the issuer's clock, not the sealer's. It is the
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
class CheckpointIssuer:
    """
    A stateful chain-statement issuer, which is what this always needed.

    The defect this closes. A stateless `issue` signs whatever it is handed,
    so a custodian can sign a statement over chain A at size five and
    another over chain B at size five, both for one assignment, and both
    verify. A sealer holding two chains produces the one it prefers together
    with the statement that matches it, and `completeness` reports CONSISTENT
    because the chain really is the length its statement names.

    A signature over a count is not the property wanted. The property is that
    the issuer has never signed anything inconsistent with this, and that
    requires the issuer to remember. `witness.Witness` enforces the same
    discipline one level up, over tree heads, at the log's scope rather than
    one chain's.

    This is a smaller-scoped analogue of the witness cosignature role in the
    C2SP transparency log specifications, not the role itself: `tlog-witness`
    requires the witness to check a proposed tree head against its previously
    recorded state before signing, over the whole log. This class checks a
    proposed chain length against its previously recorded state before
    signing, over one assignment's chain. The discipline is the same shape.
    The scope is not, which is why this class does not carry the spec's name.

    Note the cost of doing it over a hash chain. Establishing that this chain
    extends what was signed before means walking the entries, which is linear.
    A Merkle tree answers the same question with a proof logarithmic in the
    size, which is why transparency logs are trees and not chains, and it is an
    argument for moving the seal chain into a log rather than an argument for
    keeping this.
    """

    name: str
    key: ec.EllipticCurvePrivateKey
    _last: dict[str, ChainStatement] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def issue(self, statement: ChainStatement,
              entries: Optional[list] = None) -> dict[str, Any]:
        """
        Sign a chain statement, or refuse.

        Refuses rather than returning a failure value, for the reason
        `Witness.cosign` does: a caller who ignores a return code produces the
        rubber stamp this exists to prevent.

        Checking `_last` and writing to it are one locked step, for the same
        reason `Witness.cosign` locks: two concurrent requests for the same
        assignment must not both read the same prior statement, each pass its
        own consistency check against it, and both get signed, since that
        reintroduces the equivocation this class exists to prevent through a
        race rather than through a missing check.
        """
        with self._lock:
            prior = self._last.get(statement.assignment_id)
            if prior is not None:
                if (statement.entry_count == prior.entry_count
                        and statement.chain_head != prior.chain_head):
                    raise CheckpointRefusal(
                        f"already signed a different chain at size "
                        f"{prior.entry_count} for assignment "
                        f"{statement.assignment_id}; this is an equivocation")
                if statement.entry_count < prior.entry_count:
                    raise CheckpointRefusal(
                        f"assignment {statement.assignment_id} shrank from "
                        f"{prior.entry_count} to {statement.entry_count}")
                if statement.entry_count > prior.entry_count:
                    if not _extends(entries, prior, statement):
                        raise CheckpointRefusal(
                            "the chain offered is not an extension of the one "
                            "last signed for this assignment")

            signed = issue(statement, self.key)
            self._last[statement.assignment_id] = statement
            return signed


def _extends(entries: Optional[list], prior: ChainStatement,
             now: ChainStatement) -> bool:
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
    statement: ChainStatement,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    """
    Sign a chain statement with no memory of what was signed before.

    This is the primitive rather than the mechanism, and a custodian must not
    call it directly. Signing statelessly is the bug `CheckpointIssuer` exists
    to close: two chains of one size under one assignment can both be signed
    and both verify. Kept because `CheckpointIssuer` needs it and because a
    test fixture wants a statement without a custodian.

    The key must not be the one that signed the chain. Nothing here can enforce
    that, which is why the verifier refuses a statement sharing the artifact's
    key rather than trusting the issuer to have used a different one.
    """
    raw = canonical_bytes(statement.signing_payload())
    sig = private_key.sign(raw, ec.ECDSA(hashes.SHA256())).hex()
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return statement.to_payload(sig, pub)


def load(doc: dict[str, Any]) -> tuple[ChainStatement, str, str]:
    """Read a transported chain statement. No verification here."""
    return (
        ChainStatement(
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
