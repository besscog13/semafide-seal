"""
Witness cosigning, and what it does and does not do about a split view.

A custodian running an append-only log can still show one tree head to one
examiner and a different head to another. Both verify. Both are internally
perfect. Consistency proofs catch this only if the two examiners ever compare
what they were given, and nothing so far made that likely.

Be clear about the ceiling first. **Nothing here prevents a split view.** A
party determined to equivocate can always sign two documents. What changes is
the consequence: equivocating produces a permanent, transferable proof of
misbehaviour that anyone can check without having been present, and it makes
the equivocation require corrupting every witness rather than nobody.

Two mechanisms, in order of how much they buy.

**Equivocation proofs.** Two signed heads from one log that cannot both be true
are, together, evidence. Both heads carry the custodian's signature, so the
holder can hand the pair to a regulator or an opposing party and nothing further
is needed from anyone.

The two kinds are not worth the same and the code says so rather than letting a
holder assume. A CONTRADICTION is two different roots at the same size. No
document reconciles that pair, so it is final and the custodian cannot retract
it. An UNRECONCILED pair is two different sizes with no consistency proof
offered, which is the position an examiner occupies when a custodian declines to
produce one. It is rebuttable: the custodian answers it by producing the proof,
and `rebut` destroys the finding on the spot. Reporting the second as though it
were the first is the overclaim available here, and `equivocation_holds` refuses
to make it.

**Witness cosigning.** A witness is a party that keeps the last head it signed
for a log and refuses to sign anything that is not a consistent extension of
it, and refuses outright to sign two different heads at the same size. A head
carrying signatures from several independent witnesses means several parties
saw that head and none of them saw a conflicting one. Splitting the view then
requires convincing all of them, and a witness that keeps state cannot be
convinced without being compromised.

The residue is real and it is operational. Who the witnesses are, whether they
are independent, and whether anyone checks the count are not questions this
module answers. It reduces "trust the custodian" to "trust that these named
parties are not all captured," which is a better position and is not a proof.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .log import head_signature_valid, verify_consistency
from .primitives import canonical_bytes


def _pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _head_core(head: dict[str, Any]) -> dict[str, Any]:
    """The part of a head a witness attests to, excluding the log's own signature."""
    return {"size": head["size"], "root": head["root"],
            "log_id": head["log_id"], "observed_ns": head["observed_ns"]}


class WitnessRefusal(Exception):
    """Raised when a witness will not cosign. The reason is the finding."""


@dataclass
class Witness:
    """
    A party that keeps state and therefore cannot be talked into a split view.

    The state is one head per log. That is the whole mechanism: a witness with
    no memory is a rubber stamp, and a witness with memory has to be
    compromised rather than merely fooled.
    """

    name: str
    key: ec.EllipticCurvePrivateKey
    _seen: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def public_key(self) -> str:
        return _pem(self.key)

    def cosign(self, head: dict[str, Any],
               consistency: Optional[list[str]] = None) -> dict[str, Any]:
        """
        Attest that this head was seen and extends what was seen before.

        Refuses rather than returning a failure value, because a caller who
        ignores a return code produces exactly the rubber stamp this exists to
        prevent.

        Checking `_seen` and writing to it are one locked step. No standalone
        witness daemon exists yet, so nothing in this repository calls this
        concurrently, but the day one does, two requests for the same log
        arriving together must not both read the same prior head, each pass
        its own consistency check against it, and both write, since that is
        exactly the rubber stamp `_seen` exists to prevent, reintroduced
        through a race rather than through a missing check.
        """
        if not head_signature_valid(head):
            raise WitnessRefusal("the head does not verify against its own key")

        log_id = head["log_id"]

        with self._lock:
            prior = self._seen.get(log_id)

            if prior is not None:
                if prior["public_key"].strip() != head["public_key"].strip():
                    raise WitnessRefusal(
                        "a different key is signing for this log than before")
                if head["size"] == prior["size"] and head["root"] != prior["root"]:
                    raise WitnessRefusal(
                        f"already signed a different root at size {head['size']}; "
                        "this is an equivocation")
                if head["size"] < prior["size"]:
                    raise WitnessRefusal(
                        f"log shrank from {prior['size']} to {head['size']}")
                if head["size"] > prior["size"]:
                    if not verify_consistency(prior["size"], prior["root"],
                                              head["size"], head["root"],
                                              consistency or []):
                        raise WitnessRefusal(
                            "the new head is not an extension of the last one seen")

            self._seen[log_id] = dict(head)

        raw = canonical_bytes(_head_core(head))
        return {
            "witness": self.name,
            "public_key": self.public_key,
            "signature": self.key.sign(raw, ec.ECDSA(hashes.SHA256())).hex(),
        }


def cosignature_valid(head: dict[str, Any], cosig: dict[str, Any]) -> bool:
    try:
        pub = serialization.load_pem_public_key(
            cosig["public_key"].encode("ascii"))
        pub.verify(bytes.fromhex(cosig["signature"]),
                   canonical_bytes(_head_core(head)),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - hostile input is expected
        return False


def count_witnesses(head: dict[str, Any], cosigs: list[dict[str, Any]],
                    trusted: Optional[list[str]] = None) -> int:
    """
    How many distinct recognised witnesses attest to this head.

    Distinct by key rather than by name, since a name is a string the signer
    chose. Untrusted keys are not counted at all: an examiner who accepts
    witnesses they cannot name has reintroduced the problem, because the
    custodian can generate as many keys as it likes.

    Guards against a malformed entry in `cosigs`, since this is called
    directly against a bundle an examiner received from the party under
    examination rather than only through the fail-closed `verify` wrapper. A
    non-dict entry is skipped rather than raising, matching the same
    hostile-input handling `resolve_bounds` already gives `time_anchors`.
    """
    seen: set[str] = set()
    allow = {k.strip() for k in trusted} if trusted is not None else None
    for c in cosigs or []:
        if not isinstance(c, dict):
            continue
        pem = (c.get("public_key") or "").strip()
        if not pem or pem in seen:
            continue
        if allow is not None and pem not in allow:
            continue
        if cosignature_valid(head, c):
            seen.add(pem)
    return len(seen)


CONTRADICTION = "contradiction"
UNRECONCILED = "unreconciled"


def equivocation(head_a: dict[str, Any], head_b: dict[str, Any],
                 consistency: Optional[list[str]] = None
                 ) -> Optional[dict[str, Any]]:
    """
    Given two heads for one log, return transferable evidence of misbehaviour.

    Returns None when the pair is reconcilable. When it is not, the returned
    object is complete on its own: both heads carry the custodian's signature,
    so a third party who was present for neither can check it.

    `finality` says how much the holder has. CONTRADICTION is settled.
    UNRECONCILED records that no consistency proof was offered, which is the
    situation an examiner is in when a custodian declines to produce one, and
    the custodian can still answer it by producing one later.
    """
    for h in (head_a, head_b):
        if not head_signature_valid(h):
            return None  # an unsigned document proves nothing about anyone
    if head_a["log_id"] != head_b["log_id"]:
        return None
    if head_a["public_key"].strip() != head_b["public_key"].strip():
        return None

    lo, hi = sorted((head_a, head_b), key=lambda h: h["size"])

    if lo["size"] == hi["size"]:
        if lo["root"] == hi["root"]:
            return None
        finality = CONTRADICTION
        reason = (f"two heads at size {lo['size']} with different roots. "
                  "Both are signed by the same key, so one of them was shown "
                  "to somebody who was told it was the whole log. No document "
                  "reconciles this pair.")
    elif verify_consistency(lo["size"], lo["root"], hi["size"], hi["root"],
                            consistency or []):
        return None
    else:
        finality = UNRECONCILED
        reason = (f"no consistency proof was offered showing the head at size "
                  f"{hi['size']} extends the head at size {lo['size']}. Either "
                  "history was rewritten or the custodian has simply not "
                  "answered. Producing a valid proof rebuts this.")

    return {
        "kind": "equivocation",
        "finality": finality,
        "log_id": lo["log_id"],
        "reason": reason,
        "head_a": lo,
        "head_b": hi,
    }


def equivocation_holds(proof: dict[str, Any]) -> bool:
    """
    Re-check a transferable proof from scratch.

    An examiner handed one of these should not take the accompanying prose on
    faith, which is the habit this whole package exists to discourage. Note that
    True on an UNRECONCILED proof means only that no proof accompanied it, since
    checking cannot conjure a document the custodian never sent.
    """
    try:
        if proof.get("kind") != "equivocation":
            return False
        fresh = equivocation(proof["head_a"], proof["head_b"])
        return fresh is not None and fresh["finality"] == proof.get("finality")
    except Exception:  # noqa: BLE001
        return False


def rebut(proof: dict[str, Any], consistency: list[str]) -> bool:
    """
    The custodian's answer to an UNRECONCILED finding.

    True means the proof supplied reconciles the two heads and the accusation
    is spent. A CONTRADICTION cannot be rebutted, and this returns False for
    one however good the accompanying proof is.
    """
    try:
        if proof.get("finality") != UNRECONCILED:
            return False
        lo, hi = proof["head_a"], proof["head_b"]
        return equivocation(lo, hi, consistency) is None
    except Exception:  # noqa: BLE001
        return False
