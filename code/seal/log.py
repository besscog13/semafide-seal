"""
Append-only transparency log, so the custodian is constrained too.

Checkpoints moved the completeness question outside the artifact, which fixed
the appraiser being the only source of their own record. It left the same
defect one level up: the custodian is the only source of its own record.
Nothing stopped a custodian rewriting history and issuing a fresh checkpoint
over the result, and an examiner holding one checkpoint had no way to tell.

"Append-only" asserted by the party doing the appending is worth exactly what
"witness_mode: independent" was worth. What makes it checkable is a consistency
proof: given a tree head from last year and a tree head from today, the log
must demonstrate that today's tree contains last year's unchanged. If an entry
was removed or altered, no such proof exists. Not withheld, not hard to find.
It does not exist, and the failure is arithmetic rather than a matter of trust.

This is RFC 6962, the structure behind Certificate Transparency, and it is used
here for the reason it was invented: a log that cannot quietly retract.

Note the hash construction differs deliberately from `primitives.merkle_root`.
That one commits to a set of evidence rows and promotes odd nodes. This one
splits at the largest power of two below the size, which is what makes
incremental proofs possible at all. The two are not interchangeable and are not
meant to be.

WHAT THIS DOES NOT SOLVE. A custodian can still show one tree head to one
examiner and a different tree head to another, and each is internally perfect.
Consistency proofs catch that only when two parties compare what they were
given. `witness.py` raises the cost of doing it and makes an inconsistent pair
transferable evidence, and it does not prevent it. What remains after that is
operational: who the witnesses are and whether anyone checks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .primitives import canonical_bytes

# RFC 6962 domain separation. Leaves and interior nodes must not collide, or a
# leaf can be passed off as a subtree.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(payload: Any) -> str:
    """Hash of one log entry."""
    return _h(LEAF_PREFIX + canonical_bytes(payload))


def _node(left: str, right: str) -> str:
    return _h(NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))


def _split(n: int) -> int:
    """Largest power of two strictly less than n. RFC 6962 calls this k."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: list[str]) -> str:
    """Merkle tree hash over an ordered list of leaf hashes."""
    if not leaves:
        return _h(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(leaves: list[str], index: int) -> list[str]:
    """Audit path proving the leaf at `index` is in the tree."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index outside the tree")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root(leaves[:k])]


def verify_inclusion(index: int, size: int, leaf: str, expected_root: str,
                     proof: list[str]) -> bool:
    """
    Recompute the root from a leaf and its audit path.

    The path is ordered leaf to root, so verification walks the same way. A
    first attempt at this walked the tree top-down while consuming a bottom-up
    proof, which verified only where the tree happened to be symmetric. An
    exhaustive check over every index at every size to thirty-three caught it;
    spot-checking a balanced tree would not have.

    `proof` comes from whoever is being checked, not from the caller's own
    log, so a non-hex or otherwise malformed sibling must fail the check
    rather than crash it. `_node` raises on that, so the whole computation is
    guarded the same way `head_signature_valid` guards a hostile signature.
    """
    if not 0 <= index < size:
        return False
    try:
        fn, sn = index, size - 1
        node = leaf
        for sibling in proof:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                node = _node(sibling, node)
                while fn != 0 and fn & 1 == 0:
                    fn >>= 1
                    sn >>= 1
            else:
                node = _node(node, sibling)
            fn >>= 1
            sn >>= 1
        return sn == 0 and node == expected_root
    except Exception:  # noqa: BLE001 - hostile input is expected
        return False


def consistency_proof(leaves: list[str], old_size: int) -> list[str]:
    """
    Prove that the current tree extends a tree of `old_size` unchanged.

    This is the proof a custodian cannot fabricate after removing an entry.
    """
    n = len(leaves)
    if not 0 <= old_size <= n:
        raise ValueError("old_size outside the tree")
    if old_size == 0 or old_size == n:
        return []
    return _subproof(leaves, old_size, True)


def _subproof(leaves: list[str], m: int, is_complete: bool) -> list[str]:
    n = len(leaves)
    if m == n:
        return [] if is_complete else [root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(leaves[:k], m, is_complete) + [root(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [root(leaves[:k])]


def verify_consistency(old_size: int, old_root: str,
                       new_size: int, new_root: str,
                       proof: list[str]) -> bool:
    """
    Check that a tree of `new_size` actually extends one of `old_size`.

    Returns False when the older tree was rewritten rather than appended to,
    which is the property the custodian is being held to.

    `proof` is the custodian's own submission, offered to prove it did not
    rewrite history, so it is exactly the input most likely to be hostile or
    malformed. A non-hex sibling must resolve to False rather than crash the
    examiner's check, for the same reason `head_signature_valid` guards a
    hostile signature.
    """
    try:
        if old_size > new_size:
            return False
        if old_size == new_size:
            return proof == [] and old_root == new_root
        if old_size == 0:
            return proof == []

        fn, sn = old_size - 1, new_size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1

        if not proof:
            return False

        # A tree whose size is a power of two is already a complete subtree, so
        # its root is used directly instead of consuming a proof element.
        if old_size & (old_size - 1) == 0:
            fr = sr = old_root
            rest = proof
        else:
            fr = sr = proof[0]
            rest = proof[1:]

        for sibling in rest:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr = _node(sibling, fr)
                sr = _node(sibling, sr)
                while fn != 0 and fn & 1 == 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = _node(sr, sibling)
            fn >>= 1
            sn >>= 1

        return fr == old_root and sr == new_root and sn == 0
    except Exception:  # noqa: BLE001 - hostile input is expected
        return False


@dataclass(frozen=True)
class TreeHead:
    """
    The custodian's signed statement of the whole log at a moment.

    A checkpoint speaks for one assignment. A tree head speaks for everything
    the custodian has ever recorded, which is what makes it comparable across
    examiners and across years.
    """

    size: int
    root: str
    observed_ns: int
    log_id: str

    def signing_payload(self) -> dict[str, Any]:
        return {"size": self.size, "root": self.root,
                "observed_ns": self.observed_ns, "log_id": self.log_id}


def sign_head(head: TreeHead, key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    raw = canonical_bytes(head.signing_payload())
    d = head.signing_payload()
    d["signature"] = key.sign(raw, ec.ECDSA(hashes.SHA256())).hex()
    d["public_key"] = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return d


def head_signature_valid(doc: dict[str, Any]) -> bool:
    try:
        head = TreeHead(doc["size"], doc["root"], doc["observed_ns"],
                        doc["log_id"])
        pub = serialization.load_pem_public_key(doc["public_key"].encode("ascii"))
        pub.verify(bytes.fromhex(doc["signature"]),
                   canonical_bytes(head.signing_payload()),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - hostile input is expected
        return False


def heads_consistent(old: dict[str, Any], new: dict[str, Any],
                     proof: list[str]) -> tuple[bool, Optional[str]]:
    """
    The check an examiner runs against a custodian.

    Returns (ok, reason). A False here means the custodian's later log is not
    an extension of its earlier one, which is the only detectable form of a
    custodian rewriting its own history.
    """
    if not head_signature_valid(old) or not head_signature_valid(new):
        return False, "a tree head does not verify against its own key"
    if old.get("log_id") != new.get("log_id"):
        return False, "the heads describe different logs"
    if old.get("public_key", "").strip() != new.get("public_key", "").strip():
        return False, "the heads are signed by different keys"
    if new["size"] < old["size"]:
        return False, "the later head describes a smaller log"
    if not verify_consistency(old["size"], old["root"],
                              new["size"], new["root"], proof):
        return False, ("the later log is not an extension of the earlier one; "
                       "entries were altered or removed rather than appended")
    return True, None


class TransparencyLog:
    """
    A custodian-side append-only log.

    Held here so the structure is testable. Where it runs, who operates it, and
    how heads reach examiners are operational questions this module does not
    answer.
    """

    def __init__(self, log_id: str = "semafide") -> None:
        self._leaves: list[str] = []
        self.log_id = log_id

    def __len__(self) -> int:
        return len(self._leaves)

    def append(self, payload: Any) -> int:
        self._leaves.append(leaf_hash(payload))
        return len(self._leaves) - 1

    def root(self) -> str:
        return root(self._leaves)

    def head(self, observed_ns: int) -> TreeHead:
        return TreeHead(len(self._leaves), self.root(), observed_ns, self.log_id)

    def inclusion_proof(self, index: int) -> list[str]:
        return inclusion_proof(self._leaves, index)

    def consistency_proof(self, old_size: int) -> list[str]:
        return consistency_proof(self._leaves, old_size)
