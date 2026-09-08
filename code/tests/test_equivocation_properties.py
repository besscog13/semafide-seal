"""
Property-based coverage for `witness.equivocation`, `equivocation_holds`, and
`rebut`.

This is the one mechanism in the package that is genuinely novel rather than
plumbing around commodity cryptography: whether a custodian can be caught
showing two examiners two different histories, and what a witness or an
equivocation proof buys against it. It is also, until this file, the one
mechanism outside both the unit suite and the formal specs.
`specs/SPEC_witness_cosigning.py` models `Witness.cosign` to size six and
`specs/SPEC_merkle_consistency.py` proves `verify_consistency` sound to size
six, but neither touches `equivocation`, `equivocation_holds`, or `rebut` at
all -- confirmed by grep before writing this file. Everything else in this
package that reaches this level of scrutiny gets it from a spec or from
`test_properties.py`; this closes the one gap in the part of the codebase
most likely to be read closely.

The properties tested here are the ones `SPEC_merkle_consistency.py`'s own
docstring names as the shape of bug a small bound misses: soundness and
completeness sampled well past six, using real signed heads over real
forked logs rather than hand-built proof dictionaries, so a bug in how
`equivocation` and `rebut` thread their arguments to `verify_consistency`
-- as opposed to a bug in `verify_consistency` itself, which the spec
already owns -- has somewhere to show up.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from seal.log import consistency_proof, leaf_hash
from seal.log import root as tree_root
from seal.primitives import canonical_bytes
from seal.witness import CONTRADICTION, UNRECONCILED, equivocation, equivocation_holds, rebut

SLOW = settings(max_examples=60, deadline=None,
                suppress_health_check=[HealthCheck.too_slow])

_KEY = ec.generate_private_key(ec.SECP256R1())
_PUB_PEM = _KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode("ascii")


def _sign(size: int, root: str, observed_ns: int, log_id: str = "semafide") -> dict:
    """A real signed head over an arbitrary (size, root) pair, not necessarily
    produced by a real `TransparencyLog` -- callers here build `root` directly
    from a leaf list they control, including forked ones."""
    payload = {"size": size, "root": root, "observed_ns": observed_ns, "log_id": log_id}
    sig = _KEY.sign(canonical_bytes(payload), ec.ECDSA(hashes.SHA256())).hex()
    doc = dict(payload)
    doc["signature"] = sig
    doc["public_key"] = _PUB_PEM
    return doc


@given(st.integers(min_value=1, max_value=200), st.data())
@SLOW
def test_an_honest_extension_is_never_flagged_at_arbitrary_size(size, data):
    """
    Soundness in the direction that matters most for an honest custodian: a
    real extension, given its real consistency proof, must never read as
    evidence of misbehaviour, however large the log.
    """
    old = data.draw(st.integers(min_value=0, max_value=size))
    leaves = [leaf_hash({"run": i}) for i in range(size)]
    head_old = _sign(old, tree_root(leaves[:old]), 1_000)
    head_new = _sign(size, tree_root(leaves), 1_001)
    proof = consistency_proof(leaves, old)
    assert equivocation(head_old, head_new, proof) is None


@given(st.integers(min_value=2, max_value=150), st.data())
@SLOW
def test_a_rewrite_inside_the_claimed_prefix_is_caught_and_never_rebuttable(size, data):
    """
    A custodian alters one entry inside what an earlier head already claimed,
    then extends. Without a proof this must read UNRECONCILED (an examiner
    who has not yet been shown a proof cannot tell a rewrite from a
    custodian who simply has not answered yet), and no proof produced from
    the REWRITTEN tree itself -- the only proof such a custodian actually
    has -- can rebut it, because it does not reconcile against the root the
    earlier, honest head actually committed to.
    """
    old = data.draw(st.integers(min_value=1, max_value=size - 1))
    j = data.draw(st.integers(min_value=0, max_value=old - 1))
    honest = [leaf_hash({"run": i}) for i in range(size)]
    rewritten = list(honest)
    rewritten[j] = leaf_hash({"run": 10_000 + j})

    head_old = _sign(old, tree_root(honest[:old]), 1_000)
    head_new = _sign(size, tree_root(rewritten), 1_001)

    result = equivocation(head_old, head_new)
    assert result is not None
    assert result["finality"] == UNRECONCILED
    assert equivocation_holds(result)

    fabricated = consistency_proof(rewritten, old)
    assert not rebut(result, fabricated)
    assert not rebut(result, [])


@given(st.integers(min_value=1, max_value=100), st.data())
@SLOW
def test_same_size_different_root_is_always_a_contradiction_and_never_rebuttable(size, data):
    """
    Two heads at one size that disagree on the root are the settled case:
    final, and no proof -- fabricated or otherwise -- rebuts it. Sampled
    across sizes to confirm this holds independent of tree shape, not only
    at the sizes a hand-written test happens to pick.
    """
    j = data.draw(st.integers(min_value=0, max_value=size - 1))
    left = [leaf_hash({"run": i}) for i in range(size)]
    right = list(left)
    right[j] = leaf_hash({"run": 20_000 + j})

    head_a = _sign(size, tree_root(left), 1_000)
    head_b = _sign(size, tree_root(right), 1_001)

    result = equivocation(head_a, head_b)
    assert result is not None
    assert result["finality"] == CONTRADICTION
    assert equivocation_holds(result)
    assert not rebut(result, [])
    assert not rebut(result, consistency_proof(right, size))
