"""
Property-based tests. The third tool, and it covers what the other two cannot.

The division of labour across this repository is deliberate.

**SMT** proves what the construction forces, over unbounded state, at small
bounds. `specs/SPEC_merkle_consistency.py` asks whether any proof at all makes a
rewritten log verify, and answers for trees up to size six.

**Unit tests** assert explicit design rules: the decisions somebody made and
could have made differently. Those live in `test_seal_verifier.py`.

**This file** covers claims quantified over arbitrary input. Two kinds are
unreachable by the other tools. Injectivity of a serializer is a statement about
every pair of values a caller might pass, and nobody enumerates that by hand.
Totality of a verifier under hostile input is a statement about every malformed
document, and the previous coverage was ten mutations somebody thought of.

It also extends the SMT results past their bound. The solver proves soundness of
the consistency proof to size six; the completeness properties here exercise the
same code at sizes in the hundreds. Neither substitutes for the other: a sampled
size two hundred says nothing about all proofs at that size, and a proved size
six says nothing about size two hundred.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from seal import (
    EntryKind,
    SealChain,
    canonical_bytes,
    commit,
    export_artifact,
    load_artifact,
    merkle_root,
    verify,
)
from seal.log import consistency_proof, inclusion_proof, leaf_hash
from seal.log import root as tree_root
from seal.log import verify_consistency, verify_inclusion

SLOW = settings(max_examples=60, deadline=None,
                suppress_health_check=[HealthCheck.too_slow])

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Values JSON can carry. Tuples are excluded on purpose: JSON has no tuple, so
# a tuple and a list with equal contents denote the same array and canonicalize
# identically. That is intended rather than a collision.
atoms = (st.none() | st.booleans() | st.integers()
         | st.floats(allow_nan=False, allow_infinity=False)
         | st.text(max_size=12))

json_values = st.recursive(
    atoms,
    lambda child: st.lists(child, max_size=4)
    | st.dictionaries(st.text(max_size=6), child, max_size=4),
    max_leaves=8,
)

# Keys a careless caller might actually pass. A serializer that silently
# coerces these is where the collisions live, so the strategy has to be able to
# produce them or the property cannot fail.
loose_keys = st.text(max_size=6) | st.integers() | st.booleans() | st.none()

loose_values = st.recursive(
    atoms,
    lambda child: st.lists(child, max_size=4)
    | st.dictionaries(loose_keys, child, max_size=4),
    max_leaves=8,
)


def _json_key(k) -> str:
    """How `json.dumps(sort_keys=True)` renders a non-string key."""
    if isinstance(k, str):
        return k
    if k is None:
        return "null"
    if k is True:
        return "true"
    if k is False:
        return "false"
    return json.dumps(k)


def _stringify_keys(value):
    """The twin a silently coercing serializer cannot tell apart."""
    if isinstance(value, dict):
        return {_json_key(k): _stringify_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_keys(v) for v in value]
    return value


def _canonicalises(payload) -> bool:
    try:
        canonical_bytes(payload)
        return True
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Canonicalization. Injectivity is the property everything else rests on.
# ---------------------------------------------------------------------------

@given(loose_values, loose_values)
@SLOW
def test_distinct_payloads_never_share_canonical_bytes(a, b):
    """
    The load-bearing property of the whole package.

    Every commitment, every block hash, and every signature is taken over
    canonical bytes. If two different payloads can produce the same bytes, then
    two different analyses can produce the same seal, and the artifact stops
    distinguishing what it is supposed to distinguish.

    Payloads that canonicalization refuses are skipped rather than counted as
    passes. Refusing is the correct behaviour for a value that cannot be
    represented unambiguously, and it is why `allow_nan=False` is there.
    """
    assume(a != b)
    assume(_canonicalises(a) and _canonicalises(b))
    assert canonical_bytes(a) != canonical_bytes(b)


@given(loose_values)
@SLOW
def test_a_non_string_key_is_refused_rather_than_silently_coerced(payload):
    """
    The targeted form, and it is the one that finds anything.

    Drawing two payloads independently and hoping they collide almost never
    produces the near miss that matters, because the collision needs the same
    value under a key and its string form. So the twin is derived rather than
    drawn: every non-string key is replaced by exactly what a coercing
    serializer would render it as.

    Two answers are acceptable. Refuse the payload, which is what
    `allow_nan=False` already does for values that cannot be represented
    unambiguously. Or serialize it to something distinct from the twin. Quietly
    coercing is the third answer and it is a collision: two different payloads,
    one commitment.
    """
    twin = _stringify_keys(payload)
    if payload == twin:
        return                                  # every key already a string
    if _canonicalises(payload):
        assert canonical_bytes(payload) != canonical_bytes(twin)


@given(loose_values, loose_values)
@SLOW
def test_distinct_payloads_never_share_a_commitment(a, b):
    """The same property one level up, where callers actually reach it."""
    assume(a != b)
    assume(_canonicalises(a) and _canonicalises(b))
    assert commit(a) != commit(b)


@given(json_values)
@SLOW
def test_canonical_bytes_reads_back_as_the_same_value(payload):
    """
    Output has to be JSON a conforming parser accepts, and it has to mean the
    same thing on the way back. This is what `allow_nan=False` protects: NaN
    and Infinity produced output no parser could read, which would make a
    signature unverifiable for reasons unrelated to tampering.
    """
    assume(_canonicalises(payload))
    assert json.loads(canonical_bytes(payload).decode("utf-8")) == payload


@given(json_values)
@SLOW
def test_canonicalization_is_deterministic(payload):
    """A serializer that varies between calls makes every signature a coin flip."""
    assume(_canonicalises(payload))
    assert canonical_bytes(payload) == canonical_bytes(payload)


# ---------------------------------------------------------------------------
# Evidence commitment.
# ---------------------------------------------------------------------------

@given(st.lists(st.text(min_size=1, max_size=8), min_size=1, max_size=12,
                unique=True))
@SLOW
def test_merkle_root_is_order_sensitive(rows):
    """
    A comp set is an ordered list. If reordering it left the root unchanged, an
    artifact could claim a different analysis over the same rows.
    """
    assume(len(rows) > 1)
    hashes = [commit({"row": r}) for r in rows]
    assert merkle_root(hashes) != merkle_root(list(reversed(hashes)))


@given(st.lists(st.text(min_size=1, max_size=8), min_size=2, max_size=12,
                unique=True))
@SLOW
def test_a_promoted_interior_node_is_not_a_leaf(rows):
    """
    Odd nodes are promoted rather than duplicated, which avoids the duplicate
    leaf ambiguity and reintroduces it in another form unless leaves and
    interior nodes carry distinct domain prefixes.
    """
    hashes = [commit({"row": r}) for r in rows]
    assert merkle_root(hashes) not in hashes


@given(st.lists(st.text(min_size=1, max_size=8), min_size=1, max_size=10,
                unique=True),
       st.text(min_size=1, max_size=8))
@SLOW
def test_adding_a_row_changes_the_root(rows, extra):
    assume(extra not in rows)
    hashes = [commit({"row": r}) for r in rows]
    assert merkle_root(hashes) != merkle_root(hashes + [commit({"row": extra})])


# ---------------------------------------------------------------------------
# The log, at sizes the solver cannot reach.
# ---------------------------------------------------------------------------

@given(st.integers(min_value=1, max_value=300), st.data())
@SLOW
def test_inclusion_holds_at_arbitrary_size(size, data):
    """
    The SMT spec proves soundness of the consistency proof to size six. This
    samples completeness of the inclusion proof three hundred wide, which is
    the shape of bug the earlier top-down verifier had: it passed on balanced
    trees and failed everywhere else.
    """
    index = data.draw(st.integers(min_value=0, max_value=size - 1))
    leaves = [leaf_hash({"run": i}) for i in range(size)]
    assert verify_inclusion(index, size, leaves[index], tree_root(leaves),
                            inclusion_proof(leaves, index))


@given(st.integers(min_value=1, max_value=300), st.data())
@SLOW
def test_consistency_holds_at_arbitrary_size(size, data):
    old = data.draw(st.integers(min_value=0, max_value=size))
    leaves = [leaf_hash({"run": i}) for i in range(size)]
    assert verify_consistency(old, tree_root(leaves[:old]), size,
                              tree_root(leaves), consistency_proof(leaves, old))


@given(st.integers(min_value=2, max_value=120), st.data())
@SLOW
def test_a_rewritten_entry_has_no_honest_proof(size, data):
    """
    The soundness direction, sampled well past the solver's bound. The
    custodian alters one entry inside the claimed prefix and offers the proof
    its own rewritten tree produces.
    """
    old = data.draw(st.integers(min_value=1, max_value=size - 1))
    j = data.draw(st.integers(min_value=0, max_value=old - 1))
    honest = [leaf_hash({"run": i}) for i in range(size)]
    rewritten = list(honest)
    rewritten[j] = leaf_hash({"run": 10_000 + j})
    assert not verify_consistency(old, tree_root(honest[:old]), size,
                                  tree_root(rewritten),
                                  consistency_proof(rewritten, old))


# ---------------------------------------------------------------------------
# The verifier, under hostile input.
# ---------------------------------------------------------------------------

@given(st.one_of(json_values,
                 st.dictionaries(st.text(max_size=8), json_values, max_size=5)))
@SLOW
def test_verify_never_raises_and_never_trusts_garbage(doc):
    """
    The intended reader is an examiner running this years later against a
    document supplied by the opposing party. Any caller who wraps `verify` in
    try/except and treats failure as inconclusive turns every crash into a
    pass, so malformed input must return an untrustworthy report rather than
    propagate.

    Ten hand-picked mutations covered this before. This covers whatever
    Hypothesis constructs.
    """
    report = verify(doc)
    assert report.trustworthy is False


@given(st.integers(min_value=0, max_value=4))
@SLOW
def test_truncating_any_prefix_never_yields_trust(cut):
    """A chain missing its head does not verify, whichever end is removed."""
    chain = SealChain("assignment-1", opened_ns=0)
    for i in range(4):
        chain.append(EntryKind.RUN_SEAL, {"run": i}, 1_000 * (i + 1))
    doc = export_artifact(chain)
    doc["entries"] = doc["entries"][cut:]
    report = verify(doc, trusted_keys=[chain.public_key_pem])
    assert report.trustworthy is (cut == 0)


# ---------------------------------------------------------------------------
# Transport.
# ---------------------------------------------------------------------------

@given(st.lists(st.dictionaries(st.text(max_size=6), atoms, max_size=3),
                min_size=1, max_size=5))
@SLOW
def test_an_artifact_survives_export_and_reload(bodies):
    """
    A verifier reads what a transport wrote. If the round trip changes a body,
    every signature after it fails for reasons unrelated to tampering.
    """
    chain = SealChain("assignment-1", opened_ns=0)
    for i, body in enumerate(bodies):
        assume(_canonicalises(body))
        chain.append(EntryKind.RUN_SEAL, body, 1_000 * (i + 1))

    doc = json.loads(json.dumps(export_artifact(chain)))
    entries = load_artifact(doc)
    assert [e.block_hash for e in entries] == \
           [e.block_hash for e in chain.entries]
    assert verify(doc, trusted_keys=[chain.public_key_pem]).trustworthy
