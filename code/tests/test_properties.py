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

import copy
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from seal import (
    AssignmentCheckpoint,
    ChainRef,
    Checkpoint,
    EntryKind,
    EvidenceCommitment,
    Holding,
    Pinning,
    PrimitiveKind,
    PrimitiveRecord,
    EvidenceForm,
    RetentionDetermination,
    RunSeal,
    SealChain,
    TimeAnchor,
    AttestationMode,
    canonical_bytes,
    commit,
    export_artifact,
    issue_assignment_checkpoint,
    issue_checkpoint,
    issue_retention_determination,
    issue_time_anchor,
    load_artifact,
    merkle_root,
    verify,
    witness_attestation_payload,
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
# The verifier, under a hostile SIDE document rather than a hostile primary
# one.
#
# `test_verify_never_raises_and_never_trusts_garbage` above calls
# `verify(doc)` with every other parameter absent, so it never exercises a
# single line inside checkpoint, assignment-checkpoint, time-anchor, or
# retention-determination handling: none of that code runs unless a caller
# actually supplies one. Every fix made against this class of bug this
# session (a non-string `public_key`, a non-string `signature`, a non-dict
# recipe) was found by taking a real, otherwise valid, signed side document
# and corrupting exactly one field, not by throwing unstructured garbage at
# `verify`. This closes that gap permanently rather than leaving it to be
# rediscovered by hand one field at a time.
# ---------------------------------------------------------------------------

_SIDE_KEY = ec.generate_private_key(ec.SECP256R1())
_SIDE_CUSTODIAN = ec.generate_private_key(ec.SECP256R1())
_SIDE_TSA = ec.generate_private_key(ec.SECP256R1())
_SIDE_WITNESS = ec.generate_private_key(ec.SECP256R1())
_SIDE_WITNESS_PEM = _SIDE_WITNESS.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode("ascii")
_SIDE_T0 = 1_000
_SIDE_ACTION_DIGEST = commit({"a": 1})


def _side_doc_primitives():
    def rec(kind, payload, holder="appraiser"):
        return PrimitiveRecord(kind=kind, commitment=payload, pinning=Pinning.PINNED,
                                retention=EvidenceForm.FULL, holder=holder)
    return {
        PrimitiveKind.ACTION: rec(PrimitiveKind.ACTION, _SIDE_ACTION_DIGEST),
        PrimitiveKind.SURFACE: rec(PrimitiveKind.SURFACE, commit({"s": 1})),
        PrimitiveKind.EVALUATOR: rec(PrimitiveKind.EVALUATOR, commit({"e": 1})),
        PrimitiveKind.INSTANT: rec(PrimitiveKind.INSTANT, commit({"t": 1})),
        PrimitiveKind.CLAIM: rec(PrimitiveKind.CLAIM, commit({"c": 1})),
    }


def _build_side_doc_artifact():
    """One real, fully-featured artifact: a recipe, a witness attestation,
    everything a hostile side document could be checked against."""
    chain = SealChain("assignment-1", private_key=_SIDE_KEY, opened_ns=_SIDE_T0)
    root = merkle_root([commit({"r": i}) for i in range(5)])
    ev = EvidenceCommitment(commitment_id="ev-1", row_root=root, row_count=5,
                            source="MLS", as_of="2026-01-01")
    ev_hash = chain.append(EntryKind.EVIDENCE_COMMITMENT, ev.to_body(), _SIDE_T0).block_hash

    primitives = _side_doc_primitives()
    primitives[PrimitiveKind.EVIDENCE] = PrimitiveRecord(
        kind=PrimitiveKind.EVIDENCE, commitment=root, pinning=Pinning.PINNED,
        retention=EvidenceForm.FULL, holder="custodian")
    recipe = {
        "endpoint": "https://x", "tool": "t", "version": "1", "invocation": {"a": 1},
        "input_ref": ev_hash, "output_digest": _SIDE_ACTION_DIGEST,
        "service_window": "2030",
    }
    run_body = RunSeal(run_id="run-1", primitives=primitives, evidence_commitment_hash=ev_hash,
                       witness_mode=AttestationMode.INDEPENDENT, rederivation_recipe=recipe).to_body()
    attestation = {
        "witness": "w", "public_key": _SIDE_WITNESS_PEM, "signature": "",
        "capture_ref": "cap-1", "statement": "observed_execution",
    }
    run_body["witness_attestation"] = attestation
    attestation["signature"] = _SIDE_WITNESS.sign(
        canonical_bytes(witness_attestation_payload(run_body)), ec.ECDSA(hashes.SHA256())
    ).hex()
    chain.append(EntryKind.RUN_SEAL, run_body, _SIDE_T0 + 1)
    return chain, export_artifact(chain)


_SIDE_CHAIN, _SIDE_DOC = _build_side_doc_artifact()

_REAL_CHECKPOINT = issue_checkpoint(
    Checkpoint("assignment-1", len(_SIDE_CHAIN.entries), _SIDE_CHAIN.head,
              _SIDE_T0 + 2, "custodian"),
    _SIDE_CUSTODIAN,
)
_REAL_ASSIGNMENT_CHECKPOINT = issue_assignment_checkpoint(
    AssignmentCheckpoint(
        "assignment-1",
        (ChainRef(_SIDE_CHAIN.chain_id, _SIDE_CHAIN.head, len(_SIDE_CHAIN.entries)),),
        _SIDE_T0 + 2, "custodian"),
    _SIDE_CUSTODIAN,
)
_REAL_TIME_ANCHOR = issue_time_anchor(
    TimeAnchor("tsa", _SIDE_CHAIN.entries[0].block_hash, _SIDE_T0 + 3), _SIDE_TSA,
)
_REAL_DETERMINATION = issue_retention_determination(
    RetentionDetermination(tool="t", version="1", holding=Holding.OPERATOR_CANNOT_HOLD,
                           source="https://x", source_digest=commit({"d": 1}),
                           read_as_of="2026-01-01", determined_by="custodian"),
    _SIDE_CUSTODIAN,
)

_SIDE_TSA_PEM = _SIDE_TSA.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode("ascii")


def _mutate(real: dict, key, value) -> dict:
    d = copy.deepcopy(real)
    d[key] = value
    return d


@given(
    which=st.sampled_from(["checkpoint", "assignment_checkpoint", "time_anchor", "determination"]),
    key=st.sampled_from(["signature", "public_key", "entry_count", "chains", "digest",
                         "time_ns", "holding", "source_digest", "issuer", "assignment_id",
                         "chain_head", "observed_ns", "authority", "tool", "version"]),
    value=json_values,
)
@SLOW
def test_verify_never_raises_with_one_field_of_a_real_signed_side_document_corrupted(
    which, key, value,
):
    """
    A real, validly signed checkpoint, assignment checkpoint, time anchor, or
    retention determination, with exactly one field replaced by an arbitrary
    JSON value. Every prior bug in this family (a non-string `public_key`, a
    non-string `signature`) looked exactly like this: a document that is
    correct everywhere except one field a hostile or buggy party controls.
    """
    checkpoint = assignment_checkpoint = time_anchors = retention_determinations = None
    if which == "checkpoint":
        checkpoint = _mutate(_REAL_CHECKPOINT, key, value)
    elif which == "assignment_checkpoint":
        assignment_checkpoint = _mutate(_REAL_ASSIGNMENT_CHECKPOINT, key, value)
    elif which == "time_anchor":
        time_anchors = [_mutate(_REAL_TIME_ANCHOR, key, value)]
    elif which == "determination":
        retention_determinations = [_mutate(_REAL_DETERMINATION, key, value)]

    report = verify(
        _SIDE_DOC,
        trusted_keys=[_SIDE_CHAIN.public_key_pem],
        rederive=lambda r: _SIDE_ACTION_DIGEST,
        checkpoint=checkpoint,
        assignment_checkpoint=assignment_checkpoint,
        time_anchors=time_anchors,
        trusted_authorities=[_SIDE_TSA_PEM],
        retention_determinations=retention_determinations,
        trusted_witness_keys=[_SIDE_WITNESS_PEM],
    )
    # `verify()` always returns a `VerificationReport`, even when its outer
    # try/except caught an exception -- that fail-closed wrapper is exactly
    # the mechanism under test, so `report is not None` would pass whether
    # or not a raw exception was actually caught. The observable difference
    # between "handled with a specific finding" and "crashed and was caught
    # generically" is the `malformed_artifact` code, which is what every
    # bug in this family actually looked like before its fix.
    assert not any(f.code == "malformed_artifact" for f in report.findings), report.findings


@given(
    subfield=st.sampled_from([
        "witness_attestation.statement", "witness_attestation.capture_ref",
        "witness_attestation.witness", "witness_attestation.public_key",
        "witness_attestation.signature", "rederivation_recipe.endpoint",
        "rederivation_recipe.tool", "rederivation_recipe.version",
        "rederivation_recipe.invocation", "rederivation_recipe.input_ref",
        "rederivation_recipe.output_digest", "rederivation_recipe.service_window",
    ]),
    value=json_values,
)
@SLOW
def test_verify_never_raises_with_one_run_body_field_corrupted(subfield, value):
    """
    Same idea as the side-document property above, applied to the two
    nested objects a run body itself carries: `witness_attestation` and
    `rederivation_recipe`. Both are dictionaries a hostile artifact controls
    directly, one level inside a document `load_artifact` already parsed.
    """
    doc = copy.deepcopy(_SIDE_DOC)
    run_entry = next(e for e in doc["entries"] if e["kind"] == "run_seal")
    top, sub = subfield.split(".")
    run_entry["body"][top][sub] = value

    report = verify(
        doc,
        trusted_keys=[_SIDE_CHAIN.public_key_pem],
        rederive=lambda r: _SIDE_ACTION_DIGEST,
        trusted_witness_keys=[_SIDE_WITNESS_PEM],
    )
    # `verify()` always returns a `VerificationReport`, even when its outer
    # try/except caught an exception -- that fail-closed wrapper is exactly
    # the mechanism under test, so `report is not None` would pass whether
    # or not a raw exception was actually caught. The observable difference
    # between "handled with a specific finding" and "crashed and was caught
    # generically" is the `malformed_artifact` code, which is what every
    # bug in this family actually looked like before its fix.
    assert not any(f.code == "malformed_artifact" for f in report.findings), report.findings


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
