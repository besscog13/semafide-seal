"""
`demo_custody.py` is the walkthrough for `log.py`/`witness.py` that
`demo.py` and `demo_60s.py` do not provide -- neither builds a
`TransparencyLog` or asks a `Witness` to cosign anything. This locks in
that the script actually runs end to end and that its four scenarios
compute what its own printed narrative claims they do, the same way
`test_demo_60s.py` does for the sibling script.
"""
from __future__ import annotations

import io
from contextlib import redirect_stdout

from cryptography.hazmat.primitives.asymmetric import ec

from seal.demo_custody import _grown_log, main
from seal.log import heads_consistent, sign_head
from seal.witness import (
    CONTRADICTION,
    UNRECONCILED,
    Witness,
    WitnessRefusal,
    equivocation,
    equivocation_holds,
    rebut,
)

T0 = 1_753_200_000_000_000_000


def test_main_runs_end_to_end_without_error():
    """Smoke test: the whole script, exactly as `python -m seal.demo_custody` runs it."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        main()
    output = buf.getvalue()
    assert "consistent    True" in output
    assert "consistent    False" in output
    assert "refused the conflicting head" in output


def test_an_honest_extension_is_consistent():
    key = ec.generate_private_key(ec.SECP256R1())
    log = _grown_log(3, key)
    early = sign_head(log.head(T0), key)
    log.append({"assignment": "ASG-3", "run": 3})
    later = sign_head(log.head(T0 + 1), key)
    ok, reason = heads_consistent(early, later, log.consistency_proof(3))
    assert ok, reason


def test_a_rewrite_breaks_consistency():
    key = ec.generate_private_key(ec.SECP256R1())
    original = _grown_log(3, key, log_id="x")
    early = sign_head(original.head(T0), key)
    forked = _grown_log(0, key, log_id="x")
    for i in (0, 99, 2, 3):  # entry 1 replaced
        forked.append({"assignment": f"ASG-{i}", "run": i})
    later = sign_head(forked.head(T0 + 1), key)
    ok, reason = heads_consistent(early, later, forked.consistency_proof(3))
    assert not ok
    assert "altered or removed" in reason


def test_a_witness_cosigns_the_extension_and_refuses_the_split():
    key = ec.generate_private_key(ec.SECP256R1())
    log = _grown_log(3, key)
    honest = sign_head(log.head(T0), key)
    forked = _grown_log(0, key)
    for i in (0, 1, 99):
        forked.append({"assignment": f"ASG-{i}", "run": i})
    conflicting = sign_head(forked.head(T0 + 1), key)

    witness = Witness("state-board", ec.generate_private_key(ec.SECP256R1()))
    assert witness.cosign(honest)
    try:
        witness.cosign(conflicting)
        assert False, "the witness cosigned a conflicting root at a size it already signed"
    except WitnessRefusal:
        pass


def test_contradiction_is_final_and_unreconciled_is_rebuttable_with_a_real_proof():
    key = ec.generate_private_key(ec.SECP256R1())
    log = _grown_log(3, key)
    early = sign_head(log.head(T0), key)
    log.append({"assignment": "ASG-3", "run": 3})
    later = sign_head(log.head(T0 + 1), key)

    forked = _grown_log(0, key)
    for i in (0, 1, 99, 3):
        forked.append({"assignment": f"ASG-{i}", "run": i})
    conflicting = sign_head(forked.head(T0 + 1), key)

    contradiction = equivocation(later, conflicting)
    assert contradiction["finality"] == CONTRADICTION
    assert equivocation_holds(contradiction)
    assert not rebut(contradiction, [])

    unreconciled = equivocation(early, later)
    assert unreconciled["finality"] == UNRECONCILED
    assert not rebut(unreconciled, [])
    assert rebut(unreconciled, log.consistency_proof(3))
