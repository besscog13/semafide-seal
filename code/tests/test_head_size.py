"""
A signed tree head whose size is not a non-negative integer is refused.

`TreeHead` is a dataclass, and a dataclass does not enforce its annotations.
A custodian can sign a head whose size is "3", None, a list, a bool or a
negative number, and the signature verifies, because the custodian holds the
key. Every examiner and witness path compares sizes with `<` after the
signature check. Before 2026-10-19 such a head made `heads_consistent` and
`equivocation` raise instead of returning a verdict, and a `Witness` cosigned
it and then raised on every real head for that log.

The custodian is the party under examination, so its heads are hostile input.
Each test below hands one path a malformed head signed by the custodian's own
key.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from seal.log import TransparencyLog, TreeHead, heads_consistent, sign_head
from seal.witness import Witness, WitnessRefusal, equivocation

BAD_SIZES = ["3", None, [3], True, -1]


def _log_and_key():
    key = ec.generate_private_key(ec.SECP256R1())
    log = TransparencyLog("semafide")
    for i in range(3):
        log.append({"run": i})
    return log, key


def _malformed(log, key, size):
    real = log.head(0)
    return sign_head(TreeHead(size, real.root, 1, real.log_id), key)


@pytest.mark.parametrize("size", BAD_SIZES)
def test_heads_consistent_refuses_a_malformed_size_in_either_position(size):
    log, key = _log_and_key()
    good = sign_head(log.head(0), key)
    bad = _malformed(log, key, size)

    for old, new in ((good, bad), (bad, good)):
        ok, reason = heads_consistent(old, new, [])
        assert ok is False
        assert "malformed" in reason


@pytest.mark.parametrize("size", BAD_SIZES)
def test_a_witness_refuses_a_malformed_head_and_still_serves_the_log(size):
    log, key = _log_and_key()
    witness = Witness("w", ec.generate_private_key(ec.SECP256R1()))

    with pytest.raises(WitnessRefusal, match="malformed"):
        witness.cosign(_malformed(log, key, size))

    assert witness.cosign(sign_head(log.head(2), key))


@pytest.mark.parametrize("size", BAD_SIZES)
def test_equivocation_returns_no_proof_for_a_malformed_head(size):
    log, key = _log_and_key()
    good = sign_head(log.head(0), key)
    bad = _malformed(log, key, size)

    assert equivocation(good, bad) is None
    assert equivocation(bad, good) is None
