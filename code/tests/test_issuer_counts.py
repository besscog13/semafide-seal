"""
A custodian issuer refuses a count that is not a non-negative integer.

`ChainStatementIssuer` and `AssignmentIssuer` remember the last statement they
signed for each assignment and compare later counts against it with `<`. Both
statement classes are dataclasses, which do not enforce their annotations, and
neither issuer checked the type. Before 2026-10-26 a statement counting "5",
None or a list was signed and stored as the baseline. Every later statement
for that assignment then raised TypeError, so one malformed request stopped
the issuer for that assignment. A bool or negative count was signed the same
way.

The statement reaches the issuer from the party asking for it, which is the
party being sealed. Each test hands one issuer a malformed count, checks it is
refused, and checks the issuer still signs a real statement afterward.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from seal.assignment import (
    AssignmentIssuer,
    AssignmentRefusal,
    AssignmentStatement,
    ChainRef,
)
from seal.checkpoint import (
    ChainStatement,
    ChainStatementIssuer,
    ChainStatementRefusal,
)

BAD_COUNTS = ["5", None, [5], True, -1]


def _key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize("count", BAD_COUNTS)
def test_chain_statement_issuer_refuses_a_malformed_count(count):
    issuer = ChainStatementIssuer("custodian", _key())

    with pytest.raises(ChainStatementRefusal, match="non-negative integer"):
        issuer.issue(ChainStatement("ASG", count, "h" * 64, 1, "custodian"))

    assert issuer.issue(ChainStatement("ASG", 5, "h" * 64, 2, "custodian"))


@pytest.mark.parametrize("count", BAD_COUNTS)
def test_assignment_issuer_refuses_a_malformed_count(count):
    issuer = AssignmentIssuer("custodian", _key())
    chain = "c" * 64

    with pytest.raises(AssignmentRefusal, match="non-negative integer"):
        issuer.issue(AssignmentStatement(
            "ASG", (ChainRef(chain, "h", count),), 1, "custodian"))

    assert issuer.issue(AssignmentStatement(
        "ASG", (ChainRef(chain, "h", 5),), 2, "custodian"))
