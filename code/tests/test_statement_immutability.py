"""
An assignment issuer's memory of what it signed cannot be edited by its caller.

`AssignmentIssuer` refuses to sign a statement that drops a chain it has
already recorded, and it decides that against the statements it remembers.
`AssignmentStatement.chains` is annotated as a tuple, but a frozen dataclass
does not enforce the annotation. Before 2026-10-12 a caller that passed a list
kept a live handle on the chains of a statement the issuer had stored. Removing
a chain from that list after signing removed it from the issuer's memory too,
and the issuer then signed the shrunken statement it exists to refuse.
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


def _refs() -> list[ChainRef]:
    return [ChainRef(c * 64, f"head-{c}", 3) for c in "abc"]


def test_editing_the_list_after_signing_does_not_let_a_chain_be_dropped():
    issuer = AssignmentIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    refs = _refs()
    issuer.issue(AssignmentStatement("ASG", refs, 1, "custodian"))

    refs.pop()

    with pytest.raises(AssignmentRefusal, match="absent from"):
        issuer.issue(AssignmentStatement("ASG", refs, 2, "custodian"))


def test_a_statement_built_from_a_list_holds_its_own_tuple():
    refs = _refs()
    statement = AssignmentStatement("ASG", refs, 1, "custodian")

    refs.clear()

    assert isinstance(statement.chains, tuple)
    assert len(statement.chains) == 3
