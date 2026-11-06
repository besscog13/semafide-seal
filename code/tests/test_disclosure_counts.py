"""
A signed assignment statement with a malformed count is unusable.

`assess` is exported as `assess_disclosure` and is called directly by
examiners and by the custody rehearsal, outside the fail-closed `verify`
wrapper. `ChainRef` is a dataclass and does not enforce its annotation, so a
custodian can sign a statement whose count is "4", None, 2.5, a list, True or
-1, and the signature verifies. Before 2026-11-02 the first four made `assess`
raise TypeError, and True or -1 read as PARTIAL, which accuses the operator of
withholding runs for a defect in the custodian's own statement.

Each case signs such a statement over a real chain with a separate custodian
key, and checks that `assess` returns UNUSABLE and that `verify` reports the
same while leaving the chain's own result alone.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from seal.artifact import EntryKind, SealChain, chain_identity, export_artifact
from seal.assignment import (
    AssignmentStatement,
    ChainRef,
    Disclosure,
    assess,
    issue,
)
from seal.verifier import verify

BAD_COUNTS = ["4", None, 2.5, [4], True, -1]


def _chain_and_statement(count):
    chain = SealChain("ASG", ec.generate_private_key(ec.SECP256R1()))
    for i in range(3):
        chain.append(EntryKind.EVIDENCE_COMMITMENT, {"i": i}, 10 + i)
    chain_id = chain_identity(chain.entries)[1]
    statement = issue(
        AssignmentStatement("ASG", (ChainRef(chain_id, chain.head, count),),
                            99, "custodian"),
        ec.generate_private_key(ec.SECP256R1()),
    )
    return chain, statement


@pytest.mark.parametrize("count", BAD_COUNTS)
def test_assess_reads_a_malformed_count_as_unusable(count):
    chain, statement = _chain_and_statement(count)

    report = assess([export_artifact(chain)], statement)

    assert report.state is Disclosure.UNUSABLE
    assert "non-negative integer" in report.findings[0]


@pytest.mark.parametrize("count", BAD_COUNTS)
def test_verify_reads_a_malformed_count_as_unusable(count):
    chain, statement = _chain_and_statement(count)

    report = verify(export_artifact(chain), trusted_keys=[chain.public_key_pem],
                    assignment_statement=statement)

    assert report.disclosure is Disclosure.UNUSABLE
    assert report.trustworthy


def test_a_well_formed_count_is_still_whole():
    # Three appended entries after the assignment anchor make four.
    chain, statement = _chain_and_statement(4)

    assert len(chain.entries) == 4
    assert assess([export_artifact(chain)], statement).state is Disclosure.WHOLE
