"""
`demo_60s.py` is a presentation layer over the real verifier, not a second
one, and its own module docstring says so. Its printed verdicts are only
honest if they actually reflect what `verify()` returned rather than a
comparison that can never succeed regardless of the real state.
"""
from __future__ import annotations

from seal import Completeness, EvidencePropositions, VerificationReport
from seal.demo_60s import _evidentiary_reliance


def _fully_established_report(completeness: Completeness) -> VerificationReport:
    """A report where every evidence proposition holds, varying only completeness."""
    evidence = EvidencePropositions(
        precedence=True,
        witness_attestation=True,
        recipe_available=True,
        recipe_reproduced=True,
        historical_execution_established=True,
    )
    return VerificationReport(
        chain_intact=True,
        signatures_valid=True,
        key_trusted=True,
        binding_level=evidence.binding_level(),
        evidence=evidence,
        timestamp_replicable=False,
        completeness=completeness,
    )


def test_evidentiary_reliance_reaches_true_when_completeness_is_consistent():
    """
    `_evidentiary_reliance` used to compare `report.completeness.name`
    against the string "COMPLETE", which is not a member of the
    `Completeness` enum at all (the real members are UNCHECKED, CONSISTENT,
    SHORT, MISMATCHED, UNUSABLE). That comparison could never succeed, so
    the aggregate could never report full evidentiary reliance even when
    every other proposition held and completeness reached CONSISTENT, the
    best real state a checkpoint can produce.

    This is a real bug in the presentation layer only: `demo_60s.py`'s own
    `_verify` helper never supplies a checkpoint in any scenario the runner
    actually executes, so completeness stays UNCHECKED there and the bug
    was invisible in the shipped output. It becomes visible the moment a
    checkpoint enters the picture and completeness reaches CONSISTENT,
    which this test constructs directly.
    """
    report = _fully_established_report(Completeness.CONSISTENT)
    assert _evidentiary_reliance(report) is True


def test_evidentiary_reliance_stays_false_for_every_other_completeness_state():
    """
    Companion to the test above, checked against every real member of the
    enum rather than only the one CONSISTENT case: an otherwise fully
    established report must not read as complete for UNCHECKED, SHORT,
    MISMATCHED, or UNUSABLE.
    """
    for state in Completeness:
        if state is Completeness.CONSISTENT:
            continue
        report = _fully_established_report(state)
        assert _evidentiary_reliance(report) is False, state
