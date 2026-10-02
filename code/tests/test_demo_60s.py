"""
`demo_60s.py` is a presentation layer over the real verifier, not a second
one, and its own module docstring says so. Its EVIDENTIARY RELIANCE line is
only honest if it is the package's own `assess_evidentiary_reliance` rather
than a stricter or looser rule the demo keeps for itself.

An earlier version computed that line with its own rule: all five
propositions and a CONSISTENT completeness. The public instrument page
described the package's rule under the demo's label, so the two disagreed.
"""
from __future__ import annotations

import itertools

from seal import (
    Completeness,
    EvidencePropositions,
    VerificationReport,
    assess_evidentiary_reliance,
)
from seal import demo_60s
from seal.demo_60s import _evidentiary_reliance


def _report(*, evidence: EvidencePropositions, kc2: bool,
            completeness: Completeness = Completeness.UNCHECKED,
            trustworthy: bool = True) -> VerificationReport:
    return VerificationReport(
        chain_intact=trustworthy,
        signatures_valid=trustworthy,
        key_trusted=trustworthy,
        evidence=evidence,
        timestamp_replicable=kc2,
        completeness=completeness,
    )


def test_demo_line_is_the_package_rule_for_every_combination():
    """Every combination of the inputs the package rule reads agrees."""
    for witness, reproduced, kc2, trustworthy in itertools.product(
        (False, True), repeat=4,
    ):
        report = _report(
            evidence=EvidencePropositions(
                witness_attestation=witness,
                historical_execution_established=witness,
                recipe_reproduced=reproduced,
            ),
            kc2=kc2,
            trustworthy=trustworthy,
        )
        expected = assess_evidentiary_reliance(report).established
        assert _evidentiary_reliance(report) is expected, (
            witness, reproduced, kc2, trustworthy,
        )


def test_completeness_does_not_move_the_reliance_line():
    """Completeness is printed on its own line and is not in the rule."""
    for state in Completeness:
        report = _report(
            evidence=EvidencePropositions(witness_attestation=True,
                                          historical_execution_established=True),
            kc2=False,
            completeness=state,
        )
        assert _evidentiary_reliance(report) is True, state


def test_honest_run_fails_reliance_because_a_timestamp_reaches_the_same_place():
    """
    The runner supplies no retention determination, because no real
    valuation tool has a signed one. The recipe still reproduces, and the
    honest run still fails reliance, for the KC2 reason a real record would.
    """
    report = demo_60s._verify(demo_60s.build_chain())

    assert report.trustworthy
    assert report.evidence.recipe_reproduced
    assert not report.evidence.witness_attestation
    assert report.kc2_fires
    assert _evidentiary_reliance(report) is False
