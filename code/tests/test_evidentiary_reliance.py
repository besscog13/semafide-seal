"""Adversarial tests for the trust/reliance distinction."""

from __future__ import annotations

from seal import (
    BindingLevel,
    EvidencePropositions,
    EvidentiaryReliance,
    VerificationReport,
    assess_evidentiary_reliance,
)


def _report(*, evidence: EvidencePropositions, kc2: bool = False,
            trustworthy: bool = True) -> VerificationReport:
    r = VerificationReport(
        chain_intact=trustworthy,
        signatures_valid=trustworthy,
        key_trusted=True if trustworthy else False,
        binding_level=evidence.binding_level(),
        evidence=evidence,
        timestamp_replicable=kc2,
    )
    return r


def test_crypto_trust_does_not_mean_evidentiary_reliance():
    r = _report(evidence=EvidencePropositions(precedence=True), kc2=True)

    assert r.trustworthy
    assessed = assess_evidentiary_reliance(r)

    assert isinstance(assessed, EvidentiaryReliance)
    assert not assessed
    assert "no_independent_witness_attestation_or_recipe_reproduction" in assessed.reasons
    assert "commodity_timestamping_is_sufficient" in assessed.reasons


def test_bundled_artifact_can_be_authentic_but_not_relation_evidence():
    r = _report(evidence=EvidencePropositions(), kc2=True)

    assert r.trustworthy
    assert not assess_evidentiary_reliance(r).established


def test_rederived_result_can_clear_relation_threshold():
    r = _report(evidence=EvidencePropositions(
        precedence=True, recipe_available=True, recipe_reproduced=True,
    ), kc2=False)

    assert r.trustworthy
    assert assess_evidentiary_reliance(r).established


def test_witnessed_result_can_clear_relation_threshold():
    r = _report(evidence=EvidencePropositions(
        precedence=True, witness_attestation=True,
        historical_execution_established=True,
    ), kc2=False)

    assert r.trustworthy
    assert assess_evidentiary_reliance(r).established


def test_crypto_failure_blocks_evidentiary_reliance():
    r = _report(evidence=EvidencePropositions(
        precedence=True, recipe_available=True, recipe_reproduced=True,
    ), kc2=False, trustworthy=False)

    assert not r.trustworthy
    assessed = assess_evidentiary_reliance(r)
    assert not assessed
    assert "cryptographic_trust_not_established" in assessed.reasons


def test_rederivable_is_not_historical_relation_proof():
    r = _report(evidence=EvidencePropositions(
        precedence=True, recipe_available=True,
    ), kc2=False)

    assert r.trustworthy
    assessed = assess_evidentiary_reliance(r)
    assert not assessed
    assert "no_independent_witness_attestation_or_recipe_reproduction" in assessed.reasons


def test_witnessed_but_not_reproducible_keeps_the_claims_separate():
    r = _report(evidence=EvidencePropositions(
        precedence=True, witness_attestation=True,
        historical_execution_established=True,
    ))
    assert r.evidence.historical_execution_established
    assert not r.evidence.recipe_reproduced


def test_reproducible_but_not_historically_witnessed_is_not_historical_proof():
    r = _report(evidence=EvidencePropositions(
        precedence=True, recipe_available=True, recipe_reproduced=True,
    ))
    assert r.evidence.recipe_reproduced
    assert not r.evidence.historical_execution_established


def test_witnessed_and_reproduced_are_independent_combined_evidence():
    r = _report(evidence=EvidencePropositions(
        precedence=True, witness_attestation=True, recipe_available=True,
        recipe_reproduced=True, historical_execution_established=True,
    ))
    assert r.evidence.witness_attestation and r.evidence.recipe_reproduced
    assert r.evidence.historical_execution_established


def test_neither_witnessed_nor_reproduced_does_not_establish_relation():
    r = _report(evidence=EvidencePropositions(precedence=True), kc2=True)
    assert not assess_evidentiary_reliance(r)
