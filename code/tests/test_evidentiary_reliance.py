"""Adversarial tests for the trust/reliance distinction."""

from __future__ import annotations

from seal import (
    BindingLevel,
    EvidentiaryReliance,
    VerificationReport,
    assess_evidentiary_reliance,
)


def _report(*, binding: BindingLevel, kc2: bool = False,
            trustworthy: bool = True) -> VerificationReport:
    r = VerificationReport(
        chain_intact=trustworthy,
        signatures_valid=trustworthy,
        key_trusted=True if trustworthy else False,
        binding_level=binding,
        timestamp_replicable=kc2,
    )
    return r


def test_crypto_trust_does_not_mean_evidentiary_reliance():
    r = _report(binding=BindingLevel.PRECEDENCE, kc2=True)

    assert r.trustworthy
    assessed = assess_evidentiary_reliance(r)

    assert isinstance(assessed, EvidentiaryReliance)
    assert not assessed
    assert "binding_level_precedence_does_not_establish_relation" in assessed.reasons
    assert "commodity_timestamping_is_sufficient" in assessed.reasons


def test_bundled_artifact_can_be_authentic_but_not_relation_evidence():
    r = _report(binding=BindingLevel.BUNDLED, kc2=True)

    assert r.trustworthy
    assert not assess_evidentiary_reliance(r).established


def test_rederived_result_can_clear_relation_threshold():
    r = _report(binding=BindingLevel.REDERIVED, kc2=False)

    assert r.trustworthy
    assert assess_evidentiary_reliance(r).established


def test_witnessed_result_can_clear_relation_threshold():
    r = _report(binding=BindingLevel.WITNESSED, kc2=False)

    assert r.trustworthy
    assert assess_evidentiary_reliance(r).established


def test_crypto_failure_blocks_evidentiary_reliance():
    r = _report(binding=BindingLevel.REDERIVED, kc2=False, trustworthy=False)

    assert not r.trustworthy
    assessed = assess_evidentiary_reliance(r)
    assert not assessed
    assert "cryptographic_trust_not_established" in assessed.reasons


def test_rederivable_is_not_historical_relation_proof():
    r = _report(binding=BindingLevel.REDERIVABLE, kc2=False)

    assert r.trustworthy
    assessed = assess_evidentiary_reliance(r)
    assert not assessed
    assert "binding_level_rederivable_does_not_establish_relation" in assessed.reasons
