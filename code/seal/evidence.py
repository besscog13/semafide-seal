"""Evidentiary reliance is distinct from cryptographic trust.

`VerificationReport.trustworthy` answers a narrow cryptographic question:
are the chain, signatures, and supplied signer identity internally sound?

This module answers a different question: has the verifier established enough
about the relation between the claimed action and evidence to treat that
relation as evidentiary rather than merely authenticated?

The result deliberately does not assert substantive correctness, assignment
completeness, or regulatory admissibility.
"""

from __future__ import annotations

from dataclasses import dataclass

from .verifier import BindingLevel, VerificationReport


@dataclass(frozen=True)
class EvidentiaryReliance:
    """Result of the verifier's relation-level reliance test."""

    established: bool
    reasons: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.established


def assess_evidentiary_reliance(report: VerificationReport) -> EvidentiaryReliance:
    """Assess whether the report clears the current relation-level threshold.

    This is intentionally narrower than a general "safe to rely on" claim.
    It requires cryptographic trust plus a binding level that establishes the
    action/evidence relation without depending on a commodity timestamping
    service. It does not claim that the underlying analysis is correct or that
    the assignment disclosure is complete.
    """
    reasons: list[str] = []

    if not report.trustworthy:
        reasons.append("cryptographic_trust_not_established")

    if report.binding_level not in (BindingLevel.WITNESSED, BindingLevel.REDERIVED):
        reasons.append(
            f"binding_level_{report.binding_level.name.lower()}_does_not_establish_relation"
        )

    if report.kc2_fires:
        reasons.append("commodity_timestamping_is_sufficient")

    return EvidentiaryReliance(established=not reasons, reasons=tuple(reasons))


__all__ = ["EvidentiaryReliance", "assess_evidentiary_reliance"]
