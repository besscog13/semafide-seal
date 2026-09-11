"""Rehearsal of assignment handover for a later examiner.

Public purpose: show that “how many runs did this assignment hold?” is answered
by a count from a second key, not by the file the operator chooses to produce.

This is not a hosted custodian and not a supported API. Sibling artifacts are
built directly so the check has two records to compare; the live capture
decorator still cannot open a second chain under one assignment id.

A valuation that is never sent never appears in the count. The rehearsal does
not watch the operator's machine.
"""
from __future__ import annotations

from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric import ec

from ..artifact import SealChain, chain_identity, export_artifact, load_artifact
from ..assignment import (
    AssignmentIssuer,
    AssignmentStatement,
    ChainRef,
    Disclosure,
    assess,
    issue,
)


def sibling_artifacts(
    assignment_id: str,
    operator_key: ec.EllipticCurvePrivateKey,
    labels: tuple[str, ...] = ("A", "B"),
    opened_ns: int = 1,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for label in labels:
        chain = SealChain(
            assignment_id,
            private_key=operator_key,
            opened_ns=opened_ns,
            chain_label=label,
        )
        out.append(export_artifact(chain))
    return out


def refs_from_artifacts(artifacts: Iterable[dict[str, Any]]) -> tuple[str, tuple[ChainRef, ...]]:
    refs: list[ChainRef] = []
    assignment_id = ""
    for doc in artifacts:
        entries = load_artifact(doc)
        ident = chain_identity(entries)
        if ident is None:
            raise ValueError("artifact has no assignment anchor")
        aid, chain_id = ident
        if assignment_id and aid != assignment_id:
            raise ValueError("artifacts name more than one assignment")
        assignment_id = aid
        refs.append(ChainRef(chain_id, entries[-1].block_hash, len(entries)))
    if not assignment_id:
        raise ValueError("no artifacts")
    return assignment_id, tuple(refs)


def issue_statement(
    artifacts: Iterable[dict[str, Any]],
    issuer: AssignmentIssuer,
    observed_ns: int,
) -> dict[str, Any]:
    assignment_id, chains = refs_from_artifacts(artifacts)
    return issuer.issue(
        AssignmentStatement(
            assignment_id=assignment_id,
            chains=chains,
            observed_ns=observed_ns,
            issuer=issuer.name,
        )
    )


def run_cases() -> dict[str, Any]:
    assignment_id = "ASG-DUMMY"
    operator_key = ec.generate_private_key(ec.SECP256R1())
    custodian_key = ec.generate_private_key(ec.SECP256R1())
    artifacts = sibling_artifacts(assignment_id, operator_key)
    issuer = AssignmentIssuer(name="dummy-custodian", key=custodian_key)
    statement = issue_statement(artifacts, issuer, observed_ns=2)

    whole = assess(artifacts, statement)
    partial = assess(artifacts[:1], statement)
    self_issued = issue(
        AssignmentStatement(
            assignment_id=assignment_id,
            chains=refs_from_artifacts(artifacts)[1],
            observed_ns=2,
            issuer="operator",
        ),
        operator_key,
    )
    unusable = assess(artifacts, self_issued)

    return {
        "whole": whole,
        "partial": partial,
        "unusable": unusable,
        "unsent_run": (
            "A valuation that was never sent produced no record. The outside "
            "count covers only what was received. It does not cover the shop floor."
        ),
    }


def main() -> None:
    cases = run_cases()
    w, p, u = cases["whole"], cases["partial"], cases["unusable"]
    print("Whole disclosure:", w.state.value,
          f"(examiner saw {w.disclosed} of {w.expected} records the outside party held)")
    print("Partial disclosure:", p.state.value,
          f"(examiner saw {p.disclosed} of {p.expected}; {len(p.withheld)} withheld)")
    print("Self-signed count:", u.state.value,
          "(the shop that ran the valuations signed its own list)")
    print("Unsent run:", cases["unsent_run"])
    if w.state is not Disclosure.WHOLE:
        raise SystemExit(1)
    if p.state is not Disclosure.PARTIAL:
        raise SystemExit(1)
    if u.state is not Disclosure.UNUSABLE:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
