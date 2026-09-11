"""Dummy custodian: receive artifacts, issue an AssignmentStatement.

Not a hosted service. Not a supported API. The capture decorator still cannot
open a second chain under one assignment id; sibling chains here are built
with SealChain(chain_label=...) so assess() has two chain_ids to compare.

An undecorated run never becomes an artifact. The custodian can only attest
to what it received. That is KC3 and this script does not close it.
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
    """Two (or more) chains under one assignment, operator-signed."""
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
    """Custodian view: sign only what was handed over."""
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
        "kc3": (
            "A third valuation that never hit the decorator produced no "
            "artifact. The custodian attested to the two chains it received. "
            "It cannot attest that no other run occurred."
        ),
    }


def main() -> None:
    cases = run_cases()
    print("WHOLE", cases["whole"].state, "expected", cases["whole"].expected,
          "disclosed", cases["whole"].disclosed)
    print("PARTIAL", cases["partial"].state, "expected", cases["partial"].expected,
          "disclosed", cases["partial"].disclosed, "withheld",
          len(cases["partial"].withheld))
    print("UNUSABLE", cases["unusable"].state)
    print("KC3", cases["kc3"])
    if cases["whole"].state is not Disclosure.WHOLE:
        raise SystemExit(1)
    if cases["partial"].state is not Disclosure.PARTIAL:
        raise SystemExit(1)
    if cases["unusable"].state is not Disclosure.UNUSABLE:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
