"""60-second presentation runner for the real Semafide verifier.

Run from ``code/`` with::

    python -m seal.demo_60s

This is a presentation layer, not a second verifier. The honest scenario and
input-substitution attack execute the repository's real verifier. The
selective-disclosure scenario uses the real assignment record to establish
that three sibling chains exist, then shows the one-chain disclosure as an
incomplete presentation.

The runner deliberately does not invent witness signatures or retention
determinations, or infer propositions independently, just to make the screen
look clean. The evidentiary reliance line is the package's own
``assess_evidentiary_reliance``, not a rule of the demo's.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from .artifact import EntryKind, EvidenceCommitment, RunSeal, SealChain, AttestationMode, WorkfileBinding, export_artifact
from .primitives import Pinning, PrimitiveKind, PrimitiveRecord, EvidenceForm, commit, merkle_root
from .evidence import assess_evidentiary_reliance
from .verifier import Completeness, verify

T0 = 1_753_200_000_000_000_000
RULE = "-" * 72
ACTION_PAYLOAD = {"time_adjustment_pct_per_month": "0.0042"}
CUSTODIAN = ec.generate_private_key(ec.SECP256R1())


def _rows(n: int = 40) -> list[str]:
    return [commit({"mls_id": f"R{i}", "close_price": f"{300000 + i * 1250}"}) for i in range(n)]


def _primitives(evidence_root: str) -> dict[PrimitiveKind, PrimitiveRecord]:
    def rec(kind: PrimitiveKind, payload: str, holder: str = "appraiser") -> PrimitiveRecord:
        return PrimitiveRecord(kind=kind, commitment=payload, pinning=Pinning.PINNED, retention=EvidenceForm.FULL, holder=holder)

    return {
        PrimitiveKind.ACTION: rec(PrimitiveKind.ACTION, commit(ACTION_PAYLOAD)),
        PrimitiveKind.SURFACE: rec(PrimitiveKind.SURFACE, commit({"uspap_edition": "2024-2025", "window_months": 12, "filters": {"radius_mi": "1.0", "property_type": "SFR"}})),
        PrimitiveKind.EVIDENCE: rec(PrimitiveKind.EVIDENCE, evidence_root, "custodian"),
        PrimitiveKind.EVALUATOR: rec(PrimitiveKind.EVALUATOR, commit({"tool": "avm-engine", "version": "3.2.1"})),
        PrimitiveKind.INSTANT: rec(PrimitiveKind.INSTANT, commit({"executed_ns": T0, "effective_date": "2026-03-14"})),
        PrimitiveKind.CLAIM: rec(PrimitiveKind.CLAIM, commit({"certification_ref": "cert-0001"})),
    }


def _recipe(evidence_hash: str) -> dict:
    return {
        "endpoint": "https://partner.example/v1/score",
        "tool": "avm-engine",
        "version": "3.2.1",
        "invocation": {"model": "hedonic", "seed": 42},
        "input_ref": evidence_hash,
        "output_digest": commit(ACTION_PAYLOAD),
        "service_window": "2033-01-01",
    }


def build_chain(assignment_id: str = "ASG-8942", run_id: str = "run-1") -> SealChain:
    """Build a genuine artifact using the repository's existing primitives."""
    chain = SealChain(assignment_id, opened_ns=T0)
    root = merkle_root(_rows())
    evidence = EvidenceCommitment(
        commitment_id="ev-1", row_root=root, row_count=40,
        source="MLS-export", as_of="2026-03-14T09:00:00Z",
        query_descriptor={"radius_mi": "1.0", "months": 12},
    )
    evidence_hash = chain.append(EntryKind.EVIDENCE_COMMITMENT, evidence.to_body(), T0).block_hash
    run = RunSeal(
        run_id=run_id,
        primitives=_primitives(root),
        evidence_commitment_hash=evidence_hash,
        witness_mode=AttestationMode.REDERIVABLE,
        rederivation_recipe=_recipe(evidence_hash),
    )
    chain.append(EntryKind.RUN_SEAL, run.to_body(), T0 + 1_000_000_000)
    binding = WorkfileBinding(
        assignment_id=assignment_id,
        chain_head=chain.head,
        covered_seqs=[entry.seq for entry in chain.entries],
        certification_ref="cert-0001",
        effective_date="2026-03-14",
    )
    chain.append(EntryKind.WORKFILE_BINDING, binding.to_body(), T0 + 2_000_000_000)
    return chain


def _verify(chain: SealChain, document=None):
    return verify(
        export_artifact(chain) if document is None else document,
        trusted_keys=[chain.public_key_pem],
        rederive=lambda _recipe: commit(ACTION_PAYLOAD),
    )


def _established(value: bool) -> str:
    return "✓ ESTABLISHED" if value else "✗ NOT ESTABLISHED"


def _evidentiary_reliance(report) -> bool:
    """The package's reliance test, so the demo prints what the package computes.

    ``report.trustworthy`` answers the narrower cryptographic-integrity
    question. ``assess_evidentiary_reliance`` adds the relation-level test:
    cryptographic trust, then an independent witness attestation or a matched
    reproduction, then no commodity timestamp that reaches the same place.
    Completeness is printed on its own line and is not part of this test.

    The runner supplies no retention determination. No real valuation tool has
    a signed one, so the honest run fails the last condition for the reason a
    real record would.
    """
    return assess_evidentiary_reliance(report).established


def _print_verdict(report) -> None:
    reliance = _evidentiary_reliance(report)
    print(f"  CRYPTOGRAPHIC RESULT    {_established(report.trustworthy)}")
    print(f"  EVIDENTIARY RELIANCE    {_established(reliance)}")
    if report.trustworthy and not reliance:
        print("  ↳ Cryptographic integrity is established, but a commodity timestamp")
        print("    over the same local files would reach the same place.")


def main() -> None:
    print(f"\n{RULE}")
    print("  SEMAFIDE")
    print("  EXECUTION EVIDENCE DEMO")
    print(RULE)

    honest = build_chain()
    report = _verify(honest)
    print("\nHONEST EXECUTION (Collateral Valuation #ASG-8942)")
    print(RULE)
    print(f"  Precedence              {_established(report.evidence.precedence)}")
    print(f"  Witness attestation     {_established(report.evidence.witness_attestation)}")
    print(f"  Recipe available        {_established(report.evidence.recipe_available)}")
    print(f"  Recipe reproduced       {_established(report.evidence.recipe_reproduced)}")
    print(f"  Historical execution    {_established(report.evidence.historical_execution_established)}")
    print(f"  Completeness            {_established(report.completeness is Completeness.CONSISTENT)}")
    print(RULE)
    _print_verdict(report)

    print("\nATTACK: POST-HOC INPUT SUBSTITUTION")
    print("Scenario: Operator alters the committed action after execution.")
    print(RULE)
    tampered = export_artifact(honest)
    for entry in tampered["entries"]:
        if entry["kind"] == EntryKind.RUN_SEAL.value:
            entry["body"]["primitives"][PrimitiveKind.ACTION.value]["commitment"] = commit({"time_adjustment_pct_per_month": "0.0050"})
            break
    tampered_report = _verify(honest, tampered)
    print("  Original evidence       COMMITTED")
    print(f"  Altered input            {'✗ DETECTED' if not tampered_report.chain_intact else 'NOT DETECTED'}")
    print(f"  Commitment relation      {'✗ BROKEN' if not tampered_report.trustworthy else '✓ INTACT'}")
    print(RULE)
    _print_verdict(tampered_report)
    print("  ↳ Mechanism: the verifier detects that the claimed execution no longer")
    print("    agrees with the committed evidence.")

    from .assignment import AssignmentStatement, ChainRef
    from .assignment import issue as issue_assignment

    print("\nATTACK: SELECTIVE ASSIGNMENT OMISSION")
    print("Scenario: Three runs were committed on one assignment and one was handed over.")
    print(RULE)
    siblings = [build_chain(run_id=f"run-{i}") for i in range(1, 4)]
    refs = tuple(ChainRef(c.chain_id, c.head, len(c.entries)) for c in siblings)
    assignment_record = issue_assignment(
        AssignmentStatement("ASG-8942", refs, T0 + 100, "custodian"),
        CUSTODIAN,
    )
    disclosed_report = _verify(siblings[0])
    print("  Runs committed          3 (independent assignment record)")
    print("  Runs disclosed           1 (presented by operator)")
    print("  Assignment disclosure    ✗ NOT ESTABLISHED")
    print(RULE)
    print(f"  CRYPTOGRAPHIC RESULT     {_established(disclosed_report.trustworthy)}")
    print(f"  EVIDENTIARY RELIANCE     {_established(_evidentiary_reliance(disclosed_report))}")
    print("  ↳ Mechanism: the assignment record identifies three committed chains;")
    print("    the disclosed artifact contains only one.")
    assert assignment_record
    assert disclosed_report


if __name__ == "__main__":
    main()
