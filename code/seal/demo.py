"""
Runnable walkthrough of what the verifier establishes.

    pip install -r code/seal/requirements.txt
    cd code && python -m seal.demo

Nine scenarios are built and verified. Each differs from the last by one
decision, and the verdict changes accordingly. The point of the sequence is
the second kill condition: an artifact fails it when a commodity timestamping
service could have produced the same evidentiary force, and the verifier
computes that rather than being told it.

Nothing here is a test. The test suite asserts these outcomes in
`code/tests/test_seal_verifier.py`. This prints them so they can be read.
"""

from __future__ import annotations

from .artifact import (
    EntryKind,
    EvidenceCommitment,
    RunSeal,
    SealChain,
    WitnessMode,
    WorkfileBinding,
    export_artifact,
)
from .primitives import (
    Pinning,
    PrimitiveKind,
    PrimitiveRecord,
    Retention,
    commit,
    merkle_root,
)
from .checkpoint import Checkpoint, issue
from .retention import Holding, RetentionDetermination
from .retention import issue as issue_determination
from .verifier import verify

from cryptography.hazmat.primitives.asymmetric import ec

T0 = 1_753_200_000_000_000_000

# The custodian reads tool documentation and signs what it found. Generated
# here so the determinations below are signed by a key that is not the chain's,
# which is the only thing that makes them worth reading.
CUSTODIAN = ec.generate_private_key(ec.SECP256R1())

# The adjustment this artifact claims. A correct recipe must reproduce exactly
# this, which is the link whose absence fires KC2.
ACTION_PAYLOAD = {"time_adjustment_pct_per_month": "0.0042"}
RULE = "-" * 68


def _rows(n: int = 40) -> list[str]:
    """Hashes of forty comparable sales. Stand-in for an MLS export."""
    return [
        commit({"mls_id": f"R{i}", "close_price": f"{300000 + i * 1250}"})
        for i in range(n)
    ]


def _primitives(
    evidence_root: str,
    retention: Retention = Retention.COMMITMENT_ONLY,
) -> dict[PrimitiveKind, PrimitiveRecord]:
    """All six primitives for one time-adjustment run."""
    def rec(kind, payload, **kw):
        return PrimitiveRecord(
            kind=kind,
            commitment=payload,
            pinning=Pinning.PINNED,
            retention=kw.get("retention", Retention.FULL),
            holder=kw.get("holder", "appraiser"),
        )

    return {
        PrimitiveKind.ACTION: rec(PrimitiveKind.ACTION, commit(ACTION_PAYLOAD)),
        PrimitiveKind.SURFACE: rec(
            PrimitiveKind.SURFACE,
            commit({"uspap_edition": "2024-2025", "window_months": 12,
                    "filters": {"radius_mi": "1.0", "property_type": "SFR"}}),
        ),
        PrimitiveKind.EVIDENCE: rec(
            PrimitiveKind.EVIDENCE, evidence_root,
            retention=retention, holder="custodian",
        ),
        PrimitiveKind.EVALUATOR: rec(
            PrimitiveKind.EVALUATOR,
            commit({"tool": "regression-tool", "version": "3.2.1"}),
        ),
        PrimitiveKind.INSTANT: rec(
            PrimitiveKind.INSTANT,
            commit({"executed_ns": T0, "effective_date": "2026-03-14"}),
        ),
        PrimitiveKind.CLAIM: rec(
            PrimitiveKind.CLAIM, commit({"certification_ref": "cert-0001"}),
        ),
    }


def _recipe(evidence_hash: str) -> dict:
    """
    A complete and correctly linked recipe.

    Every field is required, and two of them are load-bearing. `output_digest`
    must be the Action the artifact seals, and `input_ref` must be the evidence
    commitment the run names. Without both, re-deriving the recipe proves only
    that the recipe agrees with itself.
    """
    return {
        "endpoint": "https://partner.example/v1/score",
        "tool": "avm-engine",
        "version": "3.2.1",
        "invocation": {"model": "hedonic", "seed": 42},
        "input_ref": evidence_hash,
        "output_digest": commit(ACTION_PAYLOAD),
        "service_window": "2033-01-01",
    }


def _determination(holding: Holding, key=CUSTODIAN, by: str = "custodian") -> dict:
    """
    A signed reading of what the pinned tool does with the raw input.

    Named for the tool and version the recipe pins, because a determination
    speaks for the version it was read against and no other.
    """
    return issue_determination(
        RetentionDetermination(
            tool="avm-engine", version="3.2.1", holding=holding,
            source="https://partner.example/docs/3.2.1/workflow",
            source_digest=commit({"doc": "workflow", "holding": holding.value}),
            read_as_of="2026-03-14", determined_by=by,
        ),
        key,
    )


def build(
    witness: WitnessMode,
    *,
    commit_first: bool = True,
    rederivable: bool = False,
    retention: Retention = Retention.COMMITMENT_ONLY,
    omit_from_binding: int | None = None,
    assignment_id: str = "assignment-1",
    chain_label: str = "",
    beacon: dict | None = None,
    opened_ns: int = T0,
    base_ns: int = T0,
) -> SealChain:
    """Assemble one artifact. Each keyword changes exactly one decision."""
    chain = SealChain(assignment_id, opened_ns=opened_ns,
                      chain_label=chain_label, beacon=beacon)
    root = merkle_root(_rows())
    ev_hash = None
    t = base_ns

    if commit_first:
        ev = EvidenceCommitment(
            commitment_id="ev-1", row_root=root, row_count=40,
            source="MLS-export", as_of="2026-03-14T09:00:00Z",
            query_descriptor={"radius_mi": "1.0", "months": 12},
        )
        ev_hash = chain.append(
            EntryKind.EVIDENCE_COMMITMENT, ev.to_body(), t
        ).block_hash
        t += 1_000_000_000

    run = RunSeal(
        run_id="run-1",
        primitives=_primitives(root, retention),
        evidence_commitment_hash=ev_hash,
        witness_mode=witness,
        rederivation_recipe=_recipe(ev_hash) if rederivable else None,
    )
    chain.append(EntryKind.RUN_SEAL, run.to_body(), t)
    t += 1_000_000_000

    covered = [e.seq for e in chain.entries]
    if omit_from_binding is not None:
        covered = [s for s in covered if s != omit_from_binding]
    wb = WorkfileBinding(
        assignment_id=assignment_id, chain_head=chain.head,
        covered_seqs=covered, certification_ref="cert-0001",
        effective_date="2026-03-14",
    )
    chain.append(EntryKind.WORKFILE_BINDING, wb.to_body(), t)
    return chain


def show(n: int, title: str, setup: str, chain: SealChain, rederive=None,
         because: str = "", determinations=None) -> None:
    report = verify(export_artifact(chain), trusted_keys=[chain.public_key_pem],
                    rederive=rederive,
                    retention_determinations=determinations)
    print(f"\n{RULE}\n{n}. {title}")
    print(f"   {setup}\n")
    print(f"   binding level     {report.binding_level.name}")
    print(f"   coverage          {report.coverage.name}")
    print(f"   completeness      {report.completeness.name}")
    print(f"   KC2 fires         {'yes' if report.kc2_fires else 'no'}")
    if because:
        print(f"\n   {because}")


def main() -> None:
    print(f"\n{RULE}")
    print("  What the seal establishes, and where it stops establishing it")
    print(RULE)
    print("\n  Kill condition 2: the mechanism fails if it does nothing a")
    print("  third-party-timestamped bundle of the same local files could")
    print("  not do. Each artifact below changes one decision.")

    show(
        1, "A signature over a bundle",
        "The run is sealed. No commitment to the inputs came first.",
        build(WitnessMode.SELF_ATTESTED, commit_first=False),
        because="Nothing connects the output to the inputs. This is what a\n"
                "   signing function produces when handed a dictionary.",
    )

    show(
        2, "Commit the inputs first, then seal",
        "The input set is committed before the run that consumes it.",
        build(WitnessMode.SELF_ATTESTED),
        because="Ordering is fixed, so inputs cannot be chosen after seeing the\n"
                "   output. But two ordinary timestamps achieve the same thing, so\n"
                "   KC2 still fires. Ordering is not derivation.",
    )

    show(
        3, "Carry a re-derivation recipe, but never run it",
        "A pinned endpoint, version, invocation, and expected output digest.",
        build(WitnessMode.REDERIVABLE, rederivable=True),
        because="A recipe a stranger could execute is more than co-location,\n"
                "   but until somebody executes it, it is a claim.",
    )

    show(
        4, "Execute the recipe and compare",
        "A verifier calls the pinned version and checks the output matches.\n"
        "   A custodian has read the tool documentation and signed a finding\n"
        "   that the raw input never lands on the operator's machine.",
        build(WitnessMode.REDERIVABLE, rederivable=True),
        rederive=lambda r: commit(ACTION_PAYLOAD),
        determinations=[_determination(Holding.OPERATOR_CANNOT_HOLD)],
        because="Derivation is demonstrated rather than asserted, and the fact\n"
                "   the clearance rests on came from somebody who is not the\n"
                "   sealer. Both are required. This is the mechanism the product\n"
                "   targets, under the condition that would make it necessary.",
    )

    # 5. Where the retention answer comes from, which is what decides KC2.
    chain5 = build(WitnessMode.REDERIVABLE, rederivable=True)
    sealer_key = chain5._sk  # noqa: SLF001 - demonstrating the refusal

    print(f"\n{RULE}\n5. One artifact, one fact, four sources for it")
    print("   Identical to 4 in every respect except who determined whether")
    print("   the operator can hold the raw input.\n")

    for label, dets in [
        ("nobody determined it", None),
        ("the sealer determined it",
         [_determination(Holding.OPERATOR_CANNOT_HOLD, sealer_key, "sealer")]),
        ("a custodian determined the operator holds it",
         [_determination(Holding.OPERATOR_HOLDS)]),
        ("a custodian determined the operator cannot",
         [_determination(Holding.OPERATOR_CANNOT_HOLD)]),
    ]:
        r = verify(export_artifact(chain5),
                   trusted_keys=[chain5.public_key_pem],
                   rederive=lambda x: commit(ACTION_PAYLOAD),
                   retention_determinations=dets)
        print(f"   {label}")
        print(f"     binding level  {r.binding_level.name}")
        print(f"     provenance     {r.input_provenance.name}")
        print(f"     KC2 fires      {'yes' if r.kc2_fires else 'no'}")

    print("\n   The artifact's own retention field records what this document")
    print("   carries. Whether the operator can hold the input is a fact about")
    print("   the tool's documented workflow, it is the same for every run that")
    print("   tool produces, and the sealer has an interest in the answer. The")
    print("   third row is the reading the tool export audit returned.")

    show(
        6, "A run left out of the workfile binding",
        "Same as 4, but the binding names a subset of the chain.",
        build(WitnessMode.REDERIVABLE, rederivable=True, omit_from_binding=1),
        rederive=lambda r: commit(ACTION_PAYLOAD),
        determinations=[_determination(Holding.OPERATOR_CANNOT_HOLD)],
        because="Coverage drops to SUBSET and the verifier names what was\n"
                "   dropped. This is the separate anti-cherry-picking property,\n"
                "   KC3, and it is what committing inputs early actually buys.",
    )

    # 7. The one thing the sealer does not author.
    chain = build(WitnessMode.REDERIVABLE, rederivable=True)
    custodian = CUSTODIAN
    cp = issue(Checkpoint("assignment-1", len(chain.entries), chain.head,
                          T0 + 99, "custodian"), custodian)
    doc = export_artifact(chain)
    doc["entries"] = doc["entries"][:-1]        # drop the tail, no re-signing

    for label, ckpt, note in [
        ("without a checkpoint", None,
         "The chain links from genesis and every signature verifies.\n"
         "   Nothing in the document says how long it was meant to be."),
        ("with a custodian checkpoint", cp,
         "Somebody else recorded the length. Completeness is the only\n"
         "   check here whose input the sealer did not write."),
    ]:
        r = verify(doc, trusted_keys=[chain.public_key_pem],
                   rederive=lambda x: x.get("output_digest",
                                            commit(ACTION_PAYLOAD)),
                   checkpoint=ckpt)
        print(f"\n{RULE}\n7. A truncated artifact, {label}")
        print("   The last entry was deleted from the export.\n")
        print(f"   chain_intact      {r.chain_intact}")
        print(f"   coverage          {r.coverage.name}")
        print(f"   completeness      {r.completeness.name}")
        print(f"\n   {note}")

    # 8. Five chains, one assignment, one of them disclosed.
    from .assignment import AssignmentCheckpoint, ChainRef
    from .assignment import issue as issue_assignment

    siblings = [
        build(WitnessMode.REDERIVABLE, rederivable=True,
              chain_label=f"chain-{i}")
        for i in range(5)
    ]
    refs = [ChainRef(c.chain_id, c.head, len(c.entries)) for c in siblings]
    # A per-chain checkpoint for the one chain that gets handed over. It is
    # entirely truthful, which is the point of the scenario.
    per_chain = issue(
        Checkpoint("assignment-1", len(siblings[0].entries),
                   siblings[0].head, T0 + 99, "custodian"),
        custodian,
    )
    whole = issue_assignment(
        AssignmentCheckpoint("assignment-1", tuple(refs), T0 + 100,
                             "custodian"),
        custodian,
    )

    print(f"\n{RULE}\n8. Five analyses, five chains, one handed over")
    print("   Every chain is honest. Each links from genesis, each verifies,")
    print("   and the per-chain checkpoint for the disclosed one is true.\n")

    for label, acheck in [("without an assignment checkpoint", None),
                          ("with one", whole)]:
        r = verify(export_artifact(siblings[0]),
                   trusted_keys=[siblings[0].public_key_pem],
                   rederive=lambda x: commit(ACTION_PAYLOAD),
                   checkpoint=per_chain, assignment_checkpoint=acheck)
        print(f"   {label}")
        print(f"     completeness    {r.completeness.name}")
        print(f"     disclosure      {r.disclosure.name}")
        print(f"     chains withheld {r.chains_withheld}")

    print("\n   Completeness is CONSISTENT either way, because the chain that")
    print("   was disclosed really is whole. Counting the chain was never the")
    print("   question. Counting the chains is, and only the party holding")
    print("   all five can answer it.")

    # 9. What an external clock can and cannot bound.
    from cryptography.hazmat.primitives import serialization

    from .anchor import Anchoring, Beacon, TimeAnchor
    from .anchor import issue as issue_anchor

    PULSE_VALUE, PULSE_NS = "9f" * 32, T0 - 60_000_000_000
    tsa = ec.generate_private_key(ec.SECP256R1())
    tsa_pem = tsa.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    def resolver(source, pulse):
        return (PULSE_VALUE, PULSE_NS) if pulse == "pulse-88" else None

    beacon = Beacon("nist-beacon", "pulse-88", PULSE_VALUE, PULSE_NS).to_body()

    print(f"\n{RULE}\n9. What a timestamp authority can and cannot bound")
    print("   ts_ns is signed and monotonic and is still a number the sealer")
    print("   chose. A chain built today with last year's dates verifies.\n")

    honest = build(WitnessMode.REDERIVABLE, rederivable=True, beacon=beacon)
    backdated = build(WitnessMode.REDERIVABLE, rederivable=True, beacon=beacon,
                      opened_ns=PULSE_NS - 400_000_000_000,
                      base_ns=PULSE_NS - 300_000_000_000)

    for label, chain, anchors, resolve in [
        ("nothing outside the chain", honest, None, None),
        ("a timestamp authority alone", honest,
         [issue_anchor(TimeAnchor("tsa", honest.entries[-1].block_hash,
                                  T0 + 60_000_000_000), tsa)], None),
        ("a committed beacon as well", honest,
         [issue_anchor(TimeAnchor("tsa", honest.entries[-1].block_hash,
                                  T0 + 60_000_000_000), tsa)], resolver),
        ("the same, on a backdated chain", backdated,
         [issue_anchor(TimeAnchor("tsa", backdated.entries[-1].block_hash,
                                  T0 + 60_000_000_000), tsa)], resolver),
    ]:
        r = verify(export_artifact(chain),
                   trusted_keys=[chain.public_key_pem],
                   rederive=lambda x: commit(ACTION_PAYLOAD),
                   time_anchors=anchors, trusted_authorities=[tsa_pem],
                   beacon_resolver=resolve)
        width = r.anchor_interval_ns
        print(f"   {label}")
        print(f"     anchoring  {r.anchoring.name}")
        print(f"     interval   {'unbounded' if width is None else str(width // 1_000_000_000) + 's'}")

    print("\n   An RFC 3161 token proves a document existed no later than a")
    print("   time. It bounds the later side. The attack KC1 describes is a")
    print("   workfile built after the letter arrives and dated to the run,")
    print("   which is the earlier side, and no authority can bound it. That")
    print("   needs a commitment to something not yet published, and the")
    print("   mechanism this project named for the job does the other half.")

    print(f"\n{RULE}")
    print("  Re-derivation clears KC2 only where the evidence cannot be kept")
    print("  by the party who has to prove something, and that is a fact about")
    print("  a tool rather than a field in a document. The verifier now takes")
    print("  it from a signed reading and fires KC2 without one. Read against")
    print("  the regression tools actually in circulation, the reading is that")
    print("  the operator exports the rows first, which is scenario 5 row 3.")
    print(f"{RULE}\n")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Piped into head or less, which closed the pipe early. Redirect the
        # remaining output to devnull so the interpreter does not report the
        # same error again while flushing on exit.
        import os
        import sys

        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
