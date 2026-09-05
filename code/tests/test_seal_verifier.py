"""
The KC2 experiment, run as tests, plus regressions for constructed attacks.

KC2 states the mechanism fails if it does nothing a third-party-timestamped
bundle of the same local files could not do. The first half of this file
constructs artifacts at each binding level and asserts what the verifier
concludes, which is a finding about the architecture rather than a check on the
code. The second half constructs artifacts that once verified and should not
have.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from seal import (
    BindingLevel,
    Coverage,
    EntryKind,
    EvidenceCommitment,
    Holding,
    Pinning,
    PrimitiveKind,
    PrimitiveRecord,
    Provenance,
    Retention,
    RetentionDetermination,
    RunSeal,
    SealChain,
    WitnessMode,
    WorkfileBinding,
    commit,
    canonical_bytes,
    export_artifact,
    issue_retention_determination,
    merkle_root,
    verify,
    witness_attestation_payload,
)

T0 = 1_753_200_000_000_000_000

# A custodian who reads tool documentation, and a second independent reader.
# Both are distinct from every chain key, which is what makes their signatures
# worth anything.
_CUSTODIAN_KEY = ec.generate_private_key(ec.SECP256R1())
_OTHER_KEY = ec.generate_private_key(ec.SECP256R1())

# The adjustment the artifact claims. A correct recipe must reproduce this.
ACTION_PAYLOAD = {"time_adjustment_pct_per_month": "0.0042"}
OTHER_DIGEST = "sha256:" + "ff" * 32


def _rows(n: int = 40) -> list[str]:
    return [commit({"mls_id": f"R{i}", "close_price": f"{300000 + i * 1250}"})
            for i in range(n)]


def _primitives(
    evidence_root: str,
    pinning: Pinning = Pinning.PINNED,
    retention: Retention = Retention.COMMITMENT_ONLY,
) -> dict[PrimitiveKind, PrimitiveRecord]:
    """A full primitive set for one time-adjustment run."""
    def rec(kind, payload, **kw):
        return PrimitiveRecord(
            kind=kind, commitment=payload,
            pinning=kw.get("pinning", Pinning.PINNED),
            retention=kw.get("retention", Retention.FULL),
            holder=kw.get("holder", "appraiser"),
        )

    return {
        PrimitiveKind.ACTION: rec(PrimitiveKind.ACTION, commit(ACTION_PAYLOAD)),
        PrimitiveKind.SURFACE: rec(PrimitiveKind.SURFACE, commit({
            "uspap_edition": "2024-2025", "window_months": 12,
            "filters": {"radius_mi": "1.0", "property_type": "SFR"}})),
        PrimitiveKind.EVIDENCE: rec(
            PrimitiveKind.EVIDENCE, evidence_root,
            pinning=pinning, retention=retention, holder="custodian"),
        PrimitiveKind.EVALUATOR: rec(PrimitiveKind.EVALUATOR, commit(
            {"tool": "regression-tool", "version": "3.2.1"})),
        PrimitiveKind.INSTANT: rec(PrimitiveKind.INSTANT, commit(
            {"executed_ns": T0, "effective_date": "2026-03-14"})),
        PrimitiveKind.CLAIM: rec(PrimitiveKind.CLAIM, commit(
            {"certification_ref": "cert-0001"})),
    }


def _recipe(evidence_hash: str, *, digest: str | None = None,
            input_ref: str | None = None) -> dict:
    """
    A complete and correctly linked recipe.

    `output_digest` must be the Action the artifact seals and `input_ref` must
    be the evidence commitment the run names. The overrides exist so the
    regression tests can break each link on purpose.
    """
    return {
        "endpoint": "https://partner.example/v1/score",
        "tool": "avm-engine",
        "version": "3.2.1",
        "invocation": {"model": "hedonic", "seed": 42},
        "input_ref": evidence_hash if input_ref is None else input_ref,
        "output_digest": commit(ACTION_PAYLOAD) if digest is None else digest,
        "service_window": "2033-01-01",
    }


def _build(
    witness: WitnessMode,
    *,
    commit_evidence_first: bool = True,
    rederivable: bool = False,
    recipe_digest: str | None = None,
    recipe_input_ref: str | None = None,
    recipe_override: dict | None = None,
    pinning: Pinning = Pinning.PINNED,
    retention: Retention = Retention.COMMITMENT_ONLY,
    bind: bool = True,
    omit_seq: int | None = None,
    runs_after_binding: int = 0,
    late_version: str = "3.2.1",
    assignment_id: str = "assignment-1",
    chain_label: str = "",
    beacon: dict | None = None,
    opened_ns: int = T0,
    base_ns: int | None = None,
    witness_key=None,
) -> SealChain:
    """Construct an artifact. Each keyword changes exactly one decision."""
    chain = SealChain(assignment_id, opened_ns=opened_ns,
                      chain_label=chain_label, beacon=beacon)
    root = merkle_root(_rows())
    ev_hash = None
    t = T0 if base_ns is None else base_ns

    if commit_evidence_first:
        ev = EvidenceCommitment(
            commitment_id="ev-1", row_root=root, row_count=40,
            source="MLS-export", as_of="2026-03-14T09:00:00Z",
            query_descriptor={"radius_mi": "1.0", "months": 12},
        )
        ev_hash = chain.append(
            EntryKind.EVIDENCE_COMMITMENT, ev.to_body(), t).block_hash
        t += 1_000_000_000

    if recipe_override is not None:
        recipe = recipe_override
    elif rederivable:
        recipe = _recipe(ev_hash, digest=recipe_digest,
                         input_ref=recipe_input_ref)
    else:
        recipe = None

    run_body = RunSeal(
        run_id="run-1",
        primitives=_primitives(root, pinning, retention),
        evidence_commitment_hash=ev_hash,
        witness_mode=witness,
        rederivation_recipe=recipe,
    ).to_body()
    if witness_key is not None:
        witness_pem = witness_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        attestation = {
            "witness": "independent-custodian",
            "public_key": witness_pem,
            "signature": "",
            "capture_ref": "custody-event-1",
            "statement": "observed_execution",
        }
        run_body["witness_attestation"] = attestation
        attestation["signature"] = witness_key.sign(
            canonical_bytes(witness_attestation_payload(run_body)),
            ec.ECDSA(hashes.SHA256()),
        ).hex()
    chain.append(EntryKind.RUN_SEAL, run_body, t)
    t += 1_000_000_000

    if bind:
        covered = [e.seq for e in chain.entries]
        if omit_seq is not None:
            covered = [s for s in covered if s != omit_seq]
        chain.append(EntryKind.WORKFILE_BINDING, WorkfileBinding(
            assignment_id=assignment_id, chain_head=chain.head,
            covered_seqs=covered, certification_ref="cert-0001",
            effective_date="2026-03-14",
        ).to_body(), t)
        t += 1_000_000_000

    for i in range(runs_after_binding):
        ev2 = chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
            commitment_id=f"ev-late-{i}", row_root=root, row_count=40,
            source="MLS-export", as_of="2026-03-14T09:00:00Z").to_body(),
            t).block_hash
        t += 1_000_000_000
        late = _recipe(ev2) if rederivable else None
        if late is not None:
            # `late_version` lets a test build an assignment whose runs used
            # different pinned versions of one tool, which is the case a
            # per-tool determination has to be read across rather than once.
            late["version"] = late_version
        chain.append(EntryKind.RUN_SEAL, RunSeal(
            run_id=f"run-late-{i}", primitives=_primitives(root),
            evidence_commitment_hash=ev2, witness_mode=witness,
            rederivation_recipe=late,
        ).to_body(), t)
        t += 1_000_000_000

    return chain


def _determination(
    holding: Holding = Holding.OPERATOR_CANNOT_HOLD,
    *,
    tool: str = "avm-engine",
    version: str = "3.2.1",
    key=None,
    by: str = "custodian",
) -> dict:
    """
    A signed reading of what a pinned tool does with the raw input.

    Defaults to the case that clears KC2, so a test that wants any other
    outcome has to say which one and why.
    """
    return issue_retention_determination(
        RetentionDetermination(
            tool=tool, version=version, holding=holding,
            source="https://partner.example/docs/workflow",
            source_digest=commit({"doc": "workflow", "holding": holding.value}),
            read_as_of="2026-03-14", determined_by=by,
        ),
        _CUSTODIAN_KEY if key is None else key,
    )


def _ok(recipe: dict) -> str:
    """
    A partner endpoint that faithfully reproduces the sealed value.

    It computes the answer rather than echoing it, because the verifier no
    longer passes `output_digest` to the callback. Handing the target to the
    oracle under test is the wrong shape.
    """
    assert "output_digest" not in recipe, "the oracle was handed the answer"
    return commit(ACTION_PAYLOAD)


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------

def test_clean_chain_verifies():
    chain = _build(WitnessMode.INDEPENDENT)
    r = verify(export_artifact(chain), trusted_keys=[chain.public_key_pem])
    assert r.chain_intact and r.signatures_valid and r.key_trusted
    assert r.trustworthy


def test_tampered_body_fails_signature():
    chain = _build(WitnessMode.INDEPENDENT)
    doc = export_artifact(chain)
    doc["entries"][1]["body"]["run_id"] = "run-tampered"
    r = verify(doc, trusted_keys=[chain.public_key_pem])
    assert not r.signatures_valid
    assert not r.trustworthy


def test_removing_an_entry_breaks_the_chain():
    chain = _build(WitnessMode.INDEPENDENT)
    doc = export_artifact(chain)
    del doc["entries"][0]
    r = verify(doc, trusted_keys=[chain.public_key_pem])
    assert not r.chain_intact
    assert not r.trustworthy


def test_signature_validity_does_not_establish_identity():
    """Anyone can sign anything with a key they generated."""
    chain = _build(WitnessMode.INDEPENDENT)
    r = verify(export_artifact(chain))  # no trusted key set supplied
    assert r.signatures_valid
    assert r.key_trusted is None
    assert any(f.code == "key_identity_unchecked" for f in r.findings)


# --------------------------------------------------------------------------
# KC2: what a timestamping service could replicate
# --------------------------------------------------------------------------

def test_no_evidence_commitment_is_bundling():
    chain = _build(WitnessMode.SELF_ATTESTED, commit_evidence_first=False)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.BUNDLED
    assert r.kc2_fires


def test_self_attested_precedence_still_fires_kc2():
    """
    Committing evidence before the run rules out choosing inputs after seeing
    the output, which is real. It is also exactly what two RFC-3161 timestamps
    over two local files achieve, so it does not clear KC2.
    """
    chain = _build(WitnessMode.SELF_ATTESTED)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert r.timestamp_replicable and r.kc2_fires


def test_self_declared_witness_does_not_clear_kc2():
    """
    This test previously asserted the opposite, and the assertion was the bug.
    `witness_mode` is a field the sealer writes. Granting WITNESSED on it was
    the cheapest route to clearing KC2 in the package: nine characters, no
    recipe, no re-derivation.
    """
    chain = _build(WitnessMode.INDEPENDENT)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert not r.evidence.witness_attestation
    assert not r.evidence.historical_execution_established
    assert r.kc2_fires
    assert any(f.code == "witness_self_declared" for f in r.findings)


def test_independent_observer_attestation_establishes_historical_execution():
    witness_key = ec.generate_private_key(ec.SECP256R1())
    witness_pem = witness_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   witness_key=witness_key)
    r = verify(export_artifact(chain), rederive=_ok,
               trusted_witness_keys=[witness_pem],
               retention_determinations=[_determination()])
    assert r.evidence.witness_attestation
    assert r.evidence.recipe_reproduced
    assert r.evidence.historical_execution_established


def test_complete_recipe_not_executed_is_only_rederivable():
    """A recipe that has not been run is a claim, not a proof."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.REDERIVABLE
    assert any(f.code == "not_rederived" for f in r.findings)


def test_executed_and_matched_reaches_rederived_and_clears_kc2():
    """
    Both halves are required. Re-derivation establishes that the output came
    from the input. It clears KC2 only where somebody other than the sealer has
    established that the input could not have been kept locally, which is why
    the determination is supplied here and its absence is a separate test.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[_determination()])
    assert r.binding_level is BindingLevel.REDERIVED
    assert r.input_provenance is Provenance.SOURCED
    assert not r.kc2_fires


def test_rederivation_mismatch_drops_to_precedence():
    """Re-running and getting a different answer is the whole point."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=lambda rec: OTHER_DIGEST)
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert not r.evidence.recipe_reproduced
    assert not r.evidence.historical_execution_established
    assert any(f.code == "rederivation_mismatch" for f in r.findings)


def test_unservable_pinned_version_decays_to_the_recipe():
    """The liveness dependency. A signature does not have one; this does."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=lambda rec: None)
    assert r.binding_level is BindingLevel.REDERIVABLE
    assert any(f.bears_on == "liveness" for f in r.findings)


def test_incomplete_recipe_does_not_count():
    partial = _recipe("whatever")
    del partial["endpoint"]
    del partial["service_window"]
    chain = _build(WitnessMode.REDERIVABLE, recipe_override=partial)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert any(f.code == "incomplete_recipe" for f in r.findings)


def test_rederivable_claim_without_a_recipe_does_not_count():
    chain = _build(WitnessMode.REDERIVABLE, rederivable=False)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert r.kc2_fires


def test_rederivation_over_locally_retainable_evidence_still_fires_kc2():
    """
    The finding that decides the product. If the inputs can be kept, the same
    folder can be timestamped and re-run without a custodian, so re-derivation
    buys nothing a commodity service could not.

    This is the reading the tool export audit returned against the regression
    tools in circulation: the workflow starts with the operator exporting rows
    to their own machine, so the input is in their hands before the tool runs.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[
                   _determination(Holding.OPERATOR_HOLDS)])
    assert r.binding_level is BindingLevel.REDERIVED
    assert r.evidence.recipe_reproduced
    assert not r.evidence.historical_execution_established
    assert r.input_provenance is Provenance.SOURCED
    assert r.input_holding is Holding.OPERATOR_HOLDS
    assert r.kc2_fires


# --------------------------------------------------------------------------
# KC2: where the retention answer comes from
#
# The verifier used to read `primitives.evidence.retention` out of the run body
# and treat it as the answer. That field records what the artifact carries,
# which is the sealer's own business and a different fact from whether the
# operator can hold the raw input. Only the second decides KC2, it is a
# property of the tool rather than of the document, and the sealer has an
# interest in it.
# --------------------------------------------------------------------------

def test_the_artifacts_own_retention_field_no_longer_decides_kc2():
    """
    The regression that motivated the change. An artifact declaring
    commitment-only retention and carrying no outside reading used to clear
    KC2 on a field the sealer wrote. Nine characters, no second party.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   retention=Retention.COMMITMENT_ONLY)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.binding_level is BindingLevel.REDERIVED
    assert r.input_provenance is Provenance.UNSOURCED
    assert r.kc2_fires


def test_a_determination_signed_by_the_sealer_does_not_count():
    """
    The sealer reading the sealer's own tool documentation is the sealer
    vouching for itself on the point at issue. Same shape as a self-issued
    checkpoint, and refused for the same reason.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               trusted_keys=[chain.public_key_pem],
               retention_determinations=[
                   _determination(key=chain._sk, by="sealer")])
    assert r.input_provenance is Provenance.SELF_ISSUED
    assert r.kc2_fires


def test_a_determination_for_another_version_does_not_reach_this_run():
    """
    A determination speaks for the version it was read against. A workflow is
    usually stable across versions and saying so is a claim beyond the reading.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[_determination(version="9.9.9")])
    assert r.input_provenance is Provenance.UNSOURCED
    assert r.kc2_fires


def test_a_tampered_determination_is_unusable():
    doc = _determination()
    doc["holding"] = Holding.OPERATOR_CANNOT_HOLD.value
    doc["source"] = "https://attacker.example/whatever"
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[doc])
    assert r.input_provenance is Provenance.UNUSABLE
    assert r.kc2_fires


def test_disagreeing_determinations_do_not_clear_kc2():
    """A contested reading does not clear a kill condition."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[
                   _determination(Holding.OPERATOR_CANNOT_HOLD),
                   _determination(Holding.OPERATOR_HOLDS, key=_OTHER_KEY,
                                  by="second-reader")])
    assert r.input_provenance is Provenance.MISMATCHED
    assert r.kc2_fires
    assert any(f.code == "retention_contested" for f in r.findings)


def test_an_undetermined_reading_resolves_against_clearance():
    """
    An honest reading that could not tell is recorded rather than guessed, and
    it fails closed. Recording less must never grade better.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[
                   _determination(Holding.UNDETERMINED)])
    assert r.input_provenance is Provenance.SOURCED
    assert r.input_holding is Holding.UNDETERMINED
    assert r.kc2_fires


def test_one_unsourced_run_makes_the_whole_artifact_replicable():
    """
    Read across every run rather than whichever happened to be last. A run on a
    version nobody read must not hide behind a run on a version somebody did.

    Two runs, one tool, two pinned versions. A determination covering only the
    first leaves the second unsourced, and one unsourced run is enough, because
    the analysis it produced can be timestamped and re-run locally.
    """
    both = _build(WitnessMode.REDERIVABLE, rederivable=True,
                  runs_after_binding=1)
    r = verify(export_artifact(both), rederive=_ok,
               retention_determinations=[_determination()])
    assert r.input_provenance is Provenance.SOURCED
    assert not r.kc2_fires

    split = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   runs_after_binding=1, late_version="3.3.0")
    r2 = verify(export_artifact(split), rederive=_ok,
                retention_determinations=[_determination()])
    assert r2.input_provenance is Provenance.UNSOURCED
    assert r2.kc2_fires

    # Reading the second version too is what closes it.
    r3 = verify(export_artifact(split), rederive=_ok,
                retention_determinations=[_determination(),
                                          _determination(version="3.3.0")])
    assert r3.input_provenance is Provenance.SOURCED
    assert not r3.kc2_fires


# --------------------------------------------------------------------------
# KC1: seal timing
# --------------------------------------------------------------------------

def test_evidence_committed_after_the_run_is_bundling():
    """Post-hoc assembly. The artifact records a reconstruction, not the run."""
    chain = SealChain("assignment-1", opened_ns=T0)
    root = merkle_root(_rows())
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-1", _primitives(root), None, WitnessMode.INDEPENDENT).to_body(), T0)
    chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-late", root, 40, "MLS-export", "2026-03-14T09:00:00Z").to_body(),
        T0 + 1)
    r = verify(export_artifact(chain))
    assert r.binding_level is BindingLevel.BUNDLED
    assert any(f.bears_on == "KC1" for f in r.findings)


# --------------------------------------------------------------------------
# Design question three: the seam between layers
# --------------------------------------------------------------------------

def test_contiguous_binding_makes_omission_detectable():
    chain = _build(WitnessMode.INDEPENDENT)
    r = verify(export_artifact(chain))
    assert r.coverage is Coverage.CONTIGUOUS


def test_selective_binding_is_detected():
    chain = _build(WitnessMode.INDEPENDENT, omit_seq=0)
    r = verify(export_artifact(chain))
    assert r.coverage is Coverage.SUBSET
    assert any(f.code == "selective_binding" for f in r.findings)


def test_missing_layer_two_is_reported():
    chain = _build(WitnessMode.INDEPENDENT, bind=False)
    r = verify(export_artifact(chain))
    assert r.coverage is Coverage.ABSENT


# --------------------------------------------------------------------------
# The three properties
# --------------------------------------------------------------------------

def test_all_six_primitives_are_reported():
    chain = _build(WitnessMode.INDEPENDENT)
    r = verify(export_artifact(chain))
    assert set(r.primitives_present) == {k.value for k in PrimitiveKind}
    assert all(r.primitives_present.values())


def test_floating_primitive_is_a_pinning_finding():
    """A primitive that resolves to present state fails pinning even when kept."""
    chain = _build(WitnessMode.INDEPENDENT, pinning=Pinning.FLOATING)
    r = verify(export_artifact(chain))
    assert r.primitives_pinned["evidence"] == Pinning.FLOATING.value
    assert any(f.bears_on == "pinning" for f in r.findings)


def test_reach_tracks_the_holder_not_mere_existence():
    """Evidence held only by the MLS exists but is out of reach of the liable party."""
    rec = PrimitiveRecord(
        kind=PrimitiveKind.EVIDENCE, commitment=merkle_root(_rows()),
        pinning=Pinning.PINNED, retention=Retention.COMMITMENT_ONLY,
        holder="mls",
    )
    assert rec.exists and rec.pinned
    assert not rec.reachable_by_liable_party


# --------------------------------------------------------------------------
# Evidence commitment without retention
# --------------------------------------------------------------------------

def test_merkle_root_proves_a_row_set_without_retaining_it():
    rows = _rows()
    assert merkle_root(rows) == merkle_root(list(rows))
    altered = list(rows)
    altered[7] = commit({"mls_id": "R7", "close_price": "999999"})
    assert merkle_root(altered) != merkle_root(rows)


def test_merkle_root_is_order_sensitive():
    rows = _rows(8)
    assert merkle_root(rows) != merkle_root(list(reversed(rows)))


# ==========================================================================
# Regressions for the five constructed attacks that fire KC2.
#
# Every one of these verified clean before the guard that now blocks it.
# Frozen so the gaps cannot reopen quietly.
# ==========================================================================

def test_recipe_output_must_be_the_sealed_action():
    """
    Attack D, the one that fires KC2. A verifier comparing the recipe against
    its own output_digest lets an artifact seal one adjustment, carry a recipe
    reproducing a different number, and be reported REDERIVED.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   recipe_digest=OTHER_DIGEST)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert r.kc2_fires
    assert any(f.code == "recipe_output_not_the_action" for f in r.findings)


def test_recipe_input_must_be_the_named_evidence():
    """Attack C. A recipe naming an input unrelated to the sealed evidence."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   recipe_input_ref="commitment://SOMETHING-ELSE")
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.binding_level is BindingLevel.PRECEDENCE
    assert any(f.code == "recipe_input_not_the_evidence" for f in r.findings)


def test_runs_after_certification_are_detected():
    """
    Attack B. Certify a clean run, then keep working and leave the rest
    unbound. A coverage check that examines only the entries preceding the
    binding reports CONTIGUOUS, which defeats the anti-cherry-picking property
    by the obvious move.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   runs_after_binding=2)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.coverage is Coverage.SUBSET
    assert any(f.code == "runs_after_certification" for f in r.findings)


def test_binding_naming_absent_entries_is_detected():
    """Attack E. Truncating the tail leaves chain_intact true on its own."""
    chain = _build(WitnessMode.INDEPENDENT)
    doc = export_artifact(chain)
    binding = doc["entries"][-1]
    binding["body"]["covered_seqs"] = sorted(
        binding["body"]["covered_seqs"] + [98, 99])
    r = verify(doc)
    assert r.coverage is Coverage.SUBSET
    assert any(f.code == "binding_names_missing_entries" for f in r.findings)


def test_trustworthy_requires_a_recognised_key():
    """
    Attack A. A chain forged end to end reports signatures_valid true, because
    a forger signs everything with their own key. The composite is the field a
    caller should read.
    """
    chain = _build(WitnessMode.INDEPENDENT)
    doc = export_artifact(chain)
    assert verify(doc).signatures_valid            # internally consistent
    assert not verify(doc).trustworthy             # but nobody vouched for it
    assert verify(doc, trusted_keys=[chain.public_key_pem]).trustworthy


# ==========================================================================
# Regressions for a cold read of the code, performed with no access to the
# design documents or to this file.
# ==========================================================================

def test_deleting_the_evidence_record_fires_kc2():
    """
    Retention fails closed. Anything other than an explicit commitment-only
    declaration counts as retainable, so a missing or deleted Evidence
    primitive fires KC2 rather than clearing it. A test for `== "full"` would
    let the artifact recording less about its inputs grade better on the
    input-provenance condition.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    doc = export_artifact(chain)
    run = next(e for e in doc["entries"]
               if e["kind"] == EntryKind.RUN_SEAL.value)
    del run["body"]["primitives"][PrimitiveKind.EVIDENCE.value]
    r = verify(doc, rederive=_ok)
    assert r.kc2_fires


def test_a_dirty_run_cannot_hide_behind_a_clean_later_one():
    """Primitives were read from runs[-1] only, so the last run masked the rest."""
    chain = SealChain("assignment-1", opened_ns=T0)
    root = merkle_root(_rows())
    t = T0
    ev = chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-1", root, 40, "MLS-export", "2026-03-14").to_body(), t).block_hash
    t += 1_000_000_000
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "dirty", _primitives(root, pinning=Pinning.FLOATING), ev,
        WitnessMode.SELF_ATTESTED).to_body(), t)
    t += 1_000_000_000
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "clean", _primitives(root), ev, WitnessMode.SELF_ATTESTED).to_body(), t)

    r = verify(export_artifact(chain))
    assert r.primitives_pinned["evidence"] == Pinning.FLOATING.value
    assert any(f.bears_on == "pinning" for f in r.findings)


def test_malformed_input_fails_closed_rather_than_raising():
    """
    Ten single-field mutations make a naive verifier raise. Any caller
    treating an exception as inconclusive turns each into a pass.
    """
    for bad in (
        {"entries": "nonsense"},
        {"entries": [{"kind": "not-a-kind"}]},
        {"entries": [{"kind": "run_seal"}]},
    ):
        r = verify(bad)
        assert not r.trustworthy
        assert any(f.code == "malformed_artifact" for f in r.findings)


def test_binding_seq_past_the_end_does_not_crash():
    chain = _build(WitnessMode.SELF_ATTESTED)
    doc = export_artifact(chain)
    doc["entries"][-1]["seq"] = 999
    r = verify(doc)
    assert not r.trustworthy


def test_timestamp_regression_is_reported():
    """Clock values are signed and were never read."""
    chain = SealChain("assignment-1", opened_ns=T0)
    root = merkle_root(_rows())
    ev = chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-1", root, 40, "MLS-export", "2026-03-14").to_body(),
        9_000_000_000).block_hash
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-1", _primitives(root), ev, WitnessMode.SELF_ATTESTED).to_body(), 1_000)
    r = verify(export_artifact(chain))
    assert any(f.code == "timestamp_regression" for f in r.findings)


def test_merkle_separates_leaves_from_interior_nodes():
    """Without domain separation a promoted interior node is indistinguishable
    from a leaf."""
    rows = _rows(3)
    interior = merkle_root(rows[:2])
    assert merkle_root(rows) != merkle_root([interior, rows[2]])
    assert merkle_root([rows[0]]) != rows[0]
    assert merkle_root([]) != commit("")


def test_canonicalisation_refuses_a_non_string_key():
    """
    JSON carries only string keys, so `sort_keys` coerces anything else and the
    coercion is not injective. `{None: None}` and `{"null": None}` are
    different payloads that both render as `{"null":null}`, which would let two
    different analyses share one commitment. Found by the property layer, which
    shrank it to exactly that pair.
    """
    import pytest

    from seal import canonical_bytes

    for bad in ({None: None}, {1: "x"}, {True: 1}, {"ok": {2: "nested"}}):
        with pytest.raises(ValueError):
            canonical_bytes(bad)
    assert canonical_bytes({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'


def test_canonicalisation_rejects_values_json_cannot_represent():
    """NaN produced bytes no conforming parser could read back."""
    import pytest
    from seal import canonical_bytes
    with pytest.raises(ValueError):
        canonical_bytes({"coefficient": float("nan")})


# ==========================================================================
# Completeness: the one check whose input the sealer did not write.
#
# Truncation cannot be detected inside a self-contained artifact, because
# completeness is a claim about what is not in the document and the party
# choosing what ships also chooses what to omit. A checkpoint is somebody
# else's statement of how long the chain is.
# ==========================================================================

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from seal import Checkpoint, Completeness, issue_checkpoint  # noqa: E402


def _custodian_checkpoint(chain: SealChain, key=None, *, count=None, head=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    return issue_checkpoint(
        Checkpoint(
            assignment_id="assignment-1",
            entry_count=len(chain.entries) if count is None else count,
            chain_head=chain.head if head is None else head,
            observed_ns=T0 + 99,
            issuer="custodian",
        ),
        key,
    )


def test_without_a_checkpoint_completeness_is_unchecked():
    """The honest default, and the state every artifact was in before this."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.completeness is Completeness.UNCHECKED
    assert any(f.code == "no_checkpoint" for f in r.findings)


def test_a_checkpoint_confirms_a_whole_artifact():
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               checkpoint=_custodian_checkpoint(chain))
    assert r.completeness is Completeness.CONSISTENT


def test_truncation_is_detected_against_a_checkpoint():
    """
    The finding the checkpoint exists for. This artifact reported CONTIGUOUS
    coverage and trustworthy true after truncation, and still does: the chain
    is internally perfect. What it cannot do is match a count somebody else
    recorded.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   runs_after_binding=2)
    cp = _custodian_checkpoint(chain)          # issued over the full chain
    doc = export_artifact(chain)
    doc["entries"] = doc["entries"][:4]        # disclose only up to the binding

    without = verify(doc, rederive=_ok)
    assert without.coverage is Coverage.CONTIGUOUS   # still invisible
    assert without.completeness is Completeness.UNCHECKED

    with_cp = verify(doc, rederive=_ok, checkpoint=cp)
    assert with_cp.completeness is Completeness.SHORT
    assert any(f.code == "artifact_truncated" for f in with_cp.findings)


def test_a_checkpoint_signed_by_the_sealer_is_worthless():
    """
    The sealer vouching for themselves is the situation the checkpoint exists
    to escape, so it is refused rather than counted.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    cp = _custodian_checkpoint(chain, key=chain._sk)
    r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
    assert r.completeness is Completeness.UNUSABLE
    assert any(f.code == "checkpoint_self_issued" for f in r.findings)


def test_a_checkpoint_for_another_chain_does_not_vouch_for_this_one():
    """Defeats answering a checkpoint with a different chain of the right length."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    cp = _custodian_checkpoint(chain, head="0" * 64)
    r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
    assert r.completeness is Completeness.MISMATCHED


def test_an_unsigned_or_tampered_checkpoint_is_refused():
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    cp = _custodian_checkpoint(chain)
    cp["entry_count"] = 99                      # not re-signed
    r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
    assert r.completeness is Completeness.UNUSABLE


# ==========================================================================
# Custodian accountability. Checkpoints stopped the appraiser being the only
# source of their own record and left the custodian in exactly that position.
# A consistency proof is what turns "append-only" from a claim the custodian
# makes into arithmetic anyone can check.
# ==========================================================================

from seal import TransparencyLog, heads_consistent, sign_head  # noqa: E402
from seal.log import (  # noqa: E402
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    root as log_root,
    verify_consistency,
    verify_inclusion,
)


def test_inclusion_and_consistency_hold_at_every_shape():
    """
    Exhaustive rather than illustrative. The first verify_inclusion walked the
    tree top-down against a bottom-up proof and passed on balanced trees only,
    which a spot check would have missed.
    """
    n = 33
    leaves = [leaf_hash({"run": i}) for i in range(n)]
    for size in range(1, n + 1):
        r = log_root(leaves[:size])
        for idx in range(size):
            assert verify_inclusion(idx, size, leaves[idx], r,
                                    inclusion_proof(leaves[:size], idx))
        for old in range(0, size + 1):
            assert verify_consistency(
                old, log_root(leaves[:old]), size, r,
                consistency_proof(leaves[:size], old))


def test_a_custodian_rewriting_its_own_log_is_detected():
    """
    The finding this module exists for. The custodian removes a run it dislikes
    and issues a fresh head over the result. No consistency proof exists, and
    the failure is arithmetic rather than a matter of trusting anyone.
    """
    honest = [leaf_hash({"run": i}) for i in range(5)]
    rewritten = [leaf_hash({"run": i}) for i in (0, 2, 3, 4)]
    assert not verify_consistency(
        3, log_root(honest[:3]), len(rewritten), log_root(rewritten),
        consistency_proof(rewritten, 3))


def test_no_proof_can_be_forged_for_a_rewritten_log():
    import itertools
    honest = [leaf_hash({"run": i}) for i in range(5)]
    rewritten = [leaf_hash({"run": i}) for i in (0, 2, 3, 4)]
    candidates = rewritten + [log_root(rewritten), log_root(honest[:3])]
    assert not any(
        verify_consistency(3, log_root(honest[:3]), len(rewritten),
                           log_root(rewritten), list(c))
        for length in range(4)
        for c in itertools.permutations(candidates, length)
    )


def test_two_heads_from_one_custodian_are_checkable():
    key = ec.generate_private_key(ec.SECP256R1())
    log = TransparencyLog("semafide")
    for i in range(3):
        log.append({"run": i})
    old = sign_head(log.head(T0), key)
    for i in range(3, 7):
        log.append({"run": i})
    new = sign_head(log.head(T0 + 1), key)

    ok, why = heads_consistent(old, new, log.consistency_proof(3))
    assert ok, why


def test_a_head_from_a_different_key_or_log_is_refused():
    log = TransparencyLog("semafide")
    for i in range(3):
        log.append({"run": i})
    a = sign_head(log.head(T0), ec.generate_private_key(ec.SECP256R1()))
    b = sign_head(log.head(T0 + 1), ec.generate_private_key(ec.SECP256R1()))
    ok, why = heads_consistent(a, b, [])
    assert not ok and "different keys" in why


def test_a_shrinking_log_is_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    log = TransparencyLog("semafide")
    for i in range(5):
        log.append({"run": i})
    big = sign_head(log.head(T0), key)
    small_log = TransparencyLog("semafide")
    for i in range(2):
        small_log.append({"run": i})
    small = sign_head(small_log.head(T0 + 1), key)
    ok, why = heads_consistent(big, small, [])
    assert not ok and "smaller" in why


def test_a_tampered_head_does_not_verify():
    key = ec.generate_private_key(ec.SECP256R1())
    log = TransparencyLog("semafide")
    log.append({"run": 0})
    head = sign_head(log.head(T0), key)
    head["size"] = 99
    ok, why = heads_consistent(head, head, [])
    assert not ok


# ==========================================================================
# The split view. A custodian running a correct append-only log can still show
# one head to one examiner and another to a second, and each is internally
# perfect. Nothing below prevents that. What it does is make equivocating
# produce transferable evidence, and make it require corrupting every witness
# rather than nobody.
# ==========================================================================

import json  # noqa: E402
import threading  # noqa: E402

import pytest  # noqa: E402

from seal import (  # noqa: E402
    CONTRADICTION,
    UNRECONCILED,
    Witness,
    WitnessRefusal,
    count_witnesses,
    equivocation,
    equivocation_holds,
    rebut,
)


def _log_of(n, key, ts=T0, log_id="semafide"):
    log = TransparencyLog(log_id)
    for i in range(n):
        log.append({"run": i})
    return log, sign_head(log.head(ts), key)


def test_a_witness_refuses_a_second_root_at_the_same_size():
    """
    The mechanism, in one test. A witness that keeps state cannot be shown two
    versions of the same log, so a split view requires compromising it rather
    than merely asking it twice.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    _, honest = _log_of(4, key)

    forked = TransparencyLog("semafide")
    for i in (0, 1, 2, 99):
        forked.append({"run": i})
    other = sign_head(forked.head(T0 + 1), key)

    w = Witness("state-board", ec.generate_private_key(ec.SECP256R1()))
    w.cosign(honest)
    with pytest.raises(WitnessRefusal, match="equivocation"):
        w.cosign(other)


def test_a_witness_refuses_a_split_view_offered_concurrently():
    """
    The lock in `cosign`, put under real load. Two threads race to be first
    to cosign two conflicting roots at one size for a log this witness has
    never seen. Without the lock, both could read no prior state, both pass,
    and both sign, an equivocation reintroduced through a race rather than
    through a missing check. Whichever request the witness serializes first
    wins; the other must be refused, and both must never succeed.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    _, head_a = _log_of(4, key, log_id="race")
    forked = TransparencyLog("race")
    for i in (0, 1, 2, 99):
        forked.append({"run": i})
    head_b = sign_head(forked.head(T0 + 1), key)

    w = Witness("race-witness", ec.generate_private_key(ec.SECP256R1()))
    results: list[str] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(2)

    def attempt(head):
        barrier.wait()
        try:
            w.cosign(head)
            outcome = "ok"
        except WitnessRefusal:
            outcome = "refused"
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt, args=(head_a,)),
              threading.Thread(target=attempt, args=(head_b,))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == ["ok", "refused"]


def test_a_witness_refuses_a_head_that_is_not_an_extension():
    key = ec.generate_private_key(ec.SECP256R1())
    _, early = _log_of(3, key)

    rewritten = TransparencyLog("semafide")
    for i in (0, 2, 3, 4):
        rewritten.append({"run": i})
    later = sign_head(rewritten.head(T0 + 1), key)

    w = Witness("carrier", ec.generate_private_key(ec.SECP256R1()))
    w.cosign(early)
    with pytest.raises(WitnessRefusal, match="not an extension"):
        w.cosign(later, rewritten.consistency_proof(3))


def test_a_witness_cosigns_an_honest_extension_and_refuses_a_shrink():
    key = ec.generate_private_key(ec.SECP256R1())
    log, early = _log_of(3, key)
    w = Witness("amc", ec.generate_private_key(ec.SECP256R1()))
    w.cosign(early)

    for i in range(3, 8):
        log.append({"run": i})
    later = sign_head(log.head(T0 + 1), key)
    assert w.cosign(later, log.consistency_proof(3))["witness"] == "amc"

    with pytest.raises(WitnessRefusal, match="shrank"):
        w.cosign(early)


def test_a_witness_refuses_a_head_signed_by_a_new_key():
    """
    Rotating the log key is how a custodian would otherwise walk away from its
    own history without anything registering.
    """
    _, first = _log_of(3, ec.generate_private_key(ec.SECP256R1()))
    _, second = _log_of(4, ec.generate_private_key(ec.SECP256R1()))
    w = Witness("board", ec.generate_private_key(ec.SECP256R1()))
    w.cosign(first)
    with pytest.raises(WitnessRefusal, match="different key"):
        w.cosign(second)


def test_cosignature_count_ignores_duplicates_and_strangers():
    """
    An examiner who counts witnesses they cannot name has reintroduced the
    problem, since the custodian can generate keys all day.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    _, head = _log_of(3, key)
    named = [Witness(f"w{i}", ec.generate_private_key(ec.SECP256R1()))
             for i in range(3)]
    stranger = Witness("stranger", ec.generate_private_key(ec.SECP256R1()))

    cosigs = [w.cosign(head) for w in named]
    cosigs.append(cosigs[0])                     # the same witness twice
    cosigs.append(stranger.cosign(head))         # unrecognised key

    trusted = [w.public_key for w in named]
    assert count_witnesses(head, cosigs, trusted) == 3
    assert count_witnesses(head, cosigs) == 4    # nobody named, nothing gained

    tampered = dict(head, size=head["size"] + 1)
    assert count_witnesses(tampered, cosigs, trusted) == 0


def test_two_heads_at_one_size_are_a_final_contradiction():
    """
    Transferable is the whole point. A third party present for neither
    disclosure re-checks the pair from scratch and the custodian cannot answer
    it, because no document reconciles two roots at one size.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    _, shown_to_a = _log_of(4, key)
    forked = TransparencyLog("semafide")
    for i in (0, 1, 2, 99):
        forked.append({"run": i})
    shown_to_b = sign_head(forked.head(T0 + 1), key)

    proof = equivocation(shown_to_a, shown_to_b)
    assert proof and proof["finality"] == CONTRADICTION
    assert equivocation_holds(json.loads(json.dumps(proof)))
    assert not rebut(proof, forked.consistency_proof(4))


def test_a_missing_consistency_proof_is_recorded_as_rebuttable():
    """
    The overclaim available here. Two legitimate heads at different sizes look
    identical to a rewritten history until the custodian produces the proof, so
    the finding is graded rather than reported as settled.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    log, early = _log_of(3, key)
    for i in range(3, 9):
        log.append({"run": i})
    later = sign_head(log.head(T0 + 1), key)

    proof = equivocation(early, later)
    assert proof and proof["finality"] == UNRECONCILED
    assert rebut(proof, log.consistency_proof(3))
    assert equivocation(early, later, log.consistency_proof(3)) is None


def test_an_unsigned_or_mismatched_pair_accuses_nobody():
    key = ec.generate_private_key(ec.SECP256R1())
    _, head = _log_of(3, key)
    _, other_log = _log_of(3, key, log_id="somebody-else")
    _, other_key = _log_of(4, ec.generate_private_key(ec.SECP256R1()))

    assert equivocation(head, dict(head, size=99)) is None
    assert equivocation(head, other_log) is None
    assert equivocation(head, other_key) is None
    assert not equivocation_holds({"kind": "nonsense"})
    assert not equivocation_holds(
        {"kind": "equivocation", "finality": CONTRADICTION,
         "head_a": head, "head_b": head})


# ==========================================================================
# Assignment custody. The sibling-chain hole: seal five analyses in five
# chains under one assignment and disclose the one you like. Every chain
# links from genesis, every signature verifies, and every per-chain
# checkpoint is honest, because each chain really is the length it claims.
# Counting the chain was never the question.
# ==========================================================================

from seal import (  # noqa: E402
    AssignmentAnchor,
    AssignmentCheckpoint,
    ChainRef,
    Disclosure,
    assess_disclosure,
    chain_identity,
    load_artifact,
)
from seal.assignment import issue as issue_assignment  # noqa: E402


def _assignment_checkpoint(chains, key=None, assignment_id="assignment-1",
                           observed_ns=T0 + 500):
    """The custodian's statement of which chains an assignment holds."""
    refs = tuple(ChainRef(c.chain_id, c.head, len(c.entries)) for c in chains)
    return issue_assignment(
        AssignmentCheckpoint(assignment_id, refs, observed_ns, "custodian"),
        key or ec.generate_private_key(ec.SECP256R1()))


def test_a_chain_is_anchored_to_its_assignment_before_anything_is_sealed():
    """
    Named only in the binding, the assignment is written last by the party
    with the most reason to choose it. Entry zero fixes it at open, and every
    later entry links back through prev_hash.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    entries = load_artifact(export_artifact(chain))
    assert entries[0].kind is EntryKind.ASSIGNMENT_ANCHOR
    aid, cid = chain_identity(entries)
    assert aid == "assignment-1"
    assert cid == chain.chain_id == entries[0].block_hash

    r = verify(export_artifact(chain), rederive=_ok)
    assert r.assignment_id == "assignment-1"


def test_five_chains_one_disclosed_is_invisible_without_a_statement():
    """
    The attack. The disclosed chain
    is whole and its own checkpoint says so. Nothing in it counts its siblings.
    """
    siblings = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(5)]
    handed_over = export_artifact(siblings[0])

    alone = verify(handed_over, rederive=_ok,
                   checkpoint=_custodian_checkpoint(siblings[0]))
    assert alone.completeness is Completeness.CONSISTENT
    assert alone.disclosure is Disclosure.UNCHECKED
    assert any(f.code == "no_assignment_checkpoint" for f in alone.findings)


def test_the_custodian_statement_makes_the_withheld_chains_visible():
    siblings = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(5)]
    acp = _assignment_checkpoint(siblings)

    r = verify(export_artifact(siblings[0]), rederive=_ok,
               checkpoint=_custodian_checkpoint(siblings[0]),
               assignment_checkpoint=acp)
    # Completeness is unchanged and correct. The chain really is whole.
    assert r.completeness is Completeness.CONSISTENT
    assert r.disclosure is Disclosure.PARTIAL
    assert r.chains_withheld == 4
    assert any(f.code == "sibling_chains_withheld" for f in r.findings)

    whole = assess_disclosure([export_artifact(c) for c in siblings], acp)
    assert whole.state is Disclosure.WHOLE and whole.whole
    assert whole.withheld == () and whole.expected == 5


def test_disclosure_order_does_not_change_the_verdict():
    """
    The chain list is sorted into the signature, so the custodian cannot be
    made to sign two different statements about one set of chains, and an
    examiner reading them in another order gets the same answer.
    """
    siblings = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(4)]
    acp = _assignment_checkpoint(siblings)
    docs = [export_artifact(c) for c in siblings]
    assert assess_disclosure(docs, acp).state is Disclosure.WHOLE
    assert assess_disclosure(list(reversed(docs)), acp).state is Disclosure.WHOLE


def test_a_chain_not_in_the_assignment_is_reported_rather_than_counted():
    """
    Answering a five-chain statement with a sixth chain nobody recorded is the
    obvious inversion of the attack.
    """
    siblings = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(3)]
    outsider = _build(WitnessMode.REDERIVABLE, rederivable=True,
                      chain_label="unrecorded")
    acp = _assignment_checkpoint(siblings)

    r = verify(export_artifact(outsider), rederive=_ok,
               assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.FOREIGN
    assert any(f.code == "chain_not_in_assignment" for f in r.findings)


def test_a_chain_under_another_assignment_does_not_answer_this_one():
    other = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   assignment_id="assignment-2")
    acp = _assignment_checkpoint([other], assignment_id="assignment-1")
    r = verify(export_artifact(other), rederive=_ok, assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.FOREIGN


def test_an_assignment_checkpoint_signed_by_the_sealer_is_worthless():
    """Same rule as the per-chain checkpoint. Counting your own chains is not
    a count."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    acp = _assignment_checkpoint([chain], key=chain._sk)
    r = verify(export_artifact(chain), rederive=_ok, assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.UNUSABLE
    assert any(f.code == "assignment_checkpoint_unusable" for f in r.findings)


def test_a_tampered_assignment_checkpoint_is_refused():
    siblings = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(3)]
    acp = _assignment_checkpoint(siblings)
    acp["chains"] = acp["chains"][:1]      # drop the siblings from the statement
    r = verify(export_artifact(siblings[0]), rederive=_ok,
               assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.UNUSABLE


def test_a_chain_with_no_anchor_cannot_be_checked_against_an_assignment():
    """
    Stripping the anchor is the way out of this check, so it is reported
    rather than passed. The chain also stops linking from genesis, which the
    integrity walk catches independently.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    acp = _assignment_checkpoint([chain])
    doc = export_artifact(chain)
    doc["entries"] = doc["entries"][1:]

    r = verify(doc, rederive=_ok, assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.UNANCHORED
    assert r.assignment_id is None
    assert not r.chain_intact
    assert any(f.code == "chain_names_no_assignment" for f in r.findings)


def test_a_second_anchor_cannot_re_declare_the_assignment():
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    chain.append(EntryKind.ASSIGNMENT_ANCHOR,
                 AssignmentAnchor("assignment-9").to_body(), T0 + 9_000_000_000)
    r = verify(export_artifact(chain), rederive=_ok)
    assert not r.chain_intact
    assert any(f.code == "anchor_out_of_position" for f in r.findings)


def test_a_binding_cannot_certify_an_assignment_the_chain_is_not_anchored_to():
    """
    The binding is written last. Before the anchor existed it was the only
    place the assignment appeared, so whatever it said was the answer.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True, bind=False)
    chain.append(EntryKind.WORKFILE_BINDING, WorkfileBinding(
        assignment_id="assignment-7", chain_head=chain.head,
        covered_seqs=[e.seq for e in chain.entries],
        certification_ref="cert-0001", effective_date="2026-03-14",
    ).to_body(), T0 + 9_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok)
    assert any(f.code == "binding_assignment_mismatch" for f in r.findings)


def test_a_short_sibling_chain_is_reported_against_the_statement():
    """Withholding entries from one chain and chains from the assignment are
    different omissions, and both are counted."""
    siblings = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(2)]
    acp = _assignment_checkpoint(siblings)
    docs = [export_artifact(c) for c in siblings]
    docs[1]["entries"] = docs[1]["entries"][:-1]

    result = assess_disclosure(docs, acp)
    # Both chains were produced, so nothing is in `withheld`, and the state is
    # still PARTIAL. WHOLE has to mean the disclosure is whole or a caller
    # reading one field gets a pass on a short hand-over.
    assert result.state is Disclosure.PARTIAL
    assert result.withheld == ()
    assert any("were disclosed" in f for f in result.findings)


# ==========================================================================
# External time anchoring. `ts_ns` is signed and monotonic and is still a
# number the sealer chose, so a chain assembled today with last year's
# timestamps verifies. This is the last fact in the artifact the sealer
# authored alone.
#
# The finding these assert is that RFC 3161 anchors the wrong side. A
# timestamp proves a document existed no later than a time. The attack KC1
# describes is a workfile built after the question arrives and dated to the
# run, which is the earlier side, and no authority can bound it.
# ==========================================================================

from cryptography.hazmat.primitives import serialization  # noqa: E402

from seal import Anchoring, Beacon, TimeAnchor  # noqa: E402
from seal.anchor import issue as issue_anchor  # noqa: E402

PULSE = ("nist-beacon", "pulse-88")
PULSE_VALUE = "9f" * 32
PULSE_NS = T0 - 60_000_000_000          # published a minute before the run


def _pem(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _resolver(source, pulse):
    """What an examiner does: look the pulse up at the source, not in the doc."""
    return (PULSE_VALUE, PULSE_NS) if (source, pulse) == PULSE else None


def _beacon(value=PULSE_VALUE, issued_ns=PULSE_NS):
    return Beacon(PULSE[0], PULSE[1], value, issued_ns).to_body()


def _stamp(chain, key, at_ns, authority="tsa", entry=-1):
    return issue_anchor(
        TimeAnchor(authority, chain.entries[entry].block_hash, at_ns), key)


def test_an_unanchored_chain_says_so_rather_than_passing():
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.anchoring is Anchoring.UNANCHORED
    assert r.anchor_interval_ns is None
    assert any(f.code == "no_time_anchor" for f in r.findings)


def test_a_timestamp_alone_leaves_backdating_untouched():
    """
    The correction to the plan. This project has named RFC 3161 as the external
    time anchor since the integration scope was written. It bounds the later
    side, and the attack KC1 describes is on the earlier one, so an authority
    alone is reported as UPPER_ONLY rather than counted as anchored.
    """
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    token = _stamp(chain, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UPPER_ONLY
    assert r.anchor_interval_ns is None      # unbounded below, not zero
    assert any(f.code == "backdating_unconstrained" for f in r.findings)


def test_a_committed_beacon_and_a_timestamp_pin_the_instant_to_an_interval():
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   beacon=_beacon())
    token = _stamp(chain, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)], beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.BOUNDED
    assert r.anchor_interval_ns == 120_000_000_000     # two minutes wide
    assert not any(f.bears_on == "KC1" for f in r.findings)


def test_backdating_is_caught_by_the_lower_bound_and_only_by_it():
    """
    The chain claims instants from before the value it commits to was
    published, which cannot be true. Nothing else in the package notices: the
    chain links from genesis, every signature verifies, and the timestamps are
    monotonic among themselves.
    """
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   beacon=_beacon(issued_ns=PULSE_NS),
                   opened_ns=PULSE_NS - 400_000_000_000,
                   base_ns=PULSE_NS - 300_000_000_000)

    naive = verify(export_artifact(chain), rederive=_ok)
    assert naive.chain_intact and naive.signatures_valid
    assert not any(f.code == "timestamp_regression" for f in naive.findings)

    r = verify(export_artifact(chain), rederive=_ok, beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.INCONSISTENT
    assert any(f.code == "instant_outside_anchor" and "backdating" in f.detail
               for f in r.findings)


def test_a_beacon_nobody_resolves_is_the_sealer_talking_to_itself():
    """Same shape as `witness_mode: independent`. The value has to be looked up
    somewhere other than the document it constrains."""
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("resolver" in f.detail for f in r.findings)


def test_a_fabricated_beacon_value_does_not_resolve():
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   beacon=_beacon(value="00" * 32))
    r = verify(export_artifact(chain), rederive=_ok, beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("not what that source published" in f.detail for f in r.findings)


def test_an_unrecognised_authority_is_not_counted():
    """An examiner who accepts any signature over a time has handed the sealer
    a key generator, which is the lesson `count_witnesses` already learned."""
    forger = ec.generate_private_key(ec.SECP256R1())
    real = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    token = _stamp(chain, forger, T0 + 60_000_000_000, authority="tsa")

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(real)])
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("unrecognised key" in f.detail for f in r.findings)

    # No named authorities at all is the same position, stated differently.
    r2 = verify(export_artifact(chain), rederive=_ok, time_anchors=[token])
    assert r2.anchoring is Anchoring.UNANCHORED


def test_an_anchor_over_another_document_proves_nothing_about_this_one():
    """The recipe compared to itself, one level over. A token has to name an
    entry in the chain it is offered against."""
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    other = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   chain_label="elsewhere")
    token = _stamp(other, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("not an entry in this chain" in f.detail for f in r.findings)


def test_a_tampered_token_does_not_verify():
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    token = _stamp(chain, tsa, T0 + 60_000_000_000)
    token["time_ns"] = T0 - 999_000_000_000       # move it earlier

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("does not verify" in f.detail for f in r.findings)


def test_the_earliest_recognised_anchor_is_the_one_that_binds():
    """Several tokens are not several bounds. The tightest one is the claim."""
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True,
                   beacon=_beacon())
    tokens = [_stamp(chain, tsa, T0 + n) for n in
              (600_000_000_000, 60_000_000_000, 300_000_000_000)]

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=tokens,
               trusted_authorities=[_pem(tsa)], beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.BOUNDED
    assert r.anchor_interval_ns == 120_000_000_000


def test_an_old_pulse_widens_the_interval_rather_than_defeating_the_check():
    """
    A sealer wanting a weak bound commits to a stale pulse. That is permitted
    and it is visible, because the interval is reported rather than reduced to
    a pass. The mechanism cannot be beaten quietly, only widened in the open.
    """
    tsa = ec.generate_private_key(ec.SECP256R1())
    stale_ns = T0 - 365 * 24 * 3600 * 1_000_000_000

    def stale_resolver(source, pulse):
        return (PULSE_VALUE, stale_ns) if (source, pulse) == PULSE else None

    chain = _build(WitnessMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    token = _stamp(chain, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)], beacon_resolver=stale_resolver)
    assert r.anchoring is Anchoring.BOUNDED
    assert r.anchor_interval_ns > 365 * 24 * 3600 * 1_000_000_000


def test_a_beacon_published_after_the_authority_saw_the_chain_is_impossible():
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    token = _stamp(chain, tsa, PULSE_NS - 10_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)], beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.INCONSISTENT
    assert any("cannot both be true" in f.detail for f in r.findings)


# ==========================================================================
# Stateful checkpoint issuance.
#
# A checkpoint here is a signed tree head and the signature that makes it
# worth anything is a witness cosignature, both specified at c2sp.org. The
# specification states the property this package was missing: a cosignature
# asserts that the CONSISTENT tree head with the LARGEST SIZE THE COSIGNER HAS
# OBSERVED has the given root hash. A signature over a count is not that. The
# issuer has to remember.
#
# `witness.Witness` was already built this way for tree heads, so the
# discipline existed one level up and was absent at the level an examiner
# actually sees.
# ==========================================================================

from seal.checkpoint import signature_valid as cp_signature_valid  # noqa: E402

from seal import (  # noqa: E402
    AssignmentIssuer,
    AssignmentRefusal,
    CheckpointIssuer,
    CheckpointRefusal,
)


def test_a_stateless_signer_vouches_for_two_chains_at_one_size():
    """
    The reproduction, frozen. This is what `issue` does and why a custodian
    must not call it. Both chains are honest and both checkpoints are true;
    the sealer produces whichever suits and completeness reports CONSISTENT.
    """
    custodian = ec.generate_private_key(ec.SECP256R1())
    a = _build(WitnessMode.REDERIVABLE, rederivable=True, chain_label="a")
    b = _build(WitnessMode.REDERIVABLE, rederivable=True, chain_label="b")
    assert len(a.entries) == len(b.entries) and a.head != b.head

    for chain in (a, b):
        cp = _custodian_checkpoint(chain, key=custodian)
        r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
        assert r.completeness is Completeness.CONSISTENT


def test_a_stateful_issuer_refuses_the_second_chain():
    """The fix. The issuer remembers what it signed and will not sign a
    different chain at that size."""
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    a = _build(WitnessMode.REDERIVABLE, rederivable=True, chain_label="a")
    b = _build(WitnessMode.REDERIVABLE, rederivable=True, chain_label="b")

    issuer.issue(Checkpoint("assignment-1", len(a.entries), a.head, T0, "custodian"),
                 a.entries)
    with pytest.raises(CheckpointRefusal, match="equivocation"):
        issuer.issue(
            Checkpoint("assignment-1", len(b.entries), b.head, T0 + 1, "custodian"),
            b.entries)


def test_an_issuer_signs_a_genuine_extension_and_refuses_a_shrink():
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    first = len(chain.entries)
    issuer.issue(Checkpoint("assignment-1", first, chain.head, T0, "custodian"),
                 chain.entries)

    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-2", _primitives(merkle_root(_rows())), None,
        WitnessMode.SELF_ATTESTED).to_body(), T0 + 9_000_000_000)
    signed = issuer.issue(
        Checkpoint("assignment-1", len(chain.entries), chain.head,
                   T0 + 2, "custodian"), chain.entries)
    assert cp_signature_valid(signed)

    with pytest.raises(CheckpointRefusal, match="shrank"):
        issuer.issue(Checkpoint("assignment-1", first, chain.head,
                                T0 + 3, "custodian"), chain.entries)


def test_growth_without_the_entries_cannot_be_established():
    """An issuer given nothing to check against must refuse, because assuming
    an extension is the failure being corrected."""
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    a = _build(WitnessMode.REDERIVABLE, rederivable=True, chain_label="a")
    longer = _build(WitnessMode.REDERIVABLE, rederivable=True,
                    chain_label="b", runs_after_binding=1)
    issuer.issue(Checkpoint("assignment-1", len(a.entries), a.head, T0, "custodian"),
                 a.entries)

    with pytest.raises(CheckpointRefusal, match="not an extension"):
        issuer.issue(Checkpoint("assignment-1", len(longer.entries),
                                longer.head, T0 + 1, "custodian"))
    with pytest.raises(CheckpointRefusal, match="not an extension"):
        issuer.issue(Checkpoint("assignment-1", len(longer.entries),
                                longer.head, T0 + 1, "custodian"),
                     longer.entries)


def test_one_issuer_state_does_not_leak_between_assignments():
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    a = _build(WitnessMode.REDERIVABLE, rederivable=True)
    b = _build(WitnessMode.REDERIVABLE, rederivable=True,
               assignment_id="assignment-2", chain_label="other")
    issuer.issue(Checkpoint("assignment-1", len(a.entries), a.head, T0, "custodian"),
                 a.entries)
    assert issuer.issue(
        Checkpoint("assignment-2", len(b.entries), b.head, T0 + 1, "custodian"),
        b.entries)


def test_an_assignment_issuer_refuses_to_drop_a_chain_it_recorded():
    """The same defect one level out: a five-chain statement followed by a
    three-chain statement, with the sealer producing whichever suits."""
    issuer = AssignmentIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chains = [_build(WitnessMode.REDERIVABLE, rederivable=True,
                     chain_label=f"chain-{i}") for i in range(5)]
    refs = tuple(ChainRef(c.chain_id, c.head, len(c.entries)) for c in chains)

    issuer.issue(AssignmentCheckpoint("assignment-1", refs, T0, "custodian"))
    with pytest.raises(AssignmentRefusal, match="absent from"):
        issuer.issue(AssignmentCheckpoint("assignment-1", refs[:3],
                                          T0 + 1, "custodian"))

    # Gaining a chain is ordinary and is signed.
    extra = _build(WitnessMode.REDERIVABLE, rederivable=True, chain_label="late")
    grown = refs + (ChainRef(extra.chain_id, extra.head, len(extra.entries)),)
    assert issuer.issue(
        AssignmentCheckpoint("assignment-1", grown, T0 + 2, "custodian"))


def test_an_assignment_issuer_refuses_a_chain_that_lost_entries():
    issuer = AssignmentIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chain = _build(WitnessMode.REDERIVABLE, rederivable=True)
    full = (ChainRef(chain.chain_id, chain.head, len(chain.entries)),)
    issuer.issue(AssignmentCheckpoint("assignment-1", full, T0, "custodian"))

    shortened = (ChainRef(chain.chain_id, chain.head, len(chain.entries) - 1),)
    with pytest.raises(AssignmentRefusal, match="shrank"):
        issuer.issue(AssignmentCheckpoint("assignment-1", shortened,
                                          T0 + 1, "custodian"))
