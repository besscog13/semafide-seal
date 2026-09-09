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
    Coverage,
    EntryKind,
    EvidenceCommitment,
    Holding,
    Pinning,
    PrimitiveKind,
    PrimitiveRecord,
    Provenance,
    EvidenceForm,
    RetentionDetermination,
    RunSeal,
    SealChain,
    AttestationMode,
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
    retention: EvidenceForm = EvidenceForm.COMMITMENT_ONLY,
) -> dict[PrimitiveKind, PrimitiveRecord]:
    """A full primitive set for one time-adjustment run."""
    def rec(kind, payload, **kw):
        return PrimitiveRecord(
            kind=kind, commitment=payload,
            pinning=kw.get("pinning", Pinning.PINNED),
            retention=kw.get("retention", EvidenceForm.FULL),
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
    witness: AttestationMode,
    *,
    commit_evidence_first: bool = True,
    rederivable: bool = False,
    recipe_digest: str | None = None,
    recipe_input_ref: str | None = None,
    recipe_override: dict | None = None,
    pinning: Pinning = Pinning.PINNED,
    retention: EvidenceForm = EvidenceForm.COMMITMENT_ONLY,
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
    chain = _build(AttestationMode.INDEPENDENT)
    r = verify(export_artifact(chain), trusted_keys=[chain.public_key_pem])
    assert r.chain_intact and r.signatures_valid and r.key_trusted
    assert r.trustworthy


def test_tampered_body_fails_signature():
    chain = _build(AttestationMode.INDEPENDENT)
    doc = export_artifact(chain)
    doc["entries"][1]["body"]["run_id"] = "run-tampered"
    r = verify(doc, trusted_keys=[chain.public_key_pem])
    assert not r.signatures_valid
    assert not r.trustworthy


def test_removing_an_entry_breaks_the_chain():
    chain = _build(AttestationMode.INDEPENDENT)
    doc = export_artifact(chain)
    del doc["entries"][0]
    r = verify(doc, trusted_keys=[chain.public_key_pem])
    assert not r.chain_intact
    assert not r.trustworthy


def test_concurrent_append_never_lets_two_entries_share_a_sequence_number(monkeypatch):
    """
    `append` reads `seq` and `prev_hash` from the current chain state, signs
    over them, and only then appends the result, as three separate steps.
    Without a lock, two concurrent callers can both read the same `seq` and
    the same `prev_hash` before either has appended, and both then sign and
    append an entry claiming that same position and predecessor. Reproduced
    directly against this class (widening the window the same way
    `test_append_serializes_the_write_and_its_index_read` does for
    `TransparencyLog`, since ordinary threaded hammering does not land in a
    nanosecond-wide window reliably): five threads appending concurrently
    with no lock produced a chain with entries [0, 1, 1, 1, 1, 1] instead of
    [0, 1, 2, 3, 4, 5], four different entries all claiming sequence 1 and
    all claiming the same `prev_hash`.

    This is a more serious failure than a missing entry. A verifier walking
    a chain notices a hole in the sequence; it has no reason to expect two
    validly signed entries at the same position, which is exactly the linkage
    the whole chain exists to make unforgeable.

    Existing callers in `capture/` already serialize every `append` under a
    coarser lock (`_OpenAssignment.lock`), so this has not been reachable
    through the capture layer. `SealChain` is exported directly, though, and
    nothing stops a caller from building one and calling `append` from more
    than one thread without knowing they need to add that lock themselves.
    """
    import threading as _threading
    import time as _time

    from seal import artifact as _artifact_module

    chain = SealChain("ASG-concurrent-append")
    real_signing_payload = _artifact_module.signing_payload
    delay = 0.02

    def slow_signing_payload(kind, seq, prev, body, ts_ns):
        _time.sleep(delay)
        return real_signing_payload(kind, seq, prev, body, ts_ns)

    monkeypatch.setattr(_artifact_module, "signing_payload", slow_signing_payload)

    n = 5

    def worker(i):
        chain.append(EntryKind.EVIDENCE_COMMITMENT, {"i": i}, i)

    threads = [_threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = _time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = _time.perf_counter() - t0

    assert elapsed >= delay * n * 0.8, (
        f"{n} appends took {elapsed:.3f}s for a {delay}s signing step each; "
        "they overlapped rather than being serialized by the lock")

    seqs = sorted(e.seq for e in chain.entries)
    assert seqs == list(range(n + 1)), (
        f"expected sequence numbers {list(range(n + 1))}, got {seqs}: "
        "two callers claimed the same position")
    assert len({e.block_hash for e in chain.entries}) == n + 1


def test_signature_validity_does_not_establish_identity():
    """Anyone can sign anything with a key they generated."""
    chain = _build(AttestationMode.INDEPENDENT)
    r = verify(export_artifact(chain))  # no trusted key set supplied
    assert r.signatures_valid
    assert r.key_trusted is None
    assert any(f.code == "key_identity_unchecked" for f in r.findings)


def test_a_key_set_that_does_not_include_the_signer_is_untrusted_not_unchecked():
    """
    `key_identity_unchecked` above is what happens when nobody supplies a
    trusted set at all. This is the other branch: a caller does supply one,
    correctly formed and non-empty, and it simply does not name the key
    that actually signed the chain -- a different examiner's allowlist, or
    a stale one. That must read as `key_trusted is False` with its own
    finding, not silently fall back to the unchecked case, and nothing
    before this exercised it: every other test in this file either passes
    no trusted set or passes the artifact's own key.
    """
    chain = _build(AttestationMode.INDEPENDENT)
    stranger = ec.generate_private_key(ec.SECP256R1())
    stranger_pem = stranger.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    r = verify(export_artifact(chain), trusted_keys=[stranger_pem])
    assert r.signatures_valid
    assert r.key_trusted is False
    assert not r.trustworthy
    assert any(f.code == "untrusted_key" for f in r.findings)


# --------------------------------------------------------------------------
# KC2: what a timestamping service could replicate
# --------------------------------------------------------------------------

def test_no_evidence_commitment_is_bundling():
    chain = _build(AttestationMode.SELF_ATTESTED, commit_evidence_first=False)
    r = verify(export_artifact(chain))
    assert not r.evidence.precedence
    assert r.kc2_fires


def test_self_attested_precedence_still_fires_kc2():
    """
    Committing evidence before the run rules out choosing inputs after seeing
    the output, which is real. It is also exactly what two RFC-3161 timestamps
    over two local files achieve, so it does not clear KC2.
    """
    chain = _build(AttestationMode.SELF_ATTESTED)
    r = verify(export_artifact(chain))
    assert r.evidence.precedence and not r.evidence.recipe_available
    assert r.timestamp_replicable and r.kc2_fires


def test_self_declared_witness_does_not_clear_kc2():
    """
    This test previously asserted the opposite, and the assertion was the bug.
    `witness_mode` is a field the sealer writes. Granting WITNESSED on it was
    the cheapest route to clearing KC2 in the package: nine characters, no
    recipe, no re-derivation.
    """
    chain = _build(AttestationMode.INDEPENDENT)
    r = verify(export_artifact(chain))
    assert r.evidence.precedence and not r.evidence.recipe_available
    assert not r.evidence.witness_attestation
    assert not r.evidence.historical_execution_established
    assert r.kc2_fires
    assert any(f.code == "witness_self_declared" for f in r.findings)


def test_a_witness_attestation_naming_a_non_string_public_key_is_a_specific_finding_not_a_crash():
    """
    `attestation.get("public_key")` used to be checked only with `not key`,
    which passes any truthy, non-string JSON value straight through to
    `key.strip()` a line later -- an int, a list, a dict, all raise
    AttributeError there. `verify()`'s outer try/except still catches it
    and fails closed (`trustworthy` stays False), but as an unnamed
    "malformed_artifact" quoting a raw Python exception rather than a
    finding that says what is actually wrong, the same gap
    `binding_seq_out_of_range` closed for an out-of-range `binding.seq`.
    Confirmed this reached `verify()` through a real, otherwise well-formed
    artifact before fixing it, not only against a hand-built dict.
    """
    witness_key = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.INDEPENDENT, witness_key=witness_key)
    doc = export_artifact(chain)
    for e in doc["entries"]:
        if e["kind"] == "run_seal":
            e["body"]["witness_attestation"]["public_key"] = 12345
    r = verify(doc, trusted_keys=[chain.public_key_pem],
               trusted_witness_keys=["whatever"])
    assert not r.trustworthy
    assert any(f.code == "witness_self_declared" for f in r.findings)
    assert not any(f.code == "malformed_artifact" for f in r.findings)


def test_a_witness_attestation_naming_a_non_string_signature_is_a_specific_finding_not_a_crash():
    """
    Sibling to the `public_key` bug above, one field over. `signature` used
    to reach `bytes.fromhex(attestation.get("signature", ""))` unguarded.
    `fromhex` raises `TypeError` on anything that is not a string -- not the
    `ValueError` the surrounding `except` clause already catches for a
    malformed-but-string signature -- so a manifest carrying
    `witness_attestation.signature: null` (or any other non-string JSON
    value) crashed past this function's own fail-closed finding and reached
    `verify()`'s outer try/except as an unnamed "malformed_artifact" quoting
    a raw `TypeError`. Confirmed against a real, otherwise well-formed
    artifact with a trusted witness key, matching the `public_key` test's
    own discipline, before fixing it.
    """
    witness_key = ec.generate_private_key(ec.SECP256R1())
    witness_pem = witness_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    chain = _build(AttestationMode.INDEPENDENT, witness_key=witness_key)
    doc = export_artifact(chain)
    for e in doc["entries"]:
        if e["kind"] == "run_seal":
            e["body"]["witness_attestation"]["signature"] = None
    r = verify(doc, trusted_keys=[chain.public_key_pem],
               trusted_witness_keys=[witness_pem])
    assert not r.trustworthy
    assert any(f.code == "witness_self_declared" for f in r.findings)
    assert not any(f.code == "malformed_artifact" for f in r.findings)


def test_independent_observer_attestation_establishes_historical_execution():
    witness_key = ec.generate_private_key(ec.SECP256R1())
    witness_pem = witness_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   witness_key=witness_key)
    r = verify(export_artifact(chain), rederive=_ok,
               trusted_witness_keys=[witness_pem],
               retention_determinations=[_determination()])
    assert r.evidence.witness_attestation
    assert r.evidence.recipe_reproduced
    assert r.evidence.historical_execution_established


def test_complete_recipe_not_executed_is_only_rederivable():
    """A recipe that has not been run is a claim, not a proof."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain))
    assert r.evidence.recipe_available and not r.evidence.recipe_reproduced
    assert any(f.code == "not_rederived" for f in r.findings)


def test_executed_and_matched_reaches_rederived_and_clears_kc2():
    """
    Both halves are required. Re-derivation establishes that the output came
    from the input. It clears KC2 only where somebody other than the sealer has
    established that the input could not have been kept locally, which is why
    the determination is supplied here and its absence is a separate test.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[_determination()])
    assert r.evidence.recipe_reproduced
    assert r.input_provenance is Provenance.SOURCED
    assert not r.kc2_fires


def test_rederivation_mismatch_drops_to_precedence():
    """Re-running and getting a different answer is the whole point."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=lambda rec: OTHER_DIGEST)
    assert r.evidence.precedence and not r.evidence.recipe_available
    assert not r.evidence.recipe_reproduced
    assert not r.evidence.historical_execution_established
    assert any(f.code == "rederivation_mismatch" for f in r.findings)


def test_unservable_pinned_version_decays_to_the_recipe():
    """The liveness dependency. A signature does not have one; this does."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=lambda rec: None)
    assert r.evidence.recipe_available and not r.evidence.recipe_reproduced
    assert any(f.bears_on == "liveness" for f in r.findings)


def test_incomplete_recipe_does_not_count():
    partial = _recipe("whatever")
    del partial["endpoint"]
    del partial["service_window"]
    chain = _build(AttestationMode.REDERIVABLE, recipe_override=partial)
    r = verify(export_artifact(chain))
    assert r.evidence.precedence and not r.evidence.recipe_available
    assert any(f.code == "incomplete_recipe" for f in r.findings)


def test_a_non_dict_rederivation_recipe_is_a_specific_finding_not_a_crash():
    """
    `RederivationRecipe.is_complete` checked only `not d`, which catches a
    falsy recipe (None, "", {}) but not a truthy value of the wrong type --
    a bare string or a list, which a hostile artifact can name here just as
    easily as a proper dict. `d.get(f)` on a non-dict truthy value raises
    AttributeError. Fixing only `is_complete` was not enough: the
    `incomplete_recipe` branch in `verifier.py` computed its own `missing`
    list with `(recipe or {}).get(f)`, which only substitutes `{}` for a
    falsy recipe too, so the identical crash was still reachable one level
    further in even after `is_complete` itself was fixed. Both were caught
    by `verify()`'s outer try/except before this fix, failing closed
    (`trustworthy` stays False either way) but as an unnamed
    "malformed_artifact" rather than the specific `incomplete_recipe`
    finding this hostile input should produce -- the same category of gap
    `binding_seq_out_of_range` and the non-string witness key closed
    earlier. Checked both a string and a list, since the bug was never
    specific to one wrong type.
    """
    for hostile_recipe in ("just a string, not a recipe dict", ["not", "a", "dict"]):
        chain = _build(AttestationMode.REDERIVABLE, recipe_override=hostile_recipe)
        r = verify(export_artifact(chain))
        assert (r.evidence.precedence and not r.evidence.recipe_available), hostile_recipe
        assert any(f.code == "incomplete_recipe" for f in r.findings), hostile_recipe
        assert not any(f.code == "malformed_artifact" for f in r.findings), hostile_recipe


def test_rederivable_claim_without_a_recipe_does_not_count():
    chain = _build(AttestationMode.REDERIVABLE, rederivable=False)
    r = verify(export_artifact(chain))
    assert r.evidence.precedence and not r.evidence.recipe_available
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[
                   _determination(Holding.OPERATOR_HOLDS)])
    assert r.evidence.recipe_reproduced
    assert r.evidence.recipe_reproduced
    assert not r.evidence.historical_execution_established
    assert r.input_provenance is Provenance.SOURCED
    assert r.input_holding is Holding.OPERATOR_HOLDS
    assert r.kc2_fires


def test_witness_attestation_survives_an_unexecuted_recipe():
    """
    `_run_evidence`'s own docstring says it establishes each proposition
    without treating them as a ladder. The control flow used to disagree: a
    run carrying both a complete rederivation recipe and a genuinely valid,
    trusted witness attestation lost the attestation entirely whenever the
    recipe path returned early, because every early return inside the
    REDERIVABLE branch returned bare `evidence` without ever calling
    `_attach_witness_attestation`. A recipe nobody ran and an attestation
    somebody signed are independent claims; the first not being exercised
    must not suppress the second.
    """
    witness_key = ec.generate_private_key(ec.SECP256R1())
    witness_pem = witness_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, witness_key=witness_key)
    r = verify(export_artifact(chain), rederive=None, trusted_witness_keys=[witness_pem])
    assert r.evidence.recipe_available
    assert not r.evidence.recipe_reproduced
    assert r.evidence.witness_attestation
    assert r.evidence.historical_execution_established
    assert any(f.code == "not_rederived" for f in r.findings)


def test_witness_attestation_survives_a_rederivation_mismatch():
    """
    Sibling to the test above, on the other early-return path. A
    rederivation mismatch correctly drops `recipe_available`, because a
    recipe that disagrees with its own sealed output cannot support a
    re-derivation claim. It must not also drop a separately valid witness
    attestation on the same run.
    """
    witness_key = ec.generate_private_key(ec.SECP256R1())
    witness_pem = witness_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, witness_key=witness_key)
    r = verify(export_artifact(chain), rederive=lambda recipe: "not-the-sealed-digest",
               trusted_witness_keys=[witness_pem])
    assert r.evidence.precedence
    assert not r.evidence.recipe_available
    assert r.evidence.witness_attestation
    assert r.evidence.historical_execution_established
    assert any(f.code == "rederivation_mismatch" for f in r.findings)


def test_no_spurious_witness_finding_when_no_witness_was_ever_claimed():
    """
    Before the fix above, `_attach_witness_attestation` ran unconditionally
    at the end of a successful rederivation, regardless of whether the run
    made any witness claim at all. Against an empty `witness_attestation`
    dict, `_witness_attestation_valid` always fails, so every successful
    REDERIVABLE run picked up a `witness_self_declared` finding saying it
    "declares an independent witness" -- false for a run that never
    mentioned one. Gating the call on an actual claim removes the false
    finding without weakening the three existing tests that assert on it,
    all of which build a real claim (`AttestationMode.INDEPENDENT`, or a
    supplied `witness_attestation` payload) before expecting it.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[_determination()])
    assert r.evidence.recipe_reproduced
    assert not any(f.code == "witness_self_declared" for f in r.findings)


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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   retention=EvidenceForm.COMMITMENT_ONLY)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.evidence.recipe_reproduced
    assert r.input_provenance is Provenance.UNSOURCED
    assert r.kc2_fires


def test_a_determination_signed_by_the_sealer_does_not_count():
    """
    The sealer reading the sealer's own tool documentation is the sealer
    vouching for itself on the point at issue. Same shape as a self-issued
    checkpoint, and refused for the same reason.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[_determination(version="9.9.9")])
    assert r.input_provenance is Provenance.UNSOURCED
    assert r.kc2_fires


def test_a_tampered_determination_is_unusable():
    doc = _determination()
    doc["holding"] = Holding.OPERATOR_CANNOT_HOLD.value
    doc["source"] = "https://attacker.example/whatever"
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[doc])
    assert r.input_provenance is Provenance.UNUSABLE
    assert r.kc2_fires


def test_disagreeing_determinations_do_not_clear_kc2():
    """A contested reading does not clear a kill condition."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok,
               retention_determinations=[
                   _determination(Holding.OPERATOR_CANNOT_HOLD),
                   _determination(Holding.OPERATOR_HOLDS, key=_OTHER_KEY,
                                  by="second-reader")])
    assert r.input_provenance is Provenance.MISMATCHED
    assert r.kc2_fires
    assert any(f.code == "retention_contested" for f in r.findings)


def test_garbage_entries_in_the_determinations_list_are_skipped_not_fatal():
    """
    `retention_determinations` is a list an examiner supplies, assembled from
    wherever they keep signed readings -- nothing guarantees every element
    is even a dict before `assess` gets to it. `None`, a bare string, an
    int, and a list are not hypothetical: they are what a hand-edited or
    partially-parsed JSON array degrades to. `assess`'s own guard
    (`if not isinstance(doc, dict): continue`) had no test, and mixing
    those in alongside one genuine, matching determination checks both
    halves at once: the garbage does not crash or poison the result, and
    the real determination underneath it still clears KC2 exactly as it
    would on its own.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    determinations = [None, "garbage", 42, ["nested", "list"],
                      _determination(Holding.OPERATOR_CANNOT_HOLD)]
    r = verify(export_artifact(chain), rederive=_ok,
              retention_determinations=determinations)
    assert r.input_provenance is Provenance.SOURCED
    assert r.input_holding is Holding.OPERATOR_CANNOT_HOLD
    assert not r.kc2_fires


def test_an_undetermined_reading_resolves_against_clearance():
    """
    An honest reading that could not tell is recorded rather than guessed, and
    it fails closed. Recording less must never grade better.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    both = _build(AttestationMode.REDERIVABLE, rederivable=True,
                  runs_after_binding=1)
    r = verify(export_artifact(both), rederive=_ok,
               retention_determinations=[_determination()])
    assert r.input_provenance is Provenance.SOURCED
    assert not r.kc2_fires

    split = _build(AttestationMode.REDERIVABLE, rederivable=True,
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
        "run-1", _primitives(root), None, AttestationMode.INDEPENDENT).to_body(), T0)
    chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-late", root, 40, "MLS-export", "2026-03-14T09:00:00Z").to_body(),
        T0 + 1)
    r = verify(export_artifact(chain))
    assert not r.evidence.precedence
    assert any(f.bears_on == "KC1" for f in r.findings)


def test_a_run_naming_a_commitment_sealed_after_it_is_caught_not_just_a_run_naming_none():
    """
    The test above names no commitment at all. `commitment_not_prior` is a
    different, sharper claim -- a run naming a real evidence commitment that
    the chain shows was sealed at or after the run itself, which is what a
    sealer would need if they wanted their body to name evidence they
    committed after already knowing the output. Nothing in the existing
    suite ever constructed that ordering; SECURITY.md lists exactly this
    ("obtaining precedence without the evidence commitment genuinely
    preceding the run seal") as in scope.

    Building it takes a real chain (ev-1, run naming ev-1 honestly, ev-2
    sealed after) and then doing what a sealer with their own key could do
    to their own artifact: rewrite the run's body to name ev-2 instead, and
    re-sign it. `chain_break` also fires here, honestly -- the mutated run's
    hash no longer matches what ev-2's `prev_hash` was computed against --
    and that is a second, independent detection of the same tampering, not
    a confound; `commitment_not_prior` is checked as one finding among
    several rather than the only one.
    """
    import hashlib

    from seal.artifact import signing_payload

    chain = SealChain("assignment-1", opened_ns=T0)
    root = merkle_root(_rows())
    ev1 = chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-1", root, 40, "MLS-export", "2026-03-14T09:00:00Z").to_body(), T0)
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-1", _primitives(root), ev1.block_hash, AttestationMode.INDEPENDENT
    ).to_body(), T0 + 1)
    ev2 = chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-2", root, 40, "MLS-export", "2026-03-15T09:00:00Z").to_body(), T0 + 2)

    doc = export_artifact(chain)
    run_doc = next(e for e in doc["entries"] if e["kind"] == "run_seal")
    run_doc["body"]["evidence_commitment_hash"] = ev2.block_hash
    raw = canonical_bytes(signing_payload(
        EntryKind.RUN_SEAL, run_doc["seq"], run_doc["prev_hash"],
        run_doc["body"], run_doc["ts_ns"]))
    run_doc["block_hash"] = hashlib.sha256(raw).hexdigest()
    run_doc["signature"] = chain._sk.sign(raw, ec.ECDSA(hashes.SHA256())).hex()  # noqa: SLF001

    r = verify(doc, trusted_keys=[chain.public_key_pem])
    assert not r.evidence.precedence
    assert any(f.code == "commitment_not_prior" for f in r.findings)


def test_a_run_naming_a_commitment_not_in_the_chain_is_bundling_not_a_crash():
    """
    `evidence_commitment_hash` is a string the sealer writes, and nothing
    forces it to name a real entry. A hostile or corrupted artifact can
    point it at any value: garbage, a typo, or -- more pointedly -- the
    hash of some other kind of entry entirely, hoping the lookup finds
    *something*. `commitments` is built only from `EVIDENCE_COMMITMENT`
    entries, so even naming a real `WORKFILE_BINDING`'s hash misses.
    """
    chain = SealChain("assignment-1", opened_ns=T0)
    root = merkle_root(_rows())
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-1", _primitives(root), "sha256:" + "ab" * 32, AttestationMode.INDEPENDENT
    ).to_body(), T0)
    r = verify(export_artifact(chain))
    assert not r.evidence.precedence
    assert any(f.code == "dangling_commitment" for f in r.findings)


# --------------------------------------------------------------------------
# Design question three: the seam between layers
# --------------------------------------------------------------------------

def test_contiguous_binding_makes_omission_detectable():
    chain = _build(AttestationMode.INDEPENDENT)
    r = verify(export_artifact(chain))
    assert r.coverage is Coverage.CONTIGUOUS


def test_selective_binding_is_detected():
    chain = _build(AttestationMode.INDEPENDENT, omit_seq=0)
    r = verify(export_artifact(chain))
    assert r.coverage is Coverage.SUBSET
    assert any(f.code == "selective_binding" for f in r.findings)


def test_missing_layer_two_is_reported():
    chain = _build(AttestationMode.INDEPENDENT, bind=False)
    r = verify(export_artifact(chain))
    assert r.coverage is Coverage.ABSENT


# --------------------------------------------------------------------------
# The three properties
# --------------------------------------------------------------------------

def test_all_six_primitives_are_reported():
    chain = _build(AttestationMode.INDEPENDENT)
    r = verify(export_artifact(chain))
    assert set(r.primitives_present) == {k.value for k in PrimitiveKind}
    assert all(r.primitives_present.values())


def test_floating_primitive_is_a_pinning_finding():
    """A primitive that resolves to present state fails pinning even when kept."""
    chain = _build(AttestationMode.INDEPENDENT, pinning=Pinning.FLOATING)
    r = verify(export_artifact(chain))
    assert r.primitives_pinned["evidence"] == Pinning.FLOATING.value
    assert any(f.bears_on == "pinning" for f in r.findings)


def test_reach_tracks_the_holder_not_mere_existence():
    """Evidence held only by the MLS exists but is out of reach of the liable party."""
    rec = PrimitiveRecord(
        kind=PrimitiveKind.EVIDENCE, commitment=merkle_root(_rows()),
        pinning=Pinning.PINNED, retention=EvidenceForm.COMMITMENT_ONLY,
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   recipe_digest=OTHER_DIGEST)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.evidence.precedence and not r.evidence.recipe_available
    assert r.kc2_fires
    assert any(f.code == "recipe_output_not_the_action" for f in r.findings)


def test_recipe_input_must_be_the_named_evidence():
    """Attack C. A recipe naming an input unrelated to the sealed evidence."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   recipe_input_ref="commitment://SOMETHING-ELSE")
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.evidence.precedence and not r.evidence.recipe_available
    assert any(f.code == "recipe_input_not_the_evidence" for f in r.findings)


def test_runs_after_certification_are_detected():
    """
    Attack B. Certify a clean run, then keep working and leave the rest
    unbound. A coverage check that examines only the entries preceding the
    binding reports CONTIGUOUS, which defeats the anti-cherry-picking property
    by the obvious move.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   runs_after_binding=2)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.coverage is Coverage.SUBSET
    assert any(f.code == "runs_after_certification" for f in r.findings)


def test_binding_naming_absent_entries_is_detected():
    """Attack E. Truncating the tail leaves chain_intact true on its own."""
    chain = _build(AttestationMode.INDEPENDENT)
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
    chain = _build(AttestationMode.INDEPENDENT)
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
    EvidenceForm fails closed. Anything other than an explicit commitment-only
    declaration counts as retainable, so a missing or deleted Evidence
    primitive fires KC2 rather than clearing it. A test for `== "full"` would
    let the artifact recording less about its inputs grade better on the
    input-provenance condition.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
        AttestationMode.SELF_ATTESTED).to_body(), t)
    t += 1_000_000_000
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "clean", _primitives(root), ev, AttestationMode.SELF_ATTESTED).to_body(), t)

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
    chain = _build(AttestationMode.SELF_ATTESTED)
    doc = export_artifact(chain)
    doc["entries"][-1]["seq"] = 999
    r = verify(doc)
    assert not r.trustworthy


def test_binding_seq_out_of_range_is_a_named_finding_not_a_generic_crash_catch():
    """
    Before this check, an out-of-range binding.seq fell through to
    entries[binding.seq - 1]. A large value raised IndexError, caught by
    verify()'s outer try/except and reported only as the generic
    "malformed_artifact", losing the specific cause. A seq of exactly 0 was
    worse: Python's negative indexing turned it into entries[-1] silently,
    with no exception and no finding at all, working correctly here only
    because the binding happens to be the chain's last entry -- an accident
    of this fixture's shape, not a property the code established.

    All three should now name the actual problem.
    """
    for seq in (999, 0, -5):
        chain = _build(AttestationMode.SELF_ATTESTED)
        doc = export_artifact(chain)
        doc["entries"][-1]["seq"] = seq
        r = verify(doc)
        codes = [f.code for f in r.findings]
        assert "binding_seq_out_of_range" in codes, (seq, codes)
        assert "malformed_artifact" not in codes, (seq, codes)


def test_timestamp_regression_is_reported():
    """Clock values are signed and were never read."""
    chain = SealChain("assignment-1", opened_ns=T0)
    root = merkle_root(_rows())
    ev = chain.append(EntryKind.EVIDENCE_COMMITMENT, EvidenceCommitment(
        "ev-1", root, 40, "MLS-export", "2026-03-14").to_body(),
        9_000_000_000).block_hash
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-1", _primitives(root), ev, AttestationMode.SELF_ATTESTED).to_body(), 1_000)
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.completeness is Completeness.UNCHECKED
    assert any(f.code == "no_checkpoint" for f in r.findings)


def test_a_checkpoint_confirms_a_whole_artifact():
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    cp = _custodian_checkpoint(chain, key=chain._sk)
    r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
    assert r.completeness is Completeness.UNUSABLE
    assert any(f.code == "checkpoint_self_issued" for f in r.findings)


def test_a_checkpoint_for_another_chain_does_not_vouch_for_this_one():
    """Defeats answering a checkpoint with a different chain of the right length."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    cp = _custodian_checkpoint(chain, head="0" * 64)
    r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
    assert r.completeness is Completeness.MISMATCHED


def test_an_unsigned_or_tampered_checkpoint_is_refused():
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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


def test_malformed_proof_entries_fail_rather_than_crash():
    """
    `proof` is submitted by the party being checked, in both functions, so a
    non-hex or otherwise garbage sibling is exactly the input an examiner
    should expect from a hostile or corrupted custodian. Both functions must
    resolve that to False rather than let `bytes.fromhex` raise past them,
    the same guarantee `head_signature_valid` already gives a hostile
    signature.
    """
    leaves = [leaf_hash({"run": i}) for i in range(8)]
    r = log_root(leaves)
    garbage = ["not-hex-zz", "also-garbage", "more-garbage"]

    assert verify_inclusion(0, 8, leaves[0], r, garbage) is False
    assert verify_consistency(3, log_root(leaves[:3]), 8, r, garbage) is False

    key = ec.generate_private_key(ec.SECP256R1())
    log = TransparencyLog("x")
    for i in range(5):
        log.append({"i": i})
    old = sign_head(log.head(0), key)
    for i in range(5, 12):
        log.append({"i": i})
    new = sign_head(log.head(1), key)
    ok, reason = heads_consistent(old, new, garbage)
    assert ok is False and reason


def test_verify_inclusion_rejects_an_out_of_range_index():
    """
    `verify_inclusion` opens with a bounds check before touching any
    hashing -- an index outside `[0, size)`. The exhaustive test above
    only ever calls it with real, in-range indices, and the
    malformed-proof test above only ever corrupts a sibling, never the
    index, so this guard had no test of its own.

    `verify_consistency` has the analogous guard, `old_size > new_size`,
    one line earlier in the same function. It is not tested here: an
    exhaustive search across every (old_size, new_size, proof) combination
    the real proof-producing functions can generate found none where
    disabling that specific line changes the result, because the
    arithmetic that follows already fails on its own for every
    old_size > new_size input tried. Adding a test that looks like a
    negative control but does not actually falsify anything would be the
    kind of unearned claim this sweep exists to avoid.
    """
    leaves = [leaf_hash({"run": i}) for i in range(8)]
    r = log_root(leaves)
    real_proof = inclusion_proof(leaves, 3)

    assert verify_inclusion(99, 8, leaves[3], r, real_proof) is False
    assert verify_inclusion(-1, 8, leaves[3], r, real_proof) is False


def test_inclusion_proof_and_consistency_proof_raise_on_an_out_of_range_request():
    """
    Unlike their `verify_*` counterparts, the two proof-*producing*
    functions raise rather than fail closed on an out-of-range request --
    `inclusion_proof` documents `IndexError`, `consistency_proof` documents
    `ValueError` -- because there is no proof to hand back for a leaf or a
    size the tree does not have; a caller asking for one has a bug, not a
    hostile input to be tolerated. Nothing exercised either contract.

    The negative control on `consistency_proof`'s guard found something
    worth recording: removing it does not degrade to some other clean
    error. `_subproof` recurses on `m` never converging to `n` for an
    out-of-range `old_size`, so the actual failure without the guard is
    an uncaught `RecursionError` blowing the stack, a worse failure than
    the documented contract this test locks in.
    """
    leaves = [leaf_hash({"run": i}) for i in range(5)]
    with pytest.raises(IndexError):
        inclusion_proof(leaves, 99)
    with pytest.raises(ValueError):
        consistency_proof(leaves, 99)


def test_heads_consistent_refuses_heads_naming_different_logs():
    """
    `test_a_head_from_a_different_key_or_log_is_refused` names both
    reasons in its title but only ever constructs two heads signed by
    different keys for the *same* `log_id` ("semafide" both times) --
    confirmed by reading it, not assumed from the name. The log_id
    mismatch itself, checked one line earlier in `heads_consistent`, had
    no test of its own.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    log_a = TransparencyLog("log-a")
    for i in range(3):
        log_a.append({"i": i})
    head_a = sign_head(log_a.head(0), key)

    log_b = TransparencyLog("log-b")
    for i in range(4):
        log_b.append({"i": i})
    head_b = sign_head(log_b.head(1), key)

    ok, reason = heads_consistent(head_a, head_b, [])
    assert not ok and "different logs" in reason


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


def test_append_serializes_the_write_and_its_index_read(monkeypatch):
    """
    `append` writes the leaf and reads back the list length to compute its own
    index as two separate steps. Each step alone is safe under the GIL; the
    pair is not, because a second append can land between them and leave the
    first caller holding an index that actually belongs to the second. This
    is corruption rather than a missed optimisation: `inclusion_proof(index)`
    would then prove the wrong leaf's membership.

    Ordinary threaded hammering essentially never catches this, because the
    unsafe window between the two steps is nanoseconds wide and CPython's GIL
    switches threads too rarely to land in it by luck; a stress test over
    thousands of concurrent appends found zero corrupted indices even with no
    lock at all. Widening the window deliberately, the same way a slow
    witness response was used to force the earlier `close_assignment` race
    (`context/RECORD.md`, 2026-09-05), is what actually exercises it: slow
    `leaf_hash` down and measure whether two overlapping calls to `append` ran
    serialized or in parallel. Serialized wall-clock time is what a correct
    lock produces; parallel time is what an unlocked, or incorrectly scoped,
    critical section produces, and is also the shape a wrong-index race takes.

    No caller in this repository appends to one `TransparencyLog` from more
    than one thread today, matching `Witness.cosign`'s own note that nothing
    here calls it concurrently yet either. The lock exists for the same
    reason that one does: the day something does, a claimed index must
    actually be that leaf's position.
    """
    import threading as _threading
    import time as _time

    from seal import log as _log_module

    log = TransparencyLog("serialize")
    real_leaf_hash = _log_module.leaf_hash
    delay = 0.05

    def slow_leaf_hash(payload):
        _time.sleep(delay)
        return real_leaf_hash(payload)

    monkeypatch.setattr(_log_module, "leaf_hash", slow_leaf_hash)

    results = {}

    def worker(name):
        results[name] = log.append(name)

    threads = [_threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
    t0 = _time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = _time.perf_counter() - t0

    assert elapsed >= delay * 1.8, (
        f"two appends took {elapsed:.3f}s for a {delay}s hash each; they ran "
        "concurrently rather than serialized by the lock")
    assert {results["a"], results["b"]} == {0, 1}
    assert log._leaves[results["a"]] == leaf_hash("a")
    assert log._leaves[results["b"]] == leaf_hash("b")


def test_head_stalled_mid_computation_does_not_corrupt_against_a_concurrent_append(monkeypatch):
    """
    `root`, `inclusion_proof`, and `consistency_proof` are recursive
    functions that slice their input across many separate steps -- reading
    the length, then `leaves[:k]`, then `leaves[k:]`, then the same again
    inside each recursive call. None of that was one atomic operation.
    `append` already serializes the write and its own index read for
    exactly this reason (the test above), but the read methods took no
    lock at all, so a concurrent `append` landing mid-recursion handed the
    computation a tree that grew partway through being measured:
    `leaves[:k]` reflecting the size read before the append, `leaves[k:]`
    reflecting the list after it, the two halves no longer summing to the
    `n` the split point `k` was chosen for.

    Widened deliberately, the same way the append-index race above is
    widened, since ordinary threaded hammering does not reliably land in a
    window this narrow: stall the module-level `root` function on its
    first call (the outermost `head()` invocation) with a
    `threading.Event`, append two more entries from the main thread while
    it is stalled, then release it and check whether the returned
    `TreeHead`'s `(size, root)` pair is internally consistent -- whether
    the root actually matches what a real tree of `size` leaves hashes to.

    Before the fix, this reliably returned a head whose root did not
    match its own claimed size: an internally inconsistent, signable
    statement, indistinguishable from a corrupted history to anyone who
    later tried to check it. The fix takes one locked snapshot of the
    leaves before any recursive computation starts, so the computation
    always runs over one real, whole state of the tree.
    """
    import threading as _threading

    from seal import log as _log_module

    log = TransparencyLog("stalled-head")
    for i in range(7):
        log.append({"i": i})

    real_root = _log_module.root
    stalled = _threading.Event()
    release = _threading.Event()
    call_count = [0]

    def stalling_root(leaves):
        call_count[0] += 1
        if call_count[0] == 1:
            stalled.set()
            release.wait(timeout=5)
        return real_root(leaves)

    monkeypatch.setattr(_log_module, "root", stalling_root)

    result = {}

    def read_head():
        result["head"] = log.head(observed_ns=1)

    t = _threading.Thread(target=read_head)
    t.start()
    assert stalled.wait(timeout=5), "head() never reached the stalled root computation"

    log.append({"i": 7})
    log.append({"i": 8})

    release.set()
    t.join(timeout=5)
    monkeypatch.setattr(_log_module, "root", real_root)

    head = result["head"]
    independent_root = log_root(log._leaves[:head.size])
    assert head.root == independent_root, (
        f"head() returned size={head.size} with a root that does not match "
        "any real tree of that size -- an internally inconsistent, "
        "signable (size, root) pair produced by a concurrent append landing "
        "mid-computation")


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


def test_a_witness_refuses_a_head_that_does_not_verify_against_its_own_key():
    """
    `cosign`'s very first guard, before it ever touches `_seen`, and nothing
    exercised it: every existing witness test hands it a genuinely signed
    head, whether honest, conflicting, shrunk, or from a different key.
    A witness asked to cosign a head with a corrupted signature must refuse
    outright rather than recording it as "seen" -- a witness that quietly
    remembered a head it never actually verified would be worth exactly the
    self-declared attestation this whole module exists to replace.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    log = TransparencyLog("semafide")
    for i in range(3):
        log.append({"run": i})
    head = sign_head(log.head(T0), key)
    good_sig = head["signature"]
    head["signature"] = ("0" if good_sig[0] != "0" else "1") + good_sig[1:]

    w = Witness("state-board", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(WitnessRefusal, match="does not verify"):
        w.cosign(head)


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


def test_cosignature_count_skips_a_malformed_entry_rather_than_crashing():
    """
    `count_witnesses` is called directly against a bundle an examiner
    received from the party under examination, not only through the
    fail-closed `verify` wrapper, so a hostile or corrupted entry in the list
    must be skipped rather than raising. `resolve_bounds` already gives
    `time_anchors` this treatment; this is the same guarantee here.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    _, head = _log_of(3, key)
    honest = Witness("board", ec.generate_private_key(ec.SECP256R1()))
    cosigs = [honest.cosign(head), None, "garbage", 42, {"no_key_field": True}]

    assert count_witnesses(head, cosigs) == 1


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


def test_rebut_refuses_a_proof_whose_heads_do_not_verify_even_with_no_consistency_offered():
    """
    `equivocation` returns `None` both when a consistency proof reconciles
    two heads and when it cannot construct evidence at all -- an invalid
    signature is one of the reasons it refuses, since an unsigned document
    proves nothing about anyone. `rebut` used to read that `None` as an
    unconditional "yes," which meant a party unable to produce any real
    consistency proof could rebut an UNRECONCILED finding for free by
    handing back the accused heads with one signature byte flipped: the
    corrupted signature alone made `equivocation` return `None` regardless
    of what `consistency` contained, here literally empty. Confirmed this
    was reachable through the real `equivocation()` -> `rebut()` path
    before fixing it, not only against a hand-built proof dict.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    log, early = _log_of(3, key)
    for i in range(3, 9):
        log.append({"run": i})
    later = sign_head(log.head(T0 + 1), key)

    proof = equivocation(early, later)
    assert proof and proof["finality"] == UNRECONCILED

    tampered = json.loads(json.dumps(proof))
    good_sig = tampered["head_b"]["signature"]
    tampered["head_b"]["signature"] = ("0" if good_sig[0] != "0" else "1") + good_sig[1:]

    assert not rebut(tampered, [])
    assert not rebut(tampered, log.consistency_proof(3))


def test_rebut_refuses_a_proof_pairing_heads_from_different_logs_or_keys():
    """
    `rebut` re-checks `log_id` and signing-key agreement itself rather than
    trusting `equivocation`'s own `None` return for the same reason it
    re-checks signatures (see the docstring on `rebut` and the signature
    version of this test above): `equivocation(lo, hi, consistency)` returns
    `None` for a log_id or key mismatch exactly as readily as it does for a
    genuinely reconciled pair, so a `rebut` that skipped straight to that
    call would accept a hand-built "proof" pairing two heads that were never
    from the same log as a successful rebuttal. Neither existing mismatch
    test (`test_an_unsigned_or_mismatched_pair_accuses_nobody`) calls
    `rebut` at all; both call `equivocation`, which never lets a mismatched
    pair become a `proof` object in the first place, so nothing before this
    test ever handed `rebut` one built by hand instead.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    _, head_a = _log_of(3, key, log_id="log-a")
    _, head_b = _log_of(4, key, log_id="log-b")
    fake_proof = {"kind": "equivocation", "finality": UNRECONCILED,
                 "log_id": "log-a", "reason": "manufactured for the test",
                 "head_a": head_a, "head_b": head_b}
    assert not rebut(fake_proof, [])

    other_key = ec.generate_private_key(ec.SECP256R1())
    _, head_c = _log_of(3, key)
    _, head_d = _log_of(4, other_key)
    fake_proof2 = {"kind": "equivocation", "finality": UNRECONCILED,
                  "log_id": "semafide", "reason": "manufactured for the test",
                  "head_a": head_c, "head_b": head_d}
    assert not rebut(fake_proof2, [])


def test_equivocation_holds_on_a_proof_missing_a_head_fails_closed():
    """
    `equivocation_holds` re-derives the verdict from `proof["head_a"]` and
    `proof["head_b"]`, which a hostile or truncated proof document need not
    carry. Nothing before this test handed it one missing either key, so
    the `except Exception` around the re-derivation had no test proving it
    fails closed rather than propagating a raw `KeyError`.
    """
    assert not equivocation_holds({"kind": "equivocation", "finality": CONTRADICTION})


def test_rebut_on_a_proof_missing_a_head_fails_closed():
    """
    The last of `rebut`'s own gaps: `lo, hi = proof["head_a"], proof["head_b"]`
    runs before any of the checks that follow it, on a `proof` dict a hostile
    or truncated caller need not have built completely. Nothing before this
    test handed `rebut` one missing either key, so its own `except Exception`
    had no test proving it fails closed rather than propagating a raw
    `KeyError`, the last thing separating this function from
    `equivocation_holds`'s already-tested version of the same guard.
    """
    assert not rebut({"finality": UNRECONCILED}, [])


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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    siblings = [_build(AttestationMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(5)]
    handed_over = export_artifact(siblings[0])

    alone = verify(handed_over, rederive=_ok,
                   checkpoint=_custodian_checkpoint(siblings[0]))
    assert alone.completeness is Completeness.CONSISTENT
    assert alone.disclosure is Disclosure.UNCHECKED
    assert any(f.code == "no_assignment_checkpoint" for f in alone.findings)


def test_the_custodian_statement_makes_the_withheld_chains_visible():
    siblings = [_build(AttestationMode.REDERIVABLE, rederivable=True,
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
    siblings = [_build(AttestationMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(4)]
    acp = _assignment_checkpoint(siblings)
    docs = [export_artifact(c) for c in siblings]
    assert assess_disclosure(docs, acp).state is Disclosure.WHOLE
    assert assess_disclosure(list(reversed(docs)), acp).state is Disclosure.WHOLE


def test_a_chain_that_grew_after_its_checkpoint_is_still_whole_disclosure():
    """
    `assignment.Issuer.issue`'s own docstring says sizes are allowed to
    grow between two statements, since a chain open when the first was
    made is longer by the second. The ordinary shape this covers: a
    checkpoint gets issued mid-assignment, more runs happen, and the full,
    grown chain is what actually reaches an examiner at final disclosure.

    `assess` used to compare the checkpoint's recorded head against the
    LAST entry disclosed rather than the entry at the recorded position,
    so any chain that had simply grown past its own checkpoint -- with
    the checkpointed prefix completely unchanged -- compared a newer head
    against an older one, always disagreed, and degraded a strictly more
    complete disclosure to PARTIAL. That manufactures a false accusation
    (the examined party is hiding something) out of ordinary, honest
    continued work, which is the wrong direction for a completeness check
    to fail in.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    acp = _assignment_checkpoint([chain])
    checkpointed_head_index = len(chain.entries) - 1

    # More legitimate work after the checkpoint was issued, before the
    # chain is ever handed to an examiner.
    root = merkle_root(_rows())
    ev = chain.append(
        EntryKind.EVIDENCE_COMMITMENT,
        EvidenceCommitment(commitment_id="ev-grown", row_root=root, row_count=40,
                           source="MLS-export", as_of="2026-03-14T09:00:00Z",
                           query_descriptor={"radius_mi": "1.0", "months": 12}
                           ).to_body(),
        T0 + 10_000_000_000).block_hash
    chain.append(
        EntryKind.RUN_SEAL,
        RunSeal(run_id="run-grown", primitives=_primitives(root),
               evidence_commitment_hash=ev,
               witness_mode=AttestationMode.SELF_ATTESTED).to_body(),
        T0 + 11_000_000_000)

    report = assess_disclosure([export_artifact(chain)], acp)
    assert report.state is Disclosure.WHOLE, report.findings
    assert report.findings == ()

    # A genuine divergence at the checkpointed position must still be
    # caught, even with the same later growth appended after it.
    doc = export_artifact(chain)
    doc["entries"][checkpointed_head_index]["block_hash"] = "f" * 64
    diverged = assess_disclosure([doc], acp)
    assert diverged.state is not Disclosure.WHOLE
    assert any("diverged from the checkpointed state" in f
              for f in diverged.findings)


def test_a_chain_not_in_the_assignment_is_reported_rather_than_counted():
    """
    Answering a five-chain statement with a sixth chain nobody recorded is the
    obvious inversion of the attack.
    """
    siblings = [_build(AttestationMode.REDERIVABLE, rederivable=True,
                       chain_label=f"chain-{i}") for i in range(3)]
    outsider = _build(AttestationMode.REDERIVABLE, rederivable=True,
                      chain_label="unrecorded")
    acp = _assignment_checkpoint(siblings)

    r = verify(export_artifact(outsider), rederive=_ok,
               assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.FOREIGN
    assert any(f.code == "chain_not_in_assignment" for f in r.findings)


def test_a_chain_under_another_assignment_does_not_answer_this_one():
    other = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   assignment_id="assignment-2")
    acp = _assignment_checkpoint([other], assignment_id="assignment-1")
    r = verify(export_artifact(other), rederive=_ok, assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.FOREIGN


def test_an_assignment_checkpoint_signed_by_the_sealer_is_worthless():
    """Same rule as the per-chain checkpoint. Counting your own chains is not
    a count."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    acp = _assignment_checkpoint([chain], key=chain._sk)
    r = verify(export_artifact(chain), rederive=_ok, assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.UNUSABLE
    assert any(f.code == "assignment_checkpoint_unusable" for f in r.findings)


def test_a_tampered_assignment_checkpoint_is_refused():
    siblings = [_build(AttestationMode.REDERIVABLE, rederivable=True,
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    acp = _assignment_checkpoint([chain])
    doc = export_artifact(chain)
    doc["entries"] = doc["entries"][1:]

    r = verify(doc, rederive=_ok, assignment_checkpoint=acp)
    assert r.disclosure is Disclosure.UNANCHORED
    assert r.assignment_id is None
    assert not r.chain_intact
    assert any(f.code == "chain_names_no_assignment" for f in r.findings)


def test_a_second_anchor_cannot_re_declare_the_assignment():
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, bind=False)
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
    siblings = [_build(AttestationMode.REDERIVABLE, rederivable=True,
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    token = _stamp(chain, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UPPER_ONLY
    assert r.anchor_interval_ns is None      # unbounded below, not zero
    assert any(f.code == "backdating_unconstrained" for f in r.findings)


def test_a_committed_beacon_and_a_timestamp_pin_the_instant_to_an_interval():
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
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


def test_a_resolved_beacon_with_no_time_anchor_is_bounded_only_below():
    """
    `LOWER_ONLY` had no test anywhere: every existing beacon test either
    supplies no resolver (UNANCHORED, the resolver-missing branch) or
    supplies both a resolver and a time anchor (BOUNDED). This is the
    remaining combination -- a beacon that genuinely resolves, with nothing
    from an authority at all -- which is the mirror image of
    `test_a_timestamp_alone_leaves_backdating_untouched`'s `UPPER_ONLY` on
    the other side of the interval.
    """
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    r = verify(export_artifact(chain), rederive=_ok, beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.LOWER_ONLY
    assert r.anchor_interval_ns is None
    assert any(f.code == "no_upper_time_bound" for f in r.findings)


def test_a_beacon_resolver_that_raises_is_treated_as_unresolved():
    """
    `beacon_resolver` is a callback the caller supplies, reaching out to
    whatever the examiner uses to check a published value -- a real network
    call in practice, which can fail in ways beyond returning `None`. The
    `except Exception` around that call had no test; without it, a resolver
    raising would crash `verify()` outright rather than degrading to the
    same "could not be resolved" position a resolver returning `None`
    already reaches correctly.
    """
    def exploding_resolver(source, pulse):
        raise RuntimeError("network error, not a documented None return")

    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    r = verify(export_artifact(chain), rederive=_ok,
              beacon_resolver=exploding_resolver)
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("could not be resolved" in f.detail for f in r.findings)


def test_a_time_anchor_with_an_unreadable_digest_does_not_crash_the_verifier():
    """
    `digest` is typed `str` on `TimeAnchor` and nothing enforces that at
    runtime before signing -- an authority's own signing code could carry
    the same class of bug this package has fixed elsewhere for a
    `witness_attestation.public_key` or `.signature` naming the wrong JSON
    type. Here the value survives signing (canonicalization accepts a list)
    and only breaks later, at `block_hash_to_seq.get(doc["digest"])`, which
    raises on an unhashable key. Confirmed this reaches a genuinely
    signature-valid anchor first, not one rejected earlier for a bad
    signature, which is what a naive version of this test would have
    produced instead.
    """
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    token = issue_anchor(TimeAnchor("tsa", ["not", "a", "string"],
                                    T0 + 60_000_000_000), tsa)
    from seal.anchor import signature_valid
    assert signature_valid(token)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
              trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UNANCHORED
    assert any(f.detail == "A time anchor could not be read." for f in r.findings)


def test_a_beacon_nobody_resolves_is_the_sealer_talking_to_itself():
    """Same shape as `witness_mode: independent`. The value has to be looked up
    somewhere other than the document it constrains."""
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    r = verify(export_artifact(chain), rederive=_ok)
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("resolver" in f.detail for f in r.findings)


def test_a_fabricated_beacon_value_does_not_resolve():
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   beacon=_beacon(value="00" * 32))
    r = verify(export_artifact(chain), rederive=_ok, beacon_resolver=_resolver)
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("not what that source published" in f.detail for f in r.findings)


def test_an_unrecognised_authority_is_not_counted():
    """An examiner who accepts any signature over a time has handed the sealer
    a key generator, which is the lesson `count_witnesses` already learned."""
    forger = ec.generate_private_key(ec.SECP256R1())
    real = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
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
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    other = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   chain_label="elsewhere")
    token = _stamp(other, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("not an entry in this chain" in f.detail for f in r.findings)


def test_a_tampered_token_does_not_verify():
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    token = _stamp(chain, tsa, T0 + 60_000_000_000)
    token["time_ns"] = T0 - 999_000_000_000       # move it earlier

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.UNANCHORED
    assert any("does not verify" in f.detail for f in r.findings)


def test_a_chain_that_keeps_growing_after_an_early_anchor_is_not_backdated():
    """
    An anchor over entry k bounds every entry AT OR BEFORE k, per this
    module's own docstring, not entries sealed afterward -- the chain is
    allowed to keep growing honestly past the moment an early entry (the
    evidence commitment, say) was externally timestamped for precedence.

    This used to compare the whole chain's LATEST timestamp against the
    single tightest anchor, regardless of which entry that anchor actually
    named. An anchor over the evidence commitment (entry 1) then flagged the
    run seal and workfile binding sealed afterward -- with entirely ordinary,
    later timestamps -- as `instant_outside_anchor`, manufacturing a false
    accusation of backdating against a chain that never claimed anything
    inconsistent. `_build`'s default shape is exactly this: evidence
    committed at T0, the run sealed a second later, the binding a second
    after that.
    """
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    # Anchors the evidence commitment (seq 1) shortly after it was sealed,
    # well before the run (T0 + 1s) and binding (T0 + 2s) that honestly
    # follow it.
    token = _stamp(chain, tsa, T0 + 500_000_000, entry=1)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is not Anchoring.INCONSISTENT
    assert not any(f.code == "instant_outside_anchor" for f in r.findings)


def test_an_entry_at_or_before_the_anchored_one_is_still_caught_if_it_lies():
    """
    Companion to the test above: the fix narrows the check's scope, it does
    not remove it. An entry at or before the anchored position that claims a
    timestamp later than the anchor is still exactly the KC1 attack this
    module exists to catch.
    """
    tsa = ec.generate_private_key(ec.SECP256R1())
    far_future = T0 + 999_000_000_000
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
                   base_ns=far_future)
    # Anchors the run seal (seq 2) at a time before the evidence commitment
    # (seq 1, base_ns) it is supposed to follow claims to have existed.
    token = _stamp(chain, tsa, T0 + 500_000_000, entry=2)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)])
    assert r.anchoring is Anchoring.INCONSISTENT
    assert any(f.code == "instant_outside_anchor" for f in r.findings)


def test_the_earliest_recognised_anchor_is_the_one_that_binds():
    """Several tokens are not several bounds. The tightest one is the claim."""
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True,
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

    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, beacon=_beacon())
    token = _stamp(chain, tsa, T0 + 60_000_000_000)

    r = verify(export_artifact(chain), rederive=_ok, time_anchors=[token],
               trusted_authorities=[_pem(tsa)], beacon_resolver=stale_resolver)
    assert r.anchoring is Anchoring.BOUNDED
    assert r.anchor_interval_ns > 365 * 24 * 3600 * 1_000_000_000


def test_a_beacon_published_after_the_authority_saw_the_chain_is_impossible():
    tsa = ec.generate_private_key(ec.SECP256R1())
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True, beacon=_beacon())
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
    a = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="a")
    b = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="b")
    assert len(a.entries) == len(b.entries) and a.head != b.head

    for chain in (a, b):
        cp = _custodian_checkpoint(chain, key=custodian)
        r = verify(export_artifact(chain), rederive=_ok, checkpoint=cp)
        assert r.completeness is Completeness.CONSISTENT


def test_a_stateful_issuer_refuses_the_second_chain():
    """The fix. The issuer remembers what it signed and will not sign a
    different chain at that size."""
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    a = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="a")
    b = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="b")

    issuer.issue(Checkpoint("assignment-1", len(a.entries), a.head, T0, "custodian"),
                 a.entries)
    with pytest.raises(CheckpointRefusal, match="equivocation"):
        issuer.issue(
            Checkpoint("assignment-1", len(b.entries), b.head, T0 + 1, "custodian"),
            b.entries)


def test_an_issuer_signs_a_genuine_extension_and_refuses_a_shrink():
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    first = len(chain.entries)
    issuer.issue(Checkpoint("assignment-1", first, chain.head, T0, "custodian"),
                 chain.entries)

    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-2", _primitives(merkle_root(_rows())), None,
        AttestationMode.SELF_ATTESTED).to_body(), T0 + 9_000_000_000)
    signed = issuer.issue(
        Checkpoint("assignment-1", len(chain.entries), chain.head,
                   T0 + 2, "custodian"), chain.entries)
    assert cp_signature_valid(signed)

    with pytest.raises(CheckpointRefusal, match="shrank"):
        issuer.issue(Checkpoint("assignment-1", first, chain.head,
                                T0 + 3, "custodian"), chain.entries)


def test_an_issuer_refuses_entries_claiming_a_head_they_do_not_have():
    """
    `_extends` is the function standing between `Issuer.issue` and signing an
    equivocating checkpoint, and none of its hostile-input branches had a
    test: every existing test here either hands it a genuine extension
    (which walks every check and returns True) or hands it no entries at
    all. Nothing exercised the entries list itself being wrong.

    This is the most direct version of that: an `entries` list whose actual
    last block hash does not match the `chain_head` the new checkpoint
    claims. A real custodian could reach this by accident (a chain fetched
    from the wrong place, a stale cache) as easily as by an attacker's
    construction; either way the issuer must not sign over it.
    """
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    issuer.issue(Checkpoint("assignment-1", len(chain.entries), chain.head,
                           T0, "custodian"), chain.entries)

    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-2", _primitives(merkle_root(_rows())), None,
        AttestationMode.SELF_ATTESTED).to_body(), T0 + 9_000_000_000)

    wrong_head = "sha256:" + "ee" * 32
    assert wrong_head != chain.head
    with pytest.raises(CheckpointRefusal, match="not an extension"):
        issuer.issue(
            Checkpoint("assignment-1", len(chain.entries), wrong_head,
                      T0 + 1, "custodian"),
            chain.entries)


def test_an_issuer_refuses_entries_whose_internal_linkage_is_broken():
    """
    A subtler hostile `entries` list: the first and last checks `_extends`
    makes both pass -- the count matches, the final block hash matches the
    claimed `chain_head`, and the entry at the previously-checkpointed
    boundary still matches what was signed before -- but an entry strictly
    inside the list carries a `prev_hash` that does not chain to its
    predecessor. Only the walk in `_extends`'s own loop catches that;
    nothing before this test reached it, since a genuine append-built chain
    is never broken this way and every existing test uses one.
    """
    import dataclasses

    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    issuer.issue(Checkpoint("assignment-1", len(chain.entries), chain.head,
                           T0, "custodian"), chain.entries)

    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-2", _primitives(merkle_root(_rows())), None,
        AttestationMode.SELF_ATTESTED).to_body(), T0 + 9_000_000_000)
    chain.append(EntryKind.RUN_SEAL, RunSeal(
        "run-3", _primitives(merkle_root(_rows())), None,
        AttestationMode.SELF_ATTESTED).to_body(), T0 + 10_000_000_000)

    tampered = list(chain.entries)
    broken_index = len(tampered) - 2  # strictly inside, not the final entry
    tampered[broken_index] = dataclasses.replace(
        tampered[broken_index], prev_hash="sha256:" + "cc" * 32)

    with pytest.raises(CheckpointRefusal, match="not an extension"):
        issuer.issue(
            Checkpoint("assignment-1", len(tampered), chain.head,
                      T0 + 1, "custodian"),
            tampered)


def test_a_checkpoint_issuer_refuses_a_conflicting_race_for_a_fresh_assignment():
    """
    The lock in `Issuer.issue`, put under real load. Two threads race to be
    first to issue conflicting checkpoints, same size and different head, for
    an assignment this issuer has never signed for before. Without the lock,
    both could read no prior state, both skip every check, and both sign, an
    equivocation reintroduced through a race rather than through a missing
    check. Whichever request the issuer serializes first wins; the other must
    be refused, and both must never succeed.
    """
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    a = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="race-a")
    b = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="race-b")
    assert len(a.entries) == len(b.entries) and a.head != b.head

    results: list[str] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(2)

    def attempt(chain, ts):
        barrier.wait()
        try:
            issuer.issue(
                Checkpoint("assignment-race", len(chain.entries), chain.head,
                          ts, "custodian"),
                chain.entries)
            outcome = "ok"
        except CheckpointRefusal:
            outcome = "refused"
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt, args=(a, T0)),
              threading.Thread(target=attempt, args=(b, T0 + 1))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == ["ok", "refused"]


def test_growth_without_the_entries_cannot_be_established():
    """An issuer given nothing to check against must refuse, because assuming
    an extension is the failure being corrected."""
    issuer = CheckpointIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    a = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="a")
    longer = _build(AttestationMode.REDERIVABLE, rederivable=True,
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
    a = _build(AttestationMode.REDERIVABLE, rederivable=True)
    b = _build(AttestationMode.REDERIVABLE, rederivable=True,
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
    chains = [_build(AttestationMode.REDERIVABLE, rederivable=True,
                     chain_label=f"chain-{i}") for i in range(5)]
    refs = tuple(ChainRef(c.chain_id, c.head, len(c.entries)) for c in chains)

    issuer.issue(AssignmentCheckpoint("assignment-1", refs, T0, "custodian"))
    with pytest.raises(AssignmentRefusal, match="absent from"):
        issuer.issue(AssignmentCheckpoint("assignment-1", refs[:3],
                                          T0 + 1, "custodian"))

    # Gaining a chain is ordinary and is signed.
    extra = _build(AttestationMode.REDERIVABLE, rederivable=True, chain_label="late")
    grown = refs + (ChainRef(extra.chain_id, extra.head, len(extra.entries)),)
    assert issuer.issue(
        AssignmentCheckpoint("assignment-1", grown, T0 + 2, "custodian"))


def test_an_assignment_issuer_refuses_a_dropped_chain_offered_concurrently():
    """
    The same race, one level out. Two threads race to be first to issue for
    an assignment this issuer has never signed for, with overlapping but
    unequal chain sets, {0,1,2} and {2,3,4}: whichever is recorded first, the
    other is missing a chain the first one named and must be refused.
    Without the lock, both could read no prior statement, both skip the
    dropped-chain check, and both sign, hiding exactly the sibling-chain
    omission this class exists to make visible.
    """
    issuer = AssignmentIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chains = [_build(AttestationMode.REDERIVABLE, rederivable=True,
                     chain_label=f"race-{i}") for i in range(5)]
    refs = [ChainRef(c.chain_id, c.head, len(c.entries)) for c in chains]
    left = tuple(refs[0:3])
    right = tuple(refs[2:5])

    results: list[str] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(2)

    def attempt(refs, ts):
        barrier.wait()
        try:
            issuer.issue(AssignmentCheckpoint("assignment-race", refs, ts,
                                              "custodian"))
            outcome = "ok"
        except AssignmentRefusal:
            outcome = "refused"
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt, args=(left, T0)),
              threading.Thread(target=attempt, args=(right, T0 + 1))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == ["ok", "refused"]


def test_an_assignment_issuer_refuses_a_chain_that_lost_entries():
    issuer = AssignmentIssuer("custodian", ec.generate_private_key(ec.SECP256R1()))
    chain = _build(AttestationMode.REDERIVABLE, rederivable=True)
    full = (ChainRef(chain.chain_id, chain.head, len(chain.entries)),)
    issuer.issue(AssignmentCheckpoint("assignment-1", full, T0, "custodian"))

    shortened = (ChainRef(chain.chain_id, chain.head, len(chain.entries) - 1),)
    with pytest.raises(AssignmentRefusal, match="shrank"):
        issuer.issue(AssignmentCheckpoint("assignment-1", shortened,
                                          T0 + 1, "custodian"))
