"""
Tests for `seal.capture.seal_execution`.

The point of this wrapper is that it produces something the *real* verifier
accepts, not a fixture built to look like one. Every test below calls
`seal_execution`, then feeds the manifest it wrote through `seal.verifier.verify`
directly rather than asserting against the capture module's own report, so a
bug that made the wrapper lie about its own output would still be caught.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from seal import BindingLevel, Coverage, canonical_bytes, verify
from seal.capture.assignment import (
    AssignmentError,
    close_assignment,
    reset_assignments,
)


@pytest.fixture(autouse=True)
def _isolated_assignments():
    """
    A chain now lives for its assignment, so tests sharing an assignment id
    share a chain and every assertion after the first reads a chain some other
    test built. Reset before and after: before so a test starts clean, after so
    a failure does not leak into the next one.
    """
    reset_assignments()
    yield
    reset_assignments()
from seal.capture import seal_execution


def _valuation(mls_comps: dict, property_params: dict) -> dict:
    return {
        "valuation": mls_comps["median_sqft"] * property_params["sqft"],
        "confidence": 0.93,
    }


def test_wrapped_function_still_returns_its_own_output(tmp_path):
    sealed = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        output_dir=str(tmp_path),
    )(_valuation)

    result = sealed({"median_sqft": 250}, {"sqft": 1800})

    assert result == {"valuation": 450_000, "confidence": 0.93}


def test_manifest_written_and_independently_verifies_precedence_only(tmp_path):
    sealed = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        output_dir=str(tmp_path),
    )(_valuation)

    sealed({"median_sqft": 250}, {"sqft": 1800})
    cap = sealed.last_capture

    assert cap.manifest_path is not None
    on_disk = json.loads(cap.manifest_path.read_text())
    assert on_disk == cap.manifest

    key = on_disk["entries"][0]["public_key"]
    report = verify(on_disk, trusted_keys=[key])

    assert report.trustworthy
    assert report.evidence.precedence
    assert not report.evidence.witness_attestation
    assert not report.evidence.recipe_available
    assert report.binding_level is BindingLevel.PRECEDENCE


def test_no_output_dir_skips_disk_write_but_still_seals(tmp_path):
    sealed = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        output_dir=None,
    )(_valuation)

    sealed({"median_sqft": 250}, {"sqft": 1800})
    cap = sealed.last_capture

    assert cap.manifest_path is None
    assert cap.manifest["entries"]


def test_inputs_are_committed_before_output_is_known():
    """The evidence commitment names the bound *inputs*, independent of what
    the function returns — this is what makes precedence checkable at all."""
    sealed = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        output_dir=None,
    )(_valuation)

    sealed({"median_sqft": 250}, {"sqft": 1800})
    evidence_entry = sealed.last_capture.manifest["entries"][1]

    assert evidence_entry["kind"] == "evidence_commitment"
    assert evidence_entry["body"]["row_count"] == 2  # mls_comps, property_params


def test_unreachable_witness_degrades_to_self_attested_without_raising(tmp_path):
    sealed = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        witness_url="http://127.0.0.1:1/unreachable",
        output_dir=str(tmp_path),
    )(_valuation)

    sealed({"median_sqft": 250}, {"sqft": 1800})
    cap = sealed.last_capture

    assert cap.witness_attempted
    assert not cap.witness_attestation_established
    run_body = cap.manifest["entries"][-1]["body"]
    assert run_body["witness_mode"] == "self_attested"
    assert run_body["witness_attestation"] is None


@pytest.fixture
def running_witness():
    """A witness daemon this repository does not actually have yet.

    Signs whatever payload it's handed with a real ECDSA key so the tests
    below exercise real cryptography, not a mocked verify() call. Standing
    this up for real, as an HTTP service the way `witness_url` implies, is
    separate work (see `seal.capture.witness_client` module docstring).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            payload = json.loads(self.rfile.read(length))
            signature = key.sign(
                canonical_bytes(payload), ec.ECDSA(hashes.SHA256())
            ).hex()
            body = json.dumps({
                "witness": "test-witness",
                "public_key": pub_pem,
                "signature": signature,
                "capture_ref": payload.get("capture_ref"),
                "statement": "observed_execution",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence default request logging
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/witness", pub_pem
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_witness_signature_accepted_only_when_key_is_trusted(tmp_path, running_witness):
    url, witness_pub_pem = running_witness

    trusting = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        witness_url=url, trusted_witness_keys=[witness_pub_pem],
        output_dir=str(tmp_path),
    )(_valuation)
    trusting({"median_sqft": 250}, {"sqft": 1800})
    trusted_cap = trusting.last_capture

    assert trusted_cap.witness_attestation_established
    assert trusted_cap.report.binding_level is BindingLevel.WITNESSED

    not_trusting = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        witness_url=url,  # same real signature, but key not declared trusted
        output_dir=str(tmp_path),
    )(_valuation)
    not_trusting({"median_sqft": 250}, {"sqft": 1800})
    untrusted_cap = not_trusting.last_capture

    assert not untrusted_cap.witness_attestation_established
    assert untrusted_cap.report.binding_level is BindingLevel.PRECEDENCE


def test_verify_rejects_a_manifest_if_key_list_is_forged(tmp_path, running_witness):
    """A witness's own claimed identity does not make it trusted — only a
    key the caller names out of band does. This is `seal.verifier`'s
    self-authentication refusal, exercised through the wrapper rather than
    asserted about it directly."""
    url, witness_pub_pem = running_witness

    sealed = seal_execution(
        assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2",
        witness_url=url,
        trusted_witness_keys=["-----BEGIN PUBLIC KEY-----\nnot-the-real-key\n-----END PUBLIC KEY-----"],
        output_dir=str(tmp_path),
    )(_valuation)
    sealed({"median_sqft": 250}, {"sqft": 1800})

    assert not sealed.last_capture.witness_attestation_established


# ---------------------------------------------------------------------------
# One chain per assignment.
#
# The defect these cover: a fresh chain per call produced one artifact per run,
# each verifying perfectly and none of them relating to the others. That is the
# sibling-chain hole manufactured by construction, and it made the count harder
# to establish than it had been.
# ---------------------------------------------------------------------------

def test_every_call_appends_to_one_chain_across_functions(tmp_path):
    """Two decorated functions in one assignment share one chain."""
    priced = seal_execution(
        assignment_id="ASG-2026-4400", model_id="AVM-v4.2",
        output_dir=str(tmp_path))(lambda sqft: {"valuation": sqft * 250})
    adjusted = seal_execution(
        assignment_id="ASG-2026-4400", model_id="regression-v2",
        output_dir=str(tmp_path))(lambda trend: {"pct_per_month": trend})

    for sqft in (1800, 1850, 1900):
        priced(sqft)
    adjusted(0.0042)

    manifest = adjusted.last_capture.manifest
    kinds = [e["kind"] for e in manifest["entries"]]
    assert kinds.count("run_seal") == 4
    assert kinds.count("assignment_anchor") == 1
    assert adjusted.last_capture.runs_in_assignment == 4
    # One manifest for the assignment, not one per call.
    assert len(list(tmp_path.iterdir())) == 1


def test_coverage_is_absent_until_certification(tmp_path):
    """
    The two moments. Runs are captured at execution; sign-off binds at
    certification. An assignment still in progress carries no binding, and
    ABSENT is the honest reading of that rather than a defect.
    """
    sealed = seal_execution(
        assignment_id="ASG-2026-4401", model_id="AVM-v4.2",
        output_dir=str(tmp_path))(lambda x: {"valuation": x})
    sealed(1)
    assert sealed.last_capture.report.coverage is Coverage.ABSENT

    _, report = close_assignment(
        "ASG-2026-4401", certification_ref="cert-1",
        effective_date="2026-03-14", output_dir=str(tmp_path))
    assert report.coverage is Coverage.CONTIGUOUS


def test_a_removed_run_is_detectable_after_certification(tmp_path):
    """
    The property the whole change exists for. Three runs sealed and one
    discarded before hand-over used to produce a flawless artifact. It now
    produces a broken chain, and renumbering to hide the gap does not help
    because prev-hash linkage is what breaks.
    """
    sealed = seal_execution(
        assignment_id="ASG-2026-4402", model_id="AVM-v4.2",
        output_dir=None)(lambda x: {"valuation": x * 250})
    for sqft in (1800, 1850, 1900):
        sealed(sqft)
    manifest, report = close_assignment(
        "ASG-2026-4402", certification_ref="cert-1",
        effective_date="2026-03-14", output_dir=None)
    key = manifest["entries"][0]["public_key"]
    assert report.coverage is Coverage.CONTIGUOUS

    run_indexes = [i for i, e in enumerate(manifest["entries"])
                   if e["kind"] == "run_seal"]
    cut = json.loads(json.dumps(manifest))
    del cut["entries"][run_indexes[1]]
    assert not verify(cut, trusted_keys=[key]).chain_intact

    renumbered = json.loads(json.dumps(cut))
    for n, entry in enumerate(renumbered["entries"]):
        entry["seq"] = n
    assert not verify(renumbered, trusted_keys=[key]).trustworthy


def test_a_raised_call_seals_the_attempt_and_re_raises(tmp_path):
    """
    A call that raised used to leave no trace anywhere in the chain: no
    evidence commitment, no run seal, and `runs_in_assignment` never moved.
    It now seals the evidence commitment for the attempt, reports
    `last_capture.succeeded` as False, and still re-raises the caller's own
    exception unchanged rather than swallowing or replacing it.
    """
    def flaky(x: int) -> int:
        if x < 0:
            raise ValueError("comp set rejected")
        return x * 2

    sealed = seal_execution(
        assignment_id="ASG-2026-4403", model_id="AVM-v4.2",
        output_dir=str(tmp_path))(flaky)

    sealed(5)
    assert sealed.last_capture.succeeded
    assert sealed.last_capture.runs_in_assignment == 1

    with pytest.raises(ValueError, match="comp set rejected"):
        sealed(-1)
    assert sealed.last_capture.succeeded is False
    assert sealed.last_capture.output is None
    assert sealed.last_capture.runs_in_assignment == 2

    sealed(10)
    assert sealed.last_capture.succeeded
    assert sealed.last_capture.runs_in_assignment == 3

    manifest, report = close_assignment(
        "ASG-2026-4403", certification_ref="cert-1",
        effective_date="2026-03-14", output_dir=str(tmp_path))
    kinds = [e["kind"] for e in manifest["entries"]]
    assert kinds.count("run_seal") == 2
    assert kinds.count("evidence_commitment") == 3
    assert report.coverage is Coverage.CONTIGUOUS


def test_a_second_signing_key_for_an_open_assignment_is_refused():
    """
    A chain carries one key. Accepting a second decorator's key silently would
    mean the caller never learns their own was ignored.
    """
    first = ec.generate_private_key(ec.SECP256R1())
    second = ec.generate_private_key(ec.SECP256R1())
    seal_execution(assignment_id="ASG-2026-4403", model_id="m",
                   output_dir=None, private_key=first)(lambda: {"v": 1})()
    with pytest.raises(AssignmentError):
        seal_execution(assignment_id="ASG-2026-4403", model_id="m",
                       output_dir=None, private_key=second)(lambda: {"v": 2})()


def test_closing_an_assignment_that_is_not_open_raises():
    with pytest.raises(AssignmentError):
        close_assignment("ASG-never-opened", certification_ref="c",
                         effective_date="2026-03-14", output_dir=None)
