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

from seal import BindingLevel, canonical_bytes, verify
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
