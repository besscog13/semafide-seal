"""
Load test for the capture layer under conditions closer to real production
use than any single-bug repro elsewhere in this test suite: several
assignments in flight at once (not one), several threads hammering each one
concurrently, a witness endpoint with realistic variable latency AND
occasional failures (not a fixed clean 200 every time), a mix of successful
and raising calls, and real file I/O to a real output directory throughout.

At the end, every assignment is certified and independently re-verified
through the real `verify()` (not the capture module's own report) and
cross-checked against what was actually observed happening.

Deliberately not named test_*.py or *_test.py: this takes on the order of
twenty seconds, opens real sockets, and its outcome depends on OS thread
scheduling under a fixed random seed rather than being a fast, hermetic unit
check, so it does not belong in the default `pytest -q` run pytest.ini_options
restricts to code/tests. Run it directly:

    cd code && python -m tests.manual_load_test_capture

See context/RECORD.md, 2026-09-05, for the run this file reproduces and what
it found.
"""
import json
import os
import random
import tempfile
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from http.server import BaseHTTPRequestHandler, HTTPServer

from seal import canonical_bytes, verify, Coverage
from seal.capture import seal_execution
from seal.capture.assignment import reset_assignments, close_assignment, open_assignments


def main() -> int:
    reset_assignments()
    random.seed(20260905)

    # ----------------------------------------------------------------------
    # A witness endpoint that behaves like a real one under load: variable
    # latency, and it sometimes fails outright.
    # ----------------------------------------------------------------------
    witness_key = ec.generate_private_key(ec.SECP256R1())
    witness_pub_pem = witness_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    witness_failure_rate = 0.12

    class FlakyWitnessHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            payload = json.loads(self.rfile.read(length))
            time.sleep(random.uniform(0.01, 0.06))
            if random.random() < witness_failure_rate:
                self.send_response(503)
                self.end_headers()
                return
            sig = witness_key.sign(canonical_bytes(payload), ec.ECDSA(hashes.SHA256())).hex()
            body = json.dumps({
                "witness": "load-test-witness",
                "public_key": witness_pub_pem,
                "signature": sig,
                "capture_ref": payload.get("capture_ref"),
                "statement": "observed_execution",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), FlakyWitnessHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    witness_url = f"http://127.0.0.1:{server.server_port}/witness"

    # ----------------------------------------------------------------------
    # Several assignments in flight at once, each with its own decorated
    # worker (seal_execution binds assignment_id at decoration time),
    # several threads hammering each one, and a mix of successful and
    # raising calls.
    # ----------------------------------------------------------------------
    n_assignments = 8
    threads_per_assignment = 5
    calls_per_thread = 8
    failure_rate = 0.15

    output_dir = tempfile.mkdtemp(prefix="seal_load_test_")

    sealed_fns = {}
    for i in range(n_assignments):
        aid = f"LOAD-{i:02d}"

        def make(assignment_id):
            @seal_execution(assignment_id=assignment_id, model_id="load-test-model",
                            output_dir=output_dir, witness_url=witness_url,
                            trusted_witness_keys=[witness_pub_pem])
            def value(tag, should_fail=False):
                if should_fail:
                    raise ValueError(f"simulated failure for {tag}")
                return {"assignment": assignment_id, "tag": tag}
            return value

        sealed_fns[aid] = make(aid)

    observed = {}  # assignment_id -> list of dicts describing what actually happened
    observed_lock = threading.Lock()
    unexpected_errors = []
    unexpected_errors_lock = threading.Lock()

    def run_thread(assignment_id, thread_idx):
        fn = sealed_fns[assignment_id]
        for call_idx in range(calls_per_thread):
            tag = f"{assignment_id}-t{thread_idx}-c{call_idx}"
            should_fail = random.random() < failure_rate
            try:
                if should_fail:
                    try:
                        fn(tag, should_fail=True)
                        with unexpected_errors_lock:
                            unexpected_errors.append(
                                (assignment_id, tag,
                                 "expected ValueError, call returned normally"))
                    except ValueError:
                        cap = fn.last_capture
                        with observed_lock:
                            observed.setdefault(assignment_id, []).append({
                                "tag": tag, "expected_fail": True,
                                "succeeded": cap.succeeded, "output": cap.output,
                            })
                else:
                    result = fn(tag, should_fail=False)
                    cap = fn.last_capture
                    with observed_lock:
                        observed.setdefault(assignment_id, []).append({
                            "tag": tag, "expected_fail": False,
                            "succeeded": cap.succeeded, "output": cap.output,
                            "returned": result,
                        })
            except Exception as e:  # noqa: BLE001 - anything here is a real finding
                with unexpected_errors_lock:
                    unexpected_errors.append((assignment_id, tag, f"{type(e).__name__}: {e}"))

    threads = []
    for aid in sealed_fns:
        for t in range(threads_per_assignment):
            threads.append(threading.Thread(target=run_thread, args=(aid, t)))

    start = time.time()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = time.time() - start

    total_calls = sum(len(v) for v in observed.values())
    print("=== load phase ===")
    print(f"{len(threads)} threads, {total_calls} calls across {n_assignments} assignments, "
          f"{elapsed:.2f}s wall time")
    print(f"unexpected errors during the load phase: {len(unexpected_errors)}")
    for e in unexpected_errors[:20]:
        print("  ", e)

    # ----------------------------------------------------------------------
    # Certify every assignment, then independently re-verify each one
    # through the real verifier, and cross-check the on-disk file against
    # what actually happened, not just against what the capture module
    # claims happened.
    # ----------------------------------------------------------------------
    print("\n=== certification and independent verification ===")
    findings = []

    for aid in sealed_fns:
        manifest, close_report = close_assignment(
            aid, certification_ref=f"cert-{aid}", effective_date="2026-09-05",
            output_dir=output_dir, trusted_witness_keys=[witness_pub_pem])

        on_disk_path = os.path.join(output_dir, f"{aid}.manifest.json")
        on_disk = json.loads(open(on_disk_path).read())

        if on_disk != manifest:
            findings.append(f"{aid}: on-disk manifest.json does not match what "
                            f"close_assignment returned")

        fresh_report = verify(on_disk, trusted_keys=[on_disk["entries"][0]["public_key"]],
                              trusted_witness_keys=[witness_pub_pem])

        anchor = on_disk["entries"][0]
        if anchor["kind"] != "assignment_anchor" or anchor["body"]["assignment_id"] != aid:
            findings.append(f"{aid}: chain does not open with the right anchor")

        run_seals = [e for e in on_disk["entries"] if e["kind"] == "run_seal"]
        evidence_commitments = [e for e in on_disk["entries"]
                                if e["kind"] == "evidence_commitment"]
        bindings = [e for e in on_disk["entries"] if e["kind"] == "workfile_binding"]

        expected_successes = sum(1 for o in observed[aid] if not o["expected_fail"])
        expected_failures = sum(1 for o in observed[aid] if o["expected_fail"])

        if len(run_seals) != expected_successes:
            findings.append(f"{aid}: expected {expected_successes} run_seals from "
                            f"successful calls, chain has {len(run_seals)}")
        if len(evidence_commitments) != expected_successes + expected_failures:
            findings.append(f"{aid}: expected {expected_successes + expected_failures} "
                            f"evidence_commitments, chain has {len(evidence_commitments)}")
        if len(bindings) != 1:
            findings.append(f"{aid}: expected exactly one workfile_binding, "
                            f"found {len(bindings)}")

        # cross-contamination check: nothing in this chain should reference
        # any OTHER assignment's tag anywhere in the run bodies.
        blob = json.dumps(on_disk)
        for other_aid in sealed_fns:
            if other_aid == aid:
                continue
            if f'"{other_aid}-' in blob:
                findings.append(f"{aid}: chain contains a reference to "
                                f"{other_aid}'s tag -- cross-assignment contamination")

        if not fresh_report.trustworthy:
            findings.append(f"{aid}: fresh independent verify() does not consider "
                            f"the certified manifest trustworthy: "
                            f"{[f.code for f in fresh_report.findings]}")

        if close_report.coverage != Coverage.CONTIGUOUS:
            findings.append(f"{aid}: close_assignment's own coverage is "
                            f"{close_report.coverage}, expected CONTIGUOUS")
        if fresh_report.coverage != Coverage.CONTIGUOUS:
            findings.append(f"{aid}: independent re-verification's coverage is "
                            f"{fresh_report.coverage}, expected CONTIGUOUS")

        witnessed = sum(1 for e in run_seals if e["body"].get("witness_mode") == "independent")
        print(f"{aid}: {len(run_seals)} run_seals, {len(evidence_commitments)} commitments, "
              f"{witnessed}/{len(run_seals)} independently witnessed (rest self-attested "
              f"due to the {int(witness_failure_rate*100)}% simulated witness failure rate), "
              f"coverage={fresh_report.coverage.value}, trustworthy={fresh_report.trustworthy}")

    print("\n=== registry state after closing everything ===")
    print("open_assignments() after closing all:", open_assignments())

    print("\n=== findings ===")
    if findings:
        for f in findings:
            print("  FAIL:", f)
    else:
        print("  none -- every assignment's certified, on-disk manifest matched what "
              "actually happened, independently re-verified as trustworthy and "
              "CONTIGUOUS, with no cross-assignment contamination")

    server.shutdown()

    return 1 if (findings or unexpected_errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
