"""
Unit-level tests for `seal.capture.witness_client.request_witness_signature`.

The module's own docstring promises it never raises past itself for a
network reason and returns `None` instead. `test_capture.py` exercises this
contract at the `seal_execution` integration level; this file checks the
function directly, against a real socket, for the specific failure mode a
Content-Length lie leaves uncovered.
"""
from __future__ import annotations

import socket
import threading

from seal.capture.witness_client import request_witness_signature


def _truncating_server():
    """
    A server that claims a 1000-byte JSON body and sends 19 bytes, then
    closes the connection without completing it.

    Returns (url, sock, thread). The caller must close `sock` and join
    `thread` when done.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)

    def serve():
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        try:
            conn.recv(65536)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 1000\r\n"
                b"\r\n"
                b"{\"witness\": \"trunc"
            )
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}/", sock, thread


def test_a_response_truncated_mid_body_returns_none_rather_than_raising():
    """
    `urlopen` succeeds (the status line and headers arrive intact, so it
    returns a 200 response), and the failure only appears when
    `response.read()` tries to collect the 1000 bytes the Content-Length
    header promised and the socket closes after 19. That raises
    `http.client.IncompleteRead`, which is not an `OSError` subclass and
    was not one of the exceptions this module caught, so it used to
    propagate out of `request_witness_signature` instead of degrading to
    `None` the way a refused connection or a non-200 status already did.
    """
    url, sock, thread = _truncating_server()
    try:
        result = request_witness_signature(url, {"run_id": "run-1"}, timeout_s=3.0)
    finally:
        sock.close()
        thread.join(timeout=2)

    assert result is None


def _server_sending(body: bytes):
    """
    A server that answers one request with a complete 200 response carrying
    `body`. Returns (url, sock, thread), as `_truncating_server` does.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)

    def serve():
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        try:
            conn.recv(65536)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}/", sock, thread


# Deeper than any default recursion limit, so json.loads raises
# RecursionError rather than a ValueError.
DEEPLY_NESTED = b"[" * 200_000 + b"]" * 200_000


def test_a_deeply_nested_body_returns_none_rather_than_raising():
    """
    `json.loads` raises `RecursionError` on a body nested deeper than the
    interpreter's recursion limit. That is not a `ValueError`, so before
    2026-10-19 it propagated out of `request_witness_signature`.
    """
    url, sock, thread = _server_sending(DEEPLY_NESTED)
    try:
        result = request_witness_signature(url, {"run_id": "run-1"}, timeout_s=3.0)
    finally:
        sock.close()
        thread.join(timeout=2)

    assert result is None


def test_a_deeply_nested_witness_body_still_seals_the_run(tmp_path):
    """
    The consequence at the decorator. The wrapped function has already run
    when the witness is asked, so a raise there lost the caller's output and
    left the run unsealed. The run now seals SELF_ATTESTED and the caller
    gets its value back.
    """
    from seal.capture import reset_assignments, seal_execution

    reset_assignments()
    url, sock, thread = _server_sending(DEEPLY_NESTED)
    try:
        sealed = seal_execution(assignment_id="ASG-NESTED-WITNESS",
                                model_id="m", witness_url=url,
                                output_dir=str(tmp_path))(lambda x: x * 2)
        assert sealed(21) == 42
    finally:
        sock.close()
        thread.join(timeout=2)
        reset_assignments()

    capture = sealed.last_capture
    assert capture.succeeded
    assert capture.runs_in_assignment == 1
    assert capture.trustworthy
    assert not capture.witness_attestation_established
