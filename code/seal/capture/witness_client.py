"""
Best-effort HTTP client for an external witness.

No standalone witness daemon exists in this repository yet. `seal.witness`
is an in-process library — `Witness`, `cosignature_valid`, and friends are
called directly by a caller who already holds the object, the way
`demo_60s.py` does with an in-memory `CUSTODIAN` key. Standing one up as a
service reachable over HTTP (the C2SP `tlog-witness` / `tlog-cosignature`
shape) is separate, not-yet-built work.

This client is written against a protocol this repository does not yet
implement on the other end, so it is speculative by construction. It is kept
deliberately narrow and fails closed:

* One POST, one JSON body, a short timeout.
* Any failure — connection refused, non-200, malformed JSON, a response
  missing a required field — returns `None`. It never raises past this
  module for network reasons, and it never fabricates a signature to paper
  over an unreachable endpoint. A capture wrapper that did that would be
  exactly the failure mode `demo_60s.py`'s docstring warns against: inventing
  a witness signature to make the screen look clean.
* It signs nothing itself and trusts nothing itself. It reports what the
  endpoint returned; whether that signature is valid over the right payload
  and whether the signing key is trusted is decided later, by the real
  verifier (`seal.verifier.verify`), against a `trusted_witness_keys` set the
  caller supplies out of band. This module could be handed a signature over
  the wrong payload from a malicious or buggy endpoint and would pass it
  through unexamined — that is intentional and safe, because nothing
  downstream treats an attestation as established until `verify()` says so.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_TIMEOUT_S = 5.0


class WitnessClientError(Exception):
    """Raised only for programmer error (bad arguments), never for a network failure."""


def request_witness_signature(
    witness_url: str,
    payload: dict[str, Any],
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Optional[dict[str, Any]]:
    """
    Ask an external witness to sign `payload` and return what it sent back.

    `payload` must be exactly the object `seal.verifier.witness_attestation_payload`
    would compute over the run being sealed — this function does not construct
    or check that payload, it only transports it, so the caller (`seal_execution`)
    stays the single place that payload is built.

    Returns a dict with `witness`, `public_key`, `signature`, `capture_ref`,
    and `statement` on success — the exact shape `WitnessAttestation.to_body()`
    expects — or `None` on any failure. `None` means "no attestation," not
    "attestation denied"; callers seal SELF_ATTESTED in either case.
    """
    if not witness_url:
        raise WitnessClientError("witness_url is required")

    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        witness_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            if response.status != 200:
                return None
            raw = response.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    required = ("witness", "public_key", "signature", "capture_ref")
    if not isinstance(data, dict) or not all(data.get(f) for f in required):
        return None

    return {
        "witness": data["witness"],
        "public_key": data["public_key"],
        "signature": data["signature"],
        "capture_ref": data["capture_ref"],
        "statement": data.get("statement", "observed_execution"),
    }
