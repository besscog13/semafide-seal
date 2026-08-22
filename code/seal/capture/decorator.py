"""
`seal_execution`: wrap a function so each call seals a real artifact.

    from seal.capture import seal_execution

    @seal_execution(assignment_id="ASG-2026-9901", model_id="AVM-CoreLogic-v4.2")
    def run_property_valuation(mls_comps: dict, property_params: dict) -> dict:
        valuation = mls_comps["median_sqft"] * property_params["sqft"]
        return {"valuation": valuation, "confidence": 0.93}

    result = run_property_valuation(mls_comps, property_params)

The wrapped function still returns exactly what it always returned —
`result` above is the same dict `run_property_valuation` built. Sealing is a
side effect, not a change to the caller's contract. Everything sealed is
reachable afterward on the wrapper itself: `run_property_valuation.last_capture`
holds a `CaptureResult` with the manifest, where it was written, and what the
real verifier concluded about it.

Six primitives, mapped from what a call actually gives us:

* ACTION    — the function's return value.
* SURFACE   — the bound arguments as the caller supplied them.
* EVIDENCE  — the same bound arguments, committed before the function runs.
* EVALUATOR — `model_id`, exactly as passed to the decorator.
* INSTANT   — wall-clock start and end of the call.
* CLAIM     — left ABSENT. A claim is a certification-time assertion about
              what the run supports; a single function call does not make
              one, and this scaffold does not invent one to fill the slot.

This module does not decide whether SURFACE and EVIDENCE should ever differ
for a given caller — here they are the same commitment because nothing
upstream of the function call is observed separately. A caller with a real
evidence-acquisition step (an MLS query, a document pull) ahead of the
function call should commit that step's output as SURFACE and reserve
EVIDENCE for what the function itself samples from it; that split isn't
this scaffold's problem to solve.
"""
from __future__ import annotations

import functools
import inspect
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from cryptography.hazmat.primitives.asymmetric import ec

from ..artifact import (
    EntryKind,
    EvidenceCommitment,
    RunSeal,
    SealChain,
    WitnessMode,
    export_artifact,
)
from ..primitives import Pinning, PrimitiveKind, PrimitiveRecord, Retention, commit
from ..verifier import VerificationReport, verify, witness_attestation_payload
from .witness_client import request_witness_signature


@dataclass(frozen=True)
class CaptureResult:
    """Everything sealed for one call, alongside the caller's real return value."""

    output: Any
    manifest: dict[str, Any]
    manifest_path: Optional[Path]
    report: VerificationReport
    witness_attempted: bool
    witness_attestation_established: bool

    @property
    def trustworthy(self) -> bool:
        """Mirrors `VerificationReport.trustworthy` — see `seal.verifier`."""
        return self.report.trustworthy


def seal_execution(
    *,
    assignment_id: str,
    model_id: str,
    witness_url: Optional[str] = None,
    trusted_witness_keys: Optional[Iterable[str]] = None,
    output_dir: Optional[str] = "manifests",
    run_id: Optional[str] = None,
    private_key: Optional[ec.EllipticCurvePrivateKey] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Build a decorator that seals every call to the function it wraps.

    `witness_url`, if given, is asked to co-sign the run over HTTP (see
    `witness_client.request_witness_signature`). No such endpoint exists
    anywhere in this repository yet — that's separate, not-yet-built work —
    so passing a URL here without a daemon behind it degrades to the same
    SELF_ATTESTED outcome as passing nothing.

    `trusted_witness_keys` decides whether a returned signature counts, not
    whatever `witness_url` claims about itself. Leaving it unset means every
    call seals SELF_ATTESTED regardless of what the witness endpoint
    answers — trusting a key because an attestation carries it is the
    self-authentication `seal.verifier._witness_attestation_valid` already
    refuses, and this wrapper does not reintroduce it at a different layer.

    `output_dir=None` skips writing `manifest.json` and only populates
    `wrapper.last_capture`.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            inputs = dict(bound.arguments)
            this_run_id = run_id or f"{fn.__name__}-{time.time_ns()}"

            t_start = time.time_ns()
            output = fn(*args, **kwargs)
            t_end = time.time_ns()

            chain = SealChain(assignment_id, private_key=private_key, opened_ns=t_start)

            evidence_hash_input = commit(inputs)
            evidence = EvidenceCommitment(
                commitment_id=f"ev-{this_run_id}",
                row_root=evidence_hash_input,
                row_count=len(inputs),
                source=f"function:{fn.__module__}.{fn.__qualname__}",
                as_of=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start / 1e9)),
                query_descriptor={name: commit(value) for name, value in inputs.items()},
            )
            evidence_commitment_hash = chain.append(
                EntryKind.EVIDENCE_COMMITMENT, evidence.to_body(), t_start
            ).block_hash

            primitives = {
                PrimitiveKind.ACTION: PrimitiveRecord(
                    kind=PrimitiveKind.ACTION, commitment=commit(output),
                    pinning=Pinning.PINNED, retention=Retention.COMMITMENT_ONLY,
                    holder="operator",
                ),
                PrimitiveKind.SURFACE: PrimitiveRecord(
                    kind=PrimitiveKind.SURFACE, commitment=evidence_hash_input,
                    pinning=Pinning.PINNED, retention=Retention.COMMITMENT_ONLY,
                    holder="operator",
                ),
                PrimitiveKind.EVIDENCE: PrimitiveRecord(
                    kind=PrimitiveKind.EVIDENCE, commitment=evidence_hash_input,
                    pinning=Pinning.PINNED, retention=Retention.COMMITMENT_ONLY,
                    holder="operator",
                ),
                PrimitiveKind.EVALUATOR: PrimitiveRecord(
                    kind=PrimitiveKind.EVALUATOR, commitment=commit({"model_id": model_id}),
                    pinning=Pinning.PINNED, retention=Retention.FULL,
                    holder="operator", descriptor={"model_id": model_id},
                ),
                PrimitiveKind.INSTANT: PrimitiveRecord(
                    kind=PrimitiveKind.INSTANT,
                    commitment=commit({"started_ns": t_start, "completed_ns": t_end}),
                    pinning=Pinning.PINNED, retention=Retention.FULL,
                    holder="operator",
                ),
                PrimitiveKind.CLAIM: PrimitiveRecord(
                    kind=PrimitiveKind.CLAIM, commitment=None, pinning=Pinning.ABSENT,
                    retention=Retention.NONE, holder=None,
                ),
            }

            run_body = RunSeal(
                run_id=this_run_id,
                primitives=primitives,
                evidence_commitment_hash=evidence_commitment_hash,
                witness_mode=WitnessMode.SELF_ATTESTED,
            ).to_body()

            witness_attempted = bool(witness_url)
            established = False
            if witness_url:
                # A provisional attestation carrying only capture_ref, so
                # `witness_attestation_payload` (the exact function the real
                # verifier uses) can compute what needs signing. Mirrors the
                # construction in tests/test_seal_verifier.py rather than
                # re-deriving the payload shape here.
                run_body["witness_attestation"] = {
                    "capture_ref": f"capture:{fn.__module__}.{fn.__qualname__}:{t_start}",
                }
                payload = witness_attestation_payload(run_body)
                attestation = request_witness_signature(witness_url, payload)
                if attestation is not None:
                    run_body["witness_attestation"] = attestation
                    run_body["witness_mode"] = WitnessMode.INDEPENDENT.value
                else:
                    run_body["witness_attestation"] = None
            else:
                run_body["witness_attestation"] = None

            chain.append(EntryKind.RUN_SEAL, run_body, t_end)
            manifest = export_artifact(chain)

            report = verify(
                manifest,
                trusted_keys=[chain.public_key_pem],
                trusted_witness_keys=trusted_witness_keys,
            )
            established = report.evidence.witness_attestation

            manifest_path = None
            if output_dir:
                out = Path(output_dir)
                out.mkdir(parents=True, exist_ok=True)
                manifest_path = out / f"{this_run_id}.manifest.json"
                manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

            wrapper.last_capture = CaptureResult(
                output=output,
                manifest=manifest,
                manifest_path=manifest_path,
                report=report,
                witness_attempted=witness_attempted,
                witness_attestation_established=established,
            )
            return output

        wrapper.last_capture = None
        return wrapper

    return decorator
