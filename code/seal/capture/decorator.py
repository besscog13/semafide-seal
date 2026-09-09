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
side effect, not a change to the caller's contract, with one deliberate
exception: if the assignment is closed by a concurrent `close_assignment`
call before this call's own evidence commitment is appended, sealing this
run is no longer possible, and the call raises `AssignmentError` instead of
returning `fn`'s output. That closure can land in either of two windows:
before this call's own `_open` runs at all, or after `_open` has already
returned a live assignment but before this call reaches its own lock to
append -- `_open` returns without holding any lock across the return, so a
`close_assignment` racing in that gap can finish entirely before this call
resumes. Both are checked and both raise the same way, immediately before
the append they would otherwise corrupt. `fn` may have completed and
produced a real result; that result is discarded rather than handed back
unsealed. The alternative, returning it silently while sealing quietly
failed, is the cherry-picking attack this whole package exists to catch,
reintroduced through a race between two calls into this module instead of
through a missing check: an operator whose downstream system used the
output would have no way to know the run was never recorded, and a chain a
certification already returned CONTIGUOUS for would keep changing under
it. Raising forces the caller to notice and decide, rather than letting an
unsealed result flow through indistinguishable from a sealed one, or a
certified chain keep growing past its own certification. This is the one
case where the contract above does not hold, and it is documented rather
than silently true; see
`test_capture.py::test_a_call_that_finishes_after_its_assignment_closes_raises_rather_than_returning_unsealed`
and
`test_capture.py::test_a_call_stalled_between_open_and_its_own_lock_does_not_corrupt_a_concurrent_certification`.

Everything sealed is reachable afterward on the wrapper itself:
`run_property_valuation.last_capture` holds a `CaptureResult` with the
manifest, where it was written, and what the real verifier concluded about
it.

`last_capture` answers per calling thread, not globally. A single shared slot
cannot answer "what did my call just seal" once two callers are running
concurrently, the shape of a real batch valuation pipeline: whichever call
writes last wins, and a caller reading in between two overlapping calls sees
the wrong one under its own name. See `context/RECORD.md`, 2026-09-05, for
the confirmed reproduction this replaces. The decorated function is
therefore a small callable object rather than a bare function, so
`last_capture` can be a property backed by `threading.local()` instead of a
plain attribute; everything else about calling it is unchanged.

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

A call that raises still seals. The evidence commitment is built from the
call's bound arguments, which exist whether or not the function returns, so
a wrapped call that raises seals that commitment and re-raises rather than
sealing nothing. No run seal is written, because there is no output to name
one with; the missing run seal is what marks the attempt incomplete, rather
than a self-declared failure flag the operator could misstate. `_verify`'s
coverage check already treats every chain entry as something a
certification binding has to account for, not only run seals, so a failed
attempt surfaces the same way an omitted run would: as a gap the next
binding has to explain, not one that disappears on its own.
"""
from __future__ import annotations

import functools
import inspect
import threading
import time
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from cryptography.hazmat.primitives.asymmetric import ec

from ..artifact import (
    EntryKind,
    EvidenceCommitment,
    RunSeal,
    AttestationMode,
    export_artifact,
)
from .assignment import _open, _refuse_if_closed, write_manifest
from ..primitives import Pinning, PrimitiveKind, PrimitiveRecord, EvidenceForm, commit
from ..verifier import VerificationReport, verify, witness_attestation_payload
from .witness_client import request_witness_signature


@dataclass(frozen=True)
class CaptureResult:
    """
    Everything sealed for one call, alongside the caller's real return value.

    `succeeded` is False when the wrapped call raised. `output` is then
    None, since the call never produced one, and `manifest` reflects a
    chain carrying an evidence commitment for the attempt with no matching
    run seal, rather than a completed run.
    """

    output: Any
    manifest: dict[str, Any]
    manifest_path: Optional[Path]
    report: VerificationReport
    witness_attempted: bool
    witness_attestation_established: bool
    assignment_id: str = ""
    runs_in_assignment: int = 0
    succeeded: bool = True

    @property
    def trustworthy(self) -> bool:
        """Mirrors `VerificationReport.trustworthy` — see `seal.verifier`."""
        return self.report.trustworthy


def _primitives(output: Any, model_id: str, evidence_hash: str,
                t_start: int, t_end: int) -> dict:
    """
    The six, mapped from what a call actually gives us.

    SURFACE and EVIDENCE carry the same commitment here because nothing
    upstream of the function call is observed separately. See the module
    docstring: a caller with a real evidence-acquisition step ahead of the call
    should split them, and that split is not this scaffold's to make.
    """
    return {
        PrimitiveKind.ACTION: PrimitiveRecord(
            kind=PrimitiveKind.ACTION, commitment=commit(output),
            pinning=Pinning.PINNED, retention=EvidenceForm.COMMITMENT_ONLY,
            holder="operator",
        ),
        PrimitiveKind.SURFACE: PrimitiveRecord(
            kind=PrimitiveKind.SURFACE, commitment=evidence_hash,
            pinning=Pinning.PINNED, retention=EvidenceForm.COMMITMENT_ONLY,
            holder="operator",
        ),
        PrimitiveKind.EVIDENCE: PrimitiveRecord(
            kind=PrimitiveKind.EVIDENCE, commitment=evidence_hash,
            pinning=Pinning.PINNED, retention=EvidenceForm.COMMITMENT_ONLY,
            holder="operator",
        ),
        PrimitiveKind.EVALUATOR: PrimitiveRecord(
            kind=PrimitiveKind.EVALUATOR, commitment=commit({"model_id": model_id}),
            pinning=Pinning.PINNED, retention=EvidenceForm.FULL,
            holder="operator", descriptor={"model_id": model_id},
        ),
        PrimitiveKind.INSTANT: PrimitiveRecord(
            kind=PrimitiveKind.INSTANT,
            commitment=commit({"started_ns": t_start, "completed_ns": t_end}),
            pinning=Pinning.PINNED, retention=EvidenceForm.FULL,
            holder="operator",
        ),
        # A claim is a certification-time assertion about what the run
        # supports. One function call does not make one, and this does not
        # invent one to fill the slot. `close_assignment` is that moment.
        PrimitiveKind.CLAIM: PrimitiveRecord(
            kind=PrimitiveKind.CLAIM, commitment=None, pinning=Pinning.ABSENT,
            retention=EvidenceForm.NONE, holder=None,
        ),
    }


def _seal_failed_attempt(
    fn: Callable[..., Any],
    assignment_id: str,
    run_id: str,
    inputs: dict[str, Any],
    t_start: int,
    private_key: Optional[ec.EllipticCurvePrivateKey],
    output_dir: Optional[str],
    wrapper: "_SealedFunction",
) -> None:
    """
    Seal an evidence commitment for a call that raised, before re-raising.

    `inputs` is the bound arguments, computed before `fn` was ever called, so
    it exists whether or not the call succeeded. No run seal is written: there
    is no output to build one from, and the missing run seal is what marks
    this an incomplete attempt rather than a completed run, structurally,
    not by a field an operator could misstate. `state.runs` still counts it,
    because it is something sealed into the chain, not nothing.
    """
    t_fail = time.time_ns()
    state = _open(assignment_id, t_start, private_key)

    evidence_hash_input = commit(inputs)
    evidence = EvidenceCommitment(
        commitment_id=f"ev-{run_id}",
        row_root=evidence_hash_input,
        row_count=len(inputs),
        source=f"function:{fn.__module__}.{fn.__qualname__}",
        as_of=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start / 1e9)),
        query_descriptor={name: commit(value) for name, value in inputs.items()},
    )

    with state.lock:
        _refuse_if_closed(assignment_id)
        chain = state.chain
        chain.append(EntryKind.EVIDENCE_COMMITMENT, evidence.to_body(), t_fail)
        state.runs += 1
        manifest = export_artifact(chain)
        chain_key = chain.public_key_pem
        runs_so_far = state.runs

        # The file write happens inside the same lock as the append it
        # reflects. Outside it, two concurrent calls for this assignment can
        # write manifest.json out of order: an earlier, shorter snapshot's
        # write can land after a later, longer one's, leaving the file on
        # disk short of what the chain actually holds. See
        # context/RECORD.md, 2026-09-05, for the confirmed reproduction.
        manifest_path = None
        if output_dir:
            manifest_path = write_manifest(assignment_id, manifest, output_dir)

    report = verify(manifest, trusted_keys=[chain_key])

    wrapper.last_capture = CaptureResult(
        output=None,
        manifest=manifest,
        manifest_path=manifest_path,
        report=report,
        witness_attempted=False,
        witness_attestation_established=False,
        assignment_id=assignment_id,
        runs_in_assignment=runs_so_far,
        succeeded=False,
    )


class _SealedFunction:
    """
    The callable a decorated function becomes.

    A bare function object cannot make `last_capture` resolve differently per
    calling thread, since Python gives instance-level attribute assignment to
    functions but not instance-level descriptor behaviour, and a descriptor is
    what a thread-aware property needs. Wrapping the function in a small
    object trades nothing a caller can observe: `functools.update_wrapper`
    keeps the name, docstring, module, and `__wrapped__` a plain
    `@functools.wraps` decorator would set, `__get__` keeps it usable as a
    method decorator by binding `self` the way a real function would, and
    calling it still returns exactly what the wrapped function returned.
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        *,
        assignment_id: str,
        model_id: str,
        witness_url: Optional[str],
        trusted_witness_keys: Optional[Iterable[str]],
        output_dir: Optional[str],
        run_id: Optional[str],
        private_key: Optional[ec.EllipticCurvePrivateKey],
    ) -> None:
        functools.update_wrapper(self, fn)
        self._fn = fn
        self._signature = inspect.signature(fn)
        self._assignment_id = assignment_id
        self._model_id = model_id
        self._witness_url = witness_url
        self._trusted_witness_keys = trusted_witness_keys
        self._output_dir = output_dir
        self._run_id = run_id
        self._private_key = private_key
        self._local = threading.local()

    def __get__(self, obj: Any, objtype: Optional[type] = None) -> Any:
        if obj is None:
            return self
        return types.MethodType(self, obj)

    @property
    def last_capture(self) -> Optional[CaptureResult]:
        """
        What this calling thread's most recent call sealed, or `None`.

        Thread-local rather than shared. See the module docstring: a single
        slot cannot answer "what did my call just seal" once two callers are
        running concurrently, and `context/RECORD.md`'s 2026-09-05 entry
        holds the confirmed reproduction of the failure this replaces.
        """
        return getattr(self._local, "last_capture", None)

    @last_capture.setter
    def last_capture(self, value: Optional[CaptureResult]) -> None:
        self._local.last_capture = value

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        fn = self._fn
        assignment_id = self._assignment_id
        model_id = self._model_id
        witness_url = self._witness_url
        trusted_witness_keys = self._trusted_witness_keys
        output_dir = self._output_dir
        private_key = self._private_key

        bound = self._signature.bind(*args, **kwargs)
        bound.apply_defaults()
        inputs = dict(bound.arguments)
        this_run_id = self._run_id or f"{fn.__name__}-{time.time_ns()}"

        t_start = time.time_ns()
        try:
            output = fn(*args, **kwargs)
        except BaseException:
            # Sealing the failed attempt must never replace the caller's own
            # exception with one raised by the sealing machinery itself. If
            # the assignment was closed by a concurrent close_assignment
            # call while fn was still running, _seal_failed_attempt's own
            # call to _open raises AssignmentError, and an unguarded call
            # here would let that supersede fn's real exception -- a caller
            # with `except ValueError` for their own bad-input case would
            # never see it, only an unrelated AssignmentError. Unlike the
            # same race on the success path (see the module docstring),
            # there is no output to protect here: fn already failed on its
            # own, so nothing dangerous is hidden by letting the seal
            # attempt fail quietly and re-raising fn's exception regardless.
            try:
                _seal_failed_attempt(fn, assignment_id, this_run_id, inputs,
                                     t_start, private_key, output_dir, self)
            except BaseException:
                pass
            raise
        t_end = time.time_ns()

        state = _open(assignment_id, t_start, private_key)

        evidence_hash_input = commit(inputs)
        evidence = EvidenceCommitment(
            commitment_id=f"ev-{this_run_id}",
            row_root=evidence_hash_input,
            row_count=len(inputs),
            source=f"function:{fn.__module__}.{fn.__qualname__}",
            as_of=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start / 1e9)),
            query_descriptor={name: commit(value) for name, value in inputs.items()},
        )

        primitives = _primitives(output, model_id, evidence_hash_input,
                                 t_start, t_end)

        run_body = RunSeal(
            run_id=this_run_id,
            primitives=primitives,
            evidence_commitment_hash=None,
            witness_mode=AttestationMode.SELF_ATTESTED,
        ).to_body()

        witness_attempted = bool(witness_url)
        if witness_url:
            # A provisional attestation carrying only capture_ref, so
            # `witness_attestation_payload` (the exact function the real
            # verifier uses) can compute what needs signing.
            run_body["witness_attestation"] = {
                "capture_ref": f"capture:{fn.__module__}.{fn.__qualname__}:{t_start}",
            }
        else:
            run_body["witness_attestation"] = None

        # Two locked steps rather than one held across the witness round
        # trip, which a load test measured serialising an assignment's
        # concurrent calls behind whatever the slowest one's witness
        # response took. The gap between them is real: it is exactly where
        # a run has committed its evidence but not yet sealed, and
        # state.in_flight marks it so close_assignment can refuse to
        # certify through it rather than let this run's seal land after a
        # binding that already claimed to be complete. A prior attempt at
        # this same split, without in_flight, was tested and found to do
        # exactly that. See context/RECORD.md, 2026-09-05, for both the
        # measured cost of the single lock and the confirmed failure of the
        # split alone.
        #
        # Adjacency of the two appends was never what made this correct.
        # This run's evidence_commitment_hash is fixed to a real block hash
        # the moment the first append below returns, so it names its own
        # commitment regardless of what else lands in the chain in between;
        # another call's entries interleaving here does not change which
        # commitment this run points to.
        with state.lock:
            _refuse_if_closed(assignment_id)
            chain = state.chain
            evidence_commitment_hash = chain.append(
                EntryKind.EVIDENCE_COMMITMENT, evidence.to_body(), t_start
            ).block_hash
            state.in_flight += 1

        try:
            run_body["evidence_commitment_hash"] = evidence_commitment_hash

            if witness_url:
                payload = witness_attestation_payload(run_body)
                attestation = request_witness_signature(witness_url, payload)
                if attestation is not None:
                    run_body["witness_attestation"] = attestation
                    run_body["witness_mode"] = AttestationMode.INDEPENDENT.value
                else:
                    run_body["witness_attestation"] = None
        except BaseException:
            # request_witness_signature is documented to fail closed and
            # never raise for a network reason, but state.in_flight must
            # never get stuck incremented on the strength of that alone: a
            # counter that can only go up on some unanticipated exception
            # here would permanently refuse close_assignment for this
            # assignment, which is a worse failure than the one this
            # mechanism exists to prevent.
            with state.lock:
                state.in_flight -= 1
            raise

        with state.lock:
            chain = state.chain
            chain.append(EntryKind.RUN_SEAL, run_body, t_end)
            state.runs += 1
            state.in_flight -= 1
            manifest = export_artifact(chain)
            chain_key = chain.public_key_pem
            runs_so_far = state.runs

            # Writing manifest.json inside the same lock as the append it
            # reflects. Outside it, two concurrent calls for this assignment
            # could write the file out of order: an earlier, shorter
            # snapshot's write landing after a later, longer one's would
            # leave the file on disk short of what the chain actually holds.
            # See context/RECORD.md, 2026-09-05, for the confirmed
            # reproduction.
            manifest_path = None
            if output_dir:
                manifest_path = write_manifest(assignment_id, manifest, output_dir)

        report = verify(
            manifest,
            trusted_keys=[chain_key],
            trusted_witness_keys=trusted_witness_keys,
        )

        self.last_capture = CaptureResult(
            output=output,
            manifest=manifest,
            manifest_path=manifest_path,
            report=report,
            witness_attempted=witness_attempted,
            witness_attestation_established=report.evidence.witness_attestation,
            assignment_id=assignment_id,
            runs_in_assignment=runs_so_far,
        )
        return output


def seal_execution(
    *,
    assignment_id: str,
    model_id: str,
    witness_url: Optional[str] = None,
    trusted_witness_keys: Optional[Iterable[str]] = None,
    output_dir: Optional[str] = "manifests",
    run_id: Optional[str] = None,
    private_key: Optional[ec.EllipticCurvePrivateKey] = None,
) -> Callable[[Callable[..., Any]], _SealedFunction]:
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

    def decorator(fn: Callable[..., Any]) -> _SealedFunction:
        return _SealedFunction(
            fn,
            assignment_id=assignment_id,
            model_id=model_id,
            witness_url=witness_url,
            trusted_witness_keys=trusted_witness_keys,
            output_dir=output_dir,
            run_id=run_id,
            private_key=private_key,
        )

    return decorator
