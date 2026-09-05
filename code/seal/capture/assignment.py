"""
One chain per assignment, held open across calls.

WHY THIS EXISTS. The first version of `seal_execution` built a fresh
`SealChain` inside the wrapper, so every call produced its own two-entry chain
and its own manifest. Each one verified perfectly and nothing related them.
Three calls, three artifacts, coverage ABSENT on all three.

That is the sibling-chain hole manufactured by construction. An operator running
six analyses got six independent artifacts, discarded five, and the survivor was
flawless. Capture existed and made the count harder to establish than it had
been, because there was no accumulating chain to bind at the end.

A chain that lives for the assignment fixes the shape. Each run appends to it,
sequence numbers and prev-hash linkage run unbroken across every call, and a
verifier walking the chain from genesis notices a missing sequence number. That
is what makes omission detectable rather than merely undesirable.

WHAT IT STILL DOES NOT DO, and this is KC3 rather than a defect here. The
decorator is opt-in per function. An undecorated call is invisible, a manifest
on the operator's disk can be deleted, and a chain that was never handed to a
custodian is not a chain anybody can count. Holding the chain open makes the
count *expressible*. Enforcing that every run reaches it is the other half and
nothing in this repository observes the operator's machine.

THE TWO MOMENTS ARE PRESERVED. Runs are captured at execution and appended
here. Sign-off binds at certification, which is `close_assignment`, an explicit
separate act. The decorator never writes a workfile binding, because a binding
is an assertion somebody makes about finished work rather than a side effect of
running one more analysis. Coverage therefore reads ABSENT until an assignment
is closed, which is the honest reading of an assignment still in progress.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..artifact import EntryKind, SealChain, WorkfileBinding, export_artifact
from ..verifier import VerificationReport, verify


class AssignmentError(Exception):
    """
    Raised for programmer error: a key conflict, closing what is not open,
    or opening what was already closed.
    """


@dataclass
class _OpenAssignment:
    """
    One assignment's chain, and the lock that serialises appends to it.

    `in_flight` counts calls that have committed their evidence but not yet
    appended their run seal, the gap `seal_execution` now leaves unlocked
    while it waits on a witness. `close_assignment` reads it to refuse
    certifying while it is nonzero, rather than letting a run seal land after
    a binding that already claimed to be complete. See
    `context/RECORD.md`, 2026-09-05, for the race this closes and the
    alternative that does not.
    """

    chain: SealChain
    lock: threading.Lock = field(default_factory=threading.Lock)
    runs: int = 0
    in_flight: int = 0


_REGISTRY: dict[str, _OpenAssignment] = {}
_REGISTRY_LOCK = threading.Lock()

# Assignment ids `close_assignment` has certified. `_open` refuses to reopen
# one under the bare id, because silently starting a fresh, disconnected
# chain under the same id would reuse `manifest_filename`'s exact output
# path, overwriting the certified manifest on disk with an unrelated chain
# that carries no workfile binding and no link back to what it replaced.
#
# `AssignmentAnchor.chain_label`, in `artifact.py`, is this package's
# documented way to legitimately open a second chain under one assignment,
# and this refusal is exactly the case that mechanism exists for. Naming it
# here would be the accurate fix, but `seal_execution` and `_open` do not
# accept a `chain_label` parameter at all today, so there is no supported way
# to reach it from the capture layer this refusal actually guards. Recorded
# in `context/RECORD.md` rather than silently implied in an error message a
# caller cannot act on: the real next step is either a new assignment id, or
# building a chain directly with `artifact.SealChain` outside `seal_execution`.
_CLOSED: set[str] = set()

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def manifest_filename(assignment_id: str) -> str:
    """A filesystem-safe name that still identifies the assignment."""
    return f"{_UNSAFE.sub('_', assignment_id)}.manifest.json"


def _open(assignment_id: str, opened_ns: int,
          private_key: Optional[ec.EllipticCurvePrivateKey]) -> _OpenAssignment:
    """
    Get the assignment's chain, opening it on first use.

    A chain carries one signing key, so a second decorator arriving with a
    different key is a programmer error rather than something to resolve
    quietly. `SealChain.append` would use the key the chain already holds and
    the caller would never learn their own was ignored.

    Refuses rather than silently opening a fresh chain if this assignment id
    was already certified: see the note on `_CLOSED` for what a legitimate
    second chain would look like and why this layer cannot offer it directly.
    """
    with _REGISTRY_LOCK:
        if assignment_id in _CLOSED:
            raise AssignmentError(
                f"assignment {assignment_id} was already certified and "
                "closed; seal_execution has no way to open a second, "
                "distinguishable chain under a certified id, so further work "
                "needs a new assignment id, or a chain built directly with "
                "artifact.SealChain and a distinct chain_label outside "
                "seal_execution if it must stay under this one")
        existing = _REGISTRY.get(assignment_id)
        if existing is None:
            chain = SealChain(assignment_id, private_key=private_key,
                              opened_ns=opened_ns)
            _REGISTRY[assignment_id] = _OpenAssignment(chain=chain)
            return _REGISTRY[assignment_id]

        if private_key is not None:
            offered = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
            if offered.strip() != existing.chain.public_key_pem.strip():
                raise AssignmentError(
                    f"assignment {assignment_id} is already open under a "
                    "different signing key; one chain carries one key")
        return existing


def write_manifest(assignment_id: str, manifest: dict[str, Any],
                   output_dir: str) -> Path:
    """Write the whole chain, replacing the previous state of this assignment."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / manifest_filename(assignment_id)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return path


def open_assignments() -> dict[str, int]:
    """Assignment ids currently held open, with how many runs each has sealed."""
    with _REGISTRY_LOCK:
        return {k: v.runs for k, v in _REGISTRY.items()}


def reset_assignments() -> None:
    """
    Drop every open assignment without closing it, and forget every closure.

    For tests and for a process that wants a clean slate. Discards chains rather
    than finalising them, so anything it drops was never bound and never
    disclosed. Also clears `_CLOSED`, since a genuinely fresh process has
    certified nothing yet either.
    """
    with _REGISTRY_LOCK:
        _REGISTRY.clear()
        _CLOSED.clear()


def close_assignment(
    assignment_id: str,
    *,
    certification_ref: str,
    effective_date: str,
    certified_ns: Optional[int] = None,
    output_dir: Optional[str] = "manifests",
    trusted_keys: Optional[Iterable[str]] = None,
    trusted_witness_keys: Optional[Iterable[str]] = None,
) -> tuple[dict[str, Any], VerificationReport]:
    """
    Bind the assignment at certification and close its chain.

    This is the second of the two moments and it is deliberately a separate
    call. The binding names every entry sealed before it and the head those
    entries produced, which is what turns a chain into a claim about a whole
    assignment rather than a pile of runs.

    A binding naming a contiguous chain makes omission detectable. That is the
    property, and it is worth being exact about its limit: it makes omission
    detectable *from this chain*. A run that never reached the chain leaves no
    gap in it. See the module docstring.

    Returns the final manifest and what the real verifier concluded about it.

    Refuses rather than certifying if a call is between committing its
    evidence and appending its run seal, the gap `seal_execution` leaves
    unlocked while it waits on a witness. Certifying through that gap would
    let the run land after a binding that already claimed to cover the
    chain, an omission the binding itself could never reveal. See
    `_OpenAssignment.in_flight`'s docstring and `context/RECORD.md`,
    2026-09-05, for the two-lock alternative that was tried, tested, and
    found to reopen exactly this, and for why this check, not that split,
    is the fix.
    """
    with _REGISTRY_LOCK:
        state = _REGISTRY.get(assignment_id)
    if state is None:
        detail = " (already certified and closed)" if assignment_id in _CLOSED else ""
        raise AssignmentError(f"assignment {assignment_id} is not open{detail}")

    with state.lock:
        if state.in_flight:
            raise AssignmentError(
                f"assignment {assignment_id} has {state.in_flight} call(s) "
                "still sealing, most likely waiting on a witness response; "
                "certifying now could produce a binding that does not cover "
                "a run about to land. Wait for in-flight calls to finish, "
                "then retry.")

        chain = state.chain
        covered = [e.seq for e in chain.entries]
        ts = certified_ns if certified_ns is not None else chain.entries[-1].ts_ns
        binding = WorkfileBinding(
            assignment_id=assignment_id,
            chain_head=chain.head,
            covered_seqs=covered,
            certification_ref=certification_ref,
            effective_date=effective_date,
        )
        chain.append(EntryKind.WORKFILE_BINDING, binding.to_body(), ts)
        manifest = export_artifact(chain)
        keys = list(trusted_keys) if trusted_keys is not None else [chain.public_key_pem]

        # Inside the same lock as the append it reflects, for the reason
        # `seal_execution` writes its own manifest inside `state.lock`: a
        # caller still mid-flight in `_open` before this pop can hold the
        # same `_OpenAssignment` and therefore the same lock, and its own
        # write must not be able to land out of order against this one. See
        # context/RECORD.md, 2026-09-05, for the confirmed reproduction.
        if output_dir:
            write_manifest(assignment_id, manifest, output_dir)

        # Removed from the registry and marked closed only now, atomically
        # with the binding above, while still holding state.lock: nothing
        # can have appended past in_flight==0 without this same lock, so no
        # caller can observe this assignment as still open once this step
        # runs, and the pop being conditional on the in_flight check above
        # is what makes a refusal here leave the assignment retryable rather
        # than silently discarded.
        with _REGISTRY_LOCK:
            _REGISTRY.pop(assignment_id, None)
            _CLOSED.add(assignment_id)

    report = verify(manifest, trusted_keys=keys,
                    trusted_witness_keys=trusted_witness_keys)
    return manifest, report
