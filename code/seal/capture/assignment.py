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
    """Raised for programmer error: a key conflict, or closing what is not open."""


@dataclass
class _OpenAssignment:
    """One assignment's chain, and the lock that serialises appends to it."""

    chain: SealChain
    lock: threading.Lock = field(default_factory=threading.Lock)
    runs: int = 0


_REGISTRY: dict[str, _OpenAssignment] = {}
_REGISTRY_LOCK = threading.Lock()

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
    """
    with _REGISTRY_LOCK:
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
    Drop every open assignment without closing it.

    For tests and for a process that wants a clean slate. Discards chains rather
    than finalising them, so anything it drops was never bound and never
    disclosed.
    """
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


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
    """
    with _REGISTRY_LOCK:
        state = _REGISTRY.pop(assignment_id, None)
    if state is None:
        raise AssignmentError(f"assignment {assignment_id} is not open")

    with state.lock:
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

    if output_dir:
        write_manifest(assignment_id, manifest, output_dir)

    report = verify(manifest, trusted_keys=keys,
                    trusted_witness_keys=trusted_witness_keys)
    return manifest, report
