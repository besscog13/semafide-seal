"""
seal.capture: turn a live function call into a sealed artifact.

Pre-build scaffold, same status as the rest of `seal`. Every other module in
this package reads and verifies artifacts that already exist; nothing writes
one at the moment of execution. This subpackage is that missing first step —
a decorator that hashes a function's inputs, runs it, appends the run to the
assignment's chain, optionally asks an external witness to co-sign it, and
self-checks the result against the real verifier before writing a manifest.

One chain lives for the assignment and every call appends to it, so sequence
numbers and prev-hash linkage run unbroken across calls and a discarded run
leaves a hole a verifier notices. `close_assignment` is the second moment: it
writes the workfile binding at certification and is deliberately a separate
act, because a binding is an assertion about finished work rather than a side
effect of running one more analysis.

What this does not do, on purpose:

* It does not enforce that every run reaches the chain. Holding one chain
  open makes the count expressible; an undecorated call is still invisible, a
  manifest on the operator's disk can still be deleted, and a chain never
  handed to a custodian is not a chain anybody can count. That is KC3.
* It does not site a witness. Whether an independent custodian can sit
  between an appraiser's tool call and its output is KC3 and remains open.
  `seal_execution` will call a witness endpoint if one is supplied, but a
  run seals as SELF_ATTESTED — and reports so honestly — whenever no witness
  is configured, unreachable, or not in the caller's trusted set.
* It does not pin the execution environment. See the KNOWN DEFECT note on
  `RederivationRecipe` in `seal.artifact`; this scaffold inherits it.
* It is not a production capture layer. `pyproject.toml`'s classifier
  ("2 - Pre-Alpha ... the capture layer does not exist") described the state
  before this subpackage; it describes a starting scaffold, not a finished
  answer to KC3, from here on.
"""
from __future__ import annotations

from .assignment import (
    AssignmentError,
    close_assignment,
    open_assignments,
    reset_assignments,
)
from .decorator import CaptureResult, seal_execution
from .witness_client import WitnessClientError, request_witness_signature

__all__ = [
    "AssignmentError",
    "CaptureResult",
    "close_assignment",
    "open_assignments",
    "request_witness_signature",
    "reset_assignments",
    "seal_execution",
    "WitnessClientError",
]
