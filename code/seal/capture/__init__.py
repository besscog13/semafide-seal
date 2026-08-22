"""
seal.capture: turn a live function call into a sealed artifact.

Pre-build scaffold, same status as the rest of `seal`. Every other module in
this package reads and verifies artifacts that already exist; nothing writes
one at the moment of execution. This subpackage is that missing first step —
a decorator that hashes a function's inputs, runs it, seals the run into a
real `SealChain`, optionally asks an external witness to co-sign it, and
self-checks the result against the real verifier before writing a manifest.

What this does not do, on purpose:

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

from .decorator import CaptureResult, seal_execution
from .witness_client import WitnessClientError, request_witness_signature

__all__ = [
    "CaptureResult",
    "seal_execution",
    "WitnessClientError",
    "request_witness_signature",
]
