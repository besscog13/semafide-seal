# Public API

This file is the support contract for the `semafide-seal` distribution.
The authoritative name list lives in `code/seal/public_api.py` as
`SUPPORTED_PUBLIC_API`. The list under **Supported** below must match
that set. CI asserts the relationship.

`seal.__all__` is what the package exports. It is not what Semafide
promises to support.

Installing this package lets you verify a supplied artifact and see what
the verifier will and will not establish. It does not mean Semafide
witnessed the run, holds the assignment record, or operates a custodian.

Distribution: `semafide-seal`. Import: `seal`. Version: `0.0.1`,
Development Status 2 - Pre-Alpha. This contract can change until a
later release says otherwise.

## Supported

Names an external developer may `from seal import …` and depend on.

```
AssignmentAnchor
AttestationMode
Completeness
Coverage
Entry
EntryKind
EvidenceCommitment
EvidencePropositions
EvidentiaryReliance
Finding
RederivationRecipe
RunSeal
SealChain
VerificationReport
WitnessAttestation
WorkfileBinding
assess_evidentiary_reliance
export_artifact
load_artifact
verify
```

## Present

Importable today from `seal` because they are in `__all__`, and not a
supported API. Issuers, time bounds, the experimental log, witness
scaffold, retention model, and cryptographic primitives sit here.
They may move, rename, or leave `__all__` without that counting as a
break of the Supported contract.

## Unsupported

Known experimental or scaffold behavior.

- `seal.capture` seals a decorated call into a chain. An undecorated
  call is invisible. This is not production capture.
- `python -m seal.demo`, `demo_60s`, and `demo_custody` are
  demonstrations, not API.
- Formal specs under `specs/` are not shipped in the wheel.

## Not in the package

This distribution does not provide:

- a hosted custody service
- an independent operational witness
- a production RFC 3161 timestamp authority or beacon
- a determination that a valuation was correct, fair, or compliant
- a claim that every run in an assignment reached a chain
