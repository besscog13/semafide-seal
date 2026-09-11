# Assurance of this repository

This note is about **Semafide's software**, not about a customer's historical execution.

Two questions get mixed together if they live in the same document:

1. What can later be established about an automated run that already happened?
2. Does this repository still implement the rules it claims to implement?

The executive thesis and the verifier answer the first, within stated limits. This file answers the second. Passing tests here does not mean a valuation was complete, witnessed, or historically true.

## Evidence about a run vs assurance about this code

| About the customer's execution | About this repository |
|---|---|
| Capture, witness, signatures, log, custody, re-derivation, verifier conclusions | Unit tests, property tests, formal specs, CI |

The left column produces claims an examiner might read. The right column only checks that the instrument still behaves as specified. CI going green is not market evidence and is not independent custody.

## What each assurance mechanism does

| Mechanism | What it can support | What it cannot support |
|---|---|---|
| Unit tests | A named behavior happened in a named case | That no other case fails |
| Property tests | A stated rule held across many generated inputs | Exhaustive truth over every possible history |
| SMT / formal specs | Under the written rules, certain invalid states are unreachable | That the written rule is the right business rule |
| CI | The checks we chose still run on the chosen refs | That Semafide is a valuable product, or that completeness is solved |

## Public-claim audit (compact)

Status language:

- **Implemented** — present in this repository and exercised by tests or a demo.
- **Intended** — described as architecture; not a hosted service.
- **Unknown** — commercial or operational; not decided by code.

| Claim | Status |
|---|---|
| A decorated function call can be sealed into an artifact | Implemented |
| Records can be chained and exported | Implemented |
| A standalone verifier reports five separate propositions | Implemented |
| Cryptographic validity is reported separately from evidentiary reliance | Implemented |
| An assignment-level statement can be issued and compared to disclosed artifacts | Implemented as a model |
| A second key signing that statement can be distinguished from the sealer's key | Implemented as a model |
| The dummy handover rehearsal is a hosted custodian | It is not. It is a local script |
| An independent party holds the authoritative set of executions | Intended; not built |
| A witness is operationally sited on a live execution | Intended; not built |
| Capture cannot be bypassed | Not established. An undecorated call is invisible |
| The package establishes historical truth | Too broad. The verifier reports specific propositions |
| Completeness of every real-world run | Only under capture and independence conditions that are not met here |
| A lender or examiner will pay for this | Unknown |

## What this file is not

It is not a claim that historical execution has been proved. It is not a claim that completeness has been solved. It is not part of the supported `pip install semafide-seal` API. Engineering confidence in the verifier is a separate fact from evidence about someone else's valuation.
