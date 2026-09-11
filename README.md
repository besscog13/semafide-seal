# Semafide

[![CI](https://github.com/besscog13/semafide-seal/actions/workflows/ci.yml/badge.svg)](https://github.com/besscog13/semafide-seal/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: pre-alpha scaffold](https://img.shields.io/badge/status-pre--alpha%20scaffold-orange.svg)](#verification-status)
[![Security policy](https://img.shields.io/badge/security-policy-informational.svg)](SECURITY.md)
[![PyPI](https://img.shields.io/pypi/v/semafide-seal.svg)](https://pypi.org/project/semafide-seal/)

Appraisals and automated valuations get challenged years after they run. By then the data they used may have changed, been corrected, or disappeared, and rerunning the analysis can produce a different number. Semafide is testing whether independent custody can preserve enough evidence to establish what actually happened.

Mortgage lending is the first market this is tested against, not the only one, because it was inexpensive to test.

## What a partner should look at first

Not a library clone. One sealed run, and what an examiner is allowed to say about it.

`python -m seal.demo_60s` walks an honest valuation on assignment `ASG-8942`, then two attacks. On the honest case the verifier prints:

```
HONEST EXECUTION (Collateral Valuation #ASG-8942)
------------------------------------------------------------------------
  Precedence              ✓ ESTABLISHED
  Witness attestation     ✗ NOT ESTABLISHED
  Recipe available        ✓ ESTABLISHED
  Recipe reproduced       ✓ ESTABLISHED
  Historical execution    ✗ NOT ESTABLISHED
  Completeness            ✗ NOT ESTABLISHED
------------------------------------------------------------------------
  CRYPTOGRAPHIC RESULT    ✓ ESTABLISHED
  EVIDENTIARY RELIANCE    ✗ NOT ESTABLISHED
```

An examiner can say the evidence commitment predates the seal, and that a pinned recipe later reproduced the sealed output. An examiner cannot say a witness observed the run, that historical execution is established, or that this was the only run in the assignment. Cryptographic integrity is not evidentiary reliance.

That refusal is the product. The rest of this README is the argument underneath it.

**See it run** (sixty seconds, built for someone outside the project):

```bash
pip install semafide-seal
python -m seal.demo_60s
```

`semafide-seal` is a pre-alpha verifier for inspecting a supplied artifact. Installing it does not mean Semafide witnessed a run or holds an assignment record.

Talk: eli@semafide.com

## Built / unbuilt

| | Status |
|---|---|
| Verifier for five independent propositions | **Built** |
| Capture scaffold that seals a decorated function call into a chain | **Built** |
| Assignment checkpoint and disclosure check | **Built** as a model |
| Hosted production custody service | **Unbuilt** |
| Enforcement that every run in an assignment reaches the chain | **Unbuilt** — an undecorated call is invisible |
| Independent operational witness | **Unbuilt** |

The intended architecture places the evidentiary record outside the control of the party that produced the analysis.

## What an examiner can and cannot say

The verifier records five independent propositions. They are not a ladder.

| Proposition | What it establishes | What it does not establish |
|---|---|---|
| Precedence | The evidence commitment predates the run seal. | The analysis consumed that evidence. |
| Witness attestation | A separately trusted witness key signed an observed-execution attestation covering the run, evidence, action, and capture reference. | That the witness organization is operationally independent or truthful. |
| Recipe availability | A complete recipe is present and linked to the claimed evidence and action. | That it has been executed. |
| Recipe reproduction | A verifier later produced the sealed output from that recipe. | That the historical execution ran the recipe. |
| Historical execution established | A valid observed-execution witness attestation covers the relation. | General custody completeness or substantive correctness. |

Successful re-derivation does not make `historical_execution_established` true. A generic signature over a supplied bundle does not make `witness_attestation` true.

This table and [`docs/claim-vocabulary.md`](docs/claim-vocabulary.md) are the source for these five names.

Further reading, after the table: [`docs/demos/README.md`](docs/demos/README.md) (worked example to architecture), [`docs/executive-thesis.md`](docs/executive-thesis.md) (commercial thesis), and the [system map](https://besscog13.github.io/semafide-seal/) generated from [`docs/semafide.architecture.json`](docs/semafide.architecture.json). The interactive [design canvas](https://claude.ai/code/artifact/24c8c27e-a797-4cca-851a-ac95dfe9f88a) assumes this table. A rehearsal of comparing an outside count to the files an examiner is shown is in [`docs/handover-rehearsal.md`](docs/handover-rehearsal.md).

## The problem
