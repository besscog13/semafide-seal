# `code/seal`

This package is the verification and artifact layer for Semafide. It is not the production capture or custody service.

The package models the evidence that a future capture layer will need to preserve and provides a standalone verifier for the claims that artifact can establish.

## What the verifier can establish

The verifier deliberately separates independent evidence propositions about an execution. `BindingLevel` is retained only as a backwards-compatible projection, not an ordering of those claims:

- **`BUNDLED`** means the claimed inputs and output are present together. It does not establish that the output was derived from those inputs.
- **`PRECEDENCE`** means the evidence commitment existed in the chain before the run seal that names it. This prevents selecting that commitment after seeing the output. It does not establish that the analysis consumed the committed evidence.
- **`WITNESSED`** means an independently trusted observer signed an explicit observed-execution attestation binding the run, committed evidence, sealed action, and capture reference. A self-declared witness field or signature over a supplied bundle is not enough.
- **`REDERIVABLE`** means a complete execution recipe links the claimed evidence to the claimed output and the referenced execution endpoint remains available.
- **`REDERIVED`** means the verifier actually executed that recipe and reproduced the sealed output.

These levels answer different questions. In particular, successful re-derivation establishes that a pinned recipe produces the sealed output from the referenced evidence. It does not, by itself, establish that the historical execution actually ran that recipe. That stronger claim requires capture at execution time and custody outside the control of the party whose conduct may later be examined.

## Assignment completeness

A cryptographically valid chain can still be an incomplete disclosure. An operator can seal five runs and disclose three. The three can all verify perfectly while saying nothing about the two that were withheld.

The assignment checkpoint therefore answers a separate question: whether the supplied chains constitute the assignment-level disclosure represented by the custodian. Without an independent assignment-level statement, the verifier reports that completeness was not checked rather than treating a valid chain as complete.

Assignment anchoring also has a narrower role. It commits a chain to its assignment when the chain opens and prevents relabelling the completed chain later. It does not prove that no sibling chain exists. That requires assignment-level custody and disclosure.

## External time

Author-controlled timestamps are not historical proof. A record can contain an old timestamp and still have been assembled later.

The package models two external bounds:

1. an upper bound from an external timestamp authority; and
2. a lower bound from an unpredictable published value that could not have been known before publication.

When both are independently available, the verifier reports the resulting interval. The interval is evidence about when the artifact could have existed. It is not a claim that the author's timestamp is accurate.

The package does not provide a production RFC 3161 service or production beacon. Those are deployment dependencies.

## Re-derivation limits

The current recipe pins the endpoint, tool, version, invocation, input reference, expected output digest, and service window. It does not yet pin the complete execution environment, numerical libraries, hardware, or linked BLAS.

A later re-derivation failure can therefore reflect environmental drift rather than a changed analysis. The verifier should fail conservatively rather than turn that uncertainty into a clean historical claim.

## What this package does not prove

It does not prove that:

- an appraisal or model output was substantively correct;
- the inputs were appropriate or sufficient;
- the historical execution consumed the referenced inputs merely because they were committed beforehand;
- a successful later reproduction is identical to the historical execution;
- a valid chain is the complete assignment without an independent assignment-level disclosure; or
- cryptography alone makes a custodian honest.

Those boundaries are intentional. The package is designed to make the evidence ceiling explicit rather than allowing a stronger claim to be inferred from a weaker artifact.

## Production boundary

The capture path is not implemented in this repository. A production integration will need an application-level capture mechanism, independent custody, external time services, and an operational witness model.

The experimental append-only log and witness code in this repository should not be treated as a production transparency-log implementation. Production deployments should use established transparency-log and witness specifications.

## Testing

The package includes unit, property-based, and formal checks for the artifact and verifier state machines. A green test gate means the implementation satisfies the encoded models and test properties. It does not establish that those models are complete descriptions of the real-world custody or capture problem.

To run the demo:

```bash
pip install -r code/seal/requirements.txt
cd code
python -m seal.demo
```
