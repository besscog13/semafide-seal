# Security

## Status of this code

This repository is a **pre-build verifier and artifact scaffold**. It is not a production custody service, it does not capture executions, and it has not been independently audited. Do not rely on it to preserve evidence you would need in a dispute.

The experimental transparency-log implementation in `code/seal/log.py` is not a production foundation. Production deployments should use established transparency-log and witness specifications rather than treating this scaffold as a replacement for them.

## Reporting a vulnerability

Report suspected vulnerabilities to **eli@semafide.com**. Please do not open a public issue for anything that would let someone manufacture or alter evidence undetected.

Useful reports include the affected module and version or commit, what an attacker gains, and a concrete artifact or trace that demonstrates it. A failing test against `code/tests/` is the most actionable form.

Expect acknowledgement within 5 business days. There is no bounty program and no formal SLA; this is a single-maintainer project and that constraint is stated rather than implied.

## What counts as a vulnerability here

The security property this project cares about is narrow and specific: **a party should not be able to make an epistemic claim true by declaring it.** Anything that lets a sealer obtain a proposition it has not earned is in scope.

In scope:

- Obtaining `precedence` without the evidence commitment genuinely preceding the run seal.
- Obtaining `witness_attestation` or `historical_execution_established` from a self-declared field, a generic signature over a supplied bundle, or any key the sealer controls.
- Obtaining `recipe_reproduced` without the recipe actually reproducing the sealed action.
- Truncating or reordering a chain while retaining a `CONSISTENT` completeness result.
- Withholding a sibling chain from an assignment while retaining a clean disclosure result.
- Producing a `BOUNDED` anchoring result over a backdated chain, or otherwise defeating the lower time bound.
- Causing `clears_kc2` to return true without a valid third-party retention determination.
- Canonicalization ambiguity: two distinct logical bodies that serialize to the same `canonical_bytes`, or one body that serializes differently across platforms or interpreter versions.

Out of scope:

- The verifier declining to grant a proposition on incomplete evidence. That is the intended behavior, not a bug. The system **fails closed**: absent, unusable, self-issued, mismatched, and undetermined inputs all resolve against the artifact.
- Claims about substantive correctness. The verifier does not evaluate whether a valuation, appraisal, model, or business decision was sound, and a green result never asserts that.
- A custodian or witness colluding with the party it is meant to constrain. This is a known structural limit, not a defect in the code (see below).

## Known limits

These are documented in the source and repeated here so a reader does not have to find them.

**Execution environment is not pinned.** The re-derivation recipe pins the endpoint, tool, version, invocation, input reference, output digest, and service window. It does not pin the machine, the numerical libraries, the hardware, or the linked BLAS. A partner who honors every commitment the schema asks for can still produce a different digest after moving hardware. The verifier reports `rederivation_mismatch` and declines to grant reproduction.

Note the direction of this failure: it manufactures a false accusation against an honest partner rather than a false clearance for a dishonest one. It fails loudly and conservatively. The fix is an environment manifest beside the recipe, and it is not implemented.

**Witness placement is unresolved.** Where a witness sits relative to the operator's workflow — and therefore whether it is meaningfully independent — is an open design question. The code takes no position on it. Cryptography does not establish that a witness is independent, truthful, or that anyone checked what it signed.

**Custody depends on operations, not mathematics.** Nothing in the mathematics prevents a custodian from colluding with the party it constrains. An append-only log makes later equivocation detectable *when its consistency proofs are actually checked*. Independent witnesses make conflicting views harder to sustain undetected. Neither removes the need to decide who the witnesses are and whether anyone verifies their attestations.

**Retention determinations are provenance, not proof.** Nothing establishes that whoever read a vendor's documentation read it correctly. What the verifier computes is whether a reading was recorded, by a key that is not the sealer's, against a source a later reader can check. The trust does not disappear; it moves to the determiner. That is the intent.

**No key management story.** This scaffold does not address key generation, storage, rotation, revocation, or HSM integration. A production deployment must.

**One canonicalization divergence from JCS remains.** Integral floats serialize as `1.0`. Floats are not hashed directly, because float repr is not stable across platforms or interpreter versions.

## Cryptography in use

SHA-256 for commitments and log hashing; ECDSA over NIST P-256 (via `cryptography`) for signatures; RFC 3161 timestamp tokens modeled as the upper time bound; a published unpredictable beacon value modeled as the lower time bound. The package depends on `cryptography` and the standard library only, and CI asserts that on every push.

No custom primitives are implemented. If you find one, treat it as a bug.

## Supported versions

Only `main` receives fixes. There are no tagged releases yet, so pin a commit if you depend on this.
