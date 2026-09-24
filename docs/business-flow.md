# The business flow

One business event, twelve steps. Most of the twelve are not code. This document names, for each step, the level the code actually supports, so a drift from the shipped mechanism shows up on reading rather than passing unnoticed the way it did in earlier drafts.

**Provenance.** Built and corrected across several rounds in one working session, 2026-09-09, against `semafide-seal` directly rather than from memory. Two earlier drafts of this sequence were wrong in specific, checkable ways and were corrected before this version was recorded: a claimed pre-execution commit that the decorator does not perform, a "custody begins at capture" claim the manifest-writing code contradicts, a "periodic cosigning" claim `code/seal/witness.py`'s own docstring contradicts, and a "completeness answers disclosure" overclaim that ignores what an undecorated call leaves behind. Each correction below cites what was actually read.

---

## 0. Naming

Before any run exists, entry zero is `ASSIGNMENT_ANCHOR`. It names the assignment. Every later entry hashes back to it. Confirmed in `code/seal/artifact.py`: the verifier requires `entries[0].kind` to be `ASSIGNMENT_ANCHOR`.

That is how the chain knows which file it belongs to. It is not how the chain knows whether every run that should have been in that file is in it. An undecorated call never becomes an entry, so there is no hole to find later. Coverage is still ABSENT. Completeness is still UNCHECKED.

## 1. Commit and seal (one decorator, two chain entries)

What actually happens, in wall-clock order, read directly from `code/seal/capture/decorator.py`:

1. Arguments bind.
2. `fn()` runs. The output now exists.
3. After return, the decorator hashes those bound arguments and appends `EVIDENCE_COMMITMENT`, dated to `t_start` (when the call started), written after the call finished.
4. `RUN_SEAL` is appended in the same synchronous block, dated to when it finished.
5. Between those two appends, `state.in_flight` is set so `close_assignment` cannot certify through the gap.

What Precedence checks is chain sequence: commitment before seal. It does not check that the bytes were on the chain before the function ran. They were not.

That is still better than a workfile built after a repurchase letter. It is not historical execution. Execution still needs a second signature over observed capture.

The distinction to hold on to is commitment then seal, as against sealed together. Only the first fixes an order, and neither fixes a fact about history.

## 2. Local manifest

`write_manifest(assignment_id, manifest, output_dir)` writes to a directory the operator passes in. Nothing in capture phones home. Semafide does not hold a copy. The thesis ("the producer no longer holds the only copy") has not happened yet. A file on the appraiser's disk is still the producer's file.

## 3. Certification

`close_assignment` is a separate act, not an automatic side effect of the last run. If it is called while a commitment is in flight and its seal is not on the chain yet, it is refused. Confirmed directly in `code/seal/capture/assignment.py`'s own module docstring: "Sign-off binds at certification, which is `close_assignment`, an explicit separate act."

Until this happens, Coverage is ABSENT, unconditionally. Closing it makes the count of what entered this chain expressible. It does not enforce that every run on the operator's machine entered the chain. That other half is KC3, still open, because nothing in the repository observes the operator's machine.

## 4. Dormancy

Days or years. This is most of the product's life. If the path to beating a timestamp was a recipe rather than a witness, the pinned version can disappear while nobody is looking. That decay is silent here. It becomes a named finding only at step 8: `rederivation_unavailable`.

## 5. Trigger

A letter arrives. It is almost never "please verify this hash." It is one of two questions, and they are not the same evidence object.

| Question | Evidence object | What can speak | What cannot |
| --- | --- | --- | --- |
| Were all relevant executions disclosed? | Count | Completeness against a chain statement, for runs that reached this chain | An undecorated call. KC3. |
| Which configuration produced this number? | Configuration | Only if a digest of cascade, thresholds, and pins was captured at the time | The verifier. Reproduction of an output. A later copy of "today's settings." |

The instrument can only ever answer the first, and only for what it saw. The homepage's commercial investigation is the second. If the provider cannot expose a configuration digest at capture, this whole sequence does not close the thing a lender would actually pay for.

## 6. Handover

If, and only if, the manifest is transferred: this is the first moment custody exists. Cosigning a log head could happen here. `code/seal/witness.py` implements C2SP-style memory, refusing to sign a split view. Nothing in the repository calls `cosign()` automatically. Confirmed directly in the method's own docstring: "No standalone witness daemon exists yet, so nothing in this repository calls this." There is no daemon.

Until this step, talking about Semafide as custodian is the business thesis, not a running mechanism.

## 7. Examiner inputs

`verify()` does not invent trust. The examiner must bring up to nine things, confirmed against its actual signature:

- trusted keys (without them, `key_trusted` is `None`, and `trustworthy` is false)
- trusted witness keys
- chain statement
- assignment statement
- time anchors or a beacon resolver
- retention determinations
- a rederive callback, if Reproduction should even be attempted

Omit the chain statement: Completeness is UNCHECKED, not passed. Omit keys: the bundle can be internally perfect and still not trustworthy. A forger achieves `signatures_valid` by signing with their own key.

This is why the canvas keeps trusted keys off that page: clearing four gates is not reliance.

## 8. Verification

Two computations, in parallel, not a ladder.

**About the run (five independent booleans):**

- Precedence: commitment before seal on the chain
- Witness: second, trusted key over `observed_execution`
- Recipe: complete pinned procedure
- Reproduction: examiner actually ran it and matched
- Execution: same path as Witness today; they co-vary; never inferred from a rerun

**About the record (determinations, not a sixth claim):**

- Completeness, coverage, disclosure
- Anchoring / time bounds
- Holding / input provenance
- `kc2_fires` (= `timestamp_replicable`)

**KC2, in order**, confirmed directly against the actual branching in `code/seal/verifier.py`:

1. Valid witness → not replicable by a timestamp.
2. No reproduction → replicable (two TSA stamps already give Precedence).
3. Reproduction succeeded → only if every run has a sourced, non-self-issued determination that the operator cannot hold the raw input. Unsourced, self-issued, mismatched, holds, undetermined: KC2 fires.

`EvidentiaryReliance` is later and narrower, confirmed by reading `assess_evidentiary_reliance` directly:

```
trustworthy
AND (witness OR reproduced)
AND NOT kc2_fires
```

It does not assert the analysis was correct, the assignment was complete, or a court should admit it.

The 18-cell grid (six primitives times present, pinned, reachable) runs here too. It is its own computation.

The canvas is this step, with no trusted keys and no witness signature, so Witness and Execution stay dark.

## 9. Report

The product that gets handed over. Five yes/no facts plus record determinations. Not a score. Not a verdict.

It can say: against this chain statement, this chain is CONSISTENT. That is not "all runs that should have existed were disclosed." CONSISTENT is not KC3 closed.

It cannot say which cascade, threshold, or model pin produced the number, unless that digest was captured in step 1. The demo's honest run is this report: cryptographic result established, evidentiary reliance not.

If dormancy killed the pinned version, the loud name is `rederivation_unavailable`.

## 10. Outside the fence

Examiner, court, carrier, GSE. They decide what the facts mean for their dispute. Semafide serves admissibility. It does not determine it.

## 11. Payment

Standing exists only when another institution changes behavior because it accepted something Semafide said. Until then the asset is unpaid, whether the path is utility (one AMC's counsel) or acceptance (an examiner or regulator). Both still route through one person's diligence at step 8.

## The one sentence that holds the whole thing

A function ran, two entries were written afterward in the right chain order, the file stayed with the operator until someone moved it, and years later an examiner can learn what that file establishes about count, not configuration, unless the configuration was captured in the same act as the run.
