# The claim vocabulary

One name per concept, used identically in the code, the README, the demo output, and the site. This document is the source. If a name appears anywhere that is not in the table below, it is a bug.

The public labels are the five strings `python -m seal.demo_60s` prints for the run. CI asserts that the README quotes that output verbatim. The public label and the code identifier are a fixed pair. Neither moves without the other.

## The canonical five

| Public label | Code identifier | What it tests | What a yes means | What a yes does not mean |
| --- | --- | --- | --- | --- |
| **Precedence** | `precedence` | Does the commitment appear on the chain before the seal that names it? | The commitment appears before the seal. Inputs could not be selected after this chain already contained the output. | That the bytes were on the chain before the analysis ran, that the system consumed them, or that the source data was true. |
| **Witness attestation** | `witness_attestation` | Did a party other than the sealer sign the record at the time? | The record does not rest only on the sealer's own word. | That the witness checked the analysis, or that the witness is honest. |
| **Recipe available** | `recipe_available` | Does the record carry a complete re-run procedure, meaning endpoint, version, invocation, expected digest? | A stranger could attempt the re-run. | That anyone has. Until somebody executes it, it is a claim. |
| **Recipe reproduced** | `recipe_reproduced` | Did a verifier execute the recipe and get the sealed output? | Derivation was demonstrated rather than asserted. | That the run happened at the time the record claims. A matched reproduction adds nothing a commodity timestamping service could not do unless an outside retention determination says the operator could not have kept the input. |
| **Historical execution** | `historical_execution_established` | Does the record establish that this run happened as described, when it says? | The strongest claim the instrument makes. Today this bit is set only when Witness attestation is set. | Correct, fair, wise, or lawful. Those are never established. |

Four of the five do not imply each other. Historical execution currently co-varies with Witness attestation: the verifier has one path to both, a valid `observed_execution` signature by a distinct trusted key. Unchecked is not a pass, and a yes on Precedence, Recipe available, and Recipe reproduced does not imply Witness attestation or Historical execution. Unchecked is the honest default on Completeness and on Disclosure; it never applies to the five claims.

## The word Witness carried three senses in code; one has since moved to a different name

Two senses of this word remain live in this project, down from three: the glossary sense, an independent record of the capture itself, and the cosigner role `code/seal/witness.py` implements. The third sense, formerly `WitnessMode.INDEPENDENT`, has been renamed to `AttestationMode.INDEPENDENT`, because it borrowed the English of the other two without implementing either, and a sealer-written string calling itself a witness mode was exactly the kind of drift this document exists to stop. The public label for `witness_attestation` is **Witness attestation**. That label still has to be checked against the two senses that remain.

**What `witness_attestation` actually is, stated so this table stops adding to the collision instead of naming it:** it is the glossary sense, a record of the capture independent of the sealer's own say-so, established by `verifier.py`'s own signature check over an `observed_execution` statement signed by a distinct trusted key. That check does not call into `code/seal/witness.py` at all; the two senses are validated by two separate mechanisms in two separate files, and an earlier revision of this sentence said otherwise. It is not `AttestationMode.INDEPENDENT`, and nothing in this table should be read as describing that canvas toggle.

**Where this mapping lives now.** This section is the public-facing mapping, covering two senses instead of three. The private operating notes record the rename in more detail. A public reader does not need that file. Do not ship the short label Witness to the homepage or `/instrument` in place of **Witness attestation**.

## The second axis: the record, not the run

These describe the document. They are never listed alongside the five, and never numbered as a sixth claim.

| Label | Code | Values |
| --- | --- | --- |
| Completeness | `Completeness` | unchecked, consistent, short, mismatched, unusable |
| Coverage | `Coverage` | contiguous, subset, absent |

Supporting determinations that the verifier reports but does not present as claims: `Disclosure`, `Anchoring`, `Provenance` (input provenance), `Holding` (input holding), and `kc2_fires`.

`/instrument` mirrors this split rather than collapsing it. Completeness and Coverage are titled as the record, not the run. Disclosure, Anchoring, provenance, holding, and `kc2_fires` sit under supporting determinations. The site does not present those as a single Secondary list, and does not number any of them as a sixth claim.

## Retired

**Status update, superseding the rest of this section.** The original plan below was to keep `BindingLevel` in code for backward compatibility while banning it from every user-facing surface. That plan is superseded: the enum, the method that derived it, the field that carried it, and every print statement that showed it have all been removed from `code/seal` entirely. There is no compat shim and no output path left to guard, because there is no code path left at all. The table below is kept as the historical record of what each term meant and what replaced it, for a reader who encounters the word in an old document, screenshot, or memory and needs to know it is gone rather than merely hidden.

| Retired term | Replace with |
| --- | --- |
| Binding, binding level, `BindingLevel` | The five propositions. Removed from code entirely; nothing to keep out of output, because there is no output for it anymore. |
| Bundled | The absence of Precedence. Not a result. |
| Witnessed | Witness attestation |
| Rederivable | Recipe available |
| Rederived | Recipe reproduced |
| Custody (as an instrument result) | Keep as the category word only. "Evidence custody, not judgment" stays in the footer. It is not one of the five. |
| Evidence ladder, trust score, hierarchy | "A closed set of independent results." That line is already right, so keep it. |

## Historical diagnosis

This table recorded drift that has since been closed. It is not the current inventory. It is kept because two of its lines are licensed by `.github/scripts/check_retired_vocabulary.py`, and because the change list below refers to it.

The public surfaces are one generation behind the code.

`verifier.py` already treats `EvidencePropositions` as the source of truth and marks `BindingLevel` as "a lossy, backwards-compatible display projection." But the site's Instrument page is built entirely on that deprecated projection, and the homepage list mixes three propositions with one deprecated rung and one product category:

| Surface | What it currently lists |
| --- | --- |
| Homepage | Binding, Precedence, Witness, Reproduction, Custody |
| /instrument | Bundled, Precedence, Witnessed, Rederivable, Rederived, Completeness, six items under a "five claims" heading |
| README | Precedence, Witness attestation, Recipe available, Recipe reproduced, Historical execution |
| `EvidencePropositions` | `precedence`, `witness_attestation`, `recipe_available`, `recipe_reproduced`, `historical_execution_established` |
| Demo output | `binding level`, `coverage`, `completeness`, `KC2 fires` |

Five vocabularies for one set of five things, in a project whose entire proposition is precision. A careful reader notices, and precision is the product.

`Binding` is a rung on the ladder the code deprecated. `Custody` is the category the company operates in, not a result the instrument reports. `Completeness` is a real result but it is not a sixth claim, because it describes the record, not the run.

**This diagnosis table was not independently re-verified against the live site while fixing this document.** `semafide.com` and `semafide.com/instrument` are not reachable from every environment that works on this repository, confirmed blocked again on 2026-09-09. `context/RECORD.md`'s 2026-09-04 entry already recorded one homepage fix, for a different fabrication (`identity`, `configuration`, an invented `not applicable` state). Whether the Homepage row above predates that fix, postdates it, or names a third, separate drift is not established by this document alone. Check the live page directly before treating this row as current.

**The `/instrument` row is now historical, confirmed on 2026-09-17 by the maintainer opening the live page directly.** That is the check the caveat above asks for, recorded here with its source so the two do not read as contradicting each other. No tooling working on this repository verified it, and none could. The live page is built on the canonical five. Completeness and Coverage sit on the record axis. Disclosure, Anchoring, and the timestamp-service determination sit under supporting determinations. Same treatment as the Demo output row: the row above still describes what the page listed before the rewrite and is left as the historical diagnosis, not the current state.

**The Demo output row is now stale, confirmed rather than merely suspected.** The change list below records that `demo.py` was fixed; the row above still describes what it printed before that fix and is left as the historical diagnosis, not the current state.

## Change list

**`code/seal/demo.py` and `demo_60s.py`**, done in two stages. `demo.py`'s `show()` function used to lead each artifact with `binding level`, unlabeled, and never printed the five propositions by name at all. It first went through an intermediate fix, printing the five individually, then `binding_level` last and labeled `legacy display`; once `BindingLevel` was removed from code entirely, that labeled line was removed too, since there was nothing left for it to print. `demo_60s.py`, the script `README.md` quotes verbatim and CI checks against that quote, was left untouched throughout, since it already showed the five correctly and never printed `binding level` at all.

**`README.md`**, done, and aligned again on 2026-09-23. The examiner table now uses the same five public labels as `demo_60s` and as the canonical table above: Precedence, Witness attestation, Recipe available, Recipe reproduced, Historical execution. This document is the source for those names. The site derives from it.

**Homepage**, replace the five-item list with the canonical five. Drop Custody from the list and leave it in the footer line. Note as of this revision: the live homepage no longer carries any claims list at all, of any kind; it has been rewritten around the AVM cascade/configuration story since the diagnosis table above was first written. This item may already be moot. Check the live page before acting on it.

**`/instrument`**, done against the live page, 2026-09-17, read directly by the maintainer rather than by any tooling, and the diagnosis row above is now historical. The page is built on the canonical five. Completeness is the chain-level statement, Disclosure is the assignment-level counterpart, Anchoring uses the code name rather than "Time bounds," and Unchecked is scoped to completeness and disclosure, not completeness alone. Precedence asks about chain sequence, not wall-clock execution. Completeness and Coverage sit on the record axis; Disclosure, Anchoring, provenance, holding, and `kc2_fires` sit under supporting determinations. The page names Coverage's three values (contiguous, subset, absent), states the economic caveat on Recipe reproduced, and closes with cryptographic result and evidentiary reliance. Evidentiary reliance is the three-part threshold: the chain verifies, at least one of witness attestation or recipe reproduced holds, and a commodity timestamp over the same local files would not have reached the same place. Completeness is not in that predicate. The four objects (input, configuration, output, execution) are labeled as the things a later question is about, not as per-object verdicts the verifier emits. The site mirrors this document's two tiers rather than collapsing them into one Secondary list.

**`code/seal/verifier.py`**, done and superseded by a larger change. The `BindingLevel` docstring first gained a line stating the projection must not appear in user-facing output; `BindingLevel` itself, the class, the derivation method, the `VerificationReport` field, and every reference to it in `code/seal/__init__.py`, `code/seal/evidence.py`, and `code/seal/README.md`, have since been removed entirely, along with every test assertion that referenced it (rewritten to assert the same fact directly against the five propositions instead of through the derived value).

**CI**, done and re-verified after the removal. `.github/scripts/check_retired_vocabulary.py` asserts the relationship rather than a blacklist, the same shape as `check_system_map.py`: every line naming a retired term in a licensed file must be byte-identical to one already known here, and no occurrence anywhere else under `docs/` gets any exemption. The licensed lines themselves changed from explaining a kept-but-hidden projection to recording a removed one; the check's exemptions were updated to match the new wording, and all four original negative controls (a leak into a new file, an unlicensed new line, an edited licensed line, an unlicensed line added to this document) were re-run and still fail correctly.
