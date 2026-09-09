# The claim vocabulary

One name per concept, used identically in the code, the README, the demo output, and the site. This document is the source. If a name appears anywhere that is not in the table below, it is a bug.

## The diagnosis

The public surfaces are one generation behind the code.

`verifier.py` already treats `EvidencePropositions` as the source of truth and marks `BindingLevel` as "a lossy, backwards-compatible display projection." But the site's Instrument page is built entirely on that deprecated projection, and the homepage list mixes three propositions with one deprecated rung and one product category:

| Surface | What it currently lists |
| --- | --- |
| Homepage | Binding, Precedence, Witness, Reproduction, Custody |
| /instrument | Bundled, Precedence, Witnessed, Rederivable, Rederived, Completeness — six items under a "five claims" heading |
| README | Precedence, Witness attestation, Recipe availability, Recipe reproduction, Historical execution |
| `EvidencePropositions` | `precedence`, `witness_attestation`, `recipe_available`, `recipe_reproduced`, `historical_execution_established` |
| Demo output | `binding level`, `coverage`, `completeness`, `KC2 fires` |

Five vocabularies for one set of five things, in a project whose entire proposition is precision. A careful reader notices, and precision is the product.

`Binding` is a rung on the ladder the code deprecated. `Custody` is the category the company operates in, not a result the instrument reports. `Completeness` is a real result but it is not a sixth claim — it describes the record, not the run.

**This diagnosis table was not independently re-verified against the live site while fixing this document.** `semafide.com` and `semafide.com/instrument` are not reachable from every environment that works on this repository, confirmed blocked again on 2026-09-09. `context/RECORD.md`'s 2026-09-04 entry already recorded one homepage fix, for a different fabrication (`identity`, `configuration`, an invented `not applicable` state). Whether the Homepage row above predates that fix, postdates it, or names a third, separate drift is not established by this document alone. Check the live page directly before treating this row as current.

**The Demo output row is now stale, confirmed rather than merely suspected.** The change list below records that `demo.py` was fixed; the row above still describes what it printed before that fix and is left as the historical diagnosis, not the current state.

## The canonical five

The public label and the code identifier are a fixed pair. Neither moves without the other.

| Public label | Code identifier | What it tests | What a yes means | What a yes does not mean |
| --- | --- | --- | --- | --- |
| **Precedence** | `precedence` | Was the input set committed before the run that consumed it? | Inputs could not be selected after somebody saw the output. | That the output was derived from those inputs. |
| **Witness** | `witness_attestation` | Did a party other than the sealer sign the record at the time? | The record does not rest only on the sealer's own word. | That the witness checked the analysis, or that the witness is honest. |
| **Recipe** | `recipe_available` | Does the record carry a complete re-run procedure — endpoint, version, invocation, expected digest? | A stranger could attempt the re-run. | That anyone has. Until somebody executes it, it is a claim. |
| **Reproduction** | `recipe_reproduced` | Did a verifier execute the recipe and get the sealed output? | Derivation was demonstrated rather than asserted. | That the run happened at the time the record claims. |
| **Execution** | `historical_execution_established` | Does the record establish that this run happened as described, when it says? | The strongest claim the instrument makes. | Correct, fair, wise, or lawful. Those are never established. |

Reported independently. Unchecked is not a pass, and a yes on four does not imply the fifth.

## The word `Witness` is not disambiguated by this table, and it needs to be before the label ships

Three senses of this word are already live in this project, named in `CLAUDE.md`'s own glossary collision note: the glossary sense, an independent record of the capture itself; the cosigner role `code/seal/witness.py` implements; and `WitnessMode.INDEPENDENT`, which that same note states uses neither sense. Adopting **Witness** as the public label for `witness_attestation` adds a fourth use of the word without resolving the first three, which is the exact kind of drift this document exists to stop.

**What `witness_attestation` actually is, stated so this table stops adding to the collision instead of naming it:** it is the glossary sense, a record of the capture independent of the sealer's own say-so, established in practice through the second sense's mechanism, the signature checking `code/seal/witness.py` performs. It is not `WitnessMode.INDEPENDENT`, and nothing in this table should be read as describing that canvas toggle.

Do not ship **Witness** to the homepage or `/instrument` until this mapping is written down somewhere a reader moving between the public label, the glossary entry, and the code can actually find it. This document was not that place until this paragraph; whoever finishes the rewrite should decide whether it belongs here permanently or gets pointed at from here into `CLAUDE.md` instead.

## The second axis: the record, not the run

These describe the document. They are never listed alongside the five, and never numbered as a sixth claim.

| Label | Code | Values |
| --- | --- | --- |
| Completeness | `Completeness` | unchecked, consistent, short, mismatched, unusable |
| Coverage | `Coverage` | contiguous, subset, absent |

Supporting determinations that the verifier reports but does not present as claims: `Disclosure`, `Anchoring`, `Provenance` (input provenance), `Holding` (input holding), and `kc2_fires`.

## Retired

Remove from every user-facing surface. Keep only where the code needs the compat shim.

| Retired term | Replace with |
| --- | --- |
| Binding, binding level, `BindingLevel` | The five propositions. In code the enum stays for backward compatibility and must never reach user-facing output. |
| Bundled | The absence of Precedence. Not a result. |
| Witnessed | Witness |
| Rederivable | Recipe |
| Rederived | Reproduction |
| Custody (as an instrument result) | Keep as the category word only — "evidence custody, not judgment" stays in the footer. It is not one of the five. |
| Evidence ladder, trust score, hierarchy | "A closed set of independent results." That line is already right — keep it. |

## Change list

**`code/seal/demo.py` and `demo_60s.py`** — done. `demo.py`'s `show()` function used to lead each artifact with `binding level`, unlabeled, and never printed the five propositions by name at all. It now prints the five individually first, then `coverage`, `completeness`, and `KC2 fires`, with `binding_level` last and labeled `legacy display`. `demo_60s.py`, the script `README.md` quotes verbatim and CI checks against that quote, was left untouched, since it already showed the five correctly and never printed `binding level` at all.

**`README.md`** — done. It now states directly that this document is the source for the claim vocabulary and that the site derives from it, so the two surfaces cannot drift apart again without the statement itself being visibly wrong.

**Homepage** — replace the five-item list with the canonical five. Drop Custody from the list and leave it in the footer line. Note as of this revision: the live homepage no longer carries any claims list at all, of any kind; it has been rewritten around the AVM cascade/configuration story since the diagnosis table above was first written. This item may already be moot. Check the live page before acting on it.

**`/instrument`** — the larger rewrite. Rebuild on the five propositions using the four columns from the table above, which is close to the three-part structure already there. Move Completeness and Coverage into their own short section titled for what they are: whether the record is whole, not whether the run is established. As of this revision the live `/instrument` page still presents `Anchoring` (labeled "Time bounds") as a sixth claim inside the same table as the real five, which this rewrite needs to fix along with everything else.

**`code/seal/verifier.py`** — still open. The `BindingLevel` docstring does not yet say the projection must not appear in user-facing output.

**CI** — done. `.github/scripts/check_retired_vocabulary.py` asserts the relationship rather than a blacklist, the same shape as `check_system_map.py`: every line naming a retired term in `README.md` or `docs/executive-thesis.md` must be byte-identical to one already known and licensed here, and no occurrence anywhere else under `docs/` gets any exemption. Verified with three negative controls (a leak into a new file, an unlicensed new line, an edited licensed line) before landing.
