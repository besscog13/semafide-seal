# One guide to all four demos

This repository can be seen four ways: a short scripted example, an exhaustive proof across every combination, the same proof made interactive, and a picture of the whole intended architecture. None of the four outranks the others. Together they answer one question from four directions: why is a cryptographically valid record not automatically a historically reliable one, and what closes that gap.

Read them in this order.

## 1. The 60-second demo, for the concrete version

```bash
pip install -r code/seal/requirements.txt
cd code
python -m seal.demo_60s
```

This prints one honest execution and two attacks. In the honest case, every cryptographic check passes and the verifier still refuses to grant reliance, because no witness observed the run and nothing outside the record states how many runs the assignment holds. In the first attack, an operator alters a committed input after the fact, and the verifier catches it directly: the commitment relation breaks. In the second, an operator runs three models and discloses only the favorable one, and the disclosed record passes every check on its own while an independent assignment record shows two others were withheld.

The lesson in three lines: cryptographic validity and evidentiary reliance are different claims. A tampered record can be caught by the record itself. A selectively disclosed record cannot, because nothing about the one file that was shown reveals what was not.

## 2. The full demo, for the exhaustive version

```bash
cd code
python -m seal.demo
```

This builds nine scenarios, each changing one decision from the last, and prints what the verifier concludes about every one. It starts from a bare signature over a bundle, which establishes nothing, and walks forward through committing inputs early, carrying an unexecuted recipe, executing and reproducing that recipe, and finally asking who determined that the operator could not have held the raw input themselves. That last question is the one the whole architecture turns on: the same reproduced output clears the kill condition only when an outside custodian says the operator structurally cannot hold the input, and fails when the sealer says it about itself, when nobody says it at all, or when the input turns out to be something the operator could have held and timestamped on their own.

The later scenarios turn to a separate question: not whether one record is right, but whether the full set of records was disclosed. A truncated chain with no outside checkpoint looks flawless, because nothing inside a document reveals what was cut from it. The same chain, checked against a checkpoint held by someone else, correctly reads as short. An assignment with five analyses and one disclosed reads as complete on its own and reads as four withheld the moment an independent count exists to compare it against.

## 3. The design canvas, for exploring it yourself

[Open the canvas](https://claude.ai/code/artifact/24c8c27e-a797-4cca-851a-ac95dfe9f88a)

This is the same state space as the full demo, made clickable. Five toggles on the left correspond to the same five decisions the CLI walks through in sequence. The panel on the right updates to the real verifier's answer for whichever combination is selected, covering all 96 reachable combinations, not a curated subset. The lit or dim dots are the five propositions, established or not, each on its own evidence. The single most informative thing to try: hold every other toggle fixed and change only who determined the operator cannot hold the input, and watch the headline result flip from fires to clears on exactly one of the four answers.

## 4. The system map, for where this sits in the architecture

[Open the map](https://besscog13.github.io/semafide-seal/)

This draws the same finding as a picture of who holds what: a lender, a cascade of models, the configuration governing that cascade, the seal, the append-only log, a custodian, an independent witness, the standalone verifier, and an examiner. Components are tagged built, unbuilt, or open. The custodian and witness are tagged open, and that tag is not a scheduling note. It is the architectural form of the finding above: the party who can say whether something was left out cannot be either the party who produced the record or the party whose settings are in question, because both have a reason to shade the answer.

## The throughline

A signed record can prove that nothing in it was altered and still say nothing about what was left out of it, because the party who decides what goes into a record is the same party who decides what stays out. That is true of a single automated decision and it is true of a whole batch of them. Cryptography closes the first problem completely. It does not touch the second at all, and no amount of additional cryptography changes that, because the second problem is not a math problem. It is a question about who is positioned to answer honestly, and the only honest answer comes from someone with no stake in what it turns out to be.

What this establishes is limited to the checks the verifier actually performs, described in full in the sections above the fold in the main [`README.md`](../../README.md) and argued at length in [`executive-thesis.md`](../executive-thesis.md). The scaffold here is not production-ready, the capture and custody layers are not built, and none of the four demos claims otherwise.
