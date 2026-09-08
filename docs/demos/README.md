# One guide to all five demos

This repository can be seen five ways: a short scripted example, an exhaustive proof across every combination, the same proof at the custodian's own level rather than one artifact's, the single-artifact proof made interactive, and a picture of the whole intended architecture. None of the five outranks the others. Together they answer two related questions from five directions: why is a cryptographically valid record not automatically a historically reliable one, what closes that gap, and once it is closed, can the party holding the closed record be trusted to hold it honestly.

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

The later scenarios turn to a separate question: not whether one record is right, but whether the full set of records was disclosed. A truncated chain with no outside checkpoint looks flawless, because nothing inside a document reveals what was cut from it. The same chain, checked against a checkpoint held by someone else, correctly reads as short. An assignment with five analyses and one disclosed reads as complete on its own and reads as four withheld the moment an independent count exists to compare it against. The last scenario turns to time: an external authority alone only bounds a chain from above, which catches nothing about the backdating attack this project actually worries about, and only a committed, independently resolved value published before the chain existed closes the other side. That row is also where the mechanism is shown telling the difference between a chain that lies about its age and one that was simply anchored early and kept working honestly afterward, which a cruder check would confuse for the same thing.

## 3. The custody demo, for what happens one level up

```bash
cd code
python -m seal.demo_custody
```

The first two demos ask what one artifact establishes about itself. This one asks a different question: whether the party holding the whole log, the custodian, can be caught rewriting its own history. An honest custodian growing its log produces a consistency proof that anyone holding two of its signed heads can recompute independently, without having been present for any of it. A custodian that alters one entry inside what it already committed to, then keeps extending as if nothing happened, produces no proof at all when challenged, not a suspicious one, because the arithmetic a real proof would need to walk no longer exists once the entry is gone. An independent witness that has already signed the honest head refuses outright when handed a conflicting one at that same size, and the refusal is not a policy layered on top; it is the direct consequence of the witness remembering what it last signed. The last scenario draws the line a serious reviewer will ask about directly: two different roots at one size is settled the moment it is seen, final, and no proof of any kind rebuts it; two different sizes with no proof offered is not yet evidence of anything, only an unanswered question the custodian can still close honestly by producing the real one, or leave open by failing to.

The lesson: the first two demos show what closes the gap between a valid record and a reliable one. This one shows whether the party trusted to hold the closed record can be trusted to hold it honestly, which is the same independence question behind the custodian and witness roles the architecture still leaves open.

## 4. The design canvas, for exploring it yourself

[Open the canvas](https://claude.ai/code/artifact/24c8c27e-a797-4cca-851a-ac95dfe9f88a)

This is the same state space as the full demo, made clickable. Five toggles on the left correspond to the same five decisions the CLI walks through in sequence. The panel on the right updates to the real verifier's answer for whichever combination is selected, covering all 96 reachable combinations, not a curated subset. The lit or dim dots are the five propositions, established or not, each on its own evidence. The single most informative thing to try: hold every other toggle fixed and change only who determined the operator cannot hold the input, and watch the headline result flip from fires to clears on exactly one of the four answers.

## 5. The system map, for where this sits in the architecture

[Open the map](https://besscog13.github.io/semafide-seal/)

This draws the same finding as a picture of who holds what: a lender, a cascade of models, the configuration governing that cascade, the seal, the append-only log, a custodian, an independent witness, the standalone verifier, and an examiner. Components are tagged built, unbuilt, or open. The custodian and witness are tagged open, and that tag is not a scheduling note. It is the architectural form of the finding above: the party who can say whether something was left out cannot be either the party who produced the record or the party whose settings are in question, because both have a reason to shade the answer, and it is also the architectural form of what the custody demo asks about that same open party.

## The throughline

A signed record can prove that nothing in it was altered and still say nothing about what was left out of it, because the party who decides what goes into a record is the same party who decides what stays out. That is true of a single automated decision and it is true of a whole batch of them. Cryptography closes the first problem completely. It does not touch the second at all, and no amount of additional cryptography changes that, because the second problem is not a math problem. It is a question about who is positioned to answer honestly, and the only honest answer comes from someone with no stake in what it turns out to be.

Closing that gap creates a second question rather than finishing the job: now that the record is held by a party the operator does not control, can that party itself be trusted. Cryptography answers a version of this one too, though only a partial version. A consistency proof and a witness's memory make a custodian's own rewrite arithmetically detectable and make a split view require corrupting more than one party to sustain undetected. Neither prevents either. What is left, stated plainly rather than glossed over, is operational: who the custodian and the witnesses actually are, and whether that is enough independence for the record to mean what it claims to.

What this establishes is limited to the checks the verifier actually performs, described in full in the sections above the fold in the main [`README.md`](../../README.md) and argued at length in [`executive-thesis.md`](../executive-thesis.md). The scaffold here is not production-ready, the capture and custody layers are not built, and none of the five demos claims otherwise.
