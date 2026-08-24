# Contributing

Thank you for looking at this. The project is small and pre-alpha, and the most
useful contribution is usually a demonstration that something it claims is
wrong.

## What this repository is

The verification core. It defines and tests what evidence a record needs to
support claims about an automated execution. It does not capture executions and
it does not provide production custody, so a change that assumes either of those
exists is working against a layer that has not been built.

`code/seal/` holds the artifact schema, the append-only log primitives, the
checkpoint and witness machinery, the external time-bound models, and the
standalone verifier. `code/tests/` holds the unit, adversarial, and
property-based tests. `specs/` holds formal specifications checked with Z3.

## Running everything

```bash
pip install -e .              # the live package: cryptography and stdlib only
pip install -e ".[test]"
pytest                        # unit, adversarial, and property-based tests

pip install -e ".[specs]"
python specs/SPEC_merkle_consistency.py     # each spec exits 0 or 1

cd code
python -m seal.demo           # the guided walkthrough
python -m seal.demo_60s       # the short external-facing walkthrough
```

The demo is not a smoke test. It prints verdicts, and those verdicts have been
wrong while the exit code was zero. Read what it prints against what its prose
claims. A green exit that says the opposite of its own text is the failure this
project exists to make visible elsewhere.

## Where a change belongs

The three verification tools divide by what they can establish, and putting a
check in the wrong one wastes it.

Z3 specifications prove what the construction forces, over unbounded state at
small bounds. Hypothesis covers claims quantified over arbitrary input. Unit
tests assert explicit design rules that somebody chose and could have chosen
differently. Specify what is forced by the construction, and test what was
decided by a designer.

A specification that proves a property about a model, with nothing tying that
model to the code, establishes nothing about the code. Each spec here proves a
safety property over unbounded histories and also drives the real implementation
over concrete traces. Keep both halves.

## A new gate is not trusted until it has fired

If you add a check, mutate the logic it guards and confirm that a distinct test
fails for each mutation. Then restore the mutation. A rig that has only ever
returned pass is indistinguishable from a broken one, and this repository has
shipped a check that quietly asserted nothing while reporting green.

Say in the pull request which mutations you ran and which test caught each.

## What this project will not accept

These are not style preferences. Each one is load-bearing, and a change that
crosses one is rejected however well it is written.

**Nothing blocks, scores, or evaluates quality.** The system records and seals.
A feature that says no, assigns a grade, or gates a workflow belongs to a
different product. The record is symmetric evidence: it should document a flawed
analysis as faithfully as a sound one.

**A field the sealer writes is never treated as the fact it describes.** The
verifier computes over evidence that an adversary cannot author. Reading a
self-declared field and reporting it as established is the failure mode the
whole package is arranged against, and it has been introduced by accident more
than once.

**`historical_execution_established` has exactly one path.** A valid
observed-execution attestation, signed by an independently trusted witness,
binding the run, the committed evidence, the sealed action, and a capture
reference. It is never inferred from successful re-derivation, and a signature
over a supplied bundle is not that attestation.

**`BindingLevel` is a display projection and is lossy by construction.** The
five propositions are the source of truth. Do not use the level to infer a
proposition it does not state, and do not add logic that branches on it.

**Absence is reported as unchecked, not as a pass.** When a checkpoint, a
disclosure statement, or a time anchor was not supplied, the verifier says so.
Converting missing input into a favourable verdict is the specific dishonesty
this code exists to refuse.

**`code/seal/` imports `cryptography` and the standard library only.** CI
asserts it. Test-only and specification-only dependencies never reach the live
package, and `z3` in particular is checked as forbidden there.

**No transparency log implementation.** The mechanisms here map onto the C2SP
specification family at [c2sp.org](https://c2sp.org), and the field's names are
used rather than local coinages. A checkpoint is a signed tree head. A witness
cosignature is what a witness produces. Adopt the specifications rather than
reimplementing them.

## Prose

Documentation is held to the same standard as the code, because a document that
overstates its own state is an integrity failure in miniature.

Short declarative sentences. No em dashes and no contractions. Prose rather than
bullets wherever a paragraph will carry the idea. Never invent a concrete
example. Present tense is earned, so write "we are building" until the mechanism
is verified.

Claims carry their epistemic status. Read directly, corroborated but not read,
or unverified. A finding that moves between those says so in place rather than
being quietly upgraded.

## Filing an issue

The most valuable issue is a case where the verifier grants something it should
not, or refuses something it should grant. A failing test is worth more than a
description. If you have found a way to make an epistemic claim true by
declaring it, that is the bug this project most wants to hear about.

Vulnerabilities go through [`SECURITY.md`](SECURITY.md) rather than the public
issue tracker. That file also records the known limits, which are worth reading
before reporting one of them as new.

## Licence

Contributions are accepted under the MIT licence in [`LICENSE`](LICENSE).
