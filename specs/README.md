# Formal specs

Z3 checks over the state machines that hold the custody guarantees. Run by CI on
every push, in a job separate from the seal package so the solver never reaches
the live code.

```bash
pip install -r specs/requirements.txt
python specs/SPEC_checkpoint_issuer.py    # exit 0 or 1
```

## What is here, and the rule for what belongs

The division of labour across the three tools is deliberate. **SMT for
mathematical invariants**, meaning properties forced by the construction rather
than chosen by a designer. **Property-based testing for input-shaped
questions**, meaning anything quantified over arbitrary values. **Unit tests for
explicit design rules**, meaning the decisions somebody made and could have made
differently.

That rule matters because a spec written for a chosen property reproduces the
failure mode this package already has: the author writes both the code and the
statement of intent, and a proof that they agree says nothing about whether the
intent was sufficient. A spec written for a forced property is immune to that,
because the correct statement is determined by mathematics rather than by taste.

**`SPEC_merkle_consistency`** is the forced case, and it is the strongest result
here. The claim the whole custody argument rests on is not that an honest
consistency proof verifies. It is that a dishonest one cannot exist. That is a
claim over an infinite space of candidate proofs, and the unit test that stood
in for it sampled about two hundred strings. The spec makes the adversary
symbolic: every element of the proof is a free variable over the whole hash
space, with the hash modelled as an injective, domain-separated datatype, and
the solver is asked whether any assignment at all makes the verifier accept.

**Three components keep state and refuse**: `checkpoint.Issuer`,
`assignment.Issuer`, and `witness.Witness`. Each compares a proposal against its
immediate predecessor and nothing earlier, which is O(1) memory and is the
reason a witness is cheap to run.

The guarantee an examiner needs is not local. It is that across the whole
history the issuer never signed two statements that cannot both be true. Whether
the local check delivers the global property is an induction, and it is the one
class of claim a test suite structurally cannot close, because tests check the
traces somebody thought of. That is why these three and not the rest of the
package.

Each spec does four things.

**The induction.** An invariant is preserved by every accepted transition,
therefore it holds over histories of any length.

**Necessity.** The refusals that are not merely conservative are shown to be
required, so a weaker guard would be unsound rather than cautious.

**Anti-vacuity.** A guard that refuses everything satisfies every safety
property, which is the cheapest way to pass a proof and ship a useless
component. Each spec asserts that a legitimate extension is still accepted.

**Conformance.** The specs drive the real implementation over concrete traces
and require it to accept and refuse exactly where the model says. This is the
part that makes the rest worth anything. A proof about a model that nothing ties
to the code is the same defect as a re-derivation recipe compared against
itself, which is KC2 stated, and it would be a poor joke to reproduce that
defect in the verification layer.

## The four are not equally strong, and the summary line hides it

Four green lines print the same way. They do not mean the same thing, and a
reader who takes them as four equivalent proofs has been misled by the format
rather than by the text.

**`SPEC_merkle_consistency` is bounded, and it is the only one that is.** Tree
sizes run to six and proof lengths to five. Within those bounds the adversary is
unbounded in proof content, since every proof element is a free constant over
the hash datatype, so the soundness result is a real statement about arbitrary
forgeries at small sizes. It is not a statement about all tree sizes. A
structural defect appearing only at size ninety would not be caught. For an
RFC 6962 transcription the residual risk is transcription error rather than
novel mathematics, which is why the conformance sweep carries more weight here
than the solver does. Raising the bound would buy confidence and would not turn
this into an unbounded proof, and quietly doing so while implying otherwise
would be the exact move this package refuses everywhere else.

**`SPEC_checkpoint_issuer` is a genuine unbounded induction, resting on one
uninterpreted symbol.** Heads are uninterpreted integers, only equality matters,
and the invariant is proved preserved over histories of any length. What it does
not establish is that `_extends` correctly decides extension, because `extends`
enters the model as an uninterpreted Boolean. The result is therefore that the
refusal policy is sufficient given a correct extension check. Whether the
extension check is correct is discharged only by the conformance traces, which
are finite.

**`SPEC_witness_cosigning` has the same shape and the same boundary, plus key
continuity.** The extra conjunct matters more than its size suggests: without
it, rotating a key would be an epistemic reset, letting a log walk away from its
own history and present a clean one. The spec closes that as a local escape
route. `consistent` is uninterpreted for the same reason `extends` is.

**`SPEC_assignment_issuer` is unbounded over the number of chains and proves
less than its name suggests.** It establishes that once a chain has entered the
observed set, no accepted statement can shorten it or drop it. It does not
establish that every chain which existed was observed. That gap is capture
completeness, it is open, and no amount of work on this spec closes it. Observed
history cannot shrink is a different claim from observed history equals actual
history, and only the first is proved.

The common boundary, stated once: the uninterpreted symbols in the checkpoint
and witness inductions are where the proofs hand off to the implementation, and
that hand-off is discharged by conformance over concrete traces rather than by
the solver. A defect in `_extends` or in the consistency machinery that appears
only outside the traces exercised would survive all four gates.

## What this does not do, and it is the important part

**It does not address the failure mode this project actually has.** Every gap
found here has been a specification error rather than an implementation error.
`witness_mode: "independent"` granting a level, the recipe compared against
itself, the coverage check watching the wrong window, retention failing open,
the stateless issuer. In each case the code did what the author intended and the
intent was insufficient.

A gate proving `code ⊨ spec`, where the same author writes both, does nothing
about that. It raises confidence without raising correctness, which is the
direction that hurts. An outside read of this code found in a single pass what
several rounds of adversarial self-review did not.

So a green gate here means the three state machines do what their models say.
It does not mean the models are the right models. Read it that way.

**It is not a pre-commit hook.** A local hook is skipped with `--no-verify` and
does not travel with a clone. For a project whose thesis is that the constrained
party cannot be the sole source of its own constraint, a gate the constrained
party can wave through would be a worked example of the failure it studies. CI
is the enforceable position.

## Validation of the gate itself

A gate that passes on broken code is worse than no gate, so each spec was run
against deliberately broken implementations before being committed.

Seven mutants against the three stateful refusers: the checkpoint issuer with
the equivocation refusal removed, with the shrink refusal removed, and with the
extension check removed; the witness with the equivocation refusal removed and
with the consistency check removed; the assignment issuer with the drop refusal
removed and with the shrink refusal removed. All seven caught, each naming the
trace.

Eight mutants against `verify_consistency`: the shrink refusal, the same-size
root comparison, the final `sn == 0` check, the old-root comparison, the
power-of-two branch, the node argument order, the empty-proof refusal, and the
zero-size shortcut, each removed or inverted in turn. All eight caught.

**Mutation testing is what made those specs worth anything, and it found two
holes in the harnesses rather than in the code.** The consistency conformance
pass originally ran the old size only up to the new size, so the shrink branch
was never reached and a mutation removing it went unnoticed: a pass that never
reaches a branch does not cover it. It then fed only proofs derived from honest
ones, so four of seven mutants survived: a pass that never supplies a hostile
value only covers the happy path. And it held the new root fixed at the honest
value, which leaves untested the one degree of freedom the adversary actually
has, since a custodian controls the head it publishes. Widening those three
things is what took the sweep from three of seven to eight of eight.

The witness spec also failed on its first run with model and code disagreeing.
The harness was wrong: it computed the consistency proof over the whole log
rather than over the prefix being presented. Worth recording, because a
disagreement means one of the two is wrong, and which one is not decided by
whichever is easier to edit.

## Adding a spec

Name it `SPEC_*.py` anywhere under `specs/`, exit 0 on success and 1 on
breach, and print a counterexample on failure. CI discovers recursively and
fails if it finds no specs at all, since a job that asserts nothing should not
report a pass.
