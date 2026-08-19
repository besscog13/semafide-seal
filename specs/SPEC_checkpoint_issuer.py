"""
SPEC: a checkpoint issuer that remembers only its last statement is sufficient.

WHAT IS BEING PROVED, AND WHY IT IS WORTH PROVING

`checkpoint.Issuer` keeps one checkpoint per assignment. That is O(1) state, and
it is the reason witnesses are cheap to run. It is not obvious that O(1) is
enough. The property an examiner needs is global: across the whole history, the
issuer never signed two different chains at one size. The issuer only ever
compares against its immediate predecessor.

This spec proves the local check implies the global property, for histories of
any length. That is an induction, so it is the kind of claim a test suite cannot
close: tests check the traces somebody thought of.

WHAT IS NOT BEING PROVED

This proves a protocol, not a program. A proof about a model that nothing ties
to the implementation is the same defect as a re-derivation recipe compared
against itself, which is KC2 stated. So the model is not left to speak for the
code. The conformance pass drives the real `checkpoint.Issuer` over concrete
traces and asserts it accepts and refuses exactly where the model says it must.
If the two ever disagree, this exits non-zero and names the trace.

It also does not prove the guard is the right guard. That is a specification
question. Formal machinery raises confidence in the implementation and does
nothing for the intent behind it, which is the direction that hurts.
"""

from __future__ import annotations

import itertools
import pathlib
import sys

from z3 import And, Bool, Implies, Int, Not, Or, Solver, sat, unsat

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "code"))

FAILURES: list[str] = []


def report(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        FAILURES.append(f"{name}: {detail}" if detail else name)


# ---------------------------------------------------------------------------
# The model. One predicate, used by the proofs and by the conformance check, so
# the two cannot drift apart.
# ---------------------------------------------------------------------------

def accepts(has_prior, last_size, last_head, size, head, extends, *, z3=True):
    """
    Whether an issuer holding (last_size, last_head) signs (size, head).

    Written so the same expression evaluates under Z3 and under Python. The
    guard mirrors `checkpoint.Issuer.issue` clause for clause.
    """
    and_, or_, not_, imp = (And, Or, Not, Implies) if z3 else (
        lambda *a: all(a), lambda *a: any(a), lambda a: not a,
        lambda a, b: (not a) or b)
    return or_(
        not_(has_prior),
        and_(
            not_(and_(size == last_size, head != last_head)),   # no equivocation
            not_(size < last_size),                             # no shrink
            imp(size > last_size, extends),                     # growth is proven
        ),
    )


# ---------------------------------------------------------------------------
# Part 1. The induction. Unbounded in history length.
# ---------------------------------------------------------------------------

def prove_local_check_implies_global_property() -> None:
    """
    Invariant, for any earlier accepted entry (s_e, h_e) and the current last:

        s_e <= last_size  and  (s_e == last_size implies h_e == last_head)

    If that is preserved by every accepted transition, then by induction no two
    accepted entries ever share a size and differ in head, for a history of any
    length. Heads are uninterpreted: only equality matters, so integers suffice.
    """
    s_e, h_e = Int("s_e"), Int("h_e")
    last_size, last_head = Int("last_size"), Int("last_head")
    size, head = Int("size"), Int("head")
    extends = Bool("extends")

    invariant = And(s_e <= last_size,
                    Implies(s_e == last_size, h_e == last_head))
    guard = accepts(True, last_size, last_head, size, head, extends)
    preserved = And(s_e <= size, Implies(s_e == size, h_e == head))

    solver = Solver()
    solver.add(invariant, guard, Not(preserved))
    result = solver.check()
    report("induction: local check preserves the global invariant",
           result == unsat,
           "" if result == unsat else f"counterexample {solver.model()}")


def prove_the_refusals_are_necessary() -> None:
    """
    The guard is conservative on growth, deliberately. These two refusals are
    not conservative: accepting either would break the invariant outright, so a
    weaker guard is unsound rather than merely cautious.
    """
    last_size, last_head = Int("last_size"), Int("last_head")
    size, head = Int("size"), Int("head")

    for name, breach in [
        ("equivocation", And(size == last_size, head != last_head)),
        ("shrink", size < last_size),
    ]:
        solver = Solver()
        # A proposal that breaches, yet the guard would admit it.
        solver.add(breach, accepts(True, last_size, last_head, size, head, True))
        result = solver.check()
        report(f"necessity: the guard cannot admit a {name}", result == unsat,
               "" if result == unsat else f"admitted {solver.model()}")


def prove_the_guard_is_not_vacuous() -> None:
    """
    A guard that refuses everything satisfies every safety property. That is the
    cheapest way to pass a proof and produce a useless component, so the model
    is checked for the existence of a real accepting extension.
    """
    solver = Solver()
    last_size, last_head = Int("last_size"), Int("last_head")
    size, head = Int("size"), Int("head")
    solver.add(last_size == 5, last_head == 100, size == 9, head == 200,
               accepts(True, last_size, last_head, size, head, True))
    report("anti-vacuity: a genuine extension is accepted",
           solver.check() == sat)


def prove_bounded_traces_are_clean(depth: int = 5) -> None:
    """
    The induction above is the real result. This is a separate check over fully
    symbolic traces, which would catch an invariant that is preserved but does
    not imply what it is meant to imply.
    """
    solver = Solver()
    sizes = [Int(f"size_{i}") for i in range(depth)]
    heads = [Int(f"head_{i}") for i in range(depth)]
    exts = [Bool(f"ext_{i}") for i in range(depth)]
    acc = [Bool(f"acc_{i}") for i in range(depth)]

    ls, lh, has = Int("ls_0"), Int("lh_0"), Bool("has_0")
    solver.add(Not(has))
    state = [(has, ls, lh)]
    for i in range(depth):
        h_i, ls_i, lh_i = state[-1]
        solver.add(acc[i] == accepts(h_i, ls_i, lh_i, sizes[i], heads[i], exts[i]))
        nh, nls, nlh = Bool(f"has_{i+1}"), Int(f"ls_{i+1}"), Int(f"lh_{i+1}")
        solver.add(nh == Or(h_i, acc[i]))
        solver.add(Implies(acc[i], And(nls == sizes[i], nlh == heads[i])))
        solver.add(Implies(Not(acc[i]), And(nls == ls_i, nlh == lh_i)))
        state.append((nh, nls, nlh))

    # Safety: no two accepted entries share a size and differ in head.
    breaches = [And(acc[i], acc[j], sizes[i] == sizes[j], heads[i] != heads[j])
                for i, j in itertools.combinations(range(depth), 2)]
    solver.add(Or(*breaches))
    result = solver.check()
    report(f"bounded traces to depth {depth}: no equivocation reachable",
           result == unsat,
           "" if result == unsat else f"trace {solver.model()}")


# ---------------------------------------------------------------------------
# Part 2. Conformance. The model is worthless unless it speaks for the code.
# ---------------------------------------------------------------------------

def conformance() -> None:
    """
    Drive the real issuer over every trace of three proposals drawn from two
    different chains at three sizes, and require the implementation to
    agree with the model on every step.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    from seal import Checkpoint, EntryKind, SealChain
    from seal.checkpoint import CheckpointRefusal, Issuer

    def build(label: str) -> SealChain:
        chain = SealChain("assignment-1", opened_ns=0, chain_label=label)
        for i in range(5):
            chain.append(EntryKind.RUN_SEAL, {"run": f"{label}-{i}"},
                         1_000 * (i + 1))
        return chain

    chains = {"A": build("A"), "B": build("B")}
    proposals = [(c, n) for c in ("A", "B") for n in (2, 3, 4)]

    mismatches = 0
    for trace in itertools.product(proposals, repeat=3):
        issuer = Issuer("custodian", ec.generate_private_key(ec.SECP256R1()))
        prior = None  # (label, size, head)
        for step, (label, size) in enumerate(trace):
            entries = chains[label].entries[:size]
            head = entries[-1].block_hash
            if prior is None:
                predicted = True
            else:
                predicted = accepts(
                    True, prior[1], prior[2], size, head,
                    extends=(label == prior[0] and size > prior[1]),
                    z3=False)
            try:
                issuer.issue(Checkpoint("assignment-1", size, head, 0,
                                        "custodian"), entries)
                actual = True
            except CheckpointRefusal:
                actual = False
            if actual != predicted:
                mismatches += 1
                print(f"        trace={trace} step={step} "
                      f"model={predicted} code={actual}")
                break
            if actual:
                prior = (label, size, head)

    report(f"conformance: real Issuer matches the model on "
           f"{len(proposals) ** 3} traces", mismatches == 0,
           f"{mismatches} traces disagreed")


def main() -> int:
    print("\nSPEC_checkpoint_issuer: O(1) issuer state is sufficient\n")
    prove_local_check_implies_global_property()
    prove_the_refusals_are_necessary()
    prove_the_guard_is_not_vacuous()
    prove_bounded_traces_are_clean()
    conformance()

    print()
    if FAILURES:
        print("POLICY BREACH")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("VERIFICATION SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
