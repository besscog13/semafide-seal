"""
SPEC: an assignment statement can gain chains and never lose them.

WHAT IS BEING PROVED

`assignment.Issuer` signs statements of which chains an assignment holds. The
attack it exists to stop is the same one the per-chain issuer stops, one level
out: sign a five-chain statement, then a three-chain statement, and let the
sealer produce whichever suits. An assignment only ever gains chains and no
chain ever loses entries, so the issuer refuses any statement that drops a chain
it has already recorded or shortens one.

The property wanted is monotone growth across the whole history, and the issuer
compares only against its immediate predecessor. The induction is here.

WHAT IS NOT BEING PROVED

That the custodian was told about every chain. A run sealed to a chain that was
never submitted is invisible to this and to everything else in the package,
because nothing here observes the sealer's machine. That is capture
completeness, which is KC3, and it is open. This proves the disclosure side is
monotone given what the custodian saw.
"""

from __future__ import annotations

import itertools
import pathlib
import sys

from z3 import (And, ForAll, Function, Implies, Int, IntSort, Not, Solver,
                sat, unsat)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "code"))

FAILURES: list[str] = []


def report(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        FAILURES.append(f"{name}: {detail}" if detail else name)


def prove_statements_are_monotone() -> None:
    """
    Chains are modelled as an uninterpreted membership predicate and a count
    per chain. Absent chains carry count zero, so dropping a chain and
    shortening one to nothing are the same event, which is the honest reading:
    an examiner cannot tell them apart and neither should the issuer.

    Invariant against any earlier accepted statement E and the current last L:
    every chain in E is in L at no fewer entries. The obligation is that an
    accepted successor N preserves it.
    """
    in_e = Function("in_e", IntSort(), IntSort())    # entries, 0 means absent
    in_l = Function("in_l", IntSort(), IntSort())
    in_n = Function("in_n", IntSort(), IntSort())

    c = Int("c")
    invariant = ForAll([c], Implies(in_e(c) > 0, in_l(c) >= in_e(c)))
    guard = ForAll([c], Implies(in_l(c) > 0, in_n(c) >= in_l(c)))
    preserved = ForAll([c], Implies(in_e(c) > 0, in_n(c) >= in_e(c)))

    solver = Solver()
    solver.add(invariant, guard, Not(preserved))
    result = solver.check()
    report("induction: accepted statements never lose a chain or entries",
           result == unsat,
           "" if result == unsat else "counterexample found")


def prove_the_refusals_are_necessary() -> None:
    """A dropped chain and a shortened chain must both be inadmissible."""
    in_l = Function("in_l", IntSort(), IntSort())
    in_n = Function("in_n", IntSort(), IntSort())
    c, k = Int("c"), Int("k")
    guard = ForAll([c], Implies(in_l(c) > 0, in_n(c) >= in_l(c)))

    for name, breach in [
        ("dropped chain", And(in_l(k) > 0, in_n(k) == 0)),
        ("shortened chain", And(in_l(k) > 0, in_n(k) < in_l(k), in_n(k) > 0)),
    ]:
        solver = Solver()
        solver.add(breach, guard)
        result = solver.check()
        report(f"necessity: the guard cannot admit a {name}", result == unsat,
               "" if result == unsat else "admitted")


def prove_not_vacuous() -> None:
    """Growth has to remain possible, or the issuer is useless after one call."""
    in_l = Function("in_l", IntSort(), IntSort())
    in_n = Function("in_n", IntSort(), IntSort())
    c = Int("c")
    solver = Solver()
    solver.add(ForAll([c], Implies(in_l(c) > 0, in_n(c) >= in_l(c))),
               in_l(Int("x")) == 2, in_n(Int("x")) == 7)
    report("anti-vacuity: a grown statement is accepted", solver.check() == sat)


def conformance() -> None:
    """
    Drive the real issuer over every trace of three statements drawn from
    subsets of three chains at two lengths, and require agreement at each step.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    from seal import AssignmentCheckpoint, ChainRef, EntryKind, SealChain
    from seal.assignment import AssignmentRefusal, Issuer

    def build(label: str) -> SealChain:
        chain = SealChain("assignment-1", opened_ns=0, chain_label=label)
        for i in range(3):
            chain.append(EntryKind.RUN_SEAL, {"run": f"{label}-{i}"},
                         1_000 * (i + 1))
        return chain

    chains = {k: build(k) for k in ("X", "Y")}

    def ref(label: str, n: int) -> ChainRef:
        entries = chains[label].entries[:n]
        return ChainRef(chains[label].chain_id, entries[-1].block_hash, n)

    # Statements: which chains, at what length.
    statements = []
    for labels in (("X",), ("Y",), ("X", "Y")):
        for n in (2, 4):
            statements.append(tuple((lb, n) for lb in labels))

    def model_accepts(prior, now) -> bool:
        if prior is None:
            return True
        pm = dict(prior)
        nm = dict(now)
        return all(k in nm and nm[k] >= v for k, v in pm.items())

    mismatches = 0
    for trace in itertools.product(statements, repeat=3):
        issuer = Issuer("custodian", ec.generate_private_key(ec.SECP256R1()))
        prior = None
        for step, stmt in enumerate(trace):
            predicted = model_accepts(prior, stmt)
            refs = tuple(ref(lb, n) for lb, n in stmt)
            try:
                issuer.issue(AssignmentCheckpoint("assignment-1", refs, step,
                                                  "custodian"))
                actual = True
            except AssignmentRefusal:
                actual = False
            if actual != predicted:
                mismatches += 1
                print(f"        trace={trace} step={step} "
                      f"model={predicted} code={actual}")
                break
            if actual:
                prior = stmt

    report(f"conformance: real Issuer matches the model on "
           f"{len(statements) ** 3} traces", mismatches == 0,
           f"{mismatches} traces disagreed")


def main() -> int:
    print("\nSPEC_assignment_issuer: statements grow and never shrink\n")
    prove_statements_are_monotone()
    prove_the_refusals_are_necessary()
    prove_not_vacuous()
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
