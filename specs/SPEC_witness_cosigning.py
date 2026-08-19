"""
SPEC: a stateful witness cannot be walked into cosigning a split view.

WHAT IS BEING PROVED

`witness.Witness` keeps the last tree head it signed per log and refuses
anything that is not a consistent extension. The property wanted is that across
a whole sequence of requests, no single witness ever produces two cosignatures
that cannot both be true. As with the checkpoint issuer, the witness only
compares against its immediate predecessor, so the question is whether O(1)
memory is enough to enforce a property over the entire history. It is, and the
induction is here.

WHAT IS NOT BEING PROVED

That a witness set is large enough, or independent, or that anybody counts
them. Those are operational questions. Note also what the C2SP specifications
do and do not say: `tlog-witness` frames split-view resistance as an
intersection condition between what clients accept and what monitors accept,
not as a property of witness-set parity, and no specification states that one
witness establishes append-only outright.

This proves the local refusal is sound, which is the part that lives in code.
It says nothing about how many witnesses to run.
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


def cosigns(has_prior, prior_size, prior_root, size, root, consistent,
            same_key, *, z3=True):
    """
    Whether a witness holding (prior_size, prior_root) cosigns (size, root).

    Mirrors `Witness.cosign` clause for clause: a rotated log key, an
    equivocation at one size, a shrink, and a growth without a verifying
    consistency proof are each refused.
    """
    and_, or_, not_, imp = (And, Or, Not, Implies) if z3 else (
        lambda *a: all(a), lambda *a: any(a), lambda a: not a,
        lambda a, b: (not a) or b)
    return or_(
        not_(has_prior),
        and_(
            same_key,
            not_(and_(size == prior_size, root != prior_root)),
            not_(size < prior_size),
            imp(size > prior_size, consistent),
        ),
    )


def prove_one_witness_never_signs_two_truths_at_one_size() -> None:
    """
    Invariant against any earlier cosigned head (s_e, r_e):

        s_e <= prior_size  and  (s_e == prior_size implies r_e == prior_root)

    Preserved by every accepted transition, therefore true of the whole history
    however long it runs.
    """
    s_e, r_e = Int("s_e"), Int("r_e")
    ps, pr = Int("prior_size"), Int("prior_root")
    size, root = Int("size"), Int("root")
    consistent, same_key = Bool("consistent"), Bool("same_key")

    solver = Solver()
    solver.add(
        And(s_e <= ps, Implies(s_e == ps, r_e == pr)),
        cosigns(True, ps, pr, size, root, consistent, same_key),
        Not(And(s_e <= size, Implies(s_e == size, r_e == root))),
    )
    result = solver.check()
    report("induction: one witness never cosigns two roots at one size",
           result == unsat,
           "" if result == unsat else f"counterexample {solver.model()}")


def prove_a_rotated_key_cannot_reset_the_memory() -> None:
    """
    Key rotation is how a log would otherwise walk away from its own history
    without anything registering, so it must not be a route to a fresh start.
    """
    ps, pr = Int("prior_size"), Int("prior_root")
    size, root = Int("size"), Int("root")
    solver = Solver()
    solver.add(Not(Bool("same_key")),
               cosigns(True, ps, pr, size, root, True, Bool("same_key")))
    report("necessity: a rotated log key is never cosigned",
           solver.check() == unsat)


def prove_not_vacuous() -> None:
    solver = Solver()
    solver.add(cosigns(True, Int("a"), Int("b"), Int("c"), Int("d"), True, True),
               Int("a") == 3, Int("b") == 10, Int("c") == 7, Int("d") == 11)
    report("anti-vacuity: an honest extension is cosigned",
           solver.check() == sat)


def prove_bounded_traces_are_clean(depth: int = 5) -> None:
    solver = Solver()
    sz = [Int(f"sz_{i}") for i in range(depth)]
    rt = [Int(f"rt_{i}") for i in range(depth)]
    cons = [Bool(f"cons_{i}") for i in range(depth)]
    key = [Bool(f"key_{i}") for i in range(depth)]
    acc = [Bool(f"acc_{i}") for i in range(depth)]

    has, ps, pr = Bool("has_0"), Int("ps_0"), Int("pr_0")
    solver.add(Not(has))
    state = [(has, ps, pr)]
    for i in range(depth):
        h, s, r = state[-1]
        solver.add(acc[i] == cosigns(h, s, r, sz[i], rt[i], cons[i], key[i]))
        nh, ns, nr = Bool(f"has_{i+1}"), Int(f"ps_{i+1}"), Int(f"pr_{i+1}")
        solver.add(nh == Or(h, acc[i]))
        solver.add(Implies(acc[i], And(ns == sz[i], nr == rt[i])))
        solver.add(Implies(Not(acc[i]), And(ns == s, nr == r)))
        state.append((nh, ns, nr))

    solver.add(Or(*[And(acc[i], acc[j], sz[i] == sz[j], rt[i] != rt[j])
                    for i, j in itertools.combinations(range(depth), 2)]))
    result = solver.check()
    report(f"bounded traces to depth {depth}: no split view reachable",
           result == unsat,
           "" if result == unsat else f"trace {solver.model()}")


def conformance() -> None:
    """
    Drive the real witness over every trace of three head proposals drawn from
    two divergent logs at three sizes, and require agreement at every step.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    from seal import sign_head
    from seal.log import TreeHead, consistency_proof, leaf_hash
    from seal.log import root as tree_root
    from seal.witness import Witness, WitnessRefusal

    log_key = ec.generate_private_key(ec.SECP256R1())

    # Two divergent logs as plain leaf lists. The proof offered has to run from
    # the prior size to the size actually being presented, so it is computed
    # over the prefix rather than over the whole log. Computing it over the
    # whole log is what a careless caller does, and the first run of this spec
    # did exactly that: the model said accept, the code refused, and the
    # disagreement was in the harness rather than in `Witness`.
    leaves = {
        "A": [leaf_hash({"run": i}) for i in range(5)],
        "B": [leaf_hash({"run": 900 + i}) for i in range(5)],
    }
    proposals = [(c, n) for c in ("A", "B") for n in (2, 3, 4)]

    mismatches = 0
    for trace in itertools.product(proposals, repeat=3):
        w = Witness("board", ec.generate_private_key(ec.SECP256R1()))
        prior = None
        for step, (label, size) in enumerate(trace):
            prefix = leaves[label][:size]
            head = sign_head(TreeHead(size, tree_root(prefix), 1_000 + step,
                                      "semafide"), log_key)
            if prior is None:
                predicted = True
                proof = []
            else:
                same_chain = label == prior[0]
                grows = size > prior[1]
                predicted = cosigns(True, prior[1], prior[2], size,
                                    head["root"],
                                    consistent=(same_chain and grows),
                                    same_key=True, z3=False)
                proof = (consistency_proof(prefix, prior[1])
                         if same_chain and grows else [])
            try:
                w.cosign(head, proof)
                actual = True
            except WitnessRefusal:
                actual = False
            if actual != predicted:
                mismatches += 1
                print(f"        trace={trace} step={step} "
                      f"model={predicted} code={actual}")
                break
            if actual:
                prior = (label, size, head["root"])

    report(f"conformance: real Witness matches the model on "
           f"{len(proposals) ** 3} traces", mismatches == 0,
           f"{mismatches} traces disagreed")


def main() -> int:
    print("\nSPEC_witness_cosigning: O(1) witness state is sufficient\n")
    prove_one_witness_never_signs_two_truths_at_one_size()
    prove_a_rotated_key_cannot_reset_the_memory()
    prove_not_vacuous()
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
