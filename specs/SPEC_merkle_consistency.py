"""
SPEC: no proof exists that makes a rewritten log verify as an extension.

WHAT IS BEING PROVED

`log.verify_consistency` is the arithmetic that holds a custodian to its own
history. Given a tree head an examiner recorded earlier and a head the custodian
publishes now, the custodian must produce a proof that today's tree contains the
earlier one unchanged. The claim the whole custody argument rests on is not that
an honest proof verifies. It is that a dishonest one cannot: if an entry was
removed or altered, no proof exists at all.

That is a claim over an infinite space of candidate proofs, and a test can only
sample it. The unit test that stood in for this tried about two hundred strings
built from six values. Here the adversary is symbolic. Every element of the
proof is a free variable ranging over the whole hash space, and the solver is
asked whether any assignment makes the verifier accept.

HOW THE HASH IS MODELLED

As a Z3 datatype with two constructors, `leaf(i)` and `node(l, r)`. Datatype
constructors are injective and mutually distinct by construction, which is
exactly an idealised collision-resistant hash with domain separation between
leaves and interior nodes. `log.py` enforces that separation with distinct byte
prefixes; the model gets it for free.

This is the standard symbolic treatment and it assumes what it should assume.
Collision resistance of SHA-256 is not proved here and is not the property in
question. What is proved is that the proof-checking structure is sound given a
hash that does not collide.

WHY THE CONTROL FLOW IS CONCRETE

`verify_consistency` branches on `fn` and `sn`, which derive from the two sizes,
and it iterates over the proof list. For a fixed old size, new size, and proof
length, every branch is decided before any hash value is examined. So the
algorithm can be run over symbolic terms with concrete sizes, and the result is
a condition rather than a boolean. That is what makes an unbounded adversary
tractable at all.

WHAT IS NOT BEING PROVED

Unboundedness in tree size. This is bounded model checking: sizes up to a limit,
proof lengths up to a limit. A structural defect that only appears at size
ninety would not be caught. The bound is stated in the output rather than
implied.

And, as with every spec here, the model is not left to speak for the code. The
conformance pass runs the same mirror with a real SHA-256 node function and
requires it to agree with `log.verify_consistency` on every honest case and on
every forged case, so a mirror that drifted from the implementation is a
failure rather than a silent pass.
"""

from __future__ import annotations

import itertools
import pathlib
import sys

from z3 import And, BoolVal, Const, Datatype, IntSort, Not, Solver, sat, unsat

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "code"))

FAILURES: list[str] = []
MAX_SIZE = 6
MAX_PROOF_LEN = 5


def report(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        FAILURES.append(f"{name}: {detail}" if detail else name)


CALLED_PROVE_FUNCTIONS: set[str] = set()


def _call(fn) -> None:
    """
    Run a `prove_*` function and record that it ran.

    `main` lists these calls explicitly rather than discovering them, which
    keeps the printed order deliberate. The cost is that a `prove_*` function
    added later and never added to that list would simply never run, silently
    reducing what this file checks while still printing VERIFICATION SUCCESS,
    the exact failure mode the CI `specs` job already guards against one level
    up for a spec file going missing entirely. `main`'s closing check compares
    this set against every `prove_*` name actually defined in the module, so
    the same mistake at the function level fails loudly instead.
    """
    CALLED_PROVE_FUNCTIONS.add(fn.__name__)
    fn()


# ---------------------------------------------------------------------------
# The idealised hash. Injective and domain-separated by construction.
# ---------------------------------------------------------------------------

_H = Datatype("H")
_H.declare("leaf", ("id", IntSort()))
_H.declare("node", ("l", _H), ("r", _H))
H = _H.create()


def sym_node(a, b):
    return H.node(a, b)


def sym_leaf(i):
    return H.leaf(i)


# ---------------------------------------------------------------------------
# The mirror. One implementation of the RFC 6962 structure, run over symbolic
# terms for the proofs and over real hashes for the conformance pass.
# ---------------------------------------------------------------------------

def _split(n: int) -> int:
    """Largest power of two strictly less than n. Mirrors `log._split`."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def mk_root(leaves, node):
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node(mk_root(leaves[:k], node), mk_root(leaves[k:], node))


def _mk_subproof(leaves, m, is_complete, node):
    n = len(leaves)
    if m == n:
        return [] if is_complete else [mk_root(leaves, node)]
    k = _split(n)
    if m <= k:
        return _mk_subproof(leaves[:k], m, is_complete, node) + [mk_root(leaves[k:], node)]
    return _mk_subproof(leaves[k:], m - k, False, node) + [mk_root(leaves[:k], node)]


def mk_proof(leaves, m, node):
    n = len(leaves)
    if m == 0 or m == n:
        return []
    return _mk_subproof(leaves, m, True, node)


def accepts(old_size, old_root, new_size, new_root, proof, node, AND, FALSE):
    """
    The accept condition of `log.verify_consistency`, clause for clause.

    Returns a condition rather than a boolean, so the same code serves the
    symbolic run and the concrete conformance run. Every branch below is
    decided by the sizes and the proof length, never by a hash value.
    """
    if old_size > new_size:
        return FALSE
    if old_size == new_size:
        return AND(old_root == new_root) if not proof else FALSE
    if old_size == 0:
        return FALSE if proof else AND()

    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    if not proof:
        return FALSE

    if old_size & (old_size - 1) == 0:
        fr = sr = old_root
        rest = proof
    else:
        fr = sr = proof[0]
        rest = proof[1:]

    for sibling in rest:
        if sn == 0:
            return FALSE
        if fn & 1 or fn == sn:
            fr = node(sibling, fr)
            sr = node(sibling, sr)
            while fn != 0 and fn & 1 == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr, sibling)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return FALSE
    return AND(fr == old_root, sr == new_root)


def _sym_and(*args):
    return And(*args) if args else BoolVal(True)


SYM = dict(node=sym_node, AND=_sym_and, FALSE=BoolVal(False))
CONCRETE = dict(AND=lambda *a: all(a) if a else True, FALSE=False)


# ---------------------------------------------------------------------------
# Part 1. Completeness. The honest proof always verifies.
# ---------------------------------------------------------------------------

def prove_honest_proofs_verify() -> None:
    """
    A soundness result on its own is satisfied by a verifier that rejects
    everything, so completeness is checked first and separately.
    """
    bad = []
    for n in range(2, MAX_SIZE + 1):
        leaves = [sym_leaf(i) for i in range(n)]
        for m in range(1, n):
            cond = accepts(m, mk_root(leaves[:m], sym_node), n,
                           mk_root(leaves, sym_node),
                           mk_proof(leaves, m, sym_node), **SYM)
            s = Solver()
            s.add(Not(cond))
            if s.check() != unsat:
                bad.append((m, n))
    report(f"completeness: every honest proof verifies, sizes to {MAX_SIZE}",
           not bad, f"failed at {bad}")


# ---------------------------------------------------------------------------
# Part 2. Soundness. This is the result.
# ---------------------------------------------------------------------------

def prove_no_forged_proof_is_accepted() -> None:
    """
    The custodian altered entry j and now wants the examiner's earlier head to
    verify against the rewritten tree. Every element of the proof it offers is
    a free variable. The question put to the solver is whether any assignment
    at all makes the verifier accept.

    Injectivity of the datatype is what forbids it: a root built from a
    different leaf sequence is a different term, and no chain of `node`
    applications closes the gap.
    """
    checked = 0
    breaks = []
    for n in range(2, MAX_SIZE + 1):
        honest = [sym_leaf(i) for i in range(n)]
        for m in range(1, n):
            old_root = mk_root(honest[:m], sym_node)
            for j in range(m):                       # which entry was altered
                rewritten = list(honest)
                rewritten[j] = sym_leaf(500 + j)
                new_root = mk_root(rewritten, sym_node)
                for length in range(MAX_PROOF_LEN + 1):
                    proof = [Const(f"p_{n}_{m}_{j}_{length}_{i}", H)
                             for i in range(length)]
                    cond = accepts(m, old_root, n, new_root, proof, **SYM)
                    s = Solver()
                    s.add(cond)
                    checked += 1
                    if s.check() != unsat:
                        breaks.append((m, n, j, length))
    report(f"soundness: no proof verifies a rewritten log "
           f"({checked} symbolic adversaries, sizes to {MAX_SIZE}, "
           f"proof lengths to {MAX_PROOF_LEN})",
           not breaks, f"forgery possible at {breaks[:5]}")


def prove_a_shrunken_or_swapped_head_is_refused() -> None:
    """
    Two structural refusals that do not depend on the proof at all, checked
    against a symbolic proof so a clever one cannot talk the verifier past
    them.
    """
    leaves = [sym_leaf(i) for i in range(4)]
    root4 = mk_root(leaves, sym_node)
    root2 = mk_root(leaves[:2], sym_node)

    cases = []
    for length in range(MAX_PROOF_LEN + 1):
        p = [Const(f"q_{length}_{i}", H) for i in range(length)]
        cases.append(("a later head describing a smaller log",
                      accepts(4, root4, 2, root2, p, **SYM)))
        cases.append(("two different roots at one size",
                      accepts(4, root4, 4, root2, p, **SYM)))

    bad = [name for name, cond in cases
           if (lambda s: (s.add(cond), s.check())[1])(Solver()) != unsat]
    report("necessity: a shrink and a same-size mismatch are refused "
           "against any proof", not bad, f"admitted {set(bad)}")


def prove_the_verifier_is_not_vacuous() -> None:
    """
    A verifier that accepts nothing satisfies soundness trivially. Completeness
    above rules that out for honest proofs; this states it as its own check.
    """
    leaves = [sym_leaf(i) for i in range(5)]
    cond = accepts(2, mk_root(leaves[:2], sym_node), 5,
                   mk_root(leaves, sym_node),
                   mk_proof(leaves, 2, sym_node), **SYM)
    s = Solver()
    s.add(cond)
    report("anti-vacuity: the accept condition is satisfiable",
           s.check() == sat)


# ---------------------------------------------------------------------------
# Part 3. Conformance. The mirror has to be the code.
# ---------------------------------------------------------------------------

def conformance() -> None:
    """
    Differential testing of the mirror against `log.verify_consistency`, over
    adversarial proof values rather than honest ones.

    An earlier version fed only proofs derived from honest ones and passed
    while four of seven deliberate breaks in `log.py` went unnoticed. A
    conformance pass that never reaches a branch does not cover it, and one
    that never feeds a hostile value only covers the happy path. So the proofs
    here are drawn from a pool that includes real subtree roots, a foreign
    hash, and a repeated value, enumerated exhaustively to a small length, and
    the old root is sometimes deliberately the wrong one.

    A model that has drifted from the implementation proves nothing about the
    implementation, which is the defect this package fired KC2 over.
    """
    from seal.log import _node, consistency_proof, leaf_hash
    from seal.log import root as real_root
    from seal.log import verify_consistency

    real = dict(node=_node, **CONCRETE)
    mismatches, checked = [], 0

    N = 6
    honest = [leaf_hash({"run": i}) for i in range(N)]
    foreign = leaf_hash({"run": 9999})

    # The mirror's tree hash must be the real one before anything else counts.
    for n in range(1, N + 1):
        if mk_root(honest[:n], _node) != real_root(honest[:n]):
            mismatches.append(("root", n))

    pool = [honest[0], real_root(honest[:2]), real_root(honest[2:4]), foreign]
    adversarial = [list(t) for length in range(4)
                   for t in itertools.product(pool, repeat=length)]

    for n in range(1, N + 1):
        new_root = real_root(honest[:n])
        for m in range(0, N + 1):
            honest_proof = consistency_proof(honest[:n], m) if m <= n else []
            # Two old roots: the true one, and a wrong one of the same shape.
            # Without the second, a verifier that stops comparing roots at
            # equal sizes looks correct.
            # Both heads vary. The custodian controls the head it publishes,
            # so a conformance pass that only ever supplies the honest new
            # root leaves the adversary's real degree of freedom untested.
            for o_label, old_root in (("true", real_root(honest[:m])),
                                      ("wrong", foreign)):
                for n_label, nr in (("true", new_root),
                                    ("wrong", foreign),
                                    ("spine", _node(real_root(honest[:m]),
                                                    foreign))):
                    for p in adversarial + [honest_proof]:
                        got = accepts(m, old_root, n, nr, p, **real)
                        want = verify_consistency(m, old_root, n, nr, p)
                        checked += 1
                        if bool(got) != bool(want):
                            mismatches.append((o_label, n_label, m, n, len(p)))

    report(f"conformance: mirror matches log.verify_consistency on {checked} "
           f"cases, adversarial proofs, sizes to {N}", not mismatches,
           f"disagreed at {mismatches[:5]}")


def main() -> int:
    print("\nSPEC_merkle_consistency: a rewritten log has no proof\n")
    _call(prove_honest_proofs_verify)
    _call(prove_no_forged_proof_is_accepted)
    _call(prove_a_shrunken_or_swapped_head_is_refused)
    _call(prove_the_verifier_is_not_vacuous)
    conformance()

    defined = {name for name, obj in globals().items()
              if name.startswith("prove_") and callable(obj)}
    missed = defined - CALLED_PROVE_FUNCTIONS
    report("every prove_* function this file defines was actually run",
          not missed, f"defined but never called: {sorted(missed)}")

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
