"""
Runnable walkthrough of the custody chain: `log.py` and `witness.py`.

    cd code && python -m seal.demo_custody

`demo.py` and `demo_60s.py` both answer the same question -- what does the
verifier establish about ONE sealed artifact -- and both stand in a simpler
mechanism, `checkpoint.py`'s per-chain `Checkpoint`, for the outside party
that vouches for it. Neither ever builds a `TransparencyLog` or asks a
`Witness` to cosign anything.

This script answers a different question, one level up: can the custodian
be caught rewriting ITS OWN history, across everything it has ever
recorded, and what does a witness cosignature buy against two examiners
being shown different heads. That is what the system map's `log`,
`custodian`, and `witness` nodes name, and it is real, tested code
(`code/tests/test_seal_verifier.py`'s split-view section) that had no
walkthrough until this file.

Four scenarios. Each is the custodian's log at a moment, or two moments
compared, never a single artifact in isolation.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from .log import TransparencyLog, heads_consistent, sign_head
from .witness import (
    CONTRADICTION,
    UNRECONCILED,
    Witness,
    WitnessRefusal,
    equivocation,
    equivocation_holds,
    rebut,
)

T0 = 1_753_200_000_000_000_000
RULE = "-" * 68


def _grown_log(n: int, key, log_id: str = "semafide") -> TransparencyLog:
    log = TransparencyLog(log_id)
    for i in range(n):
        log.append({"assignment": f"ASG-{i}", "run": i})
    return log


def main() -> None:
    print(f"\n{RULE}")
    print("  What the custody chain establishes, and where it stops")
    print(RULE)
    print("\n  This is one level up from a single artifact. `demo.py` asks what")
    print("  one sealed run establishes. This asks whether the custodian can")
    print("  be caught rewriting its own history, and what a witness buys")
    print("  against two examiners being shown different heads.")

    custodian_key = ec.generate_private_key(ec.SECP256R1())

    print(f"\n{RULE}\n1. An honest custodian growing its log")
    print("   Three assignments recorded, then two more, nothing removed.\n")
    honest = _grown_log(3, custodian_key)
    early = sign_head(honest.head(T0), custodian_key)
    honest.append({"assignment": "ASG-3", "run": 3})
    honest.append({"assignment": "ASG-4", "run": 4})
    later = sign_head(honest.head(T0 + 1), custodian_key)
    ok, reason = heads_consistent(early, later, honest.consistency_proof(3))
    print(f"   size {early['size']} -> size {later['size']}")
    print(f"   consistent    {ok}")
    print("\n   The proof is arithmetic, not a promise. Given the log's own")
    print("   entries, anyone can recompute it independently of the custodian.")

    print(f"\n{RULE}\n2. A custodian that rewrites instead of only extending")
    print("   Same starting point, but assignment 1 is altered before the")
    print("   log continues.\n")
    rewritten = TransparencyLog("semafide-rewrite")
    for i in range(3):
        rewritten.append({"assignment": f"ASG-{i}", "run": i})
    tampered_early = sign_head(rewritten.head(T0), custodian_key)
    forked = TransparencyLog("semafide-rewrite")
    for i in (0, 99, 2, 3, 4):  # entry 1 replaced, then extended as if honest
        forked.append({"assignment": f"ASG-{i}", "run": i})
    tampered_later = sign_head(forked.head(T0 + 1), custodian_key)
    bad_ok, bad_reason = heads_consistent(
        tampered_early, tampered_later, forked.consistency_proof(3)
    )
    print(f"   consistent    {bad_ok}")
    print(f"   reason        {bad_reason}")
    print("\n   Not withheld, not hidden. The proof does not exist, because")
    print("   the tree it would have to walk through no longer does.")

    print(f"\n{RULE}\n3. A witness refuses to cosign the split")
    print("   The witness sees the honest extension first, then a")
    print("   conflicting head at a size it has already cosigned.\n")
    witness = Witness("state-board", ec.generate_private_key(ec.SECP256R1()))
    conflicting_log = TransparencyLog("semafide")
    for i in (0, 1, 2, 77, 78):
        conflicting_log.append({"assignment": f"ASG-{i}", "run": i})
    conflicting = sign_head(conflicting_log.head(T0 + 2), custodian_key)
    cosig = witness.cosign(later)
    print(f"   cosigned the honest head at size {later['size']}: {bool(cosig)}")
    try:
        witness.cosign(conflicting)
        print("   cosigned the conflicting head too -- this should not print")
    except WitnessRefusal as e:
        print(f"   refused the conflicting head: {e}")
    print("\n   A witness with no memory is a rubber stamp. This one keeps the")
    print("   last head it signed and cannot be talked into a different one")
    print("   at a size it has already committed to, without being")
    print("   compromised rather than merely asked twice.")

    print(f"\n{RULE}\n4. Two heads that cannot both be true, and the difference")
    print("   between them")
    print("   A CONTRADICTION at one size is final. An UNRECONCILED pair at")
    print("   different sizes is rebuttable by producing the real proof.\n")

    same_size_conflict = equivocation(later, conflicting)
    print(f"   same size, different roots -> finality: {same_size_conflict['finality']}")
    assert same_size_conflict["finality"] == CONTRADICTION
    print(f"   independently re-checked    {equivocation_holds(same_size_conflict)}")
    print(f"   rebuttable                  {rebut(same_size_conflict, [])}")

    unreconciled = equivocation(early, later)
    print(f"\n   different sizes, no proof shown -> finality: {unreconciled['finality']}")
    assert unreconciled["finality"] == UNRECONCILED
    fake_proof = rebut(unreconciled, [])
    real_proof = rebut(unreconciled, honest.consistency_proof(3))
    print(f"   rebutted with nothing        {fake_proof}")
    print(f"   rebutted with the real proof {real_proof}")
    print("\n   A CONTRADICTION cannot be rebutted by any proof, however good.")
    print("   An UNRECONCILED pair is not evidence of anything until the")
    print("   custodian is asked for the proof and does not produce a real")
    print("   one. Producing an empty or unrelated proof does not count as")
    print("   an answer, only the one that actually reconciles the two heads.")

    print(f"\n{RULE}")
    print("  Neither structure here appears in `demo.py`. That file hand-signs")
    print("  a per-chain Checkpoint for one artifact; this one is the")
    print("  custodian's own history, checkable by anyone holding two of its")
    print("  signed heads, independent of whether any single artifact inside")
    print("  it verifies. Consistency proofs make a rewrite arithmetic rather")
    print("  than a matter of trust. Witnesses raise the cost of a split view.")
    print("  Neither prevents one; see `witness.py`'s own module docstring")
    print("  for what remains open after both.")
    print(f"{RULE}\n")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        import os
        import sys

        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
