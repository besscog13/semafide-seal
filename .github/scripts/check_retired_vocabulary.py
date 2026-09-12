"""
Retired vocabulary must not leak past the lines that license it.

`BindingLevel` and its five rungs (`BUNDLED`, `PRECEDENCE`, `WITNESSED`,
`REDERIVABLE`, `REDERIVED`) have been removed from `code/seal` entirely.
They still appear correctly in a handful of documentation lines that
record the removal itself and explain what the terms meant. A flat
forbidden-list fails on those correct uses the moment it runs. This check
asserts a narrower relationship instead: every line carrying one of these
terms in any file listed in EXEMPT_LINES must be byte-identical to a line
already known and licensed here. A new, unlicensed occurrence -- in one of
those files, or anywhere else under docs/ -- fails the check. Editing a
licensed line, even by one word, also fails it, since the exemption is for
that exact sentence, not for the general topic.

Run from the repository root.
"""

import pathlib
import re
import sys

RETIRED_WORDS = re.compile(r"\b(?:BUNDLED|WITNESSED|REDERIVABLE|REDERIVED)\b")
BINDING_LEVEL = re.compile(r"BindingLevel|binding level")


def hits(text: str) -> list[str]:
    return sorted(set(RETIRED_WORDS.findall(text) + BINDING_LEVEL.findall(text)))


# Every line below is copied verbatim, byte for byte, from the file it
# licenses. Each is a real, current, correctly caveated use of a retired
# term, not an aggregate passage: rewording or even trimming whitespace on
# any of these lines makes the lookup miss and the check fail loudly,
# rather than silently widening what it exempts to cover the edit.
EXEMPT_LINES: dict[pathlib.Path, set[str]] = {
    pathlib.Path("README.md"): {
        "The verifier reports the epistemic propositions above and nothing else in that register. An earlier revision of this package also exposed `BindingLevel`, a single derived value that collapsed the five propositions into one rung on a lossy summary ladder; it has been removed, since it could not even represent the strongest of the five claims and every place it could mislead a reader was easier to fix by removing it than by re-caveating it again.",
    },
    pathlib.Path("docs/executive-thesis.md"): {
        "**On the removed `BindingLevel` projection.** An earlier revision of the verifier also emitted an ordered `BindingLevel` value (`BUNDLED` → `PRECEDENCE` → `WITNESSED` → `REDERIVABLE` → `REDERIVED`), a single summary figure derived from the table above. It has been removed. It could not represent `historical_execution_established`, the strongest of the five propositions, under any combination of the others, since the derivation rule never checked it; a summary figure that cannot express the strongest real claim is a defect rather than a convenience.",
    },
    pathlib.Path("CONTRIBUTING.md"): {
        "**`BindingLevel` has been removed, and nothing replaces it.** An earlier",
        "revision of the verifier emitted an ordered level, `BUNDLED` through",
        "`REDERIVED`, derived from the five propositions. Its derivation rule never",
    },
    # This file's whole job is to name what is retired and why, so unlike the
    # other two, several of its lines legitimately carry a retired term. Each
    # one is still licensed individually rather than exempting the file as a
    # whole, for the same reason as everywhere else: a new, unlicensed line
    # added later should fail loudly rather than inherit a blanket pass.
    pathlib.Path("docs/claim-vocabulary.md"): {
        '`verifier.py` already treats `EvidencePropositions` as the source of truth and marks `BindingLevel` as "a lossy, backwards-compatible display projection." But the site\'s Instrument page is built entirely on that deprecated projection, and the homepage list mixes three propositions with one deprecated rung and one product category:',
        "| Demo output | `binding level`, `coverage`, `completeness`, `KC2 fires` |",
        "**Status update, superseding the rest of this section.** The original plan below was to keep `BindingLevel` in code for backward compatibility while banning it from every user-facing surface. That plan is superseded: the enum, the method that derived it, the field that carried it, and every print statement that showed it have all been removed from `code/seal` entirely. There is no compat shim and no output path left to guard, because there is no code path left at all. The table below is kept as the historical record of what each term meant and what replaced it, for a reader who encounters the word in an old document, screenshot, or memory and needs to know it is gone rather than merely hidden.",
        "| Binding, binding level, `BindingLevel` | The five propositions. Removed from code entirely; nothing to keep out of output, because there is no output for it anymore. |",
        "**`code/seal/demo.py` and `demo_60s.py`** — done, in two stages. `demo.py`'s `show()` function used to lead each artifact with `binding level`, unlabeled, and never printed the five propositions by name at all. It first went through an intermediate fix, printing the five individually, then `binding_level` last and labeled `legacy display`; once `BindingLevel` was removed from code entirely, that labeled line was removed too, since there was nothing left for it to print. `demo_60s.py`, the script `README.md` quotes verbatim and CI checks against that quote, was left untouched throughout, since it already showed the five correctly and never printed `binding level` at all.",
        "**`code/seal/verifier.py`** — done, superseded by a larger change. The `BindingLevel` docstring first gained a line stating the projection must not appear in user-facing output; `BindingLevel` itself, the class, the derivation method, the `VerificationReport` field, and every reference to it in `code/seal/__init__.py`, `code/seal/evidence.py`, and `code/seal/README.md`, have since been removed entirely, along with every test assertion that referenced it (rewritten to assert the same fact directly against the five propositions instead of through the derived value).",
    },
}


def main() -> int:
    failures: list[str] = []

    for path, exempt in EXEMPT_LINES.items():
        text = path.read_text(encoding="utf-8")
        unmatched_exempt = set(exempt)
        for line in text.splitlines():
            if not hits(line):
                continue
            if line in exempt:
                unmatched_exempt.discard(line)
                continue
            failures.append(f"{path}: unlicensed line carries a retired term: {line!r}")
        if unmatched_exempt:
            failures.append(
                f"{path}: {len(unmatched_exempt)} exempted line(s) no longer found "
                "verbatim in the file; the exemption may be pointing at stale text: "
                f"{sorted(unmatched_exempt)!r}"
            )

    # Every other doc surface gets no exemption at all.
    for path in pathlib.Path("docs").rglob("*.md"):
        if path in EXEMPT_LINES:
            continue
        found = hits(path.read_text(encoding="utf-8"))
        if found:
            failures.append(f"{path}: {found} appear with no licensed exemption in this file")

    if failures:
        print("::error::Retired vocabulary leaked outside its licensed lines")
        for f in failures:
            print(f" - {f}")
        return 1

    print("clean: retired terms confined to their licensed lines in "
          f"{', '.join(str(p) for p in EXEMPT_LINES)}, absent everywhere else in docs/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
