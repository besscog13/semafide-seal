"""
Retired vocabulary must not leak past the lines that license it.

`BindingLevel` and its five rungs (`BUNDLED`, `PRECEDENCE`, `WITNESSED`,
`REDERIVABLE`, `REDERIVED`) are a lossy, backward-compatible display
projection over the five real propositions -- not a claim vocabulary of
their own. They still appear correctly in a handful of places that explain
the projection or quote what an external artifact calls it. A flat
forbidden-list fails on those correct uses the moment it runs. This check
asserts a narrower relationship instead: every line carrying one of these
terms in README.md or docs/executive-thesis.md must be byte-identical to a
line already known and licensed here. A new, unlicensed occurrence --
anywhere in either file, or anywhere else under docs/ -- fails the check.
Editing a licensed line, even by one word, also fails it, since the
exemption is for that exact sentence, not for the general topic.

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
        "For the same state space explored interactively rather than read as terminal output, see [the design canvas](https://claude.ai/code/artifact/24c8c27e-a797-4cca-851a-ac95dfe9f88a): a five-decision panel showing which of the five propositions survive each of the 96 reachable combinations, driven by the real verifier rather than illustrative numbers. It speaks the verifier's own vocabulary directly (`REDERIVED`, `OPERATOR_CANNOT_HOLD`, `kc2_fires`), so it assumes the reader already has the propositions table below rather than explaining them from scratch.",
        "Successful re-derivation therefore does not make `historical_execution_established` true. A generic signature over a supplied bundle does not make `witness_attestation` true. `BindingLevel` remains only as a lossy, backward-compatible display projection.",
        "The verifier reports the epistemic propositions above. Its legacy `BindingLevel` projection is retained for existing consumers, but must not be read as an evidence ladder:",
        "- **BUNDLED:** inputs and output are present together, but nothing establishes their execution relationship.",
        "- **WITNESSED:** a separately trusted observer signed an explicit observed-execution attestation binding the run, committed evidence, sealed action, and capture reference. A signature over a supplied bundle or a self-declared witness field is not enough.",
        "- **REDERIVABLE:** a complete execution recipe links to the claimed evidence and output and remains available for execution.",
        "- **REDERIVED:** a verifier actually executed that recipe and reproduced the sealed output.",
    },
    pathlib.Path("docs/executive-thesis.md"): {
        "**On the legacy `BindingLevel` projection.** The verifier also emits an ordered `BindingLevel` value (`BUNDLED` → `PRECEDENCE` → `WITNESSED` → `REDERIVABLE` → `REDERIVED`) as a single summary figure for readers who want one. It is a **lossy display projection, not the evidence model**, and it must not be used to infer a proposition not stated in the table above. In particular `BUNDLED` is not an independent proposition; it is the floor the projection returns when `precedence` is false.",
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

    print("clean: retired terms confined to their licensed lines in README.md "
          "and executive-thesis.md, absent everywhere else in docs/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
