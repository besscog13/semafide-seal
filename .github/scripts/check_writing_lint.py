"""House style is a stated rule in this project and nothing enforced it.

`CONTRIBUTING.md` and the private `REVIEW.md` both require a lint pass before
any document ships: no em dashes, no contractions. Every other claim this
repository makes about itself is asserted by CI rather than described, and
this one was described. It had drifted by sixteen em dashes across three
files before anybody counted, which is the same shape of defect as the test
count the README carried for weeks.

Scans every tracked Markdown file. Code fences are skipped, because a fenced
block quotes real output or a real command and must stay byte-accurate; the
demo block in README.md is asserted verbatim against what `seal.demo_60s`
prints, so relinting it would break a different check.

Possessives are not contractions, and telling them apart is the whole
difficulty. `demo.py's show()` and `the sealer's claim` are ordinary English
and must not fire. So the general pattern matches the unambiguous verb
endings only, never a bare apostrophe-s.

That alone was too blunt, and the first version of this check shipped with
the hole. A handful of apostrophe-s words have no possessive form at all, so
they are always contractions: `it's` against the possessive `its`, and
`that's`, `there's`, `let's`, `what's`, `who's`, `here's`, which have no
possessive sense to protect. Those are listed by name. Everything else
ending in apostrophe-s is left alone, which is what keeps this runnable over
prose nobody wants to rewrite.

It scans tracked files, which on a CI runner is the whole tree. Locally an
unstaged new document is invisible to it, which is worth knowing before
trusting a local pass: the first negative control written against this check
appended a violation to an untracked file and reported clean, correctly.

Run from the repository root.
"""

import pathlib
import re
import subprocess
import sys

EM_DASH = "—"
# Unambiguous verb endings, plus the apostrophe-s words that have no
# possessive form and are therefore always contractions. A bare apostrophe-s
# on anything else is left alone, because it is a possessive far more often
# than it is `is`.
_ALWAYS_CONTRACTION = "it|that|there|let|what|who|here"
CONTRACTION = re.compile(
    r"\b[A-Za-z]+'(?:t|re|ve|ll|m|d)\b"
    rf"|\b(?:{_ALWAYS_CONTRACTION})'s\b",
    re.IGNORECASE,
)


def prose_lines(text: str):
    """Yield (line number, line) outside fenced code blocks."""
    fenced = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            yield n, line


def main() -> int:
    tracked = subprocess.run(
        ["git", "ls-files", "*.md"], capture_output=True, text=True, check=True
    ).stdout.split()

    if not tracked:
        sys.exit("no tracked Markdown found; this check has nothing to assert")

    findings: list[str] = []
    for name in tracked:
        path = pathlib.Path(name)
        for n, line in prose_lines(path.read_text(encoding="utf-8")):
            if EM_DASH in line:
                findings.append(f"{name}:{n}: em dash: {line.strip()[:90]}")
            for hit in CONTRACTION.findall(line):
                findings.append(f"{name}:{n}: contraction {hit!r}: {line.strip()[:70]}")

    if findings:
        print("::error::House style: no em dashes, no contractions. "
              f"{len(findings)} violation(s) in prose outside code fences.")
        for f in findings:
            print(f"  {f}")
        return 1

    print(f"clean: {len(tracked)} tracked Markdown files carry no em dash and "
          "no contraction outside code fences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
