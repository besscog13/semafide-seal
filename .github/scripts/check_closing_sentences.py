"""Hedge words in closing sentences. Item one of the three-item lint.

`REVIEW.md` names three items. The second is punctuation and runs in CI. The
third is the two moments and is gated by `check_language.py`. The first reads:

    Read only the final sentences and hunt for "only", "requires",
    "guarantees", and "cannot".

`REVIEW.md` also records that this item "is checked by nothing anywhere", and
that stayed true until this file. Run by hand on 2026-09-24 it found the one
defect in live prose that a full sweep turned up, which the claim gate could
not see: `docs/business-flow.md` said the document names the level the code
supports for each step, "so the sequence cannot drift from the shipped
mechanism". Nothing anywhere asserts that document against the code, and the
same paragraph records that two earlier drafts did drift.

Why a closing sentence and not any sentence. A hedge in the middle of a
paragraph is usually scoping and usually correct. A hedge in the sentence a
section ends on is load-bearing: it is the line a reader carries away, and it
is where an absolute gets asserted without the qualification that would have
sat beside it earlier in the paragraph.

**This reports and never fails.** Of the 24 closing sentences carrying a hedge
word in the private tree, 23 were correct scoping. A gate at that ratio is one
nobody reads, and this project has recorded that a check passing quietly is
worse than no check. The output is a reading list, and the reading is the
check.

Usage:
  python .github/scripts/check_closing_sentences.py [root]
  python .github/scripts/check_closing_sentences.py --selftest
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_language as C     # noqa: E402  the reflow and the file list

HEDGE = re.compile(r"\b(only|requires?|guarantees?|cannot)\b", re.I)

# A section ends at a heading, and a document ends at its last paragraph. Both
# are closings. Anything else is the middle.
HEADING = re.compile(r"^\s{0,3}#{1,6}\s")


def closings(text):
    """Yield (line number, last sentence) for each section of a document.

    Built on `check_language.sentences`, so a closing sentence that wrapped
    across four lines is one sentence here. The hand-run version of this check
    read the last *line* of a section, which is a fragment whenever the closing
    sentence wraps, and 58.7 percent of them do.
    """
    # Section boundaries, by line, then the last sentence before each.
    bounds = [n for n, line in enumerate(text.splitlines(), 1)
              if HEADING.match(line)]
    sents = list(C.sentences(text))
    if not sents:
        return
    edges = bounds + [10 ** 9]
    for edge in edges:
        before = [(n, s) for n, s in sents if n < edge]
        if before:
            yield before[-1]


def run(root: pathlib.Path) -> int:
    files = [f for f in C.targets(root, False) if f.endswith(".md")]
    seen, rows = set(), []
    for name in files:
        for n, s in closings((root / name).read_text(encoding="utf-8")):
            if (name, n) in seen:
                continue
            seen.add((name, n))
            m = HEDGE.search(s)
            if m:
                rows.append((name, n, m.group(0), s))

    print(f"Closing sentences carrying a hedge word: {len(rows)}. "
          "Read them; this never fails.")
    print("A hedge that scopes a claim is right. A hedge that states an "
          "absolute nothing enforces is the defect.\n")
    current = None
    for name, n, word, s in sorted(rows):
        if name != current:
            print(f"  {name}")
            current = name
        print(f"    {n:>5}  [{word}]  {s[:150]}")
    return 0


# (description, markdown, expected closing sentences)
CONTROLS = [
    ("the last sentence of a section, not its last line",
     "# H\n\nOne. A closing sentence that\nwraps across two lines.\n",
     ["A closing sentence that wraps across two lines."]),
    ("each section closes separately",
     "# A\n\nAlpha one. Alpha two.\n\n## B\n\nBeta one.\n",
     ["Alpha two.", "Beta one."]),
    ("a table at the end of a section does not become the closing",
     "# A\n\nThe closing line.\n\n| a | b |\n| c | d |\n",
     ["The closing line."]),
]


def selftest() -> int:
    bad = []
    for desc, src, expected in CONTROLS:
        got = [s for _, s in closings(src)]
        if got != expected:
            bad.append(f"{desc!r}: expected {expected}, got {got}")

    # The rule has to fire, and has to stay quiet on a sentence without a hedge.
    if not HEDGE.search("This only works at size six."):
        bad.append("HEDGE did not fire on a hedge word")
    if HEDGE.search("The chain records every decorated call."):
        bad.append("HEDGE fired on a sentence carrying no hedge word")

    if bad:
        print(f"::error::selftest: {len(bad)} problem(s)")
        for b in bad:
            print(f"  {b}")
        return 1
    print(f"selftest: all {len(CONTROLS)} closing-sentence cases behave, and "
          "the hedge pattern both fires and stays quiet")
    return 0


if __name__ == "__main__":
    # This prints a reading list, so it gets piped into `head` and `grep`.
    # Without this, closing the pipe early raises BrokenPipeError out of a
    # print and the reader sees a traceback under their own output.
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass

    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    raise SystemExit(run(pathlib.Path(args[0]) if args else pathlib.Path(".")))
