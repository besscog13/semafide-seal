"""Every code symbol a document cites still exists in the package.

`check_system_map.py` asserts that `docs/semafide-system-map.html` matches
`docs/semafide.architecture.json`. Nothing did the same for the documents that
describe the code in prose, and the asymmetry had a consequence.

`docs/business-flow.md` opened by saying it names, for each step, the level the
code actually supports, "so the sequence cannot drift from the shipped
mechanism the way earlier drafts of it did." Nothing anywhere asserted that
document against the code. Only the sync job compared its two copies, which
catches a divergence between trees and never a divergence from the package.
The document asserting correspondence was the one document nobody checked.
That sentence was corrected on 2026-09-24 and this file is the other half.

**What this asserts.** Every file path a listed document cites in backticks
exists. Every identifier and constant it cites in backticks appears somewhere
in `code/seal`, as a name or inside a string literal, so an enum member given
as a string still counts.

**Retired names are not drift.** `BindingLevel` and its five rungs were
removed from `code/seal` on purpose, and `check_retired_vocabulary.py` already
declares them and polices where they may still appear. A retired name missing
from the package is the asserted state, not a defect, so this file imports
that declaration rather than keeping a second list that could disagree with it.

**What this does not assert, stated plainly.** It does not check that the
behaviour a document describes is the behaviour the code has. The provenance
note in `business-flow.md` records three earlier drafts that were wrong that
way: a pre-execution commit the decorator does not perform, a "custody begins
at capture" claim the manifest code contradicts, and a "periodic cosigning"
claim `witness.py` contradicts. None of those cite a missing name and none of
them would fail here. A reader is still the check for what the code does. This
is the check for whether the thing being described still goes by that name,
which is what a rename silently breaks.

Usage:
  python .github/scripts/check_cited_symbols.py [root]
  python .github/scripts/check_cited_symbols.py --selftest
"""

import ast
import io
import pathlib
import re
import sys
import tokenize

# Documents that describe the package in prose and are read as current.
#
# Every one is a shared path, byte-identical in both trees and compared by the
# sync job, so this check asserts the same thing wherever it runs. `README.md`
# was in this list and had to come out: the two trees carry different files at
# that path, the private one describing the repository rather than the
# package, and it cites `sync`, which is a CI job. A shared script cannot tell
# those two files apart by path. The public README is therefore not covered
# here, and that is a stated gap rather than an oversight.
DOCS = (
    "docs/business-flow.md",
    "docs/executive-thesis.md",
    "docs/practice-statement.md",
    "code/seal/README.md",
)

PACKAGE = "code/seal"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

# The retired names are declared by `check_retired_vocabulary.py`, which
# `READING_PATH.md` keeps in the public tree only and says not to copy across.
# This file runs in both trees, so it carries a fallback and the selftest
# asserts the two agree wherever both are present. A duplicate that is checked
# for equality is a different thing from a duplicate that is hoped to match.
RETIRED_FALLBACK = re.compile(r"\b(?:BUNDLED|WITNESSED|REDERIVABLE|REDERIVED)\b")
try:
    import check_retired_vocabulary as _R    # noqa: E402
    RETIRED = _R.RETIRED_WORDS
except ImportError:                          # the private tree
    _R = None
    RETIRED = RETIRED_FALLBACK

FENCE = re.compile(r"^\s*```")
BACKTICK = re.compile(r"`([^`\n]+)`")
PATHLIKE = re.compile(r"^[\w./-]+\.(?:py|json|html|md|toml)$")
CONST = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
IDENT = re.compile(r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*(?:\(\))?$")


def cited(text):
    """Yield (line number, token) for backticked tokens outside code fences.

    Fences are skipped because a fenced block is quoted output or a command,
    not a citation, and a multi-line fence would otherwise let one backtick
    pair swallow several paragraphs.
    """
    fenced = False
    for n, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for tok in BACKTICK.findall(line):
            yield n, tok.strip()


def vocabulary(pkg: pathlib.Path):
    """Every name and string literal the package contains."""
    names = set()
    for path in sorted(pkg.rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        try:
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type == tokenize.NAME:
                    names.add(tok.string)
        except (tokenize.TokenError, IndentationError):
            pass
        # String literals, so an enum member written as "RUN_SEAL" counts.
        try:
            for node in ast.walk(ast.parse(src)):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    names.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", node.value))
        except SyntaxError:
            pass
    return names


def run(root: pathlib.Path) -> int:
    pkg = root / PACKAGE
    if not pkg.is_dir():
        sys.exit(f"{pkg} is missing; this check has nothing to assert")
    names = vocabulary(pkg)
    if not names:
        sys.exit(f"no names found in {pkg}; this check has nothing to assert")

    drift, checked = [], 0
    for doc in DOCS:
        path = root / doc
        if not path.exists():
            drift.append((doc, 0, doc, "the document itself is missing"))
            continue
        for n, tok in cited(path.read_text(encoding="utf-8")):
            bare = tok.removesuffix("()")
            if PATHLIKE.match(tok) and "/" in tok:
                checked += 1
                if not (root / tok).exists():
                    drift.append((doc, n, tok, "cited path does not exist"))
            elif (root / tok).exists():
                # A bare filename such as LICENSE reads as a constant and is
                # a citation of a file, so resolve it before classifying.
                checked += 1
            elif RETIRED.search(bare):
                # Declared retired elsewhere. Its absence is the point.
                continue
            elif CONST.match(bare) or IDENT.match(bare):
                checked += 1
                leaf = bare.split(".")[-1]
                if leaf not in names:
                    drift.append((doc, n, tok,
                                  f"not a name or string in {PACKAGE}"))

    if drift:
        print(f"::error::{len(drift)} citation(s) name something that is not "
              f"in the package. A rename is the usual cause.")
        for doc, n, tok, why in drift:
            print(f"  {doc}:{n}  `{tok}`  -> {why}")
        return 1

    print(f"clean: {checked} citations across {len(DOCS)} documents all name "
          f"something that exists in {PACKAGE}")
    return 0


CONTROLS = [
    ("a fenced block is not a citation",
     "Text `real_name` here.\n\n```\n`fenced_name`\n```\n", ["real_name"]),
    ("several citations on one line",
     "See `one` and `two`.\n", ["one", "two"]),
    ("a call keeps its parentheses in the report",
     "Call `verify()` now.\n", ["verify()"]),
]


def selftest() -> int:
    bad = []
    for desc, src, expected in CONTROLS:
        got = [t for _, t in cited(src)]
        if got != expected:
            bad.append(f"{desc!r}: expected {expected}, got {got}")

    # The classifier has to route each shape, or the check silently skips.
    for tok, pat, want in (("code/seal/verifier.py", PATHLIKE, True),
                           ("RUN_SEAL", CONST, True),
                           ("close_assignment", IDENT, True),
                           ("state.in_flight", IDENT, True),
                           ("The quick brown fox", IDENT, False)):
        if bool(pat.match(tok)) != want:
            bad.append(f"classifier: {tok!r} routed wrong")

    # Where the declaring script is present, the fallback must match it
    # exactly. This is the only thing keeping the private copy honest.
    if _R is not None and _R.RETIRED_WORDS.pattern != RETIRED_FALLBACK.pattern:
        bad.append(f"retired fallback has drifted from "
                   f"check_retired_vocabulary.py: "
                   f"{RETIRED_FALLBACK.pattern!r} vs "
                   f"{_R.RETIRED_WORDS.pattern!r}")
    for word in ("BUNDLED", "WITNESSED", "REDERIVABLE", "REDERIVED"):
        if not RETIRED.search(word):
            bad.append(f"retired pattern does not cover {word}")
    if RETIRED.search("close_assignment"):
        bad.append("retired pattern matched a live name")

    if bad:
        print(f"::error::selftest: {len(bad)} problem(s)")
        for b in bad:
            print(f"  {b}")
        return 1
    where = ("agrees with check_retired_vocabulary.py"
             if _R is not None else "using its fallback, that script is "
             "public-only")
    print(f"selftest: all {len(CONTROLS)} extraction cases and 5 classifier "
          f"cases behave; retired list {where}")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    raise SystemExit(run(pathlib.Path(args[0]) if args else pathlib.Path(".")))
