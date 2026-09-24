"""Claim-shape rules. The style half lives in check_writing_lint.py.

That script covers em dashes and contractions, which are style. This one covers
the part that is not style at all: language that describes the product as
something it is not. A document can pass every style check and still make a
claim the mechanism does not support, and that failure is the expensive one.

The rules come from the locked vocabulary rather than from a list of banned
words, so the unit each one tests is the claim and not the verb.

  Custody and not judgment. The system records. Nothing here blocks, scores,
  gates or evaluates quality.
  Capture versus content. The seal attests to what the software queried at the
  moment it ran. It does not attest to the quality or good faith of that work.
  Binding versus bundling. Bundling co-locates. Binding establishes derivation.
  Symmetric evidence. The artifact convicts as readily as it exonerates, so it
  is never a shield and never protection.
  Integrity in two senses. Record integrity is claimable. Analytical integrity
  is served and never assessed.
  Two signatures. The seal witnesses. It never substitutes for the licensed
  professional who can be sanctioned.
  Two moments. Runs are captured at execution. Sign-off binds at certification.
  Admissibility. Serve it, never solve or create it.

Proving is not banned. Proving admissibility is. A rule written as a forbidden
verb flags the sentence that refuses the claim, which is how the first draft of
this file flagged the heading "What this package does not prove". Every gating
rule therefore pairs a verb with the object it may not take, skips a match whose
gap crosses a conjunction, and skips a match under negation.

The conjunction guard costs recall, and the cost is accepted. In "the product
creates admissibility and prevents cherry-picking" the second claim is not
flagged, because the guard cannot tell a carried subject from a dropped one.
One reported defect on a line is enough to send the line back.

Two classes, and the split is the whole design.

GATING rules are high confidence. A hit is a defect and fails the build.

REPORTING rules are patterns with real false positives, such as staged reveals,
which no regular expression separates from ordinary emphasis. They print and
never fail, because a gate that cries wolf is one nobody reads, and this project
has already recorded that a check passing quietly is worse than no check.

Usage:
  python .github/scripts/check_language.py [root] [--all]
  python .github/scripts/check_language.py --selftest

Run it from a repository root, or pass one so it can be pointed at the private
tree by hand. --all includes paths skipped by default. --selftest drives one
violating and one compliant sentence through every rule, because a gate nobody
has watched fire is not a gate.
"""

import ast
import io
import pathlib
import re
import subprocess
import sys
import tokenize

# Frozen snapshots, the ledger, and this file. Editing a snapshot to match
# current vocabulary would falsify the snapshot, and a ledger's dated entries
# stay. Both are stated rules in the private tree and are honoured here so one
# script can run against either repository.
SKIP = (
    "context/business-drafts/",
    "context/RECORD.md",
    "customers/DISCOVERY_MASTER", "customers/MASTER_PROSPECTING",
    "customers/DISCOVERY_ACTION", "customers/MOTION_1",
    "customers/COMPLETENESS_OBJECT", "customers/DEMO_ROOM",
    ".github/scripts/",
)

# A rule that states a rule is not a violation of it. These files quote the
# banned forms in order to ban them.
RULE_TEXT = ("CLAUDE.md", "REVIEW.md", "CONTRIBUTING.md")
QUOTES_THE_RULES = ("banned word", "not-X-but-Y", "unearned past tense",
                    "shield framing", "judgment framing", "absolute integrity")

# What counts as the mechanism speaking. Bare "this" is deliberately absent.
# It matched "This block is copied output" and three other innocent lines in
# the first run of this file.
THING = (r"(?:system|verifier|seal|product|mechanism|artifact|record|chain|"
         r"package|tool|log|capture|platform|service)")
MECHANISM = rf"(?:(?:the|this|our|a|each) {THING}s?|semafide|semafide's)"

# A gap word may not be a conjunction, a subordinator, or a negation. The first
# lets the subject drift across a clause, as in "the chain opens and prevents",
# where the subject of the verb is no longer the mechanism. The second turns a
# refusal into a hit. Punctuation already breaks the gap, because \w+\s+ cannot
# span a comma.
BREAK = (r"(?:and|or|but|nor|rather|instead|that|which|who|when|while|where|"
         r"because|if|though|although|not|never|no|cannot|neither|without|"
         r"nothing|nowhere)")
GAP = rf"(?:(?!{BREAK}\b)\w+\s+){{0,3}}"

# Negation reaching the match from earlier in the same clause. Bridge
# characters exclude sentence punctuation, so a refusal in one clause cannot
# silence a claim in the next.
NEG_BEFORE = re.compile(
    r"\b(?:not|never|cannot|can't|no|nor|neither|without|nothing|refuses?|"
    r"declines?|stops? short of)\b[A-Za-z\s'\-]{0,30}$", re.I)

# A bound named in the same clause is not an overclaim. "The solver proves
# soundness of the consistency proof to size six" states exactly what it
# established and where it stops, and the paragraph around it in
# code/tests/test_properties.py goes on to say a proved size six says nothing
# about size two hundred. Without this guard, extending the sweep to Python
# would have shipped that sentence as a defect.
BOUND_AFTER = re.compile(
    r"^[A-Za-z\s'\-]{0,40}?\b(?:to size|to depth|up to|within the bound|"
    r"to a bound|for (?:sizes?|instances?|inputs?|traces?) |bounded|"
    r"at (?:sizes?|depth)|under the model)\b", re.I)

CLAIM_VERB = (r"(?:proves?|proving|guarantees?|guaranteeing|ensures?|ensuring|"
              r"establishes?|establishing|demonstrates?|certifies?|certifying|"
              r"confirms?|validates?|validating|attests? to|vouches? for)")

# Objects no claim verb may take. Record integrity is claimable and is absent
# from this list on purpose; analytical integrity is not.
FORBIDDEN_OBJECT = (
    r"(?:admissibilit\w+"
    r"|analytical integrity|professional integrity"
    r"|compliance\b|regulatory compliance"
    r"|(?:the |its )?(?:quality|soundness|accuracy|correctness|sufficiency|"
    r"good faith|merit|reasonableness|competence)\b"
    r"|(?:the )?analysis (?:was|is) (?:sound|correct|complete|accurate|reasonable))")

GATING = [
    ("banned word",
     re.compile(r"\b(genuinely|straightforward)\b", re.I),
     "The rule names these. Cut the adverb; the sentence is complete without it."),

    ("not-X-but-Y",
     re.compile(r"\bnot\s+(?:just\s+|merely\s+|only\s+)?[a-z][a-z ,'\-]{2,40}\s+but\s+", re.I),
     "Lead with the affirmative half and use rather-than for the contrast."),

    ("shield framing",
     re.compile(rf"{MECHANISM}\s+{GAP}(?:protects?|shields?|defends?|safeguards?|"
                r"insulates?|covers?) (?:you|the|an|a|them|against|from)\b"
                r"|\b(?:a|the|your) (?:shield|protection|defence|defense|armour|armor)"
                r"\s+(?:for|against|from)\b", re.I),
     "Symmetric evidence. The artifact convicts as readily as it exonerates."),

    ("judgment framing",
     re.compile(rf"{MECHANISM}\s+{GAP}(?:blocks?|gates?|scores?|approves?|rejects?|"
                r"denies?|grades?|rates?|evaluates?|judges?|assesses?|"
                r"flags? (?:bad|poor|weak|suspicious))\b", re.I),
     "Custody and not judgment. Anything that says no belongs to another product."),

    ("claim overclaim",
     re.compile(rf"{CLAIM_VERB}\s+{GAP}{FORBIDDEN_OBJECT}", re.I),
     "Proving is allowed. Proving this object is not. Name the narrow property "
     "the mechanism actually establishes."),

    ("capture versus content",
     re.compile(rf"{MECHANISM}\s+{GAP}(?:attests? to|speaks? to|vouches? for|"
                r"stands behind|underwrites?)\s+"
                r"(?:\w+\s+){0,2}?(?:quality|soundness|good faith|sufficiency|"
                r"judg(?:ement|ment)|reasoning|merit)\b", re.I),
     "Capture versus content. The seal attests to what was queried, never to "
     "the worth of the work."),

    ("substitutes for the professional",
     re.compile(rf"{MECHANISM}\s+{GAP}(?:replaces?|substitutes? for|stands in for|"
                r"takes the place of|does away with|removes the need for)\s+"
                r"(?:\w+\s+){0,3}?(?:appraiser|professional|reviewer|examiner|"
                r"human|analyst|licen[cs]\w+|sign-?off|certif\w+)", re.I),
     "Two signatures. The seal witnesses. Software holds no licence and cannot "
     "be sanctioned."),

    ("prevention overclaim",
     re.compile(rf"{MECHANISM}\s+{GAP}(?:prevents?|stops?|eliminates?|ends?|"
                r"deters?|catches?)\s+(?:\w+\s+){0,2}?"
                r"(?:fraud|misconduct|error|mistakes?|manipulation|abuse|"
                r"cherry-?pick\w+|bad (?:analysis|work)|negligence)\b", re.I),
     "The mechanism records. Preventing a named wrong is a claim about human "
     "behaviour that nothing here supports."),

    ("absolute integrity",
     re.compile(r"\b(?:tamper-?proof|unforgeable|un-?forgeable|fraud-?proof|"
                r"un-?hackable|bullet-?proof|100% secure|fully secure|"
                r"immutable record|cannot be faked)\b", re.I),
     "Tamper-evident, and append-only. Absolutes describe a product nobody has."),

    ("court claim",
     re.compile(r"\b(?:court-?admissible|legally admissible|admissible in court|"
                r"holds? up in court|court-?ready|will be admitted|"
                r"guaranteed admissible)\b", re.I),
     "Admissibility is a ruling by a court. Serve it, never promise it."),

    ("admissibility overclaim",
     re.compile(r"\b(?:solves?|solving|creates?|creating|establishes?|establishing|"
                r"guarantees?|guaranteeing|confers?|delivers?)\s+"
                r"(?:\w+\s+){0,2}admissibilit", re.I),
     "Serve admissibility. Never claim to solve or create it."),

    ("two moments collapsed",
     re.compile(r"\b(?:captur\w+)\s+(?:\w+\s+){0,3}?(?:at|on|during)\s+"
                r"(?:sign-?off|certification)\b"
                r"|\bsign-?off\s+(?:\w+\s+){0,3}?captur", re.I),
     "Runs are captured at execution. Sign-off binds at certification."),

    ("unearned past tense",
     re.compile(r"\bwe\s+(?:built|have built|solved|have solved|proved|"
                r"have proved|shipped|have shipped)\b", re.I),
     "Present tense is earned. Write we are building until the mechanism is verified."),
]

REPORTING = [
    ("staged reveal",
     re.compile(r"\b(?:it turns out|here is (?:why|the|what)|the (?:real|actual) "
                r"(?:question|answer|problem|reason) is|but first|before that)\b", re.I),
     "Read it. Ordinary emphasis and temporal phrases match this too."),

    ("validation opener",
     re.compile(r"^\s*(?:great|excellent|absolutely|certainly|of course|indeed|"
                r"perfect)\b", re.I),
     "Read it. A sentence can legitimately begin with some of these."),

    ("bundling as binding",
     re.compile(r"\bbundl\w+\s+(?:\w+\s+){0,3}?(?:establishes?|proves?|shows?|"
                r"means?|binds?)\b", re.I),
     "Bundling co-locates. Binding establishes derivation. KC2 turns on this."),

    ("retroactive sealing",
     re.compile(r"\b(?:seals?|sealed|sealing|captur\w+|record\w+)\s+"
                r"(?:\w+\s+){0,3}?(?:retroactively|after the fact|"
                r"after the analysis|later and dated)\b", re.I),
     "Read it. KC1 turns on assembly time. A sentence describing the failure "
     "mode matches this too."),

    # The gating shield rule needs a verb or an article, so the possessive
    # forms slip past it: "for the appraiser's protection" names the product
    # as a shield and does not fire. Gating this would fail on
    # context/BUSINESS_SHAPE.md, where an institution paying "for its own
    # protection" is the institution managing its own exposure, which is the
    # correct framing. So it reports. "cover" was in the first version of this
    # pattern and pulled seventeen instances of "liability cover" and "cover
    # note", which is how a reporting rule stops being read.
    ("protection as a noun",
     re.compile(r"\b(?:protections?|shields?|safeguards?)\b", re.I),
     "Read it. Symmetric evidence: an institution protecting itself is fine, "
     "the product protecting its buyer is not."),

    ("aggregate for distribution",
     re.compile(r"\b(?:the )?(?:report|aggregate|value|adjustment)\s+"
                r"(?:\w+\s+){0,3}?(?:shows?|reveals?|tells? you)\s+"
                r"(?:\w+\s+){0,2}?(?:how many|the count|every run|all runs)\b", re.I),
     "Read it. Six analyses and one produce the same aggregate. The count is "
     "what the aggregate hides."),
]

# One violating and one compliant sentence per gating rule. The compliant half
# is the point: most of these are sentences the project already writes, and an
# earlier draft of this file failed on four of them.
CONTROLS = {
    "banned word": (
        "This is genuinely the case.",
        "This is the case."),
    "not-X-but-Y": (
        "It is not a bundle but a binding.",
        "It is a binding rather than a bundle."),
    "shield framing": (
        "The artifact protects the appraiser against a later challenge.",
        "The artifact documents a flawed analysis as faithfully as a sound one."),
    "judgment framing": (
        "The system blocks a run that looks wrong.",
        "The system records and seals. It never blocks and never evaluates."),
    "claim overclaim": (
        "The chain proves admissibility of the workfile.",
        "The chain establishes that the commitment preceded the run seal."),
    "capture versus content": (
        "The seal attests to the quality of the analysis.",
        "The seal attests to the capture, meaning what the software queried."),
    "substitutes for the professional": (
        "The product replaces the reviewer.",
        "The seal never substitutes for the professional."),
    "prevention overclaim": (
        "The system prevents cherry-picking.",
        "A discarded run leaves a hole the verifier reports."),
    "absolute integrity": (
        "The log is a tamper-proof store.",
        "The log is append-only and the artifact is tamper-evident."),
    "court claim": (
        "The record is court-admissible.",
        "The record is built to be offered as evidence."),
    "admissibility overclaim": (
        "The product creates admissibility.",
        "Custody does not create admissibility where none existed."),
    "two moments collapsed": (
        "Runs are captured at certification.",
        "Runs are captured at execution. Sign-off binds at certification."),
    "unearned past tense": (
        "We built the enforcement layer.",
        "We are building the enforcement layer."),
}


# The guards, driven directly. Each is a place the gate deliberately stays
# quiet, and a guard that silences too much is indistinguishable from a gate
# that was never written. (description, sentence, should_fire)
#
# Three wrap cases lived here until sentences replaced lines. They asserted
# that a guard could see one line either way, which was true and insufficient:
# 58.7 percent of sentences in these trees span three or more lines. The
# window is gone and so are the controls for it. `test_sentences_reflow`
# below replaces them by asserting the reflow itself.
GUARD_CONTROLS = [
    ("negation, same clause",
     "The verifier does not prove admissibility.", False),
    ("negation cannot reach across a sentence",
     "That is not a bundle. The chain proves admissibility.", True),
    ("bound named in the same clause",
     "The solver proves soundness to size six.", False),
    ("bound named after a wrap, now one sentence",
     "The solver proves soundness of the consistency proof to size six; "
     "the completeness properties go wider.", False),
    ("no bound named",
     "The solver proves soundness of the analysis.", True),
    ("conjunction breaks the subject",
     "The chain opens and prevents relabelling the completed chain.", False),
    ("mechanism with no conjunction still fires",
     "The chain prevents cherry-picking.", True),
]

# The reflow itself, asserted rather than assumed. Each case is (description,
# source text, python?, expected sentences).
REFLOW_CONTROLS = [
    ("a sentence wrapped across three lines becomes one",
     "The solver proves\nsoundness of the proof\nto size six.\n", False,
     ["The solver proves soundness of the proof to size six."]),
    ("a blank line ends the paragraph",
     "One sentence here.\n\nAnother over\nhere.\n", False,
     ["One sentence here.", "Another over here."]),
    ("a fenced block is not prose",
     "Before it.\n\n```\nThe system blocks a run.\n```\n\nAfter it.\n",
     False, ["Before it.", "After it."]),
    ("a table row does not continue the sentence above",
     "Lead in.\n| a | b |\n| c | d |\n", False, ["Lead in."]),
    ("a heading ends the paragraph",
     "Lead in\nwrapped.\n## Heading\nNext one.\n", False,
     ["Lead in wrapped.", "Next one."]),
    ("python reads a docstring and ignores the code",
     'def proves_soundness():\n    """Reads this.\n\n    And this one\n'
     '    wrapped.\n    """\n    return proves_soundness\n', True,
     ["Reads this.", "And this one wrapped."]),
    ("python reads a comment block as one paragraph",
     "# First half of it\n# and the second half.\nx = 1\n", True,
     ["First half of it and the second half."]),
    ("python does not join comments across a gap",
     "# One.\nx = 1\n# Two.\n", True, ["One.", "Two."]),
    ("a link keeps its text and drops its address",
     "See [the protection rule](https://example.com/protection) here.\n",
     False, ["See the protection rule here."]),
    ("a badge row carries no prose at all",
     "[![CI](https://example.com/a-protection-badge.svg)](https://example.com)\n",
     False, ["CI"]),
    ("a backticked identifier is not read",
     "The field `proves_admissibility` is gone.\n", False,
     ["The field is gone."]),
]


def hits(sentence, rules, is_rule_text=False):
    """Yield (label, why) for each rule the sentence breaches.

    The unit is a whole sentence, so both guards see everything in their own
    clause without looking at neighbouring lines. NEG_BEFORE still refuses to
    bridge sentence punctuation, which now costs nothing to enforce: there is
    no other sentence in the string.
    """
    for label, pat, why in rules:
        if is_rule_text and label in QUOTES_THE_RULES:
            continue
        m = pat.search(sentence)
        if m and not NEG_BEFORE.search(sentence[:m.start()]) \
               and not BOUND_AFTER.search(sentence[m.end():]):
            yield label, why


SENTENCE_END = re.compile(r'(?<=[.!?])["\')\]]*\s+')

# Markup is not prose. A link's address is not a claim, and neither is a
# backticked identifier. Reflowing made this matter: joining three badge lines
# into one paragraph put four URLs in a single string, and one of them carried
# the word "protection". Link text is kept, because a reader reads it.
# Images before links, because a badge nests one inside the other and a single
# combined pattern eats the wrong brackets.
MARKUP = [
    (re.compile(r"!\[([^\]]*)\]\([^)]*\)"), r"\1"),    # ![alt](url)
    (re.compile(r"\[([^\]]*)\]\([^)]*\)"), r"\1"),     # [text](url)
    (re.compile(r"`[^`]*`"), " "),                       # `identifier`
    (re.compile(r"https?://\S+"), " "),                  # a bare address
]


def _strip_markup(s):
    """Reduce markup to the words a reader reads.

    Applied to a fixpoint, because a badge is a link wrapping an image and one
    pass leaves the outer half behind.
    """
    for _ in range(5):
        before = s
        for pat, repl in MARKUP:
            s = pat.sub(repl, s)
        if s == before:
            break
    return re.sub(r"\s+", " ", s).strip()

# A line that is structure rather than prose. A table row, a fence, a rule, a
# heading: none of them continue the sentence above, so a paragraph ends here.
STRUCTURAL = re.compile(r"^\s*(?:\||```|---+$|===+$|#{1,6}\s|<)")


def _paragraphs_md(text):
    """Yield (first line number, joined text) for Markdown, skipping fences."""
    fenced, buf, start = False, [], None
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            if buf:
                yield start, " ".join(buf)
            buf, start = [], None
            continue
        if fenced:
            continue
        if not line.strip() or STRUCTURAL.match(line):
            if buf:
                yield start, " ".join(buf)
            buf, start = [], None
            continue
        if not buf:
            start = n
        buf.append(line.strip())
    if buf:
        yield start, " ".join(buf)


def _paragraphs_py(text):
    """Yield (first line number, joined text) for Python prose only.

    Prose in Python means docstrings and comments. Nothing else is read, which
    drops a whole false-positive class: an identifier named `proves_soundness`
    is code and was previously scanned as though it were a sentence. Docstrings
    come from `ast` and comments from `tokenize`, so neither is found by
    guessing at quotes.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
            continue
        doc = ast.get_docstring(node, clean=True)
        if not doc:
            continue
        # Line of the docstring itself, not of the def above it.
        body = node.body[0]
        base = getattr(body, "lineno", getattr(node, "lineno", 1))
        off, buf, start = 0, [], None
        for i, line in enumerate(doc.splitlines()):
            if not line.strip():
                if buf:
                    yield base + start, " ".join(buf)
                buf, start = [], None
                continue
            if not buf:
                start = i
            buf.append(line.strip())
        if buf:
            yield base + start, " ".join(buf)

    # Comments. Consecutive `#` lines are one paragraph; a gap ends it.
    buf, start, last = [], None, None
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError):
        toks = []
    for tok in toks:
        if tok.type != tokenize.COMMENT:
            continue
        n = tok.start[0]
        body = tok.string.lstrip("#").strip()
        if last is not None and n != last + 1:
            if buf:
                yield start, " ".join(buf)
            buf, start = [], None
        if not buf:
            start = n
        buf.append(body)
        last = n
    if buf:
        yield start, " ".join(buf)


def sentences(text, python=False):
    """Yield (line number, sentence).

    Matching used to run line by line, and every file in both trees wraps at
    about eighty columns. Measured on 2026-09-24, 58.7 percent of sentences
    here span three or more lines, so a line-based rule read a fragment and
    the guards, which looked one line either way, reached only the 41.3
    percent that fit in two. Reflowing to whole sentences removes the window
    and the question of how wide it should be.

    The line number reported is where the sentence's paragraph begins, which
    is within a line or two of the sentence itself and is stable under
    rewrapping.
    """
    paras = _paragraphs_py(text) if python else _paragraphs_md(text)
    for n, para in paras:
        for s in SENTENCE_END.split(_strip_markup(para)):
            if s.strip():
                yield n, s.strip()


def selftest() -> int:
    labels = [label for label, _, _ in GATING]
    missing = [l for l in labels if l not in CONTROLS]
    if missing:
        print(f"::error::gating rules with no control: {missing}")
        return 1

    bad = []
    for label, (violating, compliant) in CONTROLS.items():
        fired = {l for l, _ in hits(violating, GATING)}
        if label not in fired:
            bad.append(f"{label}: did not fire on {violating!r}")
        clean = {l for l, _ in hits(compliant, GATING)}
        if clean:
            bad.append(f"{label}: fired {sorted(clean)} on the compliant "
                       f"sentence {compliant!r}")

    for desc, sentence, should in GUARD_CONTROLS:
        fired = bool(list(hits(sentence, GATING)))
        if fired != should:
            bad.append(f"guard {desc!r}: expected "
                       f"{'a hit' if should else 'silence'}, got "
                       f"{'a hit' if fired else 'silence'} on {sentence!r}")

    for desc, src, python, expected in REFLOW_CONTROLS:
        got = [s for _, s in sentences(src, python=python)]
        if got != expected:
            bad.append(f"reflow {desc!r}: expected {expected}, got {got}")

    if bad:
        print(f"::error::selftest: {len(bad)} problem(s)")
        for b in bad:
            print(f"  {b}")
        return 1
    print(f"selftest: all {len(labels)} gating rules fire on a violation and "
          "stay quiet on the compliant sentence beside it")
    print(f"selftest: all {len(GUARD_CONTROLS)} guard cases behave, including "
          "the three where the guard must NOT suppress")
    print(f"selftest: all {len(REFLOW_CONTROLS)} reflow cases produce exactly "
          "the sentences expected, in Markdown and in Python")
    return 0


def targets(root: pathlib.Path, include_all: bool):
    """Markdown and Python. The claims live in both.

    Scope was Markdown alone until a sweep on 2026-09-24 ran the same rules
    over the tracked Python by hand and found twelve gating hits there, two of
    them inside `seal*`, which is what `pyproject.toml` actually ships. A rule
    that holds for a document and not for the docstring beside it is a rule
    with a hole in it.
    """
    out = subprocess.run(["git", "-C", str(root), "ls-files", "*.md", "*.py"],
                         capture_output=True, text=True, check=True).stdout.split()
    if include_all:
        return out
    return [f for f in out if not any(s in f for s in SKIP)]


def run(root: pathlib.Path, include_all: bool) -> int:
    files = targets(root, include_all)
    if not files:
        sys.exit("no tracked Markdown or Python found; this check has nothing "
                 "to assert")

    failures, notes = [], []
    for name in files:
        path = root / name
        is_rule_text = name in RULE_TEXT
        for n, s in sentences(path.read_text(encoding="utf-8"),
                              python=name.endswith(".py")):
            for label, why in hits(s, GATING, is_rule_text):
                failures.append((label, name, n, s, why))
            for label, why in hits(s, REPORTING):
                notes.append((label, name, n, s, why))

    if notes:
        print(f"For reading, not failing ({len(notes)}):")
        for label, name, n, line, why in notes:
            print(f"  {label}: {name}:{n}")
            print(f"    {line[:100]}")
        print()

    if failures:
        print(f"::error::Language rules: {len(failures)} violation(s) in prose "
              "outside code fences.")
        for label, name, n, line, why in failures:
            print(f"  {label}: {name}:{n}")
            print(f"    {line[:100]}")
            print(f"    -> {why}")
        return 1

    md = sum(1 for f in files if f.endswith(".md"))
    print(f"clean: {md} Markdown and {len(files) - md} Python files carry none "
          f"of the {len(GATING)} gating claim defects")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    raise SystemExit(run(pathlib.Path(args[0]) if args else pathlib.Path("."),
                         "--all" in sys.argv))
