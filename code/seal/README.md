# seal

Artifact schema and standalone verifier. Pre-build scaffold.

This package encodes two things: what an artifact must contain, derived from the
six primitives, and what a verifier can report about one without overclaiming. It
contains no capture mechanism. The product targets the evidentiary bar through
re-derivation only, so the recipe is the load-bearing object here.

The verifier exists before the capture mechanism deliberately. What a verifier
can report without overclaiming is what an artifact must actually contain.

## Where KC2 fires, and what clears it

KC1, KC2, and KC3 are the three design constraints the architecture has to
satisfy. KC1 is seal timing: the real-time binding claim fails if the workfile
snapshot is assembled after the analysis finishes rather than captured in the
same act as the run. KC2 is binding versus bundling: the technical claim fails
if the mechanism does nothing a third-party-timestamped bundle of the same
local files could not do. KC3 is completeness enforcement: the
anti-cherry-picking property fails if capture of every run in an assignment
cannot be enforced without breaking the operator's execution workflow. KC3 is
open and nothing in this repository closes it.

KC2 states the mechanism fails if it does nothing a third-party-timestamped
bundle of the same local files could not do. That is computable from an artifact
rather than a matter of judgment, so the verifier computes it and reports it as
`timestamp_replicable`.

The verifier classifies an artifact into one of five binding levels.

**BUNDLED.** A signature over co-located inputs and outputs. Nothing relates
them. This is what a signing function produces when handed a dictionary.

**PRECEDENCE.** The evidence commitment is sealed as a strictly earlier chain
entry than the run that names it. This rules out selecting inputs after seeing
the output.

**WITNESSED.** A party outside the interested party's control observed the
capture. **Not reachable, and the code does not pretend otherwise.** Nothing in
an artifact can carry evidence that an outside party observed anything while
there is no second signature and no external anchor, so a self-declared witness
drops to PRECEDENCE with a finding. Granting this level on `witness_mode`, a
string the sealer writes, would make nine characters the cheapest way to clear
KC2 in the whole package.

**REDERIVABLE.** The artifact carries a structurally complete recipe: a pinned
endpoint and version, the exact invocation, a resolvable input reference, the
expected output digest, and the window over which the partner has committed to
keeping that version executable. Every field is required, and a partial recipe
is treated as absent.

Two of those fields are load-bearing. `output_digest` must be the Action the
artifact seals, and `input_ref` must be the evidence commitment the run names.
Without both links the verifier compares the recipe against itself, which proves
that a pinned endpoint reproduces some number and nothing about the number in
the seal. That is KC2 stated. A recipe failing either check drops to PRECEDENCE.

**REDERIVED.** The recipe was executed by a verifier and the output matched.

Two results matter, and the second one decides the product.

**Precedence does not clear KC2, and ordering does not create binding.**
Committing the input hash before the run fixes the order and nothing more. A
partner can commit hash A, run on dataset B, and post a result naming A. Two
RFC 3161 timestamps over two local files reach precedence for the price of two
HTTP requests. What the earlier commitment does buy is the coverage check, which
makes an omitted run detectable, and that is KC3 rather than KC2. The two are
separate properties and confusing them sells the fix for one as the fix for the
other.

**Re-derivation clears KC2 only where the evidence cannot be retained locally.**
If every input can be kept, the same folder can be timestamped and re-run
without a custodian, and re-derivation buys nothing a commodity service could
not. What a local timestamp cannot do is resolve an input the holder is not
permitted to keep. Licensing and mutability are therefore not obstacles to this
mechanism. They are the condition that makes it necessary.

**Whether the operator can hold the input is not a field in the artifact.** It
is a fact about a tool's documented workflow, constant across every run that
tool produces, and the sealer has an interest in the answer. The verifier read
`primitives.evidence.retention` for it once, which was wrong twice over: that
field records what this document carries, which is a different question, and the
sealer writes it. The answer now arrives through `retention_determinations`, a
signed reading naming a tool and a pinned version, what the reading found, where
it was read, and a digest of the source as read. `retention.py` holds the shape
and `input_provenance` reports what backed the answer. Absent, unusable,
self-issued, contested, and undetermined all resolve the same way: the input is
treated as locally retainable and KC2 fires.

This is provenance rather than proof. No construction verifies that somebody
read a manual accurately. What is computed is whether a reading was recorded, by
a key that is not the sealer's, against a source a later reader can check. The
trust moves to the determiner, which is the point.

**The liveness dependency.** Re-derivation is not self-contained the way a
signature is. Verification requires the partner's pinned version to still be
executable years later. Where it is not, the verifier reports REDERIVABLE with a
`liveness` finding and the evidentiary claim has decayed to its recipe.
`service_window` records what the partner committed to.

## What the verifier checks

Chain integrity by contiguous sequence and prev-hash linkage from genesis,
starting at the assignment anchor that opens the chain. Signature validity and
block-hash agreement per entry. Key identity separately, against a trusted set
the caller supplies, because an artifact carrying its own public key proves
internal consistency and nothing about who produced it.

Each of the six primitives on all three properties. Existence, meaning a
commitment is present. Reach, meaning the holder is the party carrying the
liability rather than a counterparty. Pinning, meaning the primitive is fixed to
the instant rather than resolving to present state.

Coverage of the Layer 2 binding. A binding that names the head of a contiguous
chain makes omission of a run detectable, and the verifier reports which entries
were dropped. The check covers the whole chain rather than only the entries
preceding the binding, because certifying a clean run and then continuing to
work is the obvious way to cherry-pick. Runs sealed after the last binding, and
bindings naming entries absent from the artifact, are both reported.

Completeness against a per-chain checkpoint, disclosure against an assignment
checkpoint, anchoring against a beacon and a time authority, and retention
against a signed reading of the tool. These are the inputs the sealer does not
author, and they answer different questions. Completeness asks whether this
chain is whole. Disclosure asks whether this chain is all the chains. Anchoring
asks when the chain was written, as against when it says it was. Retention asks
whether the operator could have kept the input without any of this. A truncated
hand-over fails the first; five chains with one produced passes the first and
fails the second; a chain assembled after the fact and dated backwards passes
both and fails the third; a perfectly re-derived analysis over rows the operator
exported to their own machine passes all three and fails the fourth.

`trustworthy` is the single field a caller should read. `signatures_valid` on
its own means the artifact is internally consistent, which a forger achieves by
signing everything with their own key, so trust additionally requires an intact
chain and a key the caller recognised.

## The custody layers, and the ceiling on each

Each layer moves one more fact outside the sealer's control. Each has a limit
and the limit is stated before the mechanism.

**Truncation, closed by `checkpoint.py`.** Exporting the entries up to the
binding and not the ones after it leaves a chain that links from genesis with
every signature valid. No field added to a document can fix that, because
completeness is a claim about what is not in the document and the party choosing
what ships also chooses what to omit. RFC 3161 on each entry does not close it
either: a timestamp proves a document existed at a time and says nothing about
documents nobody was shown.

A signed statement of assignment, entry count, and chain head, issued by a key
that is not the sealer's, makes a short chain detectable. Without a checkpoint
the state is UNCHECKED, which is honest rather than passing. A checkpoint signed
by the sealer is refused outright.

`Issuer` is stateful and this is the property that matters. A stateless signer
can sign a checkpoint over chain A at size five and another over chain B at size
five, both for one assignment, and both verify, because each chain really is the
length its checkpoint names. A signature over a count is not the property
wanted. The property is that the issuer has never signed anything inconsistent
with this, and that requires the issuer to remember. The bare `issue` function is
the primitive and a custodian must not call it.

**Custodian accountability, closed by `log.py`.** Checkpoints stop the sealer
being the only source of their own record and leave the custodian in exactly
that position, one level up. "Append-only" asserted by the party doing the
appending is worth what a self-declared witness was.

A consistency proof makes it checkable. Given a tree head from last year and one
from today, the log must demonstrate that today's tree contains last year's
unchanged. If an entry was removed or altered, no such proof exists, and the
failure is arithmetic rather than a matter of trusting anyone. This is RFC 6962,
the structure behind Certificate Transparency.

The hash construction differs deliberately from `primitives.merkle_root`. That
one commits to a set of evidence rows and promotes odd nodes. This one splits at
the largest power of two below the size, which is what makes incremental proofs
possible. The two are not interchangeable.

**The split view, addressed by `witness.py`, and nothing prevents it.** A
custodian determined to equivocate can show one head to one examiner and a
different head to another, and each is internally perfect. Consistency proofs
catch that only when two parties compare what they were given. What the module
changes is the consequence and the cost.

Two heads for one log that cannot both be true are, together, evidence, and both
carry the custodian's signature, so a third party present for neither disclosure
re-checks the pair from scratch. The two kinds are graded rather than reported
alike. Two different roots at the same size is a CONTRADICTION, which no
document reconciles. Two different sizes with no consistency proof offered is
UNRECONCILED, which is what an examiner holds when a custodian declines to
produce one, and `rebut` lets the custodian answer it.

A witness keeps the last head it signed for a log and refuses anything that is
not a consistent extension. The state is the whole mechanism, since a witness
with no memory is a rubber stamp. `count_witnesses` counts distinct recognised
keys and ignores the rest, because an examiner who counts witnesses they cannot
name has reintroduced the problem.

The residue is operational rather than cryptographic. Who the witnesses are,
whether they are independent, and whether anyone checks the count are not
questions this module answers. It reduces trusting the custodian to trusting
that these named parties are not all captured, which is a better position and is
not a proof.

**Assignment binding, in two halves that need different kinds of fix.** Seal five
analyses in five separate chains and disclose the one you like. Each links from
genesis, each verifies, and each per-chain checkpoint is honest. Counting the
chain was never the question.

The first half is structural and is fixed inside the artifact. `artifact.py`
opens every chain with an `ASSIGNMENT_ANCHOR` at entry zero and every later
entry links back to it, so the assignment is declared at open rather than
asserted at certification by the party with the most reason to choose it. Chain
identity is the anchor's block hash, derived rather than chosen. A binding
certifying an assignment the chain is not anchored to, a second anchor part way
through, and a stripped anchor are all reported.

The second half is truncation one dimension over and no field closes it.
Truncation hides entries inside a chain; sibling chains hide chains inside an
assignment. So `assignment.py` makes the same move one level out: a signed
statement by the custodian of which chains the assignment holds. Without a
statement the state is UNCHECKED rather than a pass, and a statement signed by a
key that also signed a chain is refused. WHOLE means the disclosure is whole, so
a chain produced but cut short degrades to PARTIAL rather than only raising a
finding, because a caller reading one field is the mistake `signatures_valid`
already invites.

**External time, and RFC 3161 anchors the wrong side.** `ts_ns` is signed and
checked for monotonicity and is still a value the sealer chose, so a chain
assembled today with last year's timestamps verifies with an intact chain and
valid signatures.

A timestamp token proves a document existed **no later than** the time it names.
It is an upper bound and says nothing about whether the document existed
earlier, so it cannot contradict a record created today and dated to last March.
That is the threat KC1 describes. Backdating is the attack, a lower bound is
what catches it, and a timestamp authority cannot supply one.

Bounding a time from below needs a commitment to something that did not exist
yet. `anchor.py` puts a published unpredictable value in the chain's anchor, so
the chain cannot have been assembled before that value existed. The
unpredictability is the whole mechanism: a value the sealer can compute in
advance buys nothing. The two bounds give an interval, `anchor_interval_ns`
reports its width, and that width is the sealer's remaining discretion.
UPPER_ONLY is a state of its own rather than a pass.

Neither half survives being read out of the artifact. The beacon resolves
through a callback the examiner supplies, an authority the examiner did not name
is refused, and an anchor must name an entry in this chain rather than an
adjacent document. Two limits: a sealer wanting a weak bound commits to a stale
pulse, which is permitted and produces a wide interval, so the mechanism can be
widened in the open but not defeated quietly. And a real deployment substitutes
an actual RFC 3161 token for the upper bound, since parsing CMS and ASN.1 needs
a dependency this package deliberately does not carry.

## What none of this closes

Capture completeness, which is KC3. The assignment statement is only as complete
as what the custodian received. A run sealed to a chain that was never submitted
is invisible to this and to everything else in the package, because nothing here
observes the sealer's machine. What is closed is the disclosure side: given that
the custodian saw the work, the party under examination no longer chooses which
parts of it the examiner learns about.

## Design notes

Numeric values are carried as strings. Regression coefficients are floats, and
float repr is not stable across platforms or interpreter versions. Hashing a
float directly makes verification fail for reasons unrelated to tampering.

Evidence is committed as a Merkle root over ordered row hashes, so a later
challenge can prove that a specific row WAS in the set without the artifact
retaining the rows. It cannot prove a row was absent: non-membership needs a
sorted or indexed structure and this is neither. Odd nodes are promoted rather
than duplicated, avoiding the duplicate-leaf ambiguity, and leaves and interior
nodes carry distinct domain prefixes because promotion reintroduces that
ambiguity in another form. The root binds the leaf count.

Canonicalization is sorted-key JSON with no insignificant whitespace. It is
adequate here and it is not RFC 8785. A verifier that must agree with an
independent implementation needs JCS proper.

Chain order is carried by sequence number and prev-hash rather than by clock
values, so a wrong clock degrades the evidence without breaking the structure.

The signing core is reimplemented rather than imported, so this package depends
on nothing outside `cryptography` and the standard library, and CI asserts that
on every push.

## Adopt rather than reimplement

The completeness machinery here is a transparency log rediscovered from first
principles. A checkpoint is a signed tree head, `tlog-checkpoint`. The custodian
signature over one is a witness cosignature, `tlog-cosignature`. `tlog-witness`
is the protocol for obtaining one and `tlog-proof` specifies an
offline-verifiable proof composing the checkpoint, the cosignatures, and the
inclusion proof. The specifications are at c2sp.org and there are production
libraries.

**Do not build a transparency log from this package.** It is a study of why the
pieces are shaped the way they are, which is what makes the specifications
readable, and it is not a foundation.

Note also what `Issuer` costs over a hash chain: establishing that a chain
extends what was signed before means walking the entries, which is linear. A
Merkle tree answers the same question with a proof logarithmic in the size,
which is the argument for moving the seal chain into a log rather than for
keeping the chain.

## Open questions

`primitives.OPEN_QUESTIONS` carries the list in code so it cannot rot silently.

## Running

This package needs `cryptography` and nothing else, and CI asserts that on every
push rather than trusting it.

```bash
pip install -r code/seal/requirements.txt
cd code && python -m seal.demo
```

The demo walks nine scenarios, each differing from the last by one decision, and
prints what the verifier concludes about each. It is the KC2 result made
watchable: precedence fires, re-derivation clears, and re-derivation over locally
retainable evidence fires again. The last three scenarios are the custody
results: a truncated chain, five chains with one handed over, and a backdated
chain against an authority that cannot see backdating.

```bash
python -m pytest code/tests -q
```

A hundred and two tests. `test_seal_verifier.py` asserts the same outcomes the
demo prints: the ones under the KC2 heading are the experiment rather than a
check on the code, and the rest are regressions for constructed attacks, frozen
so those gaps cannot reopen quietly.

`test_properties.py` covers what is quantified over arbitrary input, which no
hand-written case reaches. Injectivity of the canonicalizer is a claim about
every pair of values a caller might pass. Totality of the verifier is a claim
about every malformed document. It also samples the log at sizes in the
hundreds, well past the bound the solver in `specs/` can prove over, which is
the complement rather than a substitute: a sampled size says nothing about all
proofs at that size, and a proved small size says nothing about a large one.
