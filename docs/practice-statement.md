# Semafide practice statement

## What this document is

This states what a Semafide record asserts, what it refuses to assert, and the
procedure by which somebody other than Semafide checks both. It is the class
definition rather than a description of a product.

It exists because of a requirement this project applies to its competitors and
owes to itself. Compliance must be checkable by someone other than the attestor.
An interested party cannot attest to itself on the point at issue, and that
argument does not stop applying when the interested party is Semafide. Every
check in this repository is currently run by Semafide, every document is written
by Semafide, and no named outside party has reviewed either. This document is
what such a party would review against.

`docs/executive-thesis.md` is the source of truth for what Semafide claims and
carries the argument underneath these rules. `SECURITY.md` carries the threat
model and states which defeats are in scope. Where this document and either of
those disagree, they are correct and this one is stale, and the disagreement is
a defect to fix rather than a matter of interpretation.

## Status, stated before the rules

No custody service is operating. No independent witness is sited. The
checkpoint-signing key on which the completeness statement would rest lives
nowhere real. `code/seal/capture/dummy_custodian.py` names itself as a rehearsal
on one machine with two keys and not a custodian anybody can send work to. The
code has not been independently audited.

Sections 1 through 5 therefore describe what the verifier already computes over
an artifact presented to it, which is running software. Section 6 describes what
a custodian would be bound to, which is not. The two are separated rather than
blended, because a practice statement that reads as though a service exists
would be the first thing a reviewer caught, and it would be the same class of
failure as the records this product exists to make visible.

---

## 1. The claims a record carries

A Semafide artifact carries five propositions about one sealed run. They are
established independently, on separate evidence, and a reader is entitled to
treat each one as answering its own question.

**`precedence`** holds when the hash of the evidence the run consumed was
committed before the run was sealed. It fixes ordering and nothing else. Two
commodity timestamps over local files reach the same place, which is why
precedence alone never clears the binding constraint.

**`witness_attestation`** holds when a party outside the sealer's control signed
a statement that it observed the execution, binding the run, the committed
evidence, the sealed action, and a capture reference, under a key the verifier
independently trusts. A signature over a supplied bundle is not this. A field in
which the sealer writes the word independent is not this.

**`recipe_available`** holds when the artifact carries a complete re-derivation
recipe, meaning one a stranger could execute. `RederivationRecipe.REQUIRED`
names seven fields, and the count is stated here because a reviewer checking
this section against the code is entitled to the whole list: endpoint, tool,
version, invocation, input reference, expected output digest, and service
window. A recipe missing any one of them is treated as absent rather than as
partial.

**`recipe_reproduced`** holds when that recipe was actually executed and produced
the digest the artifact sealed as the action. A recipe that has not been run is
a claim about a future event.

**`historical_execution_established`** holds on exactly one path, a valid witness
attestation. This is the sharpest line the package draws and the one most often
misread. A re-derivation that reproduces the number does not establish that the
original execution happened, because reproduction is a statement about the
recipe and not about history.

Two disclosures about the propositions, made here rather than left for a
reviewer to discover. Four of the five do not imply each other. The fifth
currently co-varies with `witness_attestation`, because the single path to it
sets both in the same call, and whether the pair should be split into an event
claim and a record claim is open.

An earlier revision of the verifier also emitted an ordered summary derived from
these five. It has been removed from the code entirely, because its derivation
rule never checked the strongest of the five and so could not represent it under
any combination of the others. Any document presenting the five propositions as
rungs on one ordered ladder is describing something this code no longer
computes.

## 2. The claims about a set of records

The propositions describe one run. Two further results describe whether the set
is whole, and they are the part of the system that no self-contained document
can supply.

**Completeness** answers whether anything outside the artifact vouches for how
long the chain is. It reports `UNCHECKED` by default, and that default is the
load-bearing behaviour. Without a chain statement issued by a party other than
the sealer, an artifact holding three entries and an artifact truncated from
five to three are the same document, and no amount of verification separates
them. The other results are `CONSISTENT`, `SHORT`, `MISMATCHED` and `UNUSABLE`.
A checkpoint the sealer issued to itself is reported as unusable rather than
accepted.

**Coverage** answers whether omitting a run from the certified set is
detectable, and reports `CONTIGUOUS`, `SUBSET` or `ABSENT`. It reads `ABSENT`
until an assignment is closed, which is the honest reading of work still in
progress.

Two moments are involved and they are distinct events. Runs are captured at
execution. Sign-off binds at certification. A reader who collapses them into one
will misread coverage, because the binding that makes omission detectable is
written at the second moment and describes the first. The distinction is
structural rather than a matter of sequencing convenience, and it survives every
rewrite of this document.

Completeness is a claim about absence, and no field added to a self-contained
artifact establishes it. RFC 3161 does not close it either, because a timestamp
proves a document existed and says nothing about documents nobody was shown.

## 3. The claim about time

A timestamp token proves a document existed no later than the time it names. It
is an upper bound, and it leaves backdating untouched, which is the direction
that matters for a record built in response to a challenge and dated to the
original work.

Bounding a time from below requires committing to a published value that did not
exist yet, because nobody can write down a value before it is published. The two
bounds together give an interval, and the width of that interval is the sealer's
remaining discretion. A record claims the interval and never a point.

## 4. What is refused

The verifier fails closed. Absent, unusable, self-issued, mismatched and
undetermined inputs all resolve against the artifact rather than for it.
Declining to grant a proposition on incomplete evidence is the intended
behaviour and is not a defect.

The system records and seals. It does not block, score, gate, or evaluate. Any
feature that says no belongs to a different product.

The seal attests to the capture, meaning what the software queried at the moment
it ran. It does not attest to the quality, sufficiency, or good faith of what was
captured. The artifact documents a flawed analysis as faithfully as a sound one,
and it exonerates or convicts as the facts fall. Semafide does not describe this
product as a shield or as protection.

Two senses of integrity are served and only one is claimed. Record integrity
means the artifact faithfully represents what was captured and has not been
altered since, and that is what the mechanism delivers. Analytical integrity
means the reasoning was sound and the inputs were well chosen, and the verifier
cannot evaluate it. A tamper-evident seal over a badly reasoned analysis produces
a badly reasoned analysis that nobody can quietly revise. The judging stays with
the person who can be sanctioned for getting it wrong.

Admissibility is used in the evidentiary sense, meaning whether the data state
acted upon can be proven later. Semafide produces evidence an admissibility
determination rests on. It does not make the determination, and independent
custody does not create admissibility where none existed.

The certifying professional's signature is an exercise of licensed authority by a
person who can be sanctioned. The seal's signature is an act of independent
witness. The seal never substitutes for the professional, because software holds
no licence and cannot have its livelihood revoked.

## 5. What a verifier computes over, and what it merely transcribes

This is the organising principle and the fastest way for a reviewer to test any
claim in this document. A field the sealer writes is a transcription of the
sealer's claim rather than a computation of it.

Five facts originate outside the sealer: how long the chain is, which chains the
assignment holds, whether the custodian rewrote its own history, when the chain
was written, and whether the tool puts the raw input in the operator's hands.
Everything else in a record is the examined party describing itself.

That last one arrives through a retention determination, which is a reading of a
named tool at a pinned version, signed by a key that is not the chain's, citing
where it was read and fixing the source with a digest. The determination reports
`OPERATOR_HOLDS`, `OPERATOR_CANNOT_HOLD` or `UNDETERMINED`, and its provenance
reports `SOURCED`, `UNSOURCED`, `UNUSABLE`, `SELF_ISSUED` or `MISMATCHED`. This
is provenance rather than proof. Nothing verifies that a manual was read
correctly. What is computed is that a reading exists, came from somebody else,
and points at something checkable.

Relation-level reliance is assessed separately from cryptographic soundness, and
the separation is the point. A record can be cryptographically sound and
evidentiarily thin at the same time. Reliance requires cryptographic trust, plus
either an independent witness attestation or a successful recipe reproduction,
and it is withheld where a commodity timestamp over the same local files would
have reached the same place.

## 6. What a custodian would be bound to

None of this is operating. It is written down so that a reviewer can hold a
future service to it, and so that the gap between the rules and the running
software is visible rather than inferred.

A custodian holds the chain and issues the statement of how many runs an
assignment contains. It is not the party that produced the analysis, and the
verifier already refuses a checkpoint the sealer issued to itself, so this is
enforced by the code rather than promised in prose.

A witness keeps the last log head it signed and refuses to sign a conflicting
one. It has seen a tree head and not a valuation run, so a valid cosignature
never establishes that anybody observed an execution. These two senses of the
word witness do not imply each other and are never quoted as though they did.

A custodian would owe persistent state that survives a process restart, because
a witness that forgets what it already refused to contradict is not a
lighter-weight witness. It would owe a reachable endpoint, a signing key held
under a managed or hardware-backed store, a written custody agreement stating
what is attested and what is not, a retention and breach-notification
commitment, and liability cover. None of those exist today. They have been
scoped, and the scoping found that the agreement and the cover are the delay
rather than the engineering. Compute and storage for one customer's chain are
one small instance and one bucket. Counsel time and whatever a carrier will
write against this specific exposure are not compressible the way a sprint is.

How many witnesses, and which, is answerable only against a named set of parties
who might collude. That is a policy and threat-model question, and the mechanism
does not supply it.

Semafide intends to adopt the C2SP transparency-log specifications rather than
build a log. A checkpoint is a signed tree head, a custodian signature over one
is a witness cosignature, and an offline-verifiable proof composes the
checkpoint, the cosignatures and the inclusion proof. Using the field's names
rather than local coinages is part of being checkable.

## 7. How a third party checks this

Each rule above is falsifiable by somebody with the repository and no access to
Semafide.

Read `code/seal/verifier.py` and confirm that each proposition in Section 1 is
set only where this document says it is. The single path to
`historical_execution_established` is the highest-value thing to check, because
it is the claim most valuable to overstate.

Run `python -m pytest code/tests` and `python -m seal.demo`. The suite includes
constructed attacks that once verified clean and should not have, frozen so the
gaps cannot reopen quietly. Read those tests before the passing ones.

Run the four checks under `specs/`. Each proves a safety property over unbounded
histories and drives the real implementation over concrete traces, so a proof
about a model that nothing ties to the code would itself be the defect.

Build a counterexample. `SECURITY.md` lists what a defeat looks like, including
obtaining a witness proposition from a self-declared field, truncating a chain
while retaining a consistent completeness result, and withholding a sibling
chain while retaining a clean disclosure result. A failing test against
`code/tests/` is the most actionable form a report can take.

Check this document against the code rather than against itself. Any claim here
that the code does not support is the kind of defect this project treats as
disqualifying, and reporting one is more useful than confirming the rest.

## 8. Known defects and open constraints

Named here because a practice statement that lists only its guarantees is
advertising.

The re-derivation recipe pins the tool and not the environment. A partner who
keeps a version servable for a decade and changes hardware underneath it has
honoured every commitment the artifact asks for, and the re-run can still produce
a different digest. The verifier then reports a mismatch and drops the artifact,
which reads as the partner having changed the analysis when the analysis never
changed. The failure is silent in the direction that matters, because it
manufactures a false accusation rather than a false clearance. The candidate fix
was a manifest of environment fields. It has been withdrawn, because the library
documentation for a production model class names compilers and systems as axes
along which output is expected to move, so a manifest would document the drift
rather than prevent it.

Whether re-derivation has any domain at all is therefore open. It clears the
binding constraint only where the operator cannot hold the raw input and the tool
is deterministic. Across every class examined so far those two conditions have
not co-occurred.

Completeness enforcement is unsolved and is the constraint the rest of the
architecture is organised around. Capture accumulates, one chain stays open for
an assignment, and a run discarded before hand-over leaves a hole the verifier
reports. What that buys is expressibility rather than enforcement. The decorator
is opt-in per function, so an undecorated call is invisible. The manifest sits in
a directory the operator controls. A chain never handed to a custodian is not a
chain anybody can count, and nothing here observes the operator's machine.

Nobody owns the namespace, so nobody can currently say how many chains exist
under one assignment. Only the party who owns the namespace can make that
statement.

Re-derivation carries a liveness dependency a signature does not. Verification
requires a partner's pinned version to remain executable years later, and
enforcing that is a contract problem rather than a cryptographic one.

Every mechanism derived here already exists as infrastructure. Precedence is two
commodity timestamps. The external time anchor is the other half of RFC 3161.
Completeness is a standardised witness protocol with published specifications and
an existing witness network. What is defensible is the namespace, the domain
integration, and the partner commitments, and the cryptography is not a moat.

## 9. How this document stays true

Records that overstate their own state are integrity failures in miniature, and
this document is the one where that would matter most.

It is versioned with the code it describes and changes in the same pull request
as any change to what the verifier grants or refuses. A reviewer who finds a rule
here that the code does not support should treat it as a defect report rather
than as a difference of emphasis, and so should Semafide.

Reports go to eli@semafide.com. Acknowledgement inside five business days. There
is no bounty and no formal service level, which is a single-maintainer constraint
stated rather than implied.
