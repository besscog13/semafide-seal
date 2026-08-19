# Semafide

Semafide is building cryptographic custody and state-preservation middleware for batch-executed valuation and automated lending pipelines.

When an analytical tool, automated valuation model, or regression script executes, the design captures the execution context through an application-level API and binds the inputs, parameters, model version, and output into a tamper-evident record. Semafide holds that record. The party who produced the analysis does not.

## The problem

Mortgage collateral is increasingly valued by software running against live databases. Automated valuation models score properties from public records and listing data. Appraisers derive adjustments from regression analyses over comparable sales. Both run against surfaces that change continuously, because sales get corrected, listings get amended, records get merged, and the models themselves are versioned and retired.

When a repurchase demand, a regulatory examination, or a dispute arrives eighteen months later, re-running the analysis produces a different number. Not because anyone was careless. The analysis was a query against a live surface for a moment that no longer exists.

Since 1 October 2025, the interagency Quality Control Standards for Automated Valuation Models have required institutions using an AVM in a credit decision or securitization determination to maintain control systems that protect against the manipulation of data. Separately, since February 2025, appraisers have been required to summarize in the report itself the data sources, tools, and techniques behind a time adjustment. Both obligations assume the underlying execution can be accounted for. Neither is satisfied by a log entry recording what a system concluded.

## Authorization and admissibility

Authorization is prospective and structural. It asks whether an action is permitted and whether the output conforms: schema validity, licence currency, a passing risk score, the required checks completed. Nearly every system in this market is built for it, because clearing the gate is what keeps a pipeline moving.

Admissibility asks a different question. If this transaction is challenged three years from now, can the data state it rested on be proven?

Two things follow. The question is adjudicated retrospectively and the answer has to be manufactured prospectively, because an analysis cannot be made provable after the fact. And the engine that cleared the transaction cannot credibly attest to its own history, because its records are self-serving on precisely the point in dispute.

## The principle

A record showing that an analysis and its inputs sat together in one file is not evidence that the output was derived from those inputs at that moment. Co-occurrence is not binding. Workfiles and audit trails are kept as though it were. The gap does not show until someone examines a specific decision. By then it cannot be closed.

The record is meant for that examiner rather than for the party being examined. Its value is that it is held by someone other than the party whose interests it may later cut against.

## Why custody rather than a file

The obvious design hands the appraiser or the institution a signed artifact to keep. That design does not work, and the reason decides the shape of the product.

A signature proves that what a document contains has not been altered. It cannot prove that the document contains everything, because completeness is a claim about what is absent, and whoever decides what to hand over also decides what to leave out. Run five analyses, seal all five, disclose the three that support the conclusion. Each of the three verifies perfectly. Nothing in them says the other two ever existed.

Timestamping does not close this, which is worth saying plainly because it is the intuitive fix. A timestamp proves a document existed at a time. It says nothing about documents nobody was shown. Anchor all five runs to a time authority and hand over three, and all three still verify.

Splitting the work across five separate records rather than five entries in one does not help either, and it is the version of the trick worth naming, because each record is then not merely valid but honest. Every entry it contains really was part of it. The omission is a whole record rather than a line inside one.

What closes both is that the record is not the examined party's to curate. An examiner asks the custodian how many runs an assignment contains, and how many records it holds, and receives answers the examined party did not compose. That is the difference between a signature and custody, and it is why the record lives here rather than with the appraiser.

## How it integrates

Semafide does not touch data scrapers, form-filling software, or delivery pipelines. It operates as an application-level API that upstream analytical software calls with an execution manifest carrying the input dataset hash, the parameter set, the tool and model version, and the output.

The manifest also carries a re-derivation recipe, which is a required part of the integration rather than an optional field. A partner exposes a version-pinned execution endpoint that a third party can call later, and commits to a window over which that version stays runnable. A verifier calls it, re-executes, and compares. Proof of derivation comes from reproduction rather than from assertion.

On the other side, an examiner receives two things: the record of the runs, and a signed statement of what the assignment holds, meaning how many runs, what the record ends with, and how many separate records there are. The second is what makes a short disclosure visible, and it is signed by a key that is not the sealer's. Verification without it reports that completeness was never checked, rather than reporting a pass.

Each analysis is bound to its assignment when it is sealed rather than when the work is certified. The distinction matters because certification happens last, and a fact recorded last is recorded by someone who already knows how the work turned out.

The same reasoning applies to the clock, and it leads somewhere less obvious. The time a record states is a number its author wrote, so a record assembled after a question arrives and dated to the original work is indistinguishable from one made at the time. Timestamping is the intuitive fix and it addresses the opposite problem: a timestamp establishes that a document existed by a certain moment, which rules out a record made later than it claims and says nothing about one made earlier. Ruling out the earlier case requires the record to commit to something that had not been published yet when the work is claimed to have happened, because nobody can write down a value before it exists. The two together place the work inside a window that neither end of was chosen by the party being examined, and how wide that window is gets reported rather than assumed.

## What it does not do

Nothing blocks. Nothing evaluates quality. Nothing scores. Custody, not judgment.

The record is symmetric evidence. It documents a flawed analysis as faithfully as a sound one. It does not create admissibility where none existed, and it does not establish that the inputs were well chosen. It attests to the capture, meaning what the software actually consumed at the moment it ran, rather than to the quality of what was captured.

Custody carries costs that a file handed over does not, and they are real. The guarantee depends on Semafide continuing to exist and continuing to answer, which makes it an operational commitment rather than a purely cryptographic one. Verification also depends on a partner's pinned version remaining executable, so part of the guarantee rests on contract rather than on cryptography.

Nothing in the mathematics prevents a custodian from colluding with the party it is meant to constrain, so the custodian has to be accountable to something outside itself. Two things reduce what has to be taken on faith and neither eliminates it. The record is kept in an append-only structure, so a statement of the log made years apart must demonstrate arithmetically that the later contains the earlier unchanged, and a custodian that removed an entry cannot produce that demonstration. And outside parties countersign those statements, keeping what they last saw and refusing anything inconsistent with it, so showing two different accounts of the same record requires convincing all of them rather than nobody, and an inconsistent pair once obtained is permanent evidence that its author cannot withdraw. What remains is a question about who those parties are and whether anyone checks, which is a matter of how the service is operated rather than of what the mathematics forces.

## About this repository

`code/seal/` holds the record schema, the checkpoint formats for a single record and for an assignment, the external time bounds, an append-only log with the proofs that hold the custodian to its own history, the countersigning that raises the cost of telling two examiners different things, and a standalone verifier. It imports nothing from earlier work. The verifier classifies a record by what it establishes about the relation between an output and the inputs it claims, reports whether a commodity timestamping service could have produced the same evidentiary force, and reports whether anything outside the record vouches for its length, for how many records the assignment has, and for when it was written. The capture path is not implemented.

It depends on `cryptography` alone. To watch it work, `pip install -r code/seal/requirements.txt` and then `cd code && python -m seal.demo`, which builds a sequence of records differing by one decision each and prints what the verifier concludes about every one, including a truncated record, a set of five records with one handed over, and a record dated to before it could have existed, each shown before and after somebody other than its author has spoken for it.

## Contact

eli@semafide.com
