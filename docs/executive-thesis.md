# Semafide: Executive Architecture and Commercial Thesis

*An evidence model for consequential automated executions: what can be established later about what a system did, and by which party.*

## Status of the Claims

This document separates what is implemented from what Semafide is proposing and what remains commercially unproven:

- **Implemented:** Behavior currently represented in the verifier and test suite.
- **Thesis:** An architectural proposition Semafide is designed to test.
- **Hypothesis:** A commercial or institutional proposition that still requires validation.

## Canonical Claim Hierarchy

The claims in this document sit at different altitudes. Reading a claim at the wrong altitude is the most common way to misread this project, either treating the code as proving more than it does, or treating the commercial framing as more settled than it is. This hierarchy is a map, not new content; every layer is developed further in the numbered sections below.

1. **Problem.** When consequential decisions move from humans into automated systems, the question of what actually happened still has to be answered.
2. **Instrument.** Semafide is an instrument for testing whether evidence surrounding an automated execution supports specific claims about that execution.
3. **Product.** What a partner integrates at execution, what Semafide holds and the producing party does not, and what an examiner receives later (Section 3).
4. **Technical principle.** Cryptographic validity is not the same thing as evidentiary reliance (Section 4).
5. **Evidence model.** Five independent propositions: `precedence`, `witness_attestation`, `recipe_available`, `recipe_reproduced`, `historical_execution_established`. Each answers a different question; none implies another (Section 4.3).
6. **Commercial thesis.** Some high-consequence, opaque workflows face adversarial examination where the party who must prove what happened cannot retain the inputs, and there the cost of being unable to establish what happened may justify stronger evidence preservation (Section 2, applied in Section 8).
7. **Market hypothesis.** AVMs in mortgage lending are the first market being tested. This is unproven and specific to that market, not a claim about automated decision-making generally (Section 9).

The strongest claim this project can make in public today is what the repository's verifier actually establishes, which is Layers 2, 4, and 5. Layer 3 mixes what has been built with what is intended, and Section 3.4 separates the two rather than leaving a reader to guess. Layers 6 and 7 are strategy rather than proof, and should not be read back into what the code does.

## 1. Executive Summary: The Disappearance of the Human Execution Point

### 1.1 The Core Problem

For centuries, institutional trust and legal accountability often relied on a human signature:

> Person → Decision → Responsibility

In modern batch valuation pipelines, automated underwriting, and autonomous AI systems, the person who ultimately bears responsibility may no longer directly observe the execution that produced the outcome:

> Objective → Model / Algorithm → Dynamic Data Ingestion → Automated Tool Actions → Outcome

When an automated system executes, the responsible person may not be able to reconstruct the exact runtime state, input data, or configuration that was active at the time.

### 1.2 The Limit of Operator-Controlled Records

In many high-stakes automated decisions, the party responsible for the action also controls the records used to reconstruct it. That creates an evidentiary limitation when the record itself becomes subject to adversarial review.

The question is not whether internal logs are useful. They are. The harder question is whether a later examiner can independently establish that the record reflects the execution that actually occurred, rather than a reconstruction assembled afterward.

### 1.3 The Institutional Shift

The institutional shift is from trusting operator-controlled records to asking what independent evidence can establish about a consequential automated execution.

### 1.4 The Core Thesis

Semafide is building cryptographic custody and state-preservation infrastructure for independently verifiable evidence of automated executions. That is a company-level goal rather than a description of this repository.

What the accompanying codebase is: an artifact schema, a standalone verifier, and a capture scaffold. `seal.capture` seals a live function call into a real artifact and checks it against the real verifier. What it is not: it does not enforce that every run reaches the chain, because the decorator is opt-in per function and an undecorated call is invisible. And there is no custody service, so the party who would hold the records and answer an examiner does not exist yet. Those two absences are the distance between this repository and the company-level goal, and Section 9 treats the first of them as an open problem rather than a detail.

The technical proposition is narrower than a claim that every automated action needs this infrastructure. Semafide is investigating the environments where the consequences of being unable to prove what happened are large enough to justify preserving stronger evidence at the time of execution.

## 2. The Commercial Thesis

> Semafide is building independently verifiable evidence for consequential automated executions, starting where the cost of being unable to prove what happened is high and the underlying evidence cannot simply be retained by the party responsible for the decision.

Semafide is not needed wherever software makes a decision. It becomes commercially interesting where four conditions converge:

> **Necessity = Consequence × Opacity × Adversarial Verification × Evidence Unretainability**

**Consequence.** The decision carries meaningful financial, legal, regulatory, or safety impact, such as a mortgage loan, an insurance denial, or a credit price.

**Opacity.** The decision is made by an automated pipeline or a black-box model, and no person can reconstruct the exact execution state from memory.

**Adversarial verification.** An outside party, meaning a regulator, a secondary buyer, an insurer, or an opposing litigant, will eventually demand evidence of what happened.

**Evidence unretainability.** The party responsible for defending the decision cannot simply keep a copy of the inputs.

**The first three conditions create a need for better evidence. The fourth determines whether independent custody adds economic value.** If an operator already possesses the complete input and can retain it, timestamp it, and reproduce the work independently, Semafide may add little beyond what commodity services already provide.

The stronger opportunity is where the inputs, the execution environment, the model state, or the assignment history exist outside the operator's control and cannot be reconstructed faithfully after the fact.

The commercial question is therefore not how many automated decisions exist. It is where the inability to independently establish what happened creates a cost large enough for someone to pay to prevent it. Which makes the question to put to a prospective buyer a narrow one:

> Who currently bears the cost when they cannot prove what happened?

An answer of "nobody, we just re-run it" is a finding. An answer describing a vendor call, a reconstructed environment, three systems pulled together, counsel involved, and still no clear account of what the system did is the shape of a market.

Semafide is testing that question first in automated valuation workflows in mortgage lending. Section 3 says what the product is. Section 8 applies the four conditions in detail, and Section 9 records what has been checked so far and what came back.

## 3. What the Product Is

Everything above says why the problem is worth solving. This section says what the thing is, what a customer would integrate, and what an examiner would receive. Section 3.4 states plainly which parts exist today.

### 3.1 Three interfaces, and a record that outlives all of them

**The write path.** An analytical tool, an automated valuation model, or a regression engine calls an application-level interface at the moment it executes, passing a structured execution manifest: a commitment to the input evidence, the parameter set, the tool and model version, the output, and where available a re-derivation recipe. Semafide returns a signed receipt and retains the record. The calling system keeps its own logs and its own outputs, unchanged.

**Custody.** Semafide holds the record. The party who produced the analysis does not. Records accumulate against an assignment identifier, so the chain of runs for one piece of work is held by a party with no interest in how that work turns out. This is the whole product in one sentence, and everything else is mechanism supporting it.

**The read path.** An examiner receives the runs, plus a signed checkpoint issued by the custodian rather than by the sealer, stating how many runs the assignment holds and what the chain ends with. Verification without that checkpoint reports that completeness was never checked rather than reporting a pass, which is the difference between a custody product and an archive.

What is delivered is both a file and an address. The file is an offline-verifiable proof composing the checkpoint, the cosignatures, and the inclusion proof, and it can be handed to a party who trusts nobody and checked without contacting anyone. The address is the log it came from, which is what makes the count answerable at all.

### 3.2 Two moments, kept separate

Runs are captured at execution. Sign-off binds at certification. These are distinct events and the design does not collapse them.

Capture appends each run to the assignment's chain as it happens. Certification is a separate act in which the responsible party binds the finished work, naming every run sealed before it and the head those runs produced. Until certification the assignment reads as incomplete, which is the honest state of work in progress rather than a defect. A binding is an assertion somebody makes about finished work, not a side effect of running one more analysis.

### 3.3 Integration scope, and what it deliberately does not touch

Semafide operates as application-level middleware. It does not touch data scrapers, local form-filling software, or the delivery pipelines that carry finished work to its recipient. Those layers are left exactly as they are, which is what makes integration a call rather than a migration.

The integration cost sits in one requirement and it is worth naming rather than minimising. For re-derivation to establish anything, a partner has to expose a version-pinned execution endpoint that a third party can call years later, and commit to a service window over which that version stays executable. Posting a hash is trivial to replicate. Standing behind a re-runnable version for years is a commitment obtained partner by partner, which is why it is both the integration cost and part of what would be defensible.

Section 9.1 records why that requirement buys less than the original design assumed. For machine-learning models the re-run does not reliably reproduce the original number, so what a partner is really committing to is faithful capture and hand-over rather than reproduction. Whether the recipe survives in the schema for that class of model, or is retained only for tools that are deterministic in practice, is an open design question rather than a settled one.

### 3.4 What exists today, and what does not

The accompanying repository implements the record format, the verifier, the log and proof machinery, the checkpoint and witness mechanics, and a capture scaffold that seals a live function call into a real artifact.

Three things do not exist. There is no custody service, so the party that would receive records and issue checkpoints to an examiner has not been built. No witness is sited, so no independent observer watches an execution. And capture is opt-in per function, so an undecorated call is invisible and nothing observes the operator's machine.

That last one is the hardest of the three and it is not an engineering backlog item. Holding one chain open for an assignment makes the count expressible. Making every run reach that chain, without breaking the workflow the operator actually uses, is a different problem, and where the capture point should sit is unresolved.

### 3.5 What is sold, which is unsettled

The unit of sale is not decided, and stating a number here would be inventing one.

What the reasoning points at: the thing with value is a statement about a set of runs rather than a receipt for a single run. An examination scores an aggregate, and the count is the property the aggregate hides, so a per-run fee prices the wrong object and understates the thing being bought. That argues for the unit being the assignment, the panel, or the institution rather than the execution.

What decides it is what an institution turns out to be buying, which is the question in Section 9.2 and has not been asked. Until it is, this document states the unit as open rather than filling it in.

## 4. The Epistemic Evidence Model: From Co-Occurrence to Independent Propositions

### 4.1 The Core Problem: Co-Occurrence Is Not Binding

In standard analytical workflows, storing inputs and outputs together in a database or folder establishes mere co-occurrence. It does not establish that the output was derived from those inputs, that the inputs existed prior to execution, or that the record was not selectively assembled after the fact.

### 4.2 The Foundational Separation: Cryptographic Trust vs. Evidentiary Reliance

The Semafide verification engine separates two distinct questions:

- **Cryptographic Validity:** Verifies that digital signatures, SHA-256 hashes, and append-only log inclusion proofs are mathematically well-formed and untampered with.
- **Evidentiary Reliance:** Evaluates whether the available evidence supports the particular claims being made about an execution.

These are related but non-equivalent results. A cryptographically valid record can still fail to establish a historical or independent claim.

### 4.3 The Five Independent Evidence Propositions

The verifier's source of truth is five independent propositions. They are **not a ladder**: each establishes a different fact, and a claim holds only where the corresponding evidence supports it. These are the field names the verifier actually reports.

| Proposition | What it establishes | What it does not establish |
|---|---|---|
| `precedence` | The input evidence commitment existed in the append-only log before the run seal that names it. This prevents post-hoc substitution within the committed record. | That the analysis consumed that evidence, or when the underlying real-world evidence first existed. |
| `witness_attestation` | A separately trusted witness key signed an observed-execution attestation binding the run, evidence, action, and capture reference. | That the witness organization is operationally independent or truthful. A field in the operator's own manifest saying “witnessed” is not sufficient, and neither is a generic signature over a supplied bundle. |
| `recipe_available` | A complete re-derivation recipe is present and correctly linked to the claimed evidence and action. | That the recipe has ever been executed. |
| `recipe_reproduced` | A standalone verifier executed that recipe against the committed inputs and reproduced the sealed output, establishing computational equivalence under the specified environment. | That the historical execution actually ran that recipe. For machine-learning models this proposition is frequently unreachable in practice, because the libraries involved do not guarantee identical output across versions, compilers, or machines. See Section 9.1. |
| `historical_execution_established` | A valid observed-execution witness attestation covers the relation. | General custody completeness or substantive correctness. It is never inferred from re-derivation alone. |

Two consequences are load-bearing and easy to get wrong. Successful re-derivation does **not** make `historical_execution_established` true. A generic signature over a supplied bundle does **not** make `witness_attestation` true.

**On the legacy `BindingLevel` projection.** The verifier also emits an ordered `BindingLevel` value (`BUNDLED` → `PRECEDENCE` → `WITNESSED` → `REDERIVABLE` → `REDERIVED`) as a single summary figure for readers who want one. It is a **lossy display projection, not the evidence model**, and it must not be used to infer a proposition not stated in the table above. In particular `BUNDLED` is not an independent proposition; it is the floor the projection returns when `precedence` is false.

### 4.4 The Key Principle

> An epistemic fact should not become true merely because the party that created the record declared it. Where a claim depends on evidence outside the operator's unilateral control, the verifier must derive the claim from that evidence.

## 5. Verification Boundaries and Cross-Cutting Guarantees

- **Assignment disclosure:** Reports whether anything outside the supplied chain states how many chains the assignment holds. A per-chain checkpoint is honest about the chain it names and silent about every other, so five chains under one assignment can each verify perfectly and each carry a true checkpoint. Counting siblings is a question only the party holding all of them can answer, which is why the input is the custodian's rather than the sealer's. Absent that input the verifier reports the question as unchecked rather than as a pass, and it never establishes that no execution existed outside the records the custodian received.
- **External time bounds:** Can anchor execution between verifiable physical boundaries, such as an RFC 3161 timestamp authority (upper bound) and an unpredictable published public value (lower bound).

These mechanisms establish specific propositions. They should not be treated as proof of substantive business wisdom, appraisal accuracy, model quality, or legal correctness.

## 6. What Semafide Does and Does Not Do

- Semafide does not determine whether a business decision was wise, whether an appraisal was accurate, whether a model was fair, or whether an action was legally justified.
- Semafide is concerned with evidentiary custody: Preserving and verifying what execution evidence was committed, what relationships that evidence establishes, and what can still be independently established later.

The goal is not to replace judgment. It is to make the factual substrate beneath later judgment harder to reconstruct selectively.

## 7. Codebase Architecture

- `code/seal/primitives.py`: The six constituents of a decision, canonical JSON encoding, and the commitment and Merkle-root functions everything else is built on.
- `code/seal/artifact.py`: The record schema, meaning the entry kinds, the evidence commitment, the run seal, the re-derivation recipe, and the workfile binding.
- `code/seal/log.py`: Append-only log primitives with inclusion and consistency proof machinery.
- `code/seal/checkpoint.py` and `code/seal/anchor.py`: Signed log-state checkpoints, and the external time bounds that constrain when a chain was written.
- `code/seal/witness.py`: Witness cosigning, equivocation detection, and the counting rules for a cosignature set.
- `code/seal/assignment.py`: Assignment-level disclosure, meaning whether the disclosed chains are all the chains.
- `code/seal/retention.py`: Third-party retention determinations, meaning whether the operator could have held the raw input, which decides whether re-derivation establishes anything beyond a locally retained and timestamped copy.
- `code/seal/verifier.py`: The standalone verifier. It computes the five propositions, the disclosure and completeness states, the time bounds, and the findings that explain each.
- `code/seal/evidence.py`: The relation-level reliance test, which is narrower than cryptographic trust and separate from it.
- `code/seal/capture/`: The capture scaffold. A decorator that hashes a function's inputs, runs it, appends the run to the assignment's chain, optionally asks an external witness to cosign, and checks the result against the real verifier before writing a manifest. Opt-in per function, which is why it makes a run count sayable without making it enforced.
- `code/seal/demo.py` and `code/seal/demo_60s.py`: Two runnable walkthroughs over the real verifier. The first builds records differing by one decision each and prints what the verifier concludes about every one. The second is a short external-facing version.
- `code/tests/`: Adversarial and property-based tests over malformed inputs, precedence failures, witness failures, re-derivation failures, and other attempts to manufacture evidence through declaration alone.
- `specs/`: Z3/SMT specifications over the state machines that carry the custody guarantees. Each proves a safety property over unbounded histories and drives the real implementation over concrete traces.

[`CONTRIBUTING.md`](../CONTRIBUTING.md) covers how to run the tests, the specifications, and the demos, and what this project will not accept into the code.

## 8. Market Selection: Applying the Four Conditions

Section 2 names the four conditions. This section applies them, which means saying what happens when one of them is absent and what the remaining opportunity looks like when all four hold.

The strongest early markets are therefore not the markets using the most AI. A workflow can be saturated with automation, carry real consequence, and still be served adequately by a service costing pennies per request.

### 8.1 Why the fourth condition is the one that selects

Consider a workflow that satisfies the first three and where the operator holds the input file on their own machine. That operator can put the folder through a commodity timestamping service for the price of a request, re-run the analysis themselves years later, and reach the same evidentiary position without a custodian. Independent custody adds cost and adds nothing they could not obtain from an off-the-shelf service.

Semafide has tested this against one class of tool and the answer came back against the architecture. Regression tools used in appraisal document their workflow as starting from a comparable-sales file the operator exports to their own computer before the tool runs. The raw inputs are in the operator's hands, so re-derivation through a partner buys nothing over a local copy and two timestamps.

The condition that creates a seat is the opposite one. A hedonic automated valuation model predicts a price from coefficients across many variables without ever naming a specific comparable. There is no discrete input set for the operator to keep, because the inputs are the vendor's licensed dataset in the state it held at execution plus the learned model weights, and both are the vendor's core asset. That is unretainability arising from the structure of the model rather than from a contract clause, which makes it more durable than a licensing argument, because a licence can be renegotiated and a model that never names a comparable has no comparable to hand over.

This is the first condition Semafide has identified under which independent custody exceeds what a commodity service provides. It has not yet been confirmed by a party outside Semafide, and Section 9 records what that confirmation requires.

### 8.2 The discriminating test

For any candidate market, ask what the mechanism sees that the layer beneath it does not.

Applied to appraisal: the inputs, no, because the operator exports and holds them. The parameters, the tool version, and the output, no, because a workfile already carries them. The time of execution, partly, and only a lower bound. How many analyses were run, yes, and nothing beneath this layer records that.

The plain-language form of that result is the sharpest statement of what the product does. An examination scores an aggregate, meaning the report, the adjustment, the final value. Six analyses and one analysis produce the same aggregate, so a review that scores it passes both identically. The count is the distributional property the aggregate hides.

### 8.3 The dual buyer

Analytical recipes are generated in the tool layer, meaning human-hybrid appraisal software and regression plugins, which makes that layer the testing ground. The parties who hold the liability and control budget are institutional: appraisal management companies, enterprise AVM providers, and automated lenders, driven by the interagency AVM Quality Control Rule and by secondary market repurchase exposure.

That separation is a go-to-market problem rather than a technical one. The party whose workflow the product touches is not the party who pays for it, and whether adoption is driven from the institution downward or from the practitioner upward is unresolved.

### 8.4 What this competes against

Not archival software, which is the comparison the product invites and the wrong one.

The strongest competitor is risk transfer. At least one vendor sells a repurchase and loan-level price adjustment warranty attached to its appraisal review product. That is a direct commercial answer to the same pain, and it is insurance rather than evidence. An institution that can buy an indemnity against an appraisal-caused repurchase has resolved its felt problem regardless of what remains unproven about the underlying valuation. A warranty pays out and a seal does not, which makes it a harder competitor than any archive.

The second competitor is a product category that already exists and looks like a solution. Several vendors sell retrospective valuations, which return a value as of a past date by excluding data after that date. To a risk officer that appears to close the reproducibility gap without any custody layer.

It does not, and the distinction is worth stating precisely because it is easy to miss. A retrospective valuation runs today's model over historical data. It produces a new estimate about a past date rather than reproducing the number that was actually issued then. The evidence is pinned to the moment and the evaluator floats to its current version, which is a different result from the one an examiner is asking about. Semafide's position is that this distinction matters. Whether an institution agrees that it matters enough to pay for is a commercial question, not a technical one, and it is unresolved.

### 8.5 The cryptography is not the moat

A technical evaluator should ask why this is a company rather than a deployment of components that already exist. The question is correct and the answer is that the cryptography is not what would be defensible.

Every mechanism this project relies on exists as commodity infrastructure with published specifications and running implementations. Append-only logs, signed tree heads, witness cosignatures, inclusion and consistency proofs, and the protocol for obtaining a cosignature from a stateful witness are all specified openly, with general-availability libraries and an existing witness network. Trusted timestamping is a settled standard with commercial providers. Nothing in the record format here is novel, and the correct engineering decision is to adopt those specifications rather than reimplement them. The accompanying repository uses the field's vocabulary deliberately for that reason.

Three things survive that analysis, and they are commercial rather than cryptographic.

**The namespace.** Establishing how many analyses an assignment holds is a statement only the party who owns the assignment identifier can make. A per-chain proof is honest about the chain it names and silent about every other, so the counting question is answerable exactly once, by whoever holds all of them. That position is structural rather than technical, and it is the property Section 9.1 identifies as surviving every check run so far.

**The domain integration.** Knowing which questions an examiner asks, which artifacts a workfile is required to contain, and where in a real workflow a record can be captured without breaking it is knowledge accumulated per market rather than written once.

**The partner commitments.** A version-pinned execution endpoint that a third party can call years later, backed by a stated service window, is a commitment obtained from each partner individually. Posting a hash is trivial to replicate. Standing behind a re-runnable version for years is not, and Section 9.1 records why that commitment is worth less for machine-learning models than the original design assumed.

### 8.6 Who operates the log, which is unresolved

The independence claim depends on this and it is not settled.

If Semafide operates the log with independent witnesses cosigning, the independence claim holds, accountability runs to parties Semafide does not control, and proofs stay verifiable offline. The cost is becoming a log operator with liveness and key-management obligations, and the answer to Semafide ceasing to exist has to be mirrors and persistent witnesses rather than a promise.

If a partner operates the log with Semafide witnessing, the cost is low and no namespace is owned, so sibling chains under one assignment remain uncountable and the property that survives every other check is lost.

Semafide operating the log and witnessing it alone is refused by the accompanying package's own checkpoint logic, correctly, because a party cannot attest to itself on the point at issue.

The first option is the one the thesis assumes. It is stated here as an assumption rather than a decision, because the obligations it carries are real and a reader evaluating this commercially should price them.

## 9. What Is Known, What Is Hypothesized, and What Remains to Be Proven

- **Known:** Consequential automated execution is increasing, and organizations already use logs, tracing, monitoring, identity, and audit systems to reconstruct system behavior.
- **Thesis:** In some high-stakes workflows, operator-controlled records will not provide enough independent evidence to resolve later disputes about what actually happened.
- **Technical proposition:** Cryptographically binding relevant execution state and preserving evidence at the time of action can make later substitution detectable and can make specific execution claims independently verifiable. Section 9.1 records where this proposition has been narrowed by evidence.
- **Commercial hypothesis:** There are workflows where the cost of being unable to prove what happened exceeds the cost of preserving stronger evidence at execution time.
- **Unproven:** Which buyer will pay first, what evidence standard that buyer requires, and what stronger evidence is worth economically.

### 9.1 Checks that have been run against this thesis

Kill conditions were written and dated before any check ran, and each result is recorded on the day it returned. This section exists because a document that reports only supporting evidence is the kind of record this project argues against.

**Re-derivation does not survive for machine-learning valuation models.** The re-derivation mechanism assumed that a pinned model version returns the same output for the same input when re-run later. It does not, and the version does not even have to change. A published production automated valuation model runs LightGBM, and LightGBM's own parameter documentation states that results are expected to differ across different versions, across binaries compiled by different compilers, and across different systems. A widely used regression implementation produces a logistic regression intercept that moves in the third decimal place between two machines running the same library version on different processor generations. For this class of model, `recipe_reproduced` is not a proposition an artifact can rely on reaching, and the accompanying repository reports it as unestablished rather than granting it.

**Precedence alone is replicable by commodity services.** Committing an input hash before a run fixes the order of two records and nothing more. Two independent timestamps over two local files reach the same position for the price of two requests. What prior commitment does buy is a coverage check that makes an omitted run detectable, which is a completeness property rather than a binding one.

**The operator holds the input in the tool layer.** Vendor documentation for appraisal regression tools describes the workflow as exporting a comparable-sales file to the operator's own computer before the tool runs. That decides the fourth condition against this architecture for that class of tool.

**Licensing does not create the seat either.** Standard multiple listing service rules permit a subscriber to download data into their own systems and restrict retransmission. If retention is permitted, the operator can keep and timestamp the rows locally. If it were forbidden, the same restriction would forbid sending them to a custodian. Neither branch produces a position that requires this product.

**Enforcement practice does not currently prosecute short disclosure.** Twenty consecutive final disciplinary decisions from one state regulator were read as primary documents. The recordkeeping requirement that a workfile show compliance with professional standards, as distinct from supporting the conclusion reached, was never cited as an independent finding. No decision concerned analyses performed and not documented, and none concerned reproducibility. Boards prosecute deficient support for a conclusion. This does not bear on the institutional case, which requires no regulator to agree, but it removes an argument the project would otherwise have made.

**What survives all of the above.** Completeness custody. Establishing how many analyses an assignment contains requires no determinism, no re-derivation, and no observing witness. It is the one property in Section 8's discriminating test that the layer beneath does not already record, and it is what the accompanying repository's verifier reports as assignment disclosure.

**The narrowing, stated in one line, because it is easy to lose across six findings.** The architecture set out to prove what a system relied on. What survived is proof of how many times it ran. Those are different products, and this document describes the second one.

### 9.2 The question that decides this

Would one institution pay to know how many analyses its own panel ran, purely to manage its own exposure, with no external party needing to accept the statement as evidence?

If the answer is yes, the product is useful to a single buyer before anyone else recognizes it, which is how attestation businesses such as credit rating agencies established themselves over decades before regulation embedded them.

If the value appears only when an examiner treats the statement as evidence, the product requires institutional acceptance before it is worth anything to its first customer, which is how notaries and statutory auditors work and which is materially harder from a standing start.

The opening moves for those two paths are opposite, so the answer determines strategy rather than refining it. It has not been asked.

### 9.3 Primary Wedge Hypothesis: Automated Valuation Models in Mortgage Lending

- **Regulatory driver:** The interagency Quality Control Standards for Automated Valuation Models, effective 1 October 2025, which require covered institutions to maintain policies and control systems including protection against the manipulation of data. This is a controls standard rather than an evidentiary one, which matters: a regulator satisfied by documented controls may accept something well short of what an adversary in a repurchase dispute would demand. It is a reason for a budget holder to care rather than a specification to build against.
- **Financial risk:** Secondary market repurchase demands on contested collateral valuations, where the loss on a single demand is measured in tens of thousands of dollars and the lookback period runs to years.
- **Structural fit:** Hedonic and machine-learning valuation models satisfy the fourth condition, because no discrete input set exists for the operator to retain.
- **What a lender would actually obtain:** An independent statement of how many valuation runs an assignment contains and what the disclosed set omits. Given Section 9.1, it would not obtain reproduction of a historical machine-learning valuation, and this document does not claim otherwise.

This is a market hypothesis. It is not a demonstrated buyer requirement, not evidence that any institution has been unable to answer such a question, and not a claim that the accompanying repository satisfies any lender's audit standard.

### 9.4 Expansion: Multi-Vendor AI Supply Chains and Autonomous Agents

- **Expansion hypothesis:** Evidence of API-bound execution relationships could reduce disputes between enterprise orchestrators, data vendors, and model providers, where the current failure mode is that no party can establish what another party's system consumed.
- **Expansion hypothesis:** Similar infrastructure could serve consequential autonomous agents that execute financial or operational actions with no person observing each step.

These are future applications rather than current product claims, and both inherit the fourth condition. An expansion market where the operator can retain the inputs is a market a commodity timestamping service serves adequately.

## 10. Conclusion

The central problem is not that automated systems produce bad records. It is that consequential execution is moving away from directly observable humans, while the need to establish what happened remains.

Semafide is exploring infrastructure for the gap between an execution record and evidence of execution.

The company does not need every automated action to require this infrastructure. It needs to find the places where consequence, opacity, adversarial verification, and evidence unretainability converge strongly enough that someone will pay to close that gap. The fourth of those is the one that separates a market needing better records from a market needing an independent custodian, and the checks in Section 9.1 are how that separation is being tested rather than assumed.
