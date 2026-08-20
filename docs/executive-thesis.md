# Semafide: Executive Architecture & Commercial Thesis

*A record model for analytical workflows: establishing what was done, when it was done, and what evidence supports the result.*

## Status of the Claims

This document separates what is implemented from what Semafide is proposing and what remains commercially unproven:

- **Implemented:** Behavior currently represented in the verifier and test suite.
- **Thesis:** An architectural proposition Semafide is designed to test.
- **Hypothesis:** A commercial or institutional proposition that still requires validation.

## 1. Executive Summary: The Disappearance of the Human Execution Point

### The Core Problem

For centuries, institutional trust and legal accountability often relied on a human signature:

> Person → Decision → Responsibility

In modern batch valuation pipelines, automated underwriting, and autonomous AI systems, the person who ultimately bears responsibility may no longer directly observe the execution that produced the outcome:

> Objective → Model / Algorithm → Dynamic Data Ingestion → Automated Tool Actions → Outcome

When an automated system executes, the responsible person may not be able to reconstruct the exact runtime state, input data, or configuration that was active at the time.

### The Limit of Operator-Controlled Records

In many high-stakes automated decisions, the party responsible for the action also controls the records used to reconstruct it. That creates an evidentiary limitation when the record itself becomes subject to adversarial review.

The question is not whether internal logs are useful. They are. The harder question is whether a later examiner can independently establish that the record reflects the execution that actually occurred, rather than a reconstruction assembled afterward.

### The Institutional Shift

The institutional shift is from trusting operator-controlled records to asking what independent evidence can establish about a consequential automated execution.

### The Core Thesis

Semafide is building cryptographic custody and state-preservation infrastructure for independently verifiable evidence of automated executions.

The technical proposition is narrower than a claim that every automated action needs this infrastructure. Semafide is investigating the environments where the consequences of being unable to prove what happened are large enough to justify preserving stronger evidence at the time of execution.

## 2. The Epistemic Evidence Model: From Co-Occurrence to Independent Propositions

### 1. The Core Problem: Co-Occurrence Is Not Binding

In standard analytical workflows, storing inputs and outputs together in a database or folder establishes mere co-occurrence. It does not establish that the output was derived from those inputs, that the inputs existed prior to execution, or that the record was not selectively assembled after the fact.

### 2. The Foundational Separation: Cryptographic Trust vs. Evidentiary Reliance

The Semafide verification engine decouples verification into two distinct, non-conflated tiers:

- **Cryptographic Validity (Mathematical Proof):** Verifies that digital signatures, SHA-256 hashes, and append-only log inclusion proofs are mathematically well-formed and untampered with.
- **Evidentiary Reliance (Epistemic Warrant):** Evaluates whether an external examiner has structural and procedural justification to rely on the claims asserted by the execution manifest.

### 3. The 5 Independent Evidence Propositions

Rather than a one-dimensional score, the verifier evaluates five orthogonal, independent propositions:

1. **Manifest integrity and schema binding (BUNDLED):** The inputs, parameters, model version, and outputs form a coherent signed execution manifest. This establishes that the components belong to the same asserted run, but does not by itself prove historical sequence or execution correctness.
2. **Input precedence and prior commitment (PRECEDENCE):** The input evidence commitment existed in the append-only log before the run seal that names it. This can prevent post-hoc substitution within the committed record, but does not by itself prove when the underlying real-world evidence first existed.
3. **Independent witness attestation (WITNESSED):** An independently recognized witness attests to the relevant capture event and the exact state within the witness's scope. A field in the operator's own manifest saying “witnessed” is not sufficient.
4. **Recipe availability and computational rederivability (REDERIVABLE):** The computational recipe linking input evidence to output is fully specified, accessible, and executable.
5. **Deterministic reproduction (REDERIVED):** A standalone verifier independently re-executes the recipe against the committed inputs and reproduces the sealed output. This establishes computational equivalence under the specified environment. It does not, by itself, establish that the historical execution actually occurred that way.

### The Key Principle

> An epistemic fact should not become true merely because the party that created the record declared it. Where a claim depends on evidence outside the operator's unilateral control, the verifier must derive the claim from that evidence.

## 3. Contextual Verification Boundaries & Cross-Cutting Guarantees

- **Assignment completeness:** Can verify that the supplied sequence of runs represents the complete disclosure of an assignment from the custodian, reducing the risk of selective omission.
- **External time bounds:** Can anchor execution between verifiable physical boundaries, such as an RFC 3161 timestamp authority (upper bound) and an unpredictable published public value (lower bound).

These mechanisms establish specific propositions. They should not be treated as proof of substantive business wisdom, appraisal accuracy, model quality, or legal correctness.

## 4. What Semafide Does and Does Not Do

- Semafide does not determine whether a business decision was wise, whether an appraisal was accurate, whether a model was fair, or whether an action was legally justified.
- Semafide is concerned with evidentiary custody: Preserving and verifying what execution evidence was committed, what relationships that evidence establishes, and what can still be independently established later.

The goal is not to replace judgment. It is to make the factual substrate beneath later judgment harder to reconstruct selectively.

## 5. Codebase Architecture

- `code/seal/artifact.py` & `code/seal/evidence.py`: Manifest schemas, evidence encapsulation, and proposition representations.
- `code/seal/checkpoint.py` & `code/seal/anchor.py`: Append-only log state checkpoints and external time-bound anchors.
- `code/seal/witness.py`: External witness cosigning and custody-boundary interfaces.
- `code/seal/assignment.py`: Assignment aggregation and disclosure-completeness verification.
- `code/seal/verifier.py` & `code/seal/primitives.py`: Standalone verifier engine for third-party auditing.
- `code/seal/tests/`: Adversarial tests evaluating malformed inputs, precedence failures, witness failures, rederivation failures, and other attempts to manufacture evidence through declaration alone.

## 6. Market Selection & Commercial Strategy

Semafide's commercial hypothesis is that the strongest early markets are not simply the markets using the most AI. They are the workflows where three conditions overlap:

> **Necessity = Consequence × Opacity × Adversarial Verification**

1. **High Consequence:** Meaningful financial, regulatory, legal, or safety impact (e.g., mortgage loans, insurance denials, credit pricing).
2. **Execution Opacity:** The decision is made by an automated pipeline or black-box model where no human can reconstruct the exact execution state from memory.
3. **Adversarial Verification:** An external third party (regulator, secondary buyer, insurer, or opposing litigant) will eventually demand proof of what occurred.

## 7. What Is Known, What Is Hypothesized, and What Remains to Be Proven

- **Known:** Consequential automated execution is increasing; organizations already use logs, tracing, monitoring, identity, and audit systems to reconstruct system behavior.
- **Thesis:** In some high-stakes workflows, operator-controlled records will not provide enough independent evidence to resolve later disputes about what actually happened.
- **Technical proposition:** Cryptographically binding relevant execution state and preserving evidence at the time of action can make later substitution detectable and make specific execution claims independently verifiable.
- **Commercial hypothesis:** There are workflows where the cost of being unable to prove what happened exceeds the cost of preserving stronger evidence at execution time.
- **Unproven:** Which buyer will pay first, what exact evidence standard that buyer requires, and how much stronger evidence is worth economically.

### Primary Wedge: Automated Valuation Models (AVMs) in Mortgage Lending

- **Regulatory Driver:** Interagency AVM Quality Control Rule (CFPB, Fed, OCC, FDIC) and Fair Lending compliance.
- **Financial Risk:** Secondary market loan repurchase demands (Fannie Mae / Freddie Mac) on contested collateral valuations.
- **The Solution:** Lenders obtain an independent execution seal proving third-party AVM runs were bound to contemporaneous market data without post-hoc curation.

### Expansion: Multi-Vendor AI Supply Chains & Autonomous Agents

- Eliminates the B2B blame game between enterprise orchestrators, data vendors, and foundation model providers by providing immutable receipts of exchange at API boundaries.
- Serves as an unalterable flight recorder for autonomous agents executing consequential financial transactions.

## 8. Conclusion

The central problem is not that automated systems produce bad records. It is that consequential execution is moving away from directly observable humans, while the need to establish what happened remains.

Semafide is exploring infrastructure for the gap between an execution record and evidence of execution.

The company does not need every automated action to require this infrastructure. It needs to find the places where consequence, opacity, and adversarial verification converge strongly enough that someone will pay to close that gap.
