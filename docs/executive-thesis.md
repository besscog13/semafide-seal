# Semafide: Executive Architecture & Commercial Thesis

*A record model for analytical workflows: establishing what was done, when it was done, and what evidence supports the result.*

## Status of the Claims

This document separates what is implemented from what Semafide is proposing and what remains commercially unproven:

- **Implemented:** Behavior currently represented in the verifier and test suite.
- **Thesis:** An architectural proposition Semafide is designed to test.
- **Hypothesis:** A commercial or institutional proposition that still requires validation.

## Canonical Claim Hierarchy

The claims in this document sit at different altitudes. Reading a claim at the wrong altitude is the most common way to misread this project — either treating the code as proving more than it does, or treating the commercial framing as more settled than it is. This hierarchy is a map, not new content; every layer is developed further in the numbered sections below.

1. **Problem** — When consequential decisions move from humans into automated systems, the question of what actually happened still has to be answered.
2. **Instrument** — Semafide is an instrument for testing whether evidence surrounding an automated execution supports specific claims about that execution.
3. **Technical principle** — Cryptographic validity is not the same thing as evidentiary reliance (Section 2).
4. **Evidence model** — Five independent propositions: `precedence`, `witness_attestation`, `recipe_available`, `recipe_reproduced`, `historical_execution_established`. Each answers a different question; none implies another (Section 2.3).
5. **Commercial thesis** — Some high-consequence, opaque workflows face adversarial examination where the cost of being unable to establish what happened may justify stronger evidence preservation (Section 6).
6. **Market hypothesis** — AVMs in mortgage lending are the first market being tested. This is unproven and specific to that market, not a claim about automated decision-making generally (Section 7).

The strongest claim this project can make in public today is Layers 2 through 4 — what the repository's verifier actually establishes. Layers 5 and 6 are strategy, not proof, and should not be read back into what the code does.

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

Semafide is building cryptographic custody and state-preservation infrastructure for independently verifiable evidence of automated executions. That is a company-level goal, not a description of this repository: the codebase accompanying this thesis is a pre-build verifier and evidence-model scaffold, and does not itself implement capture or custody (see the README's verification status).

The technical proposition is narrower than a claim that every automated action needs this infrastructure. Semafide is investigating the environments where the consequences of being unable to prove what happened are large enough to justify preserving stronger evidence at the time of execution.

## 2. The Epistemic Evidence Model: From Co-Occurrence to Independent Propositions

### 1. The Core Problem: Co-Occurrence Is Not Binding

In standard analytical workflows, storing inputs and outputs together in a database or folder establishes mere co-occurrence. It does not establish that the output was derived from those inputs, that the inputs existed prior to execution, or that the record was not selectively assembled after the fact.

### 2. The Foundational Separation: Cryptographic Trust vs. Evidentiary Reliance

The Semafide verification engine separates two distinct questions:

- **Cryptographic Validity:** Verifies that digital signatures, SHA-256 hashes, and append-only log inclusion proofs are mathematically well-formed and untampered with.
- **Evidentiary Reliance:** Evaluates whether the available evidence supports the particular claims being made about an execution.

These are related but non-equivalent results. A cryptographically valid record can still fail to establish a historical or independent claim.

### 3. The Five Independent Evidence Propositions

The verifier's source of truth is five independent propositions. They are **not a ladder**: each establishes a different fact, and a claim holds only where the corresponding evidence supports it. These are the field names the verifier actually reports.

| Proposition | What it establishes | What it does not establish |
|---|---|---|
| `precedence` | The input evidence commitment existed in the append-only log before the run seal that names it. This prevents post-hoc substitution within the committed record. | That the analysis consumed that evidence, or when the underlying real-world evidence first existed. |
| `witness_attestation` | A separately trusted witness key signed an observed-execution attestation binding the run, evidence, action, and capture reference. | That the witness organization is operationally independent or truthful. A field in the operator's own manifest saying “witnessed” is not sufficient, and neither is a generic signature over a supplied bundle. |
| `recipe_available` | A complete re-derivation recipe is present and correctly linked to the claimed evidence and action. | That the recipe has ever been executed. |
| `recipe_reproduced` | A standalone verifier executed that recipe against the committed inputs and reproduced the sealed output, establishing computational equivalence under the specified environment. | That the historical execution actually ran that recipe. |
| `historical_execution_established` | A valid observed-execution witness attestation covers the relation. | General custody completeness or substantive correctness. It is never inferred from re-derivation alone. |

Two consequences are load-bearing and easy to get wrong. Successful re-derivation does **not** make `historical_execution_established` true. A generic signature over a supplied bundle does **not** make `witness_attestation` true.

**On the legacy `BindingLevel` projection.** The verifier also emits an ordered `BindingLevel` value (`BUNDLED` → `PRECEDENCE` → `WITNESSED` → `REDERIVABLE` → `REDERIVED`) for backwards compatibility with existing consumers. It is a **lossy display projection, not the evidence model**, and it must not be used to infer a proposition not stated in the table above. In particular `BUNDLED` is not an independent proposition; it is the floor the projection returns when `precedence` is false.

### The Key Principle

> An epistemic fact should not become true merely because the party that created the record declared it. Where a claim depends on evidence outside the operator's unilateral control, the verifier must derive the claim from that evidence.

## 3. Contextual Verification Boundaries & Cross-Cutting Guarantees

- **Assignment completeness:** Can verify that the supplied sequence of runs represents the complete disclosure of an assignment from the custodian, reducing the risk of selective omission. It does not establish that no execution existed outside the records received by that custodian.
- **External time bounds:** Can anchor execution between verifiable physical boundaries, such as an RFC 3161 timestamp authority (upper bound) and an unpredictable published public value (lower bound).

These mechanisms establish specific propositions. They should not be treated as proof of substantive business wisdom, appraisal accuracy, model quality, or legal correctness.

## 4. What Semafide Does and Does Not Do

- Semafide does not determine whether a business decision was wise, whether an appraisal was accurate, whether a model was fair, or whether an action was legally justified.
- Semafide is concerned with evidentiary custody: Preserving and verifying what execution evidence was committed, what relationships that evidence establishes, and what can still be independently established later.

The goal is not to replace judgment. It is to make the factual substrate beneath later judgment harder to reconstruct selectively.

## 5. Codebase Architecture

- `code/seal/artifact.py` & `code/seal/evidence.py`: Manifest schemas, evidence encapsulation, and proposition representations.
- `code/seal/log.py`: Append-only log primitives and inclusion/consistency proof machinery.
- `code/seal/checkpoint.py` & `code/seal/anchor.py`: Append-only log state checkpoints and external time-bound anchors.
- `code/seal/witness.py`: External witness cosigning and custody-boundary interfaces.
- `code/seal/assignment.py`: Assignment aggregation and disclosure-completeness verification.
- `code/seal/retention.py`: Third-party retention determinations — whether the operator could have held the raw input, which decides whether re-derivation establishes anything beyond a locally retained and timestamped copy.
- `code/seal/verifier.py` & `code/seal/primitives.py`: Standalone verifier engine for third-party auditing.
- `code/tests/`: Adversarial and property-based tests evaluating malformed inputs, precedence failures, witness failures, rederivation failures, and other attempts to manufacture evidence through declaration alone.
- `specs/`: Z3/SMT specifications over the state machines that carry the custody guarantees. Each proves a safety property over unbounded histories and drives the real implementation over concrete traces.

See [Verification status](../README.md#verification-status) for what currently passes.

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

### Primary Wedge Hypothesis: Automated Valuation Models (AVMs) in Mortgage Lending

- **Regulatory Driver:** Interagency AVM Quality Control Rule (CFPB, Fed, OCC, FDIC) and Fair Lending compliance.
- **Financial Risk:** Secondary market loan repurchase demands (Fannie Mae / Freddie Mac) on contested collateral valuations.
- **Current Solution Hypothesis:** A lender could use independently verifiable execution evidence about third-party AVM runs and the evidence state bound to them, rather than relying solely on an operator-curated reconstruction.

This is a market hypothesis, not a demonstrated buyer requirement or proof that the current repository satisfies a lender's audit standard.

### Expansion: Multi-Vendor AI Supply Chains & Autonomous Agents

- **Expansion hypothesis:** Immutable evidence of relevant API-bound execution relationships could reduce disputes between enterprise orchestrators, data vendors, and model providers.
- **Expansion hypothesis:** Similar evidence infrastructure could serve consequential autonomous agents that execute financial or operational actions without a human observing each step.

These are future applications, not current product claims.

## 8. Conclusion

The central problem is not that automated systems produce bad records. It is that consequential execution is moving away from directly observable humans, while the need to establish what happened remains.

Semafide is exploring infrastructure for the gap between an execution record and evidence of execution.

The company does not need every automated action to require this infrastructure. It needs to find the places where consequence, opacity, and adversarial verification converge strongly enough that someone will pay to close that gap.
