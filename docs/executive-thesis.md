**Semafide: Executive Architecture & Commercial Thesis**

A record model for analytical workflows: establishing what was done, when it was done, and what evidence supports the result.

**Status of the claims**

This document separates what is implemented from what Semafide is proposing and what remains commercially unproven.

**Implemented: behavior currently represented in the verifier and tests.**

**Thesis: an architectural proposition Semafide is designed to test.**

**Hypothesis: a commercial or institutional proposition that still requires validation.**

**1. Executive Summary: The Disappearance of the Human Execution Point**

**The Core Problem**

For centuries, institutional trust and legal accountability often relied on a human signature:

Person → Decision → Responsibility

In modern batch valuation pipelines, automated underwriting, and autonomous AI systems, the person who ultimately bears responsibility may no longer directly observe the execution that produced the outcome:

Objective → Model / Algorithm → Dynamic Data Ingestion → Automated Tool Actions → Outcome

When an automated system executes, the responsible person may not be able to reconstruct the exact runtime state, input data, or configuration that was active at the time.

**The Limit of Operator-Controlled Records**

In many high-stakes automated decisions, the party responsible for the action also controls the records used to reconstruct it. That creates an evidentiary limitation when the record itself becomes subject to adversarial review.

The question is not whether internal logs are useful. They are. The harder question is whether a later examiner can independently establish that the record reflects the execution that actually occurred, rather than a reconstruction assembled afterward.

**The Institutional Shift**

The institutional shift is from trusting operator-controlled records to asking what independent evidence can establish about a consequential automated execution.

**The Core Thesis**

Semafide is building cryptographic custody and state-preservation infrastructure for independently verifiable evidence of automated executions.

The technical proposition is narrower than a claim that every automated action needs this infrastructure. Semafide is investigating the environments where the consequences of being unable to prove what happened are large enough to justify preserving stronger evidence at the time of execution.

**2. The Epistemic Evidence Model: From Co-Occurrence to Independent Propositions**

**The Core Problem: Co-Occurrence Is Not Binding**

Storing inputs and outputs together in a database or folder establishes co-occurrence. It does not by itself establish that the output was derived from those inputs, that the inputs existed before execution, or that the record was not selectively assembled after the fact.

**Cryptographic Trust vs. Evidentiary Reliance**

The verification engine separates two questions:

Cryptographic validity: are the signatures, hashes, and append-only log relationships mathematically well-formed and untampered with?

Evidentiary reliance: has the verifier established enough independent evidence about the relevant relationship that an external examiner has reason to rely on the claim?

**The Evidence Propositions**

1. Manifest integrity and schema binding. The inputs, parameters, model version, and outputs form a coherent signed execution manifest. This establishes that the components belong to the same asserted run, but does not by itself prove historical sequence or execution correctness.
2. Input precedence and prior commitment. The input evidence commitment existed in the append-only log before the run seal that names it. This can prevent post-hoc substitution within the committed record, but does not by itself prove when the underlying real-world evidence first existed.
3. Independent witness attestation. An independently recognized witness attests to the relevant capture event and the exact state within the witness's scope. A field in the operator's own manifest saying “witnessed” is not sufficient.
4. Recipe availability and computational rederivability. The computational recipe linking input evidence to output is fully specified, accessible, and executable.
5. Deterministic reproduction. A standalone verifier independently re-executes the recipe against the committed inputs and reproduces the sealed output. This establishes computational equivalence under the specified environment. It does not, by itself, establish that the historical execution actually occurred that way.

**The key principle**

An epistemic fact should not become true merely because the party that created the record declared it. Where a claim depends on evidence outside the operator's unilateral control, the verifier must derive the claim from that evidence.

**3. Contextual Verification Boundaries & Cross-Cutting Guarantees**

Assignment completeness can verify that the supplied sequence of runs represents the complete disclosure of an assignment from the custodian, reducing the risk of selective omission.

External time bounds can anchor execution between verifiable physical boundaries, such as an RFC 3161 timestamp authority and an unpredictable published public value.

These mechanisms establish specific propositions. They should not be treated as proof of substantive business wisdom, appraisal accuracy, model quality, or legal correctness.

**4. What Semafide Does and Does Not Do**

Semafide does not determine whether a business decision was wise, whether an appraisal was accurate, whether a model was fair, or whether an action was legally justified.

Semafide is concerned with evidentiary custody: preserving and verifying what execution evidence was committed, what relationships that evidence establishes, and what can still be independently established later.

The goal is not to replace judgment. It is to make the factual substrate beneath later judgment harder to reconstruct selectively.

**5. Codebase Architecture**

artifact.py & evidence.py: manifest schemas, evidence encapsulation, and proposition representations.

checkpoint.py & anchor.py: append-only log state checkpoints and external time-bound anchors.

witness.py: external witness cosigning and custody-boundary interfaces.

assignment.py: assignment aggregation and disclosure-completeness verification.

verifier.py & primitives.py: standalone verifier engine for third-party auditing.

tests/: adversarial tests evaluating malformed inputs, precedence failures, witness failures, rederivation failures, and other attempts to manufacture evidence through declaration alone.

**6. Market Selection & Commercial Strategy**

Semafide's commercial hypothesis is that the strongest early markets are not simply the markets using the most AI. They are the workflows where three conditions overlap:

**Necessity = Consequence × Opacity × Adversarial Verification**

High consequence: the automated action has meaningful financial, regulatory, legal, safety, or operational impact.

Execution opacity: the responsible human cannot reliably reconstruct the exact execution state later.

Adversarial verification: a regulator, buyer, insurer, auditor, litigant, or other external party may eventually demand evidence of what occurred.

**Primary commercial hypothesis: automated valuation models in mortgage lending**

This is a market hypothesis, not a proven buyer thesis.

Potential drivers include regulatory quality-control requirements, fair-lending concerns, secondary-market valuation disputes, and the difficulty of reconstructing third-party automated valuation runs after the fact.

The discovery question is who has the strongest economic incentive to preserve independently verifiable execution evidence: the lender, AMC, valuation provider, quality-control function, investor, insurer, or another participant.

**Expansion hypothesis: multi-vendor AI supply chains and autonomous agents**

As autonomous systems act across organizational boundaries, the same evidentiary problem may arise at API and agent-to-agent boundaries: who authorized the action, what state and constraints governed it, and what evidence can establish what actually happened?

This is an expansion opportunity, not a claim that the entire autonomous economy already requires Semafide.

**7. What Is Known, What Is Hypothesized, and What Remains to Be Proven**

Known: consequential automated execution is increasing; organizations already use logs, tracing, monitoring, identity, and audit systems to reconstruct system behavior.

Thesis: in some high-stakes workflows, operator-controlled records will not provide enough independent evidence to resolve later disputes about what actually happened.

Technical proposition: cryptographically binding relevant execution state and preserving evidence at the time of action can make later substitution detectable and make specific execution claims independently verifiable.

Commercial hypothesis: there are workflows where the cost of being unable to prove what happened exceeds the cost of preserving stronger evidence at execution time.

Unproven: which buyer will pay first, what exact evidence standard that buyer requires, and how much stronger evidence is worth economically.

**8. Conclusion**

The central problem is not that automated systems produce bad records. It is that consequential execution is moving away from directly observable humans, while the need to establish what happened remains.

Semafide is exploring infrastructure for the gap between an execution record and evidence of execution.

The company does not need every automated action to require this infrastructure. It needs to find the places where consequence, opacity, and adversarial verification converge strongly enough that someone will pay to close that gap.
