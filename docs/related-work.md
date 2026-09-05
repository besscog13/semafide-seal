# Related work and positioning

Semafide sits inside a real and growing category: cryptographic provenance,
attestation, and audit-trail systems for software builds and for AI agent
execution. This document records what a direct search of that category
found on 2026-08-22 and states where Semafide overlaps with it and where its
present claim differs.

## What the search found

[SLSA](https://slsa.dev/spec/v1.0/provenance) defines provenance as an
attestation that a builder produced an artifact through a build definition.
Its own specification states the trust model directly: the builder is
trusted to have faithfully recorded the provenance, and there is no option
but to trust the builder. [slsa-verifier](https://github.com/slsa-framework/slsa-verifier)
checks that a provenance envelope is signed by a trusted builder identity and
that the recorded source and digest match expectations.
[in-toto](https://github.com/in-toto/attestation/blob/main/spec/predicates/README.md)
defines the attestation format SLSA provenance is expressed in, and its
[Runtime Trace predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md)
represents a system-level trace of a build step without mandating a
monitoring tool. [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
generates signed provenance and SBOM attestations for binaries and container
images, verifiable through the GitHub CLI.

Several projects apply the same primitives, hash chains, signatures, and
external timestamps, to AI agent execution specifically rather than to
software builds. [AgentProvenance](https://pkg.go.dev/github.com/byteyellow/agentprovenance/internal/launch)
correlates application-side agent context with system telemetry into a
signable causality graph for sandboxed coding agents, aimed at risk, replay,
and forensics. [Aevum](https://aevum.build/) describes itself as an
independent black box for AI agents: every action is recorded into an
Ed25519-signed, SHA3-256 hash-chained ledger, wrapped in a COSE_Sign1 receipt
with an RFC 3161 trusted timestamp, and can be anchored to a public
transparency log. [HDP](https://arxiv.org/abs/2604.04522) is a lightweight
token protocol that binds a human authorization event to a session and
records each agent's delegated action as a signed, append-only hop,
verifiable from the issuer's public key and the session identifier alone.

A recent survey, [From Agent Traces to Trust](https://arxiv.org/html/2606.04990v2),
covers this territory directly. It defines execution provenance as the
complete typed graph of an agent run and evidence tracing as that graph's
projection onto evidence-support relations, and treats claim support,
whether a specific claim is actually justified by a specific evidence unit,
as distinct from whether a citation merely exists, as one of six dimensions
of the same problem.

One project referenced in an earlier draft of this comparison, described as
a cryptographic chain-of-custody protocol for AI agent sessions under the
name Tesserae, was not found under that name in this search. The closest
verified match to that description is HDP, cited above. A claim attributed
to Tesserae should be treated as UNVERIFIED until a primary source for it is
located and read directly.

A wider pass against three additional entries closed part of the gap this
document left open below. The
[SCITT AI Agent Execution Profile](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/),
an Internet-Draft, requires that every material action produce exactly one
record, rejects a registration whose sequence number or timing breaks the
chain, and assigns that check to an Evidence Custodian defined as a party
with no financial or operational interest in the agent's behavior; the draft
states its own guarantees are void if the operator and the custodian are the
same entity. The
[ContextNest paper](https://arxiv.org/abs/2607.02116) records what version of
a context an agent consumed and on whose authority, through a hash-chained
version history, and states plainly that its hash chain gives evidence of
tampering rather than prevention of it. The
[PSI AI Agent Action Sealing and Liability Protocol draft](https://www.ietf.org/archive/id/draft-singh-psi-agent-00.txt)
announces the same problem in its title but its published text has no
mechanism, so it supports no comparison beyond that shared framing.

## Where Semafide overlaps and where it differs

Each of the projects above answers some form of: can this record be verified
as authentic and unaltered. Semafide's current model, recorded in the
[README](https://github.com/besscog13/semafide-seal/blob/main/README.md),
separates that question from a further one: given a record that verifies,
what does it actually establish. That separation is not only a framing in
this document; the repository enforces it directly. An evidence commitment
predating its run seal establishes precedence, not that the analysis
consumed that evidence. A witness attestation establishes that a separately
trusted key signed the observed execution, not that the witness was
independent or truthful. Successful re-derivation establishes that a recipe
reproduces a claimed output, not that the historical execution ran that
recipe. None of the three upgrades `historical_execution_established` on
its own, and the demo and test suite exercise that refusal directly rather
than asserting it in prose alone.

SLSA's provenance and Aevum's signed ledger both stop at authenticity: a
valid signature from the recorded builder or agent, chained and timestamped.
Neither, by construction, asks whether a verifying party can distinguish a
complete record from a selected subset of one. The SCITT profile comes
closer than the rest of the category to that same structural move: it puts
the completeness check in the hands of a custodian outside the sealing
operator rather than in the operator's own instrumentation, which is the
same reasoning behind Semafide's assignment-disclosure layer. Its scope is
narrower. The profile checks that one agent's hash chain has no missing
link, a property visible from the chain the custodian already holds. It does
not ask whether the runs disclosed for a named assignment are the whole set
of runs performed for that assignment, a question that survives even when
every disclosed chain is internally continuous. That narrower question, not
the existence of any third-party check at all, is what Semafide's layer is
built to isolate.

## A mortgage-lending instance, found 2026-09-05

A search run specifically against the mortgage-lending wedge, rather than
the general AI-agent-provenance category above, found
[custody-ledger](https://github.com/Himansh97/custody), a single-maintainer
Python library published to PyPI the same day this search was run. It wraps
a lender's AI/ML model calls, logs each decision into a signed, append-only
hash chain, and produces a compliance disclosure packet, built directly
against Fannie Mae Lender Letter LL-2026-04's requirement that a lender
using AI/ML disclose, on request, what it uses and what safeguards exist.
Its own documentation states its limits in language close to this project's
own: an inventory can read as complete when it is not, and its verifier
cannot prove that nothing was withheld.

It sits closer to Semafide's domain than anything above and differs on the
same axis SLSA and Aevum do. The ledger is deployed and operated by the
lender being examined. Its documentation recommends externalizing an anchor
hash somewhere its own operator cannot edit and states plainly that an
anchor kept in the same database protects nothing, but nothing in the design
requires that step or names the outside party who would hold it. Every
record it produces is self-issued, in the sense this repository's own demo
tests directly: the same fact, asserted by the party being examined rather
than by an outside custodian, does not clear the same bar. The project is
early, a single maintainer, minimal adoption to date, and scoped to AI/ML
lending decisions generally rather than to the specific configuration
retention question described in Section 8.1 of `docs/executive-thesis.md`.
It is recorded here as the closest instance found to date of the same
underlying pain being felt and answered from inside a lending organization
rather than from outside it.

## Zero-knowledge verifiable machine learning, a different route to the same question

A precedence commitment proves an input hash existed in the log before the
run seal that names it. It does not prove the run consumed that input rather
than something else entirely: a partner can commit hash A, run on dataset B,
and post a result naming A. A research field exists to close exactly that
gap by a different route than a witness. [ZKML, zero-knowledge verifiable
machine learning](https://kudelskisecurity.com/modern-ciso-blog/zkml-verifiable-machine-learning-using-zero-knowledge-proof),
uses zero-knowledge proofs to demonstrate mathematically that a specific
output came from running a specific committed model on a specific committed
input, without requiring anyone to have observed the run. [A 2026 survey of
the field](https://arxiv.org/pdf/2502.18535) frames the target statements
directly: proving that a prediction equals the output of a committed model
on a declared input, or that updated parameters came from a declared
training procedure on a committed dataset.

The gap it closes and the one it does not are both worth stating plainly. A
mature zero-knowledge proof would establish computational faithfulness for
one execution more strongly than a witness attestation does, since it would
be a mathematical certainty rather than a signed statement from a trusted
party. It would not establish completeness. A valid proof over one honest
execution says nothing about how many other executions were run and
discarded before that one was submitted, because the proof is scoped to the
single computation it was generated for. KC3 survives a world where every
proof in it is true.

The approach is also some distance from deployable at the scale this
project targets. Generating a zero-knowledge proof over a real model's
inference is expensive, and the same survey states that membership itself,
whether a specific record was part of what a model consumed, can be
neither reliably confirmed nor refuted for large overparameterized models
by inspecting the model alone. That finding motivates pre-commitment
mechanisms of exactly the kind this project already uses, rather than
proving consumption after the fact through the model's behavior. The
witness attestation here is a cheaper, more practical answer to the same
worry, at the cost of requiring a trusted third party where a mature
zero-knowledge proof would require none.

## What this does not establish

Finding no product that asks the exact same question, at the same scope, is
evidence about this search, the wider pass that followed it, and the
mortgage-specific search that followed both, not proof that the category
will never contain one. The field is active: the survey
cited above alone references dozens of adjacent efforts this document does
not enumerate, and standards work covering the same ground, including the
SCITT profile above, is still in progress at the IETF. A search run again
later could find a system that closes even the narrower gap this document
describes.
