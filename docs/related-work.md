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
complete record from a selected subset of one. That is the question
Semafide's assignment-completeness and disclosure layer is built to isolate.

## What this does not establish

Finding no product that asks the same narrower question is evidence about
this search, not about the category. The field is active: the survey cited
above alone references dozens of adjacent efforts this document does not
enumerate, and standards work covering the same ground is in progress at the
IETF. A wider pass against that literature, checked source by source rather
than assumed from a single earlier list, is a separate piece of work from
this document and is tracked outside it.
