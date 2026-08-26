# Watermarking, content credentials, and custody

This document covers consumer-facing content marking. For the build-provenance and
agent-attestation category, SLSA, in-toto, SCITT, and the rest, see
[related-work.md](related-work.md).

## Why this document exists

Article 50 of the EU AI Act has applied since 2 August 2026, requiring providers
of generative systems to mark synthetic output in a machine-readable and
detectable form. Systems already on the market before that date have until
2 December 2026 to meet the machine-readable marking requirement in Article
50(2), under the AI Omnibus provisional agreement of May 2026, and the European
Commission has published guidelines on the transparency obligations. The effect
is that provenance is now a term most readers arrive with rather than one this
repository has to introduce.

That is useful and it is also a hazard. A technical reader may ask whether this
repository is a watermarking scheme, or Content Credentials with extra steps. It
is neither, and the reason is the same reason the repository exists at all.

## What a mark answers

A watermark answers a question about origin. It says that a particular model
produced a particular file, and in the stronger implementations it survives
ordinary handling well enough that alteration shows. A signature answers a
question about integrity. It says that what a document contains is what it
contained when it was signed.

Both questions are worth answering and neither is the question here.

## Three limits, in ascending order of seriousness

The first is robustness. Rewriting, translation, and heavy editing weaken or
remove the signal, and short output carries too little room to hold one
reliably. This is an engineering problem and engineering problems get better.

The second is coverage. A detector finds the marks it was built to find. A
negative result means that no mark of that kind was located, not that a human
wrote the thing. Absence of a mark establishes nothing at all, which means the
guarantee only ever runs in one direction.

The third is curation, and it is not an engineering problem. A mark travels
attached to the artifact it marks, which leaves it in the hands of whoever
chooses which artifacts to hand over. Mark every analysis perfectly, then
disclose the ones that support the conclusion. Each disclosed one verifies.
Nothing in any of them says the others were ever run.

Completeness is a claim about what is absent. No field added to a document can
establish that the document is whole, because the party choosing which fields
ship also chooses which to omit. That is a category limit rather than a schema
gap, and adding a stronger mark does not move it.

## Content Credentials are closer, and inherit the same limit

C2PA manifests are nearer to this repository than watermarking is. They are
signed assertions about how an asset was made, carried with the asset,
verifiable by anyone.

They still fail the third limit, for a structural reason rather than an
implementation one. The signer composes the manifest, so the manifest reports
what the signer chose to record about the assets the signer chose to produce.
Timestamping does not close it either, which is worth stating because it is the
intuitive fix. A timestamp proves a document existed at a time. It says nothing
about documents nobody was shown.

## What this repository does instead

The record does not stay with the party being examined.

A checkpoint is a statement about how long a chain is, made by a key that is not
the sealer's. An assignment checkpoint is a statement about how many chains the
assignment holds. Both are things the sealer does not author, and the verifier
computes over inputs of that kind, because a field the sealer writes is a
transcription of the sealer's claim rather than a computation of it. An examiner
holding a checkpoint can detect a short chain, because the count and the head
disagree with what they were handed.

The vocabulary already exists. A checkpoint here is a signed tree head and the
signature that makes it worth anything is a witness cosignature, both specified
at c2sp.org. The transparency-log implementation in this repository is a
scaffold rather than a production foundation, and a deployment should use the
established specifications rather than this code.

Trust does not disappear under this design. It moves to whoever signs the
checkpoint. That is the point. The party being examined stops being the only
source of the record they are being examined on.

## What this is not

This is not a marking scheme and it produces nothing that satisfies a marking
obligation. Nothing here detects whether a given file was machine-generated, and
nothing here is a reading of what Article 50 requires of anyone. The regulation
is context for why the words in this document now carry meaning, not a claim of
compliance with it.

The capture path is opt-in and enforcing capture of every run in an assignment,
without breaking the way an operator actually works, remains open. Nothing in
this repository closes it.

## The distinction in one line

A mark tells you where a file came from. Custody tells you whether you were
shown all of them.
