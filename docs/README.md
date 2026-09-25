# Docs

This folder is the published document set. It is not the operating company.

Two kinds of file live here. Shared sources are byte-identical to
`besscog13/semafide-authorization-provenance` and the private sync job
compares them. Public-only files exist in this repository and nowhere else.
This page is public-only. It is not in the sync loop.

This page does not restate the argument. If a row and a source file disagree,
the source file is right.

## Shared sources

Edit these. The private sync job compares each one with its private copy, so
an edit made to one copy alone turns that job red on its next run.

| File | Owns |
|---|---|
| [executive-thesis.md](executive-thesis.md) | The published argument |
| [claim-vocabulary.md](claim-vocabulary.md) | The five public labels and their code identifiers |
| [practice-statement.md](practice-statement.md) | What an examiner may and may not infer |
| [business-flow.md](business-flow.md) | The twelve steps, each pinned to what the code supports |
| [public-api.md](public-api.md) | The supported public Python surface |
| [related-work.md](related-work.md) | Adjacent systems, named so this project is not them |
| [watermarking.md](watermarking.md) | Why watermarking is not the mechanism |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Capture versus custody, and how the checks divide |
| [../code/seal/README.md](../code/seal/README.md) | Module boundaries of the package |
| [../specs/README.md](../specs/README.md) | What the formal specs prove |

## Public-only

These are derived or operational. They point at the shared sources. They do
not keep a private ledger.

| File | Owns |
|---|---|
| [../README.md](../README.md) | The external landing page |
| [assurance.md](assurance.md) | What a green CI run does and does not mean |
| [handover-rehearsal.md](handover-rehearsal.md) | A rehearsal script for handing the instrument over |
| [repository-state-protocol.md](repository-state-protocol.md) | How this repository refuses silent drift |
| [demos/README.md](demos/README.md) | How to run or open each of them, in reading order |
| [semafide-system-map.html](semafide-system-map.html) | The public system map |
| [semafide.architecture.json](semafide.architecture.json) | Machine-readable map input |
| `.github/scripts/check_writing_lint.py` | House style on this tree |
| `.github/scripts/check_retired_vocabulary.py` | Retired names on this tree |

The writing and retired-vocabulary lints stay in this repository. They are
not ported to the private tree.

## Not here

`ROADMAP.md`, `CLAUDE.md`, `context/RECORD.md`, `customers/`, and the C2SP
draft live only in the private repository. C2SP itself is an external spec
at c2sp.org. This tree cites it. It does not implement it.
