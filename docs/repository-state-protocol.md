# Repository State Verification Protocol

This repository is an executable research instrument. Claims about its current state must be grounded in the current repository, not in remembered conversation state or an earlier checkout.

## Operating rule

> A statement about the current repository is actionable only after the current repository state has been checked.

Conversation history is context. It is not repository state.

## Required workflow

### 1. Before modifying a file, open the current file

Read the file from the GitHub ref that will actually be modified.

Do not reconstruct the file from memory, an earlier response, a previous diff, or a stale local representation.

Record the ref and, when useful, the blob SHA used as the modification basis.

**Required evidence:** current file contents from the target ref.

### 2. Before claiming something is missing, search the current repository

A statement such as "the repository does not have X" requires a repository search first.

Search for:

- the claimed filename or path;
- the relevant symbol, phrase, configuration key, or test name;
- reasonable variants when naming is uncertain.

If the search is inconclusive, say that it was not found rather than asserting that it does not exist.

**Required evidence:** search result or direct inspection showing the relevant absence.

### 3. Before changing a claim about tests or CI, inspect the current configuration

Open the current workflow files and the relevant test configuration before changing a statement about what CI asserts.

At minimum inspect:

- `.github/workflows/` workflows relevant to the claim;
- test configuration and discovery rules;
- the directories, globs, or commands actually executed by CI.

Do not infer CI coverage from a previous version of the workflow.

**Required evidence:** the current workflow/test configuration supporting the claim.

### 4. Before proposing a PR from a previous audit, re-audit the current branch

A previous audit is a hypothesis about the current state, not the current state itself.

Before opening the PR:

1. identify the current base and head refs;
2. inspect the files implicated by the earlier audit;
3. search for the claims or behavior again;
4. determine whether the proposed change is still necessary;
5. record any recommendation that is already satisfied and do not change it merely because the earlier audit said it was missing.

**Required evidence:** current repository inspection supporting each proposed change.

### 5. After making changes, inspect the resulting diff

Do not validate a change by comparing the result with the intended patch from memory.

Inspect the actual diff between the PR base and head. Confirm:

- every changed file was intentional;
- every changed line is supported by the current-state audit;
- no unrelated file changed;
- wording did not introduce a stronger claim than the evidence supports;
- tests and CI statements still correspond to actual configuration.

For code changes, run the relevant tests and inspect their result where available.

**Required evidence:** PR diff plus relevant test/CI result.

### 6. Never treat conversation history as repository state

Prior messages can preserve rationale, decisions, and hypotheses. They cannot establish what a file currently contains.

The following are not substitutes for current inspection:

- "we changed this earlier";
- "the README used to say";
- a code block copied from a previous response;
- an earlier audit result;
- an earlier PR description;
- a remembered branch state.

When current state matters, open it.

## Claim provenance

When making consequential repository statements, classify the basis internally as one of:

- **Observed:** directly inspected in the current repository/ref.
- **Derived:** computed from currently observed repository state.
- **Historical:** supported only by an earlier state and therefore not sufficient for a current-state claim.
- **Hypothesis:** proposed future behavior or interpretation not established by the repository.

Only **Observed** and **Derived** state should be used as the basis for an actionable claim about what the repository currently does.

## PR gate

Before opening a PR, the author should be able to answer yes to all applicable questions:

- [ ] Did I open every file I am changing on the current base/head basis?
- [ ] Did I search before claiming anything was missing?
- [ ] Did I inspect the current CI workflow before changing any CI/test claim?
- [ ] Did I re-run the relevant portion of any earlier audit against current state?
- [ ] Did I inspect the actual resulting diff?
- [ ] Did I verify that the final wording does not exceed what the current implementation establishes?
- [ ] Did I run the relevant tests or explicitly record why they could not be run?

## Why this exists

This is not a generic contribution guideline. It is a control against a specific failure mode: reasoning from a stale model of the repository and then making that stale model executable through a commit.

The failure is especially important here because Semafide is itself concerned with preserving the relationship between claims and the state that supports them. The development process should not silently violate the same boundary.
