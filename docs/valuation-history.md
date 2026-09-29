# How valuation became automated

This page is for a reader who has never worked in mortgage lending. It tells
how the value of a house came to be set by software, what each change did to
the record of how a value was reached, and why one question about that record
has no owner today.

It is derived from section 9.5 of [`executive-thesis.md`](executive-thesis.md).
The dated events, their sources, and the two tables that summarise the stages
are there. If this page and the thesis disagree, the thesis is right.

The thesis labels its claims, and the labels carry over. The dated events are
public record. The pattern drawn across them is a Thesis. Where this page says
where the pattern leads, that is a Hypothesis, and nothing here establishes
that anybody will pay to act on it.

---

## Why the history matters

A lender needs a value for the house behind a loan. That value is sometimes
questioned years later, when a loan goes bad, when an investor demands that
the lender buy a loan back, or when a regulator or a court looks at one file.
Whoever answers that question has to show how the value was reached. What they
can show depends on who set the value and what they kept, and both have
changed several times.

## Five stages

**A licensed appraiser.** A person visits the house, picks recent sales of
similar houses, adjusts for the differences, and reaches an opinion of value.
The rules that govern appraisers require them to keep a workfile of that work
for at least five years for most assignments. The person who answers for the
value is the person who keeps the record of it. A state board examines that
person.

**A statistical model.** Hedonic price theory treats the price of a house as
the sum of prices for its parts: its size, its rooms, its location, its age. A
regression fitted to past sales gives each part a fixed number, and the value
of a new house is the sum of its parts multiplied by those numbers. Tax
assessors used this to value whole cities, and lenders adopted it to check
appraisals and then to value lower-risk loans. The numbers are fixed, so
running the model again on the same house gives the same value. Anyone who
keeps the inputs and the numbers can reproduce the result. Appraisers now run
regression tools of their own, on a file of sales they export to their own
computer before the tool runs, so they hold the inputs too.

**A cascade of vendors.** Several companies came to sell valuation models, and
none was equally good everywhere. Lenders began to try them in a ranked order
and take the first value that came back with enough confidence. The ranking and
the confidence cutoffs are set by whoever runs the cascade and change on that
party's schedule. The lender receives the value that cleared, usually with its
score. Whether the attempts that did not clear are kept depends on the
platform. Oversight arrived later and looks at the whole portfolio: how often
models return a value, and how accurate they are on average.

**Machine learning.** The models became ensembles and neural networks trained
on listings, photographs and public records, and retrained on the vendor's own
schedule. The data and the trained model are the vendor's core asset and are
not handed to the lender. The software these models run on does not promise
the same output on a different machine or version, so running the model again
later does not recover the value it gave. A new run is a new estimate. In the
same period, the mortgage enterprises reduced the share of loans that a person
appraises.

**Software agents.** Lenders have begun to use software agents built on
language models to run steps of the lending process. An agent can order a
valuation, read it, compare it with another, try again with a different
provider, and pass one value to the loan file. How many attempts it makes is
decided as it runs. The record of those attempts is the agent's own log, kept
by whoever runs the agent.

## What moved across the five

Four things moved together, and each move made valuation cheaper or faster.

**Who decides** moved from a licensed person to a pipeline of software.

**Who holds the inputs** moved away from the person answering for the value.
The appraiser holds the sales. The regression user holds the inputs and the
numbers. The cascade settings sit with the platform, the trained model sits
with the vendor, and the agent's working record sits with whoever runs the
agent.

**Whether a later run gives the same value** changed from yes to no. From the
machine-learning stage on, the value that was issued can be recorded when it
is issued, and after that moment no rerun recovers it.

**How many attempts came before the value in the file** grew, and moved out of
sight. One appraisal. Then cheap regression variants. Then a cascade that is a
series of attempts by design. Then an agent that decides for itself how many to
make. The file keeps the value that was used. Six attempts and one attempt
leave the same file.

## The portfolio and the single loan

Routine oversight moved to the portfolio. The interagency rule for automated
valuation models, effective 1 October 2025, is met across a population of
estimates. Liability did not move with it. A repurchase demand names one loan.
A complaint to a state board names one report. A lawsuit names one property.
Every moment where a loss actually lands concerns one file, and it arrives
years after the value was set.

Nobody is assigned the question of how many attempts came before the value in
one loan's file, and the reasons are ordinary. Keeping every attempt on every
loan costs money on all of them, and almost none are ever challenged. The
party that could keep the attempts is often the party whose conduct would be
examined, and a record of missed attempts can be used against it. A loan-level
loss already has a remedy that pays out: a lender can buy a warranty against
having to repurchase a loan, sold by at least one vendor alongside its
appraisal review product. Twenty consecutive disciplinary decisions from one
state regulator, read as primary documents, contain no decision concerning
analyses performed and not documented. And until machine learning,
a kept record reproduced its value, so the count mattered less.

**One hypothesis about how the count could matter to the portfolio.** A
cascade, or an agent that retries until a value clears a threshold, passes
only cleared values into the population that validation measures. The
attempts that missed never reach it. If so, portfolio accuracy is measured over
a set the selection has already filtered, and it may overstate how good the
models are. The count of attempts behind each loan would then be an input to
the portfolio figures the rule already asks for. This is analysis. No source
read for this project states it. It is falsified if validation already runs
over every attempt rather than over cleared values, or if the missed attempts
make no material difference to measured accuracy.

## What this history does not establish

It describes a gap that has widened. It does not create an obligation to
close it. Regulation arrived fifteen years after the cascade, and the rule
that arrived measures a population. Whether any institution will pay for an
independent count of attempts on its own loans is the open question in
section 9.2 of the thesis. The agent stage extends the same question beyond
valuation, and that extension is a hypothesis subject to the same test.

## Where to read next

The dated events and their sources: [`executive-thesis.md`](executive-thesis.md),
section 9.5. The two tables there set the five stages side by side.

What the verifier in this repository can and cannot say about one sealed run:
the table under "What an examiner can and cannot say" in the
[README](../README.md), and [`claim-vocabulary.md`](claim-vocabulary.md).
