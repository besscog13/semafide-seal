# Handover rehearsal

This repository ships a verifier. Installing it does not mean Semafide held your records.

What a later examiner actually needs, if the dispute is “was this every run,” is a count from someone other than the shop that produced the number. That handover is the commercial layer. It is not hosted here.

`code/seal/capture/dummy_custodian.py` is a rehearsal of that layer on one machine, with two keys. It is not a custodian you can send work to.

## What a partner should take from it

A loan or valuation assignment can produce more than one automated run. The operator can seal all of them and later produce only the favorable file. Each file can verify. Nothing inside a file proves its siblings exist.

The rehearsal walks three examiner outcomes:

| Outcome | Plain meaning |
|---|---|
| Whole disclosure | The files shown to the examiner match the list the outside party signed for that assignment. |
| Partial disclosure | The outside party was given more records than the examiner was shown. |
| Unusable count | The shop that ran the valuations signed the count themselves. That is not an outside statement. |

A fourth fact is printed on purpose and is not an outcome of the check:

A run that was never sent to anyone cannot appear on the list. The rehearsal does not watch the operator’s machine. Semafide-the-company would still need capture at the tool and a real intake. This script does not provide those.

## How to run it

From a checkout:

```bash
python -m seal.capture.dummy_custodian
```

You should see whole disclosure, partial disclosure, an unusable self-signed count, and the unsent-run limit.

## What this is not

- Not production custody
- Not independent observation in the operational sense
- Not part of `pip install semafide-seal`’s supported API
- Not a claim that installing the package gives you Semafide as a custodian
