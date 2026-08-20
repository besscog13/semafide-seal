# Semafide

Semafide is building cryptographic custody and state-preservation middleware for batch-executed valuation and automated lending pipelines.

The current repository is a pre-build verifier and artifact scaffold. It does not capture executions or provide custody yet. The intended architecture places the evidentiary record outside the control of the party that produced the analysis.

When the capture layer exists, an analytical tool, automated valuation model, or regression script will submit an execution manifest containing the input evidence commitment, parameters, tool and model version, and output. The verifier in this repository defines what that record must establish without treating a self-authored declaration as independent evidence.

## The problem

Mortgage valuation increasingly relies on software and data sources that can change after an analysis runs. Automated valuation models can use public records, listings, market data, and other inputs. Appraisers can use statistical analysis and regression-based methods to support adjustments. The underlying data, tools, and model versions may change, be corrected, or become unavailable.

When a repurchase demand, regulatory examination, or dispute arrives later, rerunning an analysis can produce a different result. The problem is not necessarily carelessness. The historical execution may have depended on a state that is no longer available in the same form.

The interagency Quality Control Standards for Automated Valuation Models became effective October 1, 2025. For covered mortgage originators and secondary market issuers, the rule requires policies, practices, procedures, and control systems designed to comply with specified quality-control standards, including protection against the manipulation of data. The rule does not itself prescribe Semafide's evidence model. Separately, Fannie Mae's Selling Guide requires appraisal reports dated on or after March 1, 2025 to summarize the data sources, tools, and techniques used to support time adjustments. Neither requirement should be read as establishing a general legal rule that a particular logging mechanism is insufficient. Semafide's narrower question is whether the underlying execution state can later be established rather than merely asserted.

## Authorization and admissibility

Authorization is prospective and structural. It asks whether an action is permitted and whether the output conforms: schema validity, licence currency, a passing risk score, the required checks completed.

Admissibility asks a different question. If a transaction is challenged three years from now, can the data state it rested on be established?

The question is adjudicated retrospectively, but the evidence needed to answer it has to be preserved prospectively. An analysis cannot be made historically reproducible after the relevant state has disappeared. The system that produced the analysis also cannot provide independent evidence of the completeness of its own record without some external control over that record.

## The principle

A record showing that an analysis and its inputs sat together in one file is not evidence that the output was derived from those inputs at that moment. **Co-occurrence is not binding.**

A prior evidence commitment establishes precedence: the evidence commitment existed in the chain before the run seal that names it. That rules out selecting the committed evidence after seeing the output. It does not by itself prove that the analysis actually consumed those inputs.

That distinction is why the verifier records independent evidence propositions: precedence, witness attestation, recipe availability, recipe reproduction, and historical execution established. `BindingLevel` remains only as a backward-compatible display projection. Re-derivation can establish that a pinned execution recipe, applied to the referenced evidence, produces the sealed output. It does not by itself prove that the historical execution actually ran that recipe. That stronger historical claim depends on an independently trusted witness attestation covering the observed execution relation.

## Why custody rather than a file

The obvious design hands the appraiser or institution a signed artifact to keep. A signature does not solve completeness.

A signature proves that what a document contains has not been altered, assuming the signing key and verification process are trusted. It cannot prove that the document contains everything. Completeness is a claim about what is absent, and the party deciding what to disclose can also decide what to omit. Run five analyses, seal all five, and disclose the three that support the conclusion. Each of the three can verify perfectly. Nothing inside them establishes that the other two existed.

Timestamping does not close this. A timestamp can establish that a particular document existed by a stated time. It says nothing about documents nobody was shown. Timestamp all five runs and hand over three, and all three still verify.

Splitting the work across five separate records does not help. Each record can be internally complete and authentic while the disclosure remains incomplete.

The intended custody architecture addresses that problem by putting assignment-level disclosure outside the control of the party being examined. An examiner can then ask the custodian how many runs and records it received and compare that statement with the supplied artifact. This is a custody property, not something a signature alone provides.

The current repository implements the verification side of that model. It does not yet implement the capture mechanism or the production custody service.

## How the intended architecture integrates

The intended integration is at the application boundary. Semafide is not intended to replace data scrapers, form-filling software, appraisal tools, or delivery pipelines. Upstream analytical software would submit an execution manifest carrying the evidence commitment, parameter set, tool and model version, and output.

The manifest can also carry a re-derivation recipe. The current schema requires a pinned endpoint and version, the exact invocation, the input reference, the expected output digest, and a service window. A verifier can later execute the recipe and compare the produced output with the sealed output when the partner still serves that environment.

Successful re-derivation establishes reproducibility of the claimed execution recipe. It does not, standing alone, establish that the historical execution used that recipe. Historical capture and custody are the remaining operational layer.

The intended examiner workflow has two distinct statements. One concerns the supplied chain and its completeness. The other concerns the assignment-level disclosure: how many chains the assignment contains and what the custodian says it holds. The latter must come from a party other than the sealer. Without that independent statement, the verifier reports that assignment disclosure was not checked rather than treating the artifact as complete.

Each analysis is committed to its assignment when the chain opens, rather than being assigned at certification. The anchor fixes the assignment before later entries are added. This prevents a completed chain from being relabelled after the fact. It does not establish that the assignment contains no sibling chains; that requires an assignment-level disclosure from outside the chain.

## External time

The time a record states is a value chosen by its author. A chain assembled today can therefore contain timestamps from last year and still have internally valid signatures.

A conventional timestamp authority addresses a different side of the problem. It can establish that a particular document existed no later than the time asserted by the timestamp token. It does not establish that the document did not exist earlier.

The repository therefore models two external bounds. An upper bound comes from an external time authority. A lower bound comes from a published unpredictable value that could not have been known before it was issued. If both are available and independently resolved, the verifier reports the resulting interval rather than treating the author's timestamp as historical proof.

The current package models these bounds but does not itself provide a production RFC 3161 service or a production beacon. Those are deployment dependencies.

## What it does not do

Nothing blocks. Nothing evaluates quality. Nothing scores. Custody, not judgment.

The intended record is symmetric evidence. It should document a flawed analysis as faithfully as a sound one. It does not establish that the inputs were well chosen, that an appraisal conclusion was correct, or that an automated decision was substantively sound.

It also does not claim that successful re-derivation proves historical execution. The strongest historical claim requires capture at the time of execution and a custody arrangement that prevents the interested party from selecting the evidence after seeing the outcome.

Custody carries costs that a file handed over does not. A production guarantee would depend on Semafide continuing to operate, a custodian preserving the records it received, and partners keeping pinned execution environments available. Those are operational and contractual dependencies, not consequences of cryptography alone.

Nothing in the mathematics prevents a custodian from colluding with the party it is meant to constrain. An append-only log can make later equivocation detectable when its consistency proofs are checked. Independent witnesses can make conflicting views harder to maintain without detection. Neither mechanism eliminates the need to decide who the witnesses are, whether they are independent, and whether anyone checks what they signed.

## About this repository

`code/seal/` contains the artifact schema, checkpoint formats, external time-bound models, append-only log primitives, witness machinery, and standalone verifier. It is a pre-build scaffold. The capture path is not implemented.

The verifier reports independent propositions about the relation between an output and the evidence it claims. Its legacy `BindingLevel` projection is retained for existing consumers, but must not be read as an evidence ladder:

- **BUNDLED:** inputs and output are present together, but nothing establishes their execution relationship.
- **PRECEDENCE:** the evidence commitment precedes the run seal. This rules out choosing that commitment after seeing the output, but does not prove the analysis consumed it.
- **WITNESSED:** an independently trusted observer signed an explicit observed-execution attestation binding the run, committed evidence, sealed action, and capture reference. A signature over a supplied bundle or a self-declared witness field is not enough.
- **REDERIVABLE:** a complete execution recipe links to the claimed evidence and output and remains available for execution.
- **REDERIVED:** a verifier actually executed that recipe and reproduced the sealed output.

The verifier also reports chain completeness, assignment disclosure, external time bounds, and input-retention determinations. These answer different questions. Completeness asks whether a supplied chain is whole. Disclosure asks whether the chain is the whole assignment. Anchoring asks what external evidence constrains when the chain existed. Retention asks whether the operator could have kept the input, which determines whether re-derivation provides something beyond a locally retained and timestamped copy.

A green verification result is not a claim that the underlying model, appraisal, or business decision was correct. It means the artifact satisfied the particular checks the verifier performed against the evidence supplied to it.

The package also documents known limits. The current re-derivation recipe pins the endpoint, tool, version, invocation, input reference, output digest, and service window, but does not yet pin the full execution environment, numerical libraries, hardware, or linked BLAS. A later mismatch can therefore reflect environmental drift rather than a changed analysis. The verifier fails conservatively rather than converting that uncertainty into a clean pass.

The package deliberately does not present its experimental transparency-log implementation as a production foundation. Production deployments should use established transparency-log and witness specifications rather than treating this scaffold as a replacement for them.

It depends on `cryptography` alone. To watch it work, `pip install -r code/seal/requirements.txt` and then `cd code && python -m seal.demo`. The demo exercises the verifier against cases including truncation, assignment-level disclosure, and time-bound failures.

## Contact

eli@semafide.com
