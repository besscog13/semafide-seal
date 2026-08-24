"""
The end-to-end scenario a design partner should be shown.

Three AVM runs are sealed into one assignment, the assignment is certified,
and the artifact is fed to the real verifier. Then one run is deleted from the
manifest and the artifact is verified again.

WHY THIS FILE ASSERTS MOSTLY FALSE. The obvious version of this test stands up
an in-process witness, puts its key in the caller's trusted set, and asserts
that `historical_execution_established` is True. That version is the sealer
signing its own work at a different variable name, and if it ever passed it
would be a bug report against `seal.verifier` rather than a demonstration.
Independence is the whole content of that proposition, and a witness the
sealing process instantiates holds none of it.

So the assertions below are the product's actual claim surface. Precedence
holds. Witness attestation does not, because nothing observed the run.
Historical execution does not, and no amount of re-derivation would change
that. Completeness and disclosure read UNCHECKED, because the inputs that
would settle them come from a custodian and no custodian was supplied. What
survives is the count: three runs went in, the binding names all three, and
removing one is reported rather than absorbed.

That last property is the one the audits left standing. An examination scores
an aggregate, and six analyses and one analysis produce the same aggregate.
The count is the distributional property the aggregate hides, and this is the
test that shows it being kept.
"""
from __future__ import annotations

import json

import pytest

from seal import (
    BindingLevel,
    Completeness,
    Coverage,
    Disclosure,
    verify,
)
from seal.capture import seal_execution
from seal.capture.assignment import close_assignment, reset_assignments

ASSIGNMENT = "ASG-2026-VAL-001"

# Three comparable sets for one subject property, the shape an appraiser
# actually produces: the same subject re-run as the filter is widened.
COMP_SETS = [
    {"median_price_per_sqft": 210, "comp_count": 4, "radius_mi": 0.5},
    {"median_price_per_sqft": 204, "comp_count": 7, "radius_mi": 1.0},
    {"median_price_per_sqft": 198, "comp_count": 11, "radius_mi": 2.0},
]
SUBJECT = {"sqft": 2400, "condition_score": 4}


@pytest.fixture(autouse=True)
def _isolated_assignments():
    """The registry is module-level state, so a shared assignment id would let
    one test read a chain another test built."""
    reset_assignments()
    yield
    reset_assignments()


def _avm_run(property_data: dict, market_trends: dict) -> dict:
    base = property_data["sqft"] * market_trends["median_price_per_sqft"]
    return {
        "valuation": base + (property_data["condition_score"] * 5000),
        "confidence": 0.94,
    }


def _seal_three_and_certify():
    """Three runs into one chain, then the second moment.

    Returns the certified manifest, the verifier's report on it, and the
    chain's own key, which is what a recipient would be handed out of band.
    """
    sealed = seal_execution(
        assignment_id=ASSIGNMENT,
        model_id="AVM-Hedonic-Regressor-4.2.1",
        output_dir=None,
    )(_avm_run)

    for comps in COMP_SETS:
        sealed(SUBJECT, comps)

    assert sealed.last_capture.runs_in_assignment == 3
    # Still in progress, so the binding does not exist yet. The two moments
    # stay separate: runs are captured at execution, sign-off binds at
    # certification.
    assert sealed.last_capture.report.coverage is Coverage.ABSENT

    manifest, report = close_assignment(
        ASSIGNMENT,
        certification_ref="cert-2026-03-14-001",
        effective_date="2026-03-14",
        output_dir=None,
    )
    return manifest, report, manifest["entries"][0]["public_key"]


def test_three_certified_runs_establish_the_count_and_nothing_else():
    manifest, report, key = _seal_three_and_certify()

    # The artifact is internally sound and signed by the key the recipient
    # was given. This is the narrow cryptographic question, not the
    # evidentiary one.
    assert report.trustworthy
    assert report.chain_intact
    assert report.signatures_valid

    # The propositions are the result. Precedence is the only one that holds,
    # and it holds on entry ordering rather than on anything about what the
    # function consumed.
    assert report.evidence.precedence
    assert report.evidence.witness_attestation is False
    assert report.evidence.recipe_available is False
    assert report.evidence.recipe_reproduced is False
    assert report.evidence.historical_execution_established is False

    # The display projection agrees, which it must, since it is computed from
    # the propositions rather than alongside them.
    assert report.binding_level is BindingLevel.PRECEDENCE

    # Nothing outside this document vouches for how long the chain is or for
    # how many chains the assignment holds. UNCHECKED is the honest reading
    # and the verifier reports it rather than treating absence as a pass.
    assert report.completeness is Completeness.UNCHECKED
    assert report.disclosure is Disclosure.UNCHECKED

    codes = {f.code for f in report.findings}
    assert "no_checkpoint" in codes
    assert "no_assignment_checkpoint" in codes

    # KC2 fires. Two commodity timestamps over local files reach precedence,
    # so on this artifact alone the mechanism does nothing an RFC 3161 service
    # could not, and the verifier says so instead of claiming the seat.
    assert report.kc2_fires

    # What does survive: the binding names every run, so the count is fixed.
    assert report.coverage is Coverage.CONTIGUOUS
    binding = manifest["entries"][-1]["body"]
    run_seqs = [e["seq"] for e in manifest["entries"] if e["kind"] == "run_seal"]
    assert len(run_seqs) == 3
    assert binding["covered_seqs"] == [e["seq"] for e in manifest["entries"][:-1]]
    assert set(run_seqs) <= set(binding["covered_seqs"])

    # And the sealed outputs are the real ones the function returned.
    valuations = [
        e["body"]["primitives"]["action"]["commitment"]
        for e in manifest["entries"] if e["kind"] == "run_seal"
    ]
    assert len(set(valuations)) == 3, "three distinct runs, three distinct actions"


def test_deleting_the_second_run_is_reported_rather_than_absorbed():
    """
    The property that survived every audit against this thesis.

    Before the chain lived for the assignment, an operator who ran three
    analyses held three unrelated artifacts, discarded two, and the survivor
    verified perfectly. Here the discard leaves a hole the verifier names.
    """
    manifest, report, key = _seal_three_and_certify()
    assert report.coverage is Coverage.CONTIGUOUS

    run_indexes = [i for i, e in enumerate(manifest["entries"])
                   if e["kind"] == "run_seal"]
    cut = json.loads(json.dumps(manifest))
    removed = cut["entries"].pop(run_indexes[1])
    assert removed["kind"] == "run_seal"

    cut_report = verify(cut, trusted_keys=[key])

    # Linkage is what breaks, so the document does not merely look short, it
    # fails to be a chain at all.
    assert cut_report.chain_intact is False
    assert cut_report.trustworthy is False

    # The workfile binding still names the sequence number that is now missing,
    # which is the second, independent way the omission surfaces.
    binding = cut["entries"][-1]["body"]
    present = {e["seq"] for e in cut["entries"]}
    assert removed["seq"] in binding["covered_seqs"]
    assert removed["seq"] not in present


def test_renumbering_to_hide_the_gap_does_not_help():
    """Closing the sequence numbers over the hole leaves prev-hash linkage
    broken, and linkage is not a field an editor can renumber."""
    manifest, _report, key = _seal_three_and_certify()

    run_indexes = [i for i, e in enumerate(manifest["entries"])
                   if e["kind"] == "run_seal"]
    cut = json.loads(json.dumps(manifest))
    del cut["entries"][run_indexes[1]]
    for n, entry in enumerate(cut["entries"]):
        entry["seq"] = n

    assert verify(cut, trusted_keys=[key]).trustworthy is False
