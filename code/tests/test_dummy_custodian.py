"""Handover rehearsal: outside count vs disclosed files."""
from __future__ import annotations

from seal.assignment import Disclosure
from seal.capture.dummy_custodian import run_cases


def test_handover_rehearsal_whole_partial_unusable_and_unsent_limit():
    cases = run_cases()
    assert cases["whole"].state is Disclosure.WHOLE
    assert cases["whole"].expected == 2
    assert cases["whole"].disclosed == 2
    assert cases["whole"].withheld == ()

    assert cases["partial"].state is Disclosure.PARTIAL
    assert cases["partial"].expected == 2
    assert cases["partial"].disclosed == 1
    assert len(cases["partial"].withheld) == 1

    assert cases["unusable"].state is Disclosure.UNUSABLE
    assert "shop floor" in cases["unsent_run"]
