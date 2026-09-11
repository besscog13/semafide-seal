"""SUPPORTED_PUBLIC_API is the support contract. seal.__all__ is the export
list. They must not drift from each other in the one direction that would
advertise a name we cannot import, and the Supported section of
docs/public-api.md must be that same set.
"""
from __future__ import annotations

from pathlib import Path

import seal
from seal.public_api import SUPPORTED_PUBLIC_API


def test_supported_is_subset_of_all():
    missing = SUPPORTED_PUBLIC_API - set(seal.__all__)
    assert not missing, (
        f"{sorted(missing)} listed as supported but absent from seal.__all__"
    )


def test_every_supported_name_imports_from_seal():
    for name in sorted(SUPPORTED_PUBLIC_API):
        assert hasattr(seal, name), f"{name!r} is supported but seal has no such attribute"


def test_docs_supported_block_matches_the_module():
    text = Path(__file__).resolve().parents[2].joinpath("docs/public-api.md").read_text(
        encoding="utf-8"
    )
    heading = "## Supported"
    assert heading in text, "docs/public-api.md has no Supported section"
    after = text.split(heading, 1)[1]
    block = after.split("```", 2)
    assert len(block) >= 3, "docs/public-api.md Supported section has no fenced list"
    documented = {line.strip() for line in block[1].splitlines() if line.strip()}
    assert documented == set(SUPPORTED_PUBLIC_API), (
        f"docs/public-api.md Supported list {sorted(documented)} != "
        f"SUPPORTED_PUBLIC_API {sorted(SUPPORTED_PUBLIC_API)}"
    )
