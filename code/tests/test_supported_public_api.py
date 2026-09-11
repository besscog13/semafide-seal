"""SUPPORTED_PUBLIC_API is the support contract. seal.__all__ is the export
list. They must not drift from each other in the one direction that would
advertise a name we cannot import, and the Supported section of
docs/public-api.md must be that same set.
"""
from __future__ import annotations

import os
from pathlib import Path

import seal
from seal.public_api import SUPPORTED_PUBLIC_API


def _public_api_doc() -> Path:
    """docs/public-api.md lives in the repository, not in the wheel.

    The clean-install job copies code/tests into $RUNNER_TEMP and runs
    pytest there. parents[2] of that copy is $RUNNER_TEMP, not the
    checkout, which is why this test failed with FileNotFoundError.
    Walk from the test file, then from GITHUB_WORKSPACE / cwd.
    """
    names = []
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        names.append(Path(workspace) / "docs" / "public-api.md")
    here = Path(__file__).resolve()
    for parent in here.parents:
        names.append(parent / "docs" / "public-api.md")
    names.append(Path.cwd() / "docs" / "public-api.md")
    for path in names:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "docs/public-api.md not found from the test file, "
        "GITHUB_WORKSPACE, or cwd"
    )


def test_supported_is_subset_of_all():
    missing = SUPPORTED_PUBLIC_API - set(seal.__all__)
    assert not missing, (
        f"{sorted(missing)} listed as supported but absent from seal.__all__"
    )


def test_every_supported_name_imports_from_seal():
    for name in sorted(SUPPORTED_PUBLIC_API):
        assert hasattr(seal, name), f"{name!r} is supported but seal has no such attribute"


def test_docs_supported_block_matches_the_module():
    text = _public_api_doc().read_text(encoding="utf-8")
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
