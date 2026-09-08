"""
`seal.__all__` is the package's own declaration of its public API, and
nothing checked that the declaration matched the imports sitting right next
to it in the same file.

`resolve_bounds` was imported into `seal/__init__.py` from `.anchor` along
with `Anchoring`, `AnchorReport`, `Beacon`, `TimeAnchor`, and
`issue_time_anchor`, and was the only one of the six missing from
`__all__`. A direct `from seal import resolve_bounds` still worked, since
`__all__` only governs `from seal import *`, so the omission was invisible
to any test exercising the function through a direct import -- confirmed
directly: `from seal import *` did not bind the name, while `from seal
import resolve_bounds` did, silently and differently, from the same
package.
"""
from __future__ import annotations

import ast
import inspect

import seal


def _names_imported_into_seal_init() -> set[str]:
    """Every name `seal/__init__.py` imports via `from .module import (...)`,
    as written in the source rather than as observed at runtime, so a name
    shadowed or reassigned after import cannot hide a missing declaration."""
    source = inspect.getsource(seal)
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.asname or alias.name)
    return imported


def test_every_name_seal_init_imports_is_declared_in_all():
    """
    The direction that actually broke: a name imported from a submodule but
    never added to `__all__`, which `from seal import *` silently drops
    while `from seal import <name>` keeps working, so nothing exercising the
    package through a direct import would ever notice.
    """
    imported = _names_imported_into_seal_init()
    missing = imported - set(seal.__all__)
    assert not missing, (
        f"{sorted(missing)} imported into seal/__init__.py but absent from "
        "seal.__all__; from seal import * silently drops these"
    )


def test_every_name_in_all_is_actually_importable_from_seal():
    """
    The other direction, for completeness: a name declared in `__all__`
    that the module does not actually carry raises `AttributeError` the
    moment `import seal` runs, so this can only ever hold -- checked
    directly anyway, since a test asserting a tautology is still a
    documented guarantee rather than an assumption.
    """
    for name in seal.__all__:
        assert hasattr(seal, name), f"{name!r} is in seal.__all__ but seal has no such attribute"
