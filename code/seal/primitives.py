"""
The six primitives and three properties.

A decision occurs. Later someone asks about it. Six things must be true for an
answer to exist: Action, Surface, Evidence, Evaluator,
Instant, Claim. Each is interrogated on three properties: Existence, Reach,
Pinning.

This module encodes the framework only. It contains no capture mechanism and
takes no position on where a witness sits. That question is KC3 and it is open.

Numeric values are carried as strings throughout. Regression coefficients are
floats, and float repr is not stable across platforms or interpreter versions.
Hashing a float directly makes verification fail for reasons unrelated to
tampering. Callers format numbers once, at capture, and the artifact carries
what was formatted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# Open questions this module cannot answer from the engineering side.
# Each resolves against the domain, not through code.
OPEN_QUESTIONS = [
    "What belongs in Surface for a time adjustment beyond USPAP edition and "
    "the GSE twelve-month window. The appraiser's filter and methodology "
    "choices appear to be Surface and appear to be recorded nowhere. "
    "Discovery question 5 and 6.",
    "Whether MLS licensing permits retaining exported rows, or whether "
    "Evidence must be commitment-only. Discovery question 11.",
    "Whether MLS platforms already offer as-of historical retrieval, which "
    "would close part of the pinning gap without this product. "
    "Discovery question 9.",
    "Whether the effective date and the execution instant need separate "
    "treatment in the artifact. Retrospective assignments separate them by "
    "years. Claude construction, unrebuilt.",
]


class PrimitiveKind(Enum):
    """The six. Order is the order of the framework, not of execution."""

    ACTION = "action"
    SURFACE = "surface"
    EVIDENCE = "evidence"
    EVALUATOR = "evaluator"
    INSTANT = "instant"
    CLAIM = "claim"


class Pinning(Enum):
    """
    Is the primitive fixed to the instant, or does it float to present state.

    A system that returns today's answer to a historical query has a pinning
    failure even with perfect retention. FLOATING is the failure mode this
    product exists to address.
    """

    PINNED = "pinned"
    FLOATING = "floating"
    ABSENT = "absent"


class Retention(Enum):
    """
    Whether the artifact holds the bytes or only a commitment to them.

    COMMITMENT_ONLY is not a weakness. Where licensing forbids retaining
    third-party compilations, a Merkle commitment proves a specific row set
    without holding it. Whether MLS terms permit retention is open.
    """

    FULL = "full"
    COMMITMENT_ONLY = "commitment_only"
    NONE = "none"


def _refuse_ambiguous(value: Any, path: str = "payload") -> None:
    """
    Walk a payload and reject anything JSON would render ambiguously.

    Note `isinstance(True, int)` holds in Python, so a boolean key is caught
    here by the same check that catches an integer one.
    """
    if isinstance(value, dict):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"{path}: object key {key!r} is not a string. JSON carries "
                    "only string keys, so serializing this would coerce it and "
                    "a different payload would share the commitment.")
            _refuse_ambiguous(sub, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, sub in enumerate(value):
            _refuse_ambiguous(sub, f"{path}[{i}]")


def canonical_bytes(payload: Any) -> bytes:
    """
    Deterministic serialization for hashing.

    Sorted keys, no insignificant whitespace, unicode preserved. This is the
    pattern is adequate for a scaffold and is not RFC 8785.

    Ambiguous input is refused rather than serialized. Two classes of it.

    `allow_nan=False` rejects NaN and Infinity, which produce output no
    conforming JSON parser reads back, making a signature unverifiable for
    reasons unrelated to tampering.

    Non-string object keys are rejected because JSON has only string keys, so
    `sort_keys` coerces them and the coercion is not injective. `{None: None}`
    and `{"null": None}` are different payloads and both render as
    `{"null":null}`. Every commitment, block hash, and signature in this
    package is taken over these bytes, so a collision here means two different
    analyses can produce one seal. Refusing is the only answer that keeps the
    artifact distinguishing what it exists to distinguish.

    A tuple and a list with equal contents render identically. That is
    intended: JSON has no tuple, so both denote the same array.

    One known divergence from JCS remains. Integral floats serialize as `1.0`
    where JCS emits `1`, so an independent JCS verifier disagrees with this one
    on every such value. A production verifier needs JCS proper.
    """
    _refuse_ambiguous(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,          # NaN and Infinity are not JSON
    ).encode("utf-8")


def commit(payload: Any) -> str:
    """SHA-256 over the canonical serialization."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    """
    Root over an ordered list of leaf hashes.

    Evidence is a row set. A Merkle root lets a later challenge prove that a
    specific row WAS in the set without the artifact retaining the rows
    themselves. It cannot prove a row was absent: non-membership requires a
    sorted or indexed structure, and this is neither. Do not describe this as
    proving absence.

    Odd nodes are promoted rather than duplicated, which avoids the
    CVE-2012-2459 duplicate-leaf ambiguity. Promotion introduces a second
    ambiguity if leaves and interior nodes hash identically, because a
    promoted interior node is then indistinguishable from a leaf. The cold
    review demonstrated the collision. Leaves and interior nodes therefore
    carry distinct domain-separation prefixes, and the leaf count is folded
    into the root so a root commits to the shape of its tree.
    """
    n = len(leaf_hashes)
    if n == 0:
        # Distinct from any real root, rather than sha256(b"") which reads as
        # a legitimate commitment to nothing.
        return hashlib.sha256(b"semafide.merkle.empty").hexdigest()

    level = [hashlib.sha256(b"\x00" + h.encode()).hexdigest() for h in leaf_hashes]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(
                b"\x01" + (level[i] + level[i + 1]).encode()).hexdigest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    # Bind the leaf count so a single leaf is not its own root and a root
    # commits to how many leaves produced it.
    return hashlib.sha256(f"{n}:{level[0]}".encode()).hexdigest()


@dataclass(frozen=True)
class PrimitiveRecord:
    """
    One primitive, with its three properties made explicit.

    `commitment` is the content hash. `holder` carries the Reach property:
    the party who can actually retrieve the underlying material. A record
    whose holder is a counterparty is a reach failure even when the
    commitment verifies, and reach failures need a different product than
    existence failures.
    """

    kind: PrimitiveKind
    commitment: Optional[str]
    pinning: Pinning
    retention: Retention = Retention.NONE
    holder: Optional[str] = None
    descriptor: dict[str, Any] = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        """Existence. Was it recorded at all."""
        return self.commitment is not None

    @property
    def reachable_by_liable_party(self) -> bool:
        """
        Reach. Whether the party holding the liability can get to it.

        The liable party in this domain is the appraiser, whose license is at
        risk. Anything held solely by an MLS, an AMC, or a tool vendor is out
        of reach regardless of whether it exists.
        """
        return self.holder in ("appraiser", "custodian")

    @property
    def pinned(self) -> bool:
        """Pinning. Fixed to the instant rather than floating to present."""
        return self.pinning is Pinning.PINNED

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "commitment": self.commitment,
            "pinning": self.pinning.value,
            "retention": self.retention.value,
            "holder": self.holder,
            "descriptor": self.descriptor,
        }


REQUIRED_PRIMITIVES = frozenset(PrimitiveKind)
