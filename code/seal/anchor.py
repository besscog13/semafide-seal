"""
External time anchoring, and why RFC 3161 alone anchors the wrong side.

`ts_ns` is signed and checked for monotonicity, and it is still a number the
sealer chose. Monotonicity forces internal consistency and nothing else, so a
chain built today with last year's timestamps verifies perfectly. A verifier can
only compute over facts an adversary cannot author, and time is the last fact
in the artifact the sealer would otherwise author alone.

THE CORRECTION, and it is a change to the plan rather than an implementation of
it. This project has described artifacts as RFC 3161 timestamped since the
integration scope was written. A timestamp token proves a document existed NO
LATER THAN the time it names. It is an upper bound. It says nothing whatever
about whether the document existed earlier, so it cannot contradict a document
that was created today and dated to last March.

That is the threat. KC1 is the condition that fires if the workfile is
assembled after the fact, and the practical version is an appraiser who
receives a letter and builds the record in response to it. Backdating is the
attack, a lower bound is what catches it, and a timestamp authority cannot
supply one. The mechanism the project named for this job does the opposite half
of it.

Bounding a time from below needs something else: a commitment to a value that
did not exist yet. If a chain's anchor commits to a published, unpredictable
value, then the chain cannot have been assembled before that value was
published, because nobody could have written it down beforehand. A randomness
beacon is the ordinary source. The unpredictability is the whole mechanism. A
beacon a sealer can compute in advance, a clock reading or a counter, buys
exactly nothing, in the way `witness_mode: independent` bought nothing.

Together the two give an interval. The lower bound comes from what the sealer
could not have known; the upper bound comes from a party who saw the artifact.
The sealer's claimed instant has to fall inside it, and the width of the
interval is the sealer's remaining discretion, reported rather than hidden.

Two limits stated plainly.

A sealer who wants a weak bound commits to an old beacon pulse, which is
permitted and produces a wide interval. The mechanism cannot be defeated
quietly, only visibly widened, and `interval_ns` is where that shows.

Neither half is worth anything if the verifier takes the artifact's word for it.
The beacon value and the authority's signature are both fields in a document the
sealer shipped, so this module resolves the first through a callback the
examiner supplies and refuses the second unless it carries a key the examiner
named. An anchor from an authority nobody recognised is a key the sealer
generated.

On the token format. A real deployment substitutes an RFC 3161 token from a
time stamping authority. Parsing one means CMS and ASN.1, which is a dependency
this package deliberately does not carry, so what is implemented here is the
shape of the statement and the checking a verifier owes it: that a party who is
not the sealer signed THIS digest, and that the digest is an entry in THIS
chain. An anchor over an adjacent document is the recipe compared to itself, one
level over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .artifact import Entry, EntryKind
from .primitives import canonical_bytes

# Resolves (source, pulse) to the value that was actually published and when.
# The examiner supplies it, because the alternative is reading both from the
# document under examination.
BeaconResolver = Callable[[str, str], Optional[tuple]]


@dataclass(frozen=True)
class Beacon:
    """
    A published value that could not have been predicted before it was issued.

    `value` is what the sealer commits to and `issued_ns` is when the source
    published it. A verifier resolves both independently: a beacon read out of
    the artifact it is meant to constrain establishes nothing.
    """

    source: str
    pulse: str
    value: str
    issued_ns: int

    def to_body(self) -> dict[str, Any]:
        return {"source": self.source, "pulse": self.pulse,
                "value": self.value, "issued_ns": self.issued_ns}


@dataclass(frozen=True)
class TimeAnchor:
    """
    An outside party's statement that a digest existed by a time.

    The upper bound. Shape-compatible with an RFC 3161 token and checked the
    same way: the digest must be an entry in the chain being examined, and the
    signer must be an authority the examiner named.
    """

    authority: str
    digest: str
    time_ns: int

    def signing_payload(self) -> dict[str, Any]:
        return {"authority": self.authority, "digest": self.digest,
                "time_ns": self.time_ns}


def issue(anchor: TimeAnchor,
          private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """Sign a time anchor. The key must belong to the authority, not the sealer."""
    raw = canonical_bytes(anchor.signing_payload())
    d = anchor.signing_payload()
    d["signature"] = private_key.sign(raw, ec.ECDSA(hashes.SHA256())).hex()
    d["public_key"] = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return d


def load(doc: dict[str, Any]) -> TimeAnchor:
    return TimeAnchor(doc["authority"], doc["digest"], doc["time_ns"])


def signature_valid(doc: dict[str, Any]) -> bool:
    try:
        anchor = load(doc)
        pub = serialization.load_pem_public_key(
            doc["public_key"].encode("ascii"))
        pub.verify(bytes.fromhex(doc["signature"]),
                   canonical_bytes(anchor.signing_payload()),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - hostile input is expected
        return False


class Anchoring(Enum):
    """
    Which side of the sealer's claimed instant anything outside it constrains.

    UNANCHORED is the honest default. UPPER_ONLY is what RFC 3161 alone
    reaches, and it is named
    separately rather than counted as anchored because it leaves backdating
    untouched, which is the attack KC1 describes.
    """

    UNANCHORED = "unanchored"
    LOWER_ONLY = "lower_only"
    UPPER_ONLY = "upper_only"
    BOUNDED = "bounded"
    INCONSISTENT = "inconsistent"


@dataclass
class AnchorReport:
    state: Anchoring = Anchoring.UNANCHORED
    lower_ns: Optional[int] = None
    upper_ns: Optional[int] = None
    findings: list[str] = field(default_factory=list)

    @property
    def interval_ns(self) -> Optional[int]:
        """
        How much discretion over the instant the sealer keeps.

        None where one side is missing, which is unbounded rather than zero and
        must not be reported as a small number.
        """
        if self.lower_ns is None or self.upper_ns is None:
            return None
        return self.upper_ns - self.lower_ns


def _beacon_of(entries: list[Entry]) -> Optional[dict[str, Any]]:
    if not entries or entries[0].kind is not EntryKind.ASSIGNMENT_ANCHOR:
        return None
    b = entries[0].body.get("beacon")
    return b if isinstance(b, dict) and b else None


def resolve_bounds(
    entries: list[Entry],
    *,
    beacon_resolver: Optional[BeaconResolver] = None,
    time_anchors: Optional[Iterable[dict[str, Any]]] = None,
    trusted_authorities: Optional[Iterable[str]] = None,
) -> AnchorReport:
    """
    Bound the chain's instants using facts the sealer did not author.

    The lower bound comes from the beacon committed in the anchor at entry
    zero. Every later entry links forward from it, so a bound on when the chain
    was opened is a bound on all of them. The upper bound comes from the
    earliest recognised anchor over any entry, since an anchor over entry k
    bounds every entry at or before k and the chain is ordered.
    """
    report = AnchorReport()
    if not entries:
        return report

    lower: Optional[int] = None
    committed = _beacon_of(entries)
    if committed is None:
        report.findings.append(
            "The chain commits to no beacon, so nothing establishes it was not "
            "assembled after the fact and dated backwards. A timestamp cannot "
            "supply this, because it bounds the later side.")
    elif beacon_resolver is None:
        report.findings.append(
            "The chain commits to a beacon and no resolver was supplied, so "
            "the value was read from the document it is meant to constrain. "
            "A self-reported beacon is worth what a self-declared witness was.")
    else:
        try:
            actual = beacon_resolver(committed.get("source", ""),
                                     committed.get("pulse", ""))
        except Exception:  # noqa: BLE001
            actual = None
        if actual is None:
            report.findings.append(
                f"Beacon pulse {committed.get('pulse')} from "
                f"{committed.get('source')} could not be resolved, so the "
                "committed value stands unchecked.")
        elif actual[0] != committed.get("value"):
            report.findings.append(
                "The committed beacon value is not what that source published "
                "for that pulse. Either the commitment is fabricated or it "
                "names a pulse that does not exist.")
        else:
            lower = int(actual[1])

    upper: Optional[int] = None
    block_hashes = {e.block_hash for e in entries}
    allow = ({k.strip() for k in trusted_authorities}
             if trusted_authorities is not None else None)
    for doc in list(time_anchors or []):
        try:
            if not signature_valid(doc):
                report.findings.append(
                    "A time anchor does not verify against its own key.")
                continue
            pem = (doc.get("public_key") or "").strip()
            if allow is None:
                report.findings.append(
                    "A time anchor was supplied with no set of recognised "
                    "authorities, so it establishes nothing. Anyone can sign a "
                    "statement about a time.")
                continue
            if pem not in allow:
                report.findings.append(
                    f"A time anchor claiming to be {doc.get('authority')!r} is "
                    "signed by an unrecognised key and is not counted.")
                continue
            if doc["digest"] not in block_hashes:
                report.findings.append(
                    "A time anchor names a digest that is not an entry in this "
                    "chain, so it timestamps some other document.")
                continue
            t = int(doc["time_ns"])
            upper = t if upper is None else min(upper, t)
        except Exception:  # noqa: BLE001
            report.findings.append("A time anchor could not be read.")

    report.lower_ns, report.upper_ns = lower, upper

    if lower is not None and upper is not None and lower > upper:
        report.state = Anchoring.INCONSISTENT
        report.findings.append(
            "The chain commits to a beacon published after an authority says "
            "the chain already existed. The two cannot both be true.")
        return report

    stamps = [e.ts_ns for e in entries]
    if lower is not None and min(stamps) < lower:
        report.findings.append(
            f"Entries claim instants before {lower}, which is when the value "
            "they commit to was published. The chain could not have existed "
            "then. This is backdating and it is the reason a timestamp alone "
            "does not close KC1.")
        report.state = Anchoring.INCONSISTENT
        return report
    if upper is not None and max(stamps) > upper:
        report.findings.append(
            f"Entries claim instants after {upper}, which is when an authority "
            "recorded the chain as already existing.")
        report.state = Anchoring.INCONSISTENT
        return report

    if lower is not None and upper is not None:
        report.state = Anchoring.BOUNDED
    elif lower is not None:
        report.state = Anchoring.LOWER_ONLY
        report.findings.append(
            "The chain is bounded below and not above. Nothing outside it "
            "establishes an upper limit on when the entries were written.")
    elif upper is not None:
        report.state = Anchoring.UPPER_ONLY
        report.findings.append(
            "The chain is bounded above and not below, which is what a "
            "timestamp authority alone reaches. It rules out a chain written "
            "later than it claims and leaves one written earlier untouched, "
            "and the second is the direction KC1 is about.")
    return report


__all__ = [
    "Anchoring",
    "AnchorReport",
    "Beacon",
    "BeaconResolver",
    "TimeAnchor",
    "issue",
    "load",
    "resolve_bounds",
    "signature_valid",
]
