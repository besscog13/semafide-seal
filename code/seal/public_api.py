"""Supported public API for the semafide-seal distribution.

This module is the single source of truth for which names an external
developer may depend on. `seal.__all__` is the export list. This set is
the support contract. They are not the same thing.

SUPPORTED ⊆ seal.__all__ is asserted by tests. Do not copy this set into
docs or tests by hand.
"""

from __future__ import annotations

# Names a caller may import from `seal` and treat as the verifier contract.
# Adding a name here is a support decision. Removing one is a breaking change
# to the contract, even if the name remains in __all__.
SUPPORTED_PUBLIC_API: frozenset[str] = frozenset(
    {
        "verify",
        "load_artifact",
        "export_artifact",
        "VerificationReport",
        "EvidencePropositions",
        "Finding",
        "Completeness",
        "Coverage",
        "EvidentiaryReliance",
        "assess_evidentiary_reliance",
        "SealChain",
        "Entry",
        "EntryKind",
        "RunSeal",
        "EvidenceCommitment",
        "RederivationRecipe",
        "AssignmentAnchor",
        "WitnessAttestation",
        "AttestationMode",
        "WorkfileBinding",
    }
)
