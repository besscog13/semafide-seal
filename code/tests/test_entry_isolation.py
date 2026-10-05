"""
A sealed entry's body cannot be changed from outside the chain.

`Entry` is a frozen dataclass, but its body is a dict. Before 2026-10-05 the
chain stored the caller's dict as given, `entries` returned the stored
entries, and `to_payload` put the stored dict into the exported document. Any
of the three let a caller edit a sealed body in place. The chain then
exported a body its signature was never computed over, and a record that
verified a moment earlier failed its signature check with no append between.

Each test below edits one of those three handles and checks that the chain
still exports exactly what it exported before, and still verifies.
"""
from __future__ import annotations

from seal.artifact import EntryKind, SealChain, export_artifact
from seal.verifier import verify


def _chain_with_body(body: dict) -> SealChain:
    chain = SealChain("ASG-ISOLATION")
    chain.append(EntryKind.EVIDENCE_COMMITMENT, body, 10)
    return chain


def _verifies(chain: SealChain) -> bool:
    report = verify(export_artifact(chain), trusted_keys=[chain.public_key_pem])
    return report.chain_intact and report.signatures_valid


def test_editing_the_dict_passed_to_append_does_not_edit_the_sealed_entry():
    body = {"rows": ["a", "b"], "nested": {"k": 1}}
    chain = _chain_with_body(body)
    before = export_artifact(chain)

    body["rows"].append("c")
    body["nested"]["k"] = 2

    assert export_artifact(chain) == before
    assert _verifies(chain)


def test_editing_an_exported_document_does_not_edit_the_chain():
    chain = _chain_with_body({"rows": ["a"], "nested": {"k": 1}})
    before = export_artifact(chain)

    doc = export_artifact(chain)
    doc["entries"][1]["body"]["nested"]["k"] = 2
    doc["entries"][1]["body"]["rows"].clear()

    assert export_artifact(chain) == before
    assert _verifies(chain)


def test_editing_a_body_read_through_entries_does_not_edit_the_chain():
    chain = _chain_with_body({"rows": ["a"], "nested": {"k": 1}})
    before = export_artifact(chain)

    chain.entries[1].body["nested"]["k"] = 2
    chain.entries[1].body["rows"].append("z")

    assert export_artifact(chain) == before
    assert _verifies(chain)
