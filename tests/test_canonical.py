"""Cross-SDK golden vectors for canonical JSON + identity_commitment.

This file MUST stay in sync with the equivalent suites in
@aria-registry/enroll-sdk-node, @aria-registry/enroll-sdk-web, and the Go
aria-bootstrap binary. The shared fixture in
``tests/testdata/golden-vectors.json`` is the contract: each SDK
must produce the same canonical-JSON bytes and the same SHA-256
``identity_commitment`` for identical input.

If you bump the fixture, update every sibling SDK in the same PR.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aria_enroll_sdk.canonical import canonical_json

FIXTURE_PATH = Path(__file__).parent / "testdata" / "golden-vectors.json"


def _load_vectors() -> list[dict]:
    with FIXTURE_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data["vectors"]


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_canonical_matches_golden(vector: dict) -> None:
    """Canonical JSON byte-identical to the fixture."""
    got = canonical_json(vector["input"])
    assert got == vector["expected_canonical_json"], (
        f"canonical JSON mismatch\n got: {got}\nwant: {vector['expected_canonical_json']}"
    )


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_identity_commitment_matches_golden(vector: dict) -> None:
    """SHA-256 of the canonical JSON matches expected_identity_commitment."""
    canonical = canonical_json(vector["input"])
    got = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert got == vector["expected_identity_commitment"], (
        f"identity_commitment mismatch\n got: {got}\nwant: {vector['expected_identity_commitment']}"
    )
