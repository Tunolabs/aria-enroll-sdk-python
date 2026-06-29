"""Manifest builder + identity commitment + composite signature attachment.

Construction is byte-identical to the TS SDKs and the Go binary:
same field set, same canonical JSON, same SHA-256 ``identity_commitment``,
same composite signature suite. The golden vectors in
``tests/testdata/golden-vectors.json`` are shared with every sibling
SDK and pin the contract.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from aria_enroll_sdk.canonical import canonical_json

SUITE = "mldsa65-ed25519-2026"

TrustLevel = Literal["L0", "L1", "L2", "L3"]
"""Trust levels recognised by aria-core. The agent echoes the org's level."""


@dataclass
class ExternalDIDProof:
    """Optional proof linking an external DID to the holder key (spec v1.2)."""

    type: Literal["Ed25519Signature2020", "JsonWebSignature2020"]
    challenge: str  # 64-char lowercase hex
    signature: str  # base64url, no padding


@dataclass
class BuildManifestParams:
    """Inputs to :func:`build_manifest`.

    Fields marked ``Optional`` with a default of ``None`` / empty string
    are omitted from the canonical JSON if absent — important because
    canonical bytes differ if a key is present-with-null vs absent.
    """

    enrollment_session_id: str
    enrollment_token_hash: str  # lowercase-hex SHA-256
    principal_did: str
    agent_name: str
    trust_level: TrustLevel

    selected_scopes: list[str]
    holder_ed25519_multibase: str
    holder_mldsa65_multibase: str

    sdk_name: str
    sdk_version: str
    sdk_platform: str
    runtime: str
    runtime_version: str

    target_domain: str | None = None
    external_did: str | None = None
    external_did_proof: ExternalDIDProof | None = None
    hitl_required: list[str] | None = None
    region_hint: str | None = None
    created_at: datetime | None = None
    """Override the creation timestamp. Used by tests; production callers
    leave this ``None`` and the builder stamps ``datetime.now(timezone.utc)``."""


class Signer(Protocol):
    """Minimum surface needed by :func:`build_manifest`.

    Keeps the manifest module independent of the keygen module — tests
    can supply a fake signer that returns deterministic bytes.
    """

    def sign_ed25519(self, payload: bytes) -> bytes: ...
    def sign_mldsa65(self, payload: bytes) -> bytes: ...


def build_unsigned_manifest(p: BuildManifestParams) -> dict[str, Any]:
    """Assemble the unsigned manifest body.

    Field order in the returned dict is irrelevant — canonical JSON
    sorts keys at serialisation time. Optional fields are omitted (not
    set to None) so they don't appear as ``null`` in canonical output.
    """
    out: dict[str, Any] = {
        "spec_version": "1.0",
        "enrollment_session_id": p.enrollment_session_id,
        "enrollment_token_hash": p.enrollment_token_hash,
        "principal_did": p.principal_did,
        "agent_name": p.agent_name,
        "trust_level": p.trust_level,
        "selected_scopes": list(p.selected_scopes),
        "holder_public_key": {
            "suite": SUITE,
            "ed25519_multibase": p.holder_ed25519_multibase,
            "mldsa65_multibase": p.holder_mldsa65_multibase,
        },
        "sdk_attestation": {
            "name": p.sdk_name,
            "version": p.sdk_version,
            "platform": p.sdk_platform,
        },
        "environment": _build_environment(p),
        "created_at": _format_created_at(p.created_at),
    }
    if p.target_domain:
        out["target_domain"] = p.target_domain
    if p.external_did:
        out["external_did"] = p.external_did
    if p.external_did_proof is not None:
        out["external_did_proof"] = {
            "type": p.external_did_proof.type,
            "challenge": p.external_did_proof.challenge,
            "signature": p.external_did_proof.signature,
        }
    if p.hitl_required:
        out["hitl_required"] = list(p.hitl_required)
    return out


def _build_environment(p: BuildManifestParams) -> dict[str, Any]:
    env: dict[str, Any] = {"runtime": p.runtime, "runtime_version": p.runtime_version}
    if p.region_hint:
        env["region_hint"] = p.region_hint
    return env


def _format_created_at(value: datetime | None) -> str:
    """Format the timestamp as ``YYYY-MM-DDTHH:MM:SS.sssZ``.

    Matches JavaScript's ``new Date().toISOString()`` — millisecond
    precision, ``Z`` suffix for UTC. Python's ``isoformat`` would emit
    microseconds or ``+00:00``; build the format manually.
    """
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    # Truncate to milliseconds.
    millis = value.microsecond // 1000
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"


def compute_identity_commitment(unsigned: dict[str, Any]) -> str:
    """Lowercase-hex SHA-256 over the canonical JSON of the unsigned manifest."""
    canonical = canonical_json(unsigned).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class SignedManifest:
    """The signed manifest, ready to POST to ``/v1/enrollment/submit``.

    ``manifest`` is the dict aria-core wants under the ``manifest``
    key of the request body. canonical JSON of this dict is what the
    registry recomputes when re-deriving identity_commitment.
    """

    manifest: dict[str, Any]


def build_manifest(p: BuildManifestParams, signer: Signer) -> SignedManifest:
    """Build the full signed manifest.

    Computes the identity commitment over the canonical JSON of the
    unsigned manifest, asks ``signer`` for both signature halves, and
    attaches them under ``self_signature``. aria-core re-derives the
    commitment from the same canonical JSON; any byte mismatch surfaces
    as ``MANIFEST_INVALID`` on /submit.
    """
    unsigned = build_unsigned_manifest(p)
    commitment = compute_identity_commitment(unsigned)
    # The signature payload is the UTF-8 bytes of the commitment HEX
    # STRING, not the raw 32-byte hash — same convention as the TS SDKs.
    payload = commitment.encode("utf-8")
    ed_sig = signer.sign_ed25519(payload)
    mldsa_sig = signer.sign_mldsa65(payload)

    signed: dict[str, Any] = dict(unsigned)
    signed["identity_commitment"] = commitment
    signed["self_signature"] = {
        "suite": SUITE,
        "ed25519": _bytes_to_base64url(ed_sig),
        "mldsa65": _bytes_to_base64url(mldsa_sig),
    }
    return SignedManifest(manifest=signed)


def _bytes_to_base64url(raw: bytes) -> str:
    """Base64url encode without padding (RFC 4648 § 5)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
