"""End-to-end enrollment orchestrator.

Two surface methods, identical contract except for sync/async:

    enroll(...)   →  EnrollResult       (sync)
    aenroll(...)  →  EnrollResult       (async coroutine)

Both:

  1. Open an :class:`EnrollmentClient` bound to the magic token.
  2. ``GET /scopes`` to discover principal_did + trust_level + org_domain.
  3. Validate the caller's scopes against the catalog (refuse unknowns).
  4. Generate a fresh composite keypair locally.
  5. Build + self-sign the manifest.
  6. ``POST /submit``.
  7. Poll ``/status`` until the admin confirms (or the row hits a
     terminal state).
  8. On ``completed`` — write the PEM files, zeroize the in-memory keypair.

Any failure path zeroizes the keypair before raising.
"""

from __future__ import annotations

import asyncio
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from aria_enroll_sdk import __version__ as SDK_VERSION
from aria_enroll_sdk.client import (
    DEFAULT_REGISTRY_URL,
    AsyncEnrollmentClient,
    EnrollmentClient,
    ScopesResponse,
    is_terminal,
)
from aria_enroll_sdk.magic_token import MAGIC_TOKEN_LENGTH, hash_magic_token
from aria_enroll_sdk.manifest import BuildManifestParams, build_manifest
from aria_enroll_sdk.signer import CompositeKeyPair, generate_keypair
from aria_enroll_sdk.storage import StoredPaths, store_keypair

SDK_NAME = "aria-enroll-sdk"
"""Identity emitted under ``sdk_attestation.name`` — accepted by
aria-core alongside the Node, web-keygen, and bootstrap clients."""

POLL_INTERVAL_SECONDS = 3.0
DEFAULT_POLL_TIMEOUT_SECONDS = 30 * 60  # 30 min — matches token TTL.


@dataclass
class EnrollOptions:
    """Inputs to :func:`enroll` / :func:`aenroll`.

    ``scopes`` is required and must be a non-empty subset of the
    registry's catalog (call :func:`fetch_available_scopes` first or use
    the ``aria-enroll scopes`` CLI command to discover what's accepted).
    Over-permissioned agents are a security liability the admin can't
    easily catch at review, so the SDK refuses to default to "all".
    """

    token: str
    agent_name: str
    scopes: list[str]
    registry_url: str = DEFAULT_REGISTRY_URL
    hitl: list[str] = field(default_factory=list)
    target_domain: str | None = None
    region_hint: str | None = None
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS
    poll_timeout_seconds: float = DEFAULT_POLL_TIMEOUT_SECONDS
    out_dir: Path | None = None


@dataclass
class EnrollResult:
    """Returned by :func:`enroll` on success."""

    session_id: str
    status: str
    visual_hash: str
    manifest_hash: str
    aid_did: str | None = None
    credential_id: str | None = None
    pem_paths: StoredPaths | None = None
    rejection_reason: str | None = None


# ── Sync ──────────────────────────────────────────────────────────────────


def enroll(opts: EnrollOptions) -> EnrollResult:
    """Run the full enrollment flow synchronously.

    Blocks on the polling loop until either the admin confirms (and the
    AID is signed) or ``poll_timeout_seconds`` elapses. Raises on any
    transport / validation error and on non-``completed`` terminal
    states.
    """
    _validate(opts)

    with EnrollmentClient(opts.registry_url, opts.token) as client:
        catalog = client.get_scopes()
        _assert_scopes_in_catalog(opts.scopes, catalog)

        keypair = generate_keypair()
        try:
            signed = _build_signed_manifest(opts, catalog, keypair)
            submit_res = client.submit(signed.manifest)
            deadline = time.monotonic() + opts.poll_timeout_seconds

            while True:
                time.sleep(opts.poll_interval_seconds)
                status = client.status(submit_res.session_id)
                if is_terminal(status.status):
                    return _finalize(opts, keypair, submit_res, status)
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"enrollment {submit_res.session_id} did not reach a terminal status within "
                        f"{opts.poll_timeout_seconds:.0f}s"
                    )
        finally:
            # Defensive: zeroize on every exit path. Some paths (success
            # via _finalize) already zeroize before returning, so this is
            # an idempotent overwrite of a zeroed buffer.
            keypair.zeroize()


# ── Async ─────────────────────────────────────────────────────────────────


async def aenroll(opts: EnrollOptions) -> EnrollResult:
    """Async variant of :func:`enroll`. Same contract."""
    _validate(opts)

    async with AsyncEnrollmentClient(opts.registry_url, opts.token) as client:
        catalog = await client.get_scopes()
        _assert_scopes_in_catalog(opts.scopes, catalog)

        keypair = generate_keypair()
        try:
            signed = _build_signed_manifest(opts, catalog, keypair)
            submit_res = await client.submit(signed.manifest)
            deadline = time.monotonic() + opts.poll_timeout_seconds

            while True:
                await asyncio.sleep(opts.poll_interval_seconds)
                status = await client.status(submit_res.session_id)
                if is_terminal(status.status):
                    return _finalize(opts, keypair, submit_res, status)
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"enrollment {submit_res.session_id} did not reach a terminal status within "
                        f"{opts.poll_timeout_seconds:.0f}s"
                    )
        finally:
            keypair.zeroize()


# ── Internals ─────────────────────────────────────────────────────────────


def _validate(opts: EnrollOptions) -> None:
    if not opts.token:
        raise ValueError("token is required")
    if len(opts.token) != MAGIC_TOKEN_LENGTH:
        raise ValueError(
            f"token must be {MAGIC_TOKEN_LENGTH} base64url characters (got {len(opts.token)})"
        )
    if not opts.agent_name:
        raise ValueError("agent_name is required")
    if not opts.scopes:
        raise ValueError(
            "scopes is required and must be non-empty — discover the catalog with "
            "`aria-enroll scopes --token=...` or fetch_available_scopes()"
        )


def _assert_scopes_in_catalog(selected: list[str], catalog: ScopesResponse) -> None:
    available = set(catalog.scopes_available)
    unknown = [s for s in selected if s not in available]
    if unknown:
        raise ValueError(
            f"scopes not in the registry's catalog: {unknown} "
            f"(available: {sorted(catalog.scopes_available)})"
        )


def _build_signed_manifest(
    opts: EnrollOptions,
    catalog: ScopesResponse,
    keypair: CompositeKeyPair,
):
    target_domain = opts.target_domain
    if not target_domain and catalog.trust_level != "L0":
        target_domain = catalog.org_domain
    if catalog.trust_level != "L0" and not target_domain:
        raise ValueError(
            f"target_domain is required for trust level {catalog.trust_level} and the registry "
            f"did not report an org_domain"
        )

    params = BuildManifestParams(
        enrollment_session_id=catalog.enrollment_session_id,
        enrollment_token_hash=hash_magic_token(opts.token),
        principal_did=catalog.principal_did,
        agent_name=opts.agent_name,
        trust_level=catalog.trust_level,  # type: ignore[arg-type]
        selected_scopes=opts.scopes,
        hitl_required=opts.hitl or None,
        target_domain=target_domain,
        region_hint=opts.region_hint,
        holder_ed25519_multibase=keypair.ed25519_multibase,
        holder_mldsa65_multibase=keypair.mldsa65_multibase,
        sdk_name=SDK_NAME,
        sdk_version=SDK_VERSION,
        sdk_platform="python",
        runtime="python",
        runtime_version=f"Python {sys.version.split()[0]} {platform.platform(terse=True)}",
    )
    return build_manifest(params, keypair)


def _finalize(
    opts: EnrollOptions,
    keypair: CompositeKeyPair,
    submit_res,
    status,
) -> EnrollResult:
    res = EnrollResult(
        session_id=submit_res.session_id,
        status=status.status,
        visual_hash=submit_res.visual_hash,
        manifest_hash=submit_res.manifest_hash,
        aid_did=status.aid_did,
        credential_id=status.credential_id,
        rejection_reason=status.rejection_reason,
    )
    if status.status != "completed":
        reason = status.rejection_reason or "unknown"
        raise RuntimeError(f"enrollment terminated with status={status.status} ({reason})")

    # PEM goes to disk BEFORE we zeroize the in-memory copies.
    res.pem_paths = store_keypair(keypair, opts.agent_name, out_dir=opts.out_dir)
    keypair.zeroize()
    return res
