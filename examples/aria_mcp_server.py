"""MCP server for ARIA agent self-enrollment.

Splits enrollment into NON-BLOCKING tools so MCP timeouts don't kill
the call while the human admin confirms the OTP (which may take
minutes):

    1. aria_list_scopes(token)
       Returns the catalog the registry will accept. Synchronous, ~200ms.

    2. aria_submit_manifest(token, agent_name, scopes)
       Generates the composite keypair locally, builds and self-signs
       the manifest, posts to /v1/enrollment/submit. Returns
       session_id and visual_hash. The keypair is held in this
       process's memory keyed by session_id until finalisation. ~1s.

    3. aria_finalize_enrollment(session_id)
       Polls /status once. If still pending, returns a "call me again
       in a few seconds" payload. If completed, writes the PEM files
       to ~/.aria/agents/<name>.pem and returns the AID DID. The LLM
       loops on this tool until it gets a terminal status — that's
       its responsibility, not the server's.

The keypair NEVER leaves this Python process. It's generated in tool
2, sits in memory until tool 3 writes it to disk, then is zeroized.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from aria_enroll_sdk import __version__ as SDK_VERSION
from aria_enroll_sdk.client import EnrollmentClient, is_terminal
from aria_enroll_sdk.magic_token import hash_magic_token
from aria_enroll_sdk.manifest import BuildManifestParams, build_manifest
from aria_enroll_sdk.signer import CompositeKeyPair, generate_keypair
from aria_enroll_sdk.storage import store_keypair

mcp = FastMCP("aria-enroll")

# Pending enrollments keyed by session_id. The keypair lives here
# between aria_submit_manifest and aria_finalize_enrollment so the
# LLM can complete the flow across multiple tool calls.
_PENDING: dict[str, dict[str, Any]] = {}

# Terminal results cached for idempotent re-calls. LLMs in tool-loop
# patterns often call finalize once more "to be sure" after success;
# without this cache the second call would error with "no in-flight
# enrollment" and confuse the model. Keep the response forever (or
# until the process restarts) — it's tiny and read-only.
_TERMINAL: dict[str, dict[str, Any]] = {}


@mcp.tool()
def aria_list_scopes(token: str, registry_url: str = "http://localhost:3001") -> dict[str, Any]:
    """List the catalog of scopes the registry will accept for this enrollment.

    Call this BEFORE aria_submit_manifest so the LLM can pick a sensible
    subset of scopes. Synchronous, completes in ~200ms.
    """
    with EnrollmentClient(registry_url, token) as client:
        catalog = client.get_scopes()
    return {
        "scopes_available": catalog.scopes_available,
        "principal_did": catalog.principal_did,
        "enrollment_session_id": catalog.enrollment_session_id,
        "trust_level": catalog.trust_level,
        "org_domain": catalog.org_domain,
    }


@mcp.tool()
def aria_submit_manifest(
    token: str,
    agent_name: str,
    scopes: list[str],
    registry_url: str = "http://localhost:3001",
) -> dict[str, Any]:
    """Step 1 of 2 — generate the keypair, build the manifest, submit it.

    Generates a fresh composite (Ed25519 + ML-DSA-65) keypair on this
    machine, builds + self-signs the manifest, posts to aria-core's
    /v1/enrollment/submit. Returns session_id + visual_hash quickly
    (no polling). The LLM must then call aria_finalize_enrollment
    repeatedly until it returns a terminal status.

    Args:
        token: 22-char base64url magic token from the registry portal.
        agent_name: 1-64 alphanumeric / hyphen chars. Appears in the AID.
        scopes: Non-empty subset of aria_list_scopes() output.
        registry_url: aria-core base URL. Defaults to localhost dev.
    """
    with EnrollmentClient(registry_url, token) as client:
        catalog = client.get_scopes()
        available = set(catalog.scopes_available)
        unknown = [s for s in scopes if s not in available]
        if unknown:
            raise ValueError(
                f"scopes not in catalog: {unknown} (available: {sorted(available)})"
            )

        kp = generate_keypair()
        target_domain = catalog.org_domain if catalog.trust_level != "L0" else None

        params = BuildManifestParams(
            enrollment_session_id=catalog.enrollment_session_id,
            enrollment_token_hash=hash_magic_token(token),
            principal_did=catalog.principal_did,
            agent_name=agent_name,
            trust_level=catalog.trust_level,  # type: ignore[arg-type]
            selected_scopes=scopes,
            target_domain=target_domain,
            holder_ed25519_multibase=kp.ed25519_multibase,
            holder_mldsa65_multibase=kp.mldsa65_multibase,
            sdk_name="aria-enroll-sdk",
            sdk_version=SDK_VERSION,
            sdk_platform="python",
            runtime="python",
            runtime_version=f"Python {sys.version.split()[0]} {platform.platform(terse=True)}",
        )
        signed = build_manifest(params, kp)
        try:
            submit_res = client.submit(signed.manifest)
        except Exception:
            kp.zeroize()
            raise

    _PENDING[submit_res.session_id] = {
        "keypair": kp,
        "agent_name": agent_name,
        "registry_url": registry_url,
        "token": token,
    }

    return {
        "session_id": submit_res.session_id,
        "visual_hash": submit_res.visual_hash,
        "manifest_hash": submit_res.manifest_hash,
        "status": submit_res.status,
        "next_step": (
            "Tell the operator to keep the registry wizard tab open: review the manifest, "
            "click 'Aceptar y firmar', then enter the OTP that arrives by email. Once they "
            f"start that flow, call aria_finalize_enrollment(session_id='{submit_res.session_id}') "
            "every few seconds until status is terminal."
        ),
    }


@mcp.tool()
def aria_finalize_enrollment(session_id: str) -> dict[str, Any]:
    """Step 2 of 2 — poll status; on completion, write PEM and return DID.

    Non-blocking — single /status call. If the row is still awaiting
    admin confirmation, returns {"ready": False, "status": "..."} and
    the LLM should call again in ~3 seconds. If terminal, returns
    {"ready": True, ...} with the AID DID (on success) or
    rejection_reason (on failure).

    The keypair lives in this process's memory across calls until a
    terminal status fires, at which point it's either written to disk
    (on `completed`) and zeroized, or just zeroized (on rejection).

    Args:
        session_id: The ULID returned by aria_submit_manifest.
    """
    # Idempotency: if the session already reached terminal state in a
    # prior call, return the cached result without touching the network
    # again. LLMs sometimes loop "just to be sure" — without this they'd
    # see "no in-flight" and panic.
    if session_id in _TERMINAL:
        cached = dict(_TERMINAL[session_id])
        cached["note"] = "enrollment already finalised — returning cached result."
        return cached

    state = _PENDING.get(session_id)
    if not state:
        raise ValueError(
            f"no in-flight enrollment for session {session_id} — did you call "
            f"aria_submit_manifest first?"
        )

    with EnrollmentClient(state["registry_url"], state["token"]) as client:
        status = client.status(session_id)

    if not is_terminal(status.status):
        return {
            "ready": False,
            "status": status.status,
            "note": (
                "still waiting for the admin to confirm the OTP. "
                "Call aria_finalize_enrollment again in 3-5 seconds."
            ),
        }

    keypair: CompositeKeyPair = state["keypair"]
    try:
        if status.status != "completed":
            result = {
                "ready": True,
                "status": status.status,
                "rejection_reason": status.rejection_reason,
            }
        else:
            paths = store_keypair(keypair, state["agent_name"])
            result = {
                "ready": True,
                "status": "completed",
                "aid_did": status.aid_did,
                "credential_id": status.credential_id,
                "pem_paths": {
                    "ed25519": str(paths.ed25519_path),
                    "mldsa65": str(paths.mldsa65_path),
                    "out_dir": str(paths.out_dir),
                },
            }
        _TERMINAL[session_id] = result
        return result
    finally:
        keypair.zeroize()
        _PENDING.pop(session_id, None)


if __name__ == "__main__":
    mcp.run()
