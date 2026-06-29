"""HTTP client for aria-core's enrollment endpoints.

Three endpoints, all authenticated with the magic-token in the
``Authorization: aria-magic-<token>`` header:

    GET  /v1/enrollment/scopes               → ScopesResponse
    POST /v1/enrollment/submit               → SubmitResponse
    GET  /v1/enrollment/{session_id}/status  → StatusResponse

Two client flavours are exposed: :class:`EnrollmentClient` (sync,
via httpx.Client) and :class:`AsyncEnrollmentClient` (async, via
httpx.AsyncClient). Both share the same wire types and error shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_REGISTRY_URL = "https://core.aria.bar"
"""Production registry. Override via the ``registry_url`` parameter for
dev (http://localhost:3001) or staging deployments."""

DEFAULT_TIMEOUT = 30.0  # seconds


# ── Wire types ────────────────────────────────────────────────────────────


@dataclass
class ScopesResponse:
    """Body of ``GET /v1/enrollment/scopes`` after unwrapping ``.data``."""

    scopes_available: list[str]
    principal_did: str
    enrollment_session_id: str
    trust_level: str
    org_domain: str | None


@dataclass
class SubmitResponse:
    """Body of a successful ``POST /v1/enrollment/submit``."""

    session_id: str
    manifest_hash: str
    visual_hash: str
    status: str  # 'awaiting_admin_2fa'


@dataclass
class StatusResponse:
    """Body of ``GET /v1/enrollment/{session_id}/status``."""

    session_id: str
    status: str  # 'awaiting_manifest' | 'awaiting_admin_2fa' | terminal ...
    aid_did: str | None
    credential_id: str | None
    visual_hash: str | None
    rejection_reason: str | None
    expires_at: str


# ── Error type ────────────────────────────────────────────────────────────


class EnrollmentHTTPError(Exception):
    """Raised for any non-2xx response from aria-core.

    ``code`` is aria-core's error envelope code (``UNAUTHORIZED``,
    ``MANIFEST_INVALID``, …). ``details`` carries the structured
    ``error.details`` field — populated for validation errors so the
    caller can pinpoint the offending manifest field.
    """

    def __init__(
        self,
        method: str,
        path: str,
        status: int,
        code: str,
        message: str,
        details: Any | None = None,
    ) -> None:
        self.method = method
        self.path = path
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        base = f"{method} {path}: HTTP {status} {code} — {message}"
        if details is not None:
            base += f" — details: {details}"
        super().__init__(base)


# ── Helpers ───────────────────────────────────────────────────────────────


def _build_auth_header(token: str) -> str:
    return f"aria-magic-{token}"


def _raise_for_error(method: str, path: str, response: httpx.Response) -> None:
    """Convert non-2xx httpx responses into :class:`EnrollmentHTTPError`."""
    if 200 <= response.status_code < 300:
        return
    try:
        envelope = response.json()
    except ValueError:
        envelope = None
    error = (envelope or {}).get("error", {}) if isinstance(envelope, dict) else {}
    code = error.get("code") or "UNKNOWN"
    message = error.get("message") or response.reason_phrase or "unknown error"
    details = error.get("details")
    raise EnrollmentHTTPError(method, path, response.status_code, code, message, details)


def _unwrap_data(body: Any) -> Any:
    """aria-core wraps successful responses as ``{"data": ...}``. Unwrap."""
    if isinstance(body, dict) and "data" in body:
        return body["data"]
    return body


def _scopes_from_json(data: Any) -> ScopesResponse:
    return ScopesResponse(
        scopes_available=list(data["scopes_available"]),
        principal_did=data["principal_did"],
        enrollment_session_id=data["enrollment_session_id"],
        trust_level=data["trust_level"],
        org_domain=data.get("org_domain"),
    )


def _submit_from_json(data: Any) -> SubmitResponse:
    return SubmitResponse(
        session_id=data["session_id"],
        manifest_hash=data["manifest_hash"],
        visual_hash=data["visual_hash"],
        status=data["status"],
    )


def _status_from_json(data: Any) -> StatusResponse:
    return StatusResponse(
        session_id=data["session_id"],
        status=data["status"],
        aid_did=data.get("aid_did"),
        credential_id=data.get("credential_id"),
        visual_hash=data.get("visual_hash"),
        rejection_reason=data.get("rejection_reason"),
        expires_at=data.get("expires_at", ""),
    )


TERMINAL_STATUSES: set[str] = {"completed", "rejected", "cancelled", "expired"}


def is_terminal(status: str) -> bool:
    """True when the status is one we shouldn't continue polling past."""
    return status in TERMINAL_STATUSES


# ── Sync client ───────────────────────────────────────────────────────────


class EnrollmentClient:
    """Synchronous httpx-backed client for aria-core's enrollment endpoints."""

    def __init__(
        self,
        registry_url: str,
        token: str,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not registry_url:
            raise ValueError("registry_url is required")
        if not token:
            raise ValueError("token is required")
        self._base = registry_url.rstrip("/")
        self._auth = _build_auth_header(token)
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(timeout=timeout)

    def __enter__(self) -> EnrollmentClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying httpx.Client if we own it."""
        if self._owns_client:
            self._client.close()

    def get_scopes(self) -> ScopesResponse:
        return _scopes_from_json(self._unwrap("GET", "/v1/enrollment/scopes"))

    def submit(self, signed_manifest: dict[str, Any]) -> SubmitResponse:
        return _submit_from_json(
            self._unwrap("POST", "/v1/enrollment/submit", json={"manifest": signed_manifest})
        )

    def status(self, session_id: str) -> StatusResponse:
        return _status_from_json(
            self._unwrap("GET", f"/v1/enrollment/{session_id}/status")
        )

    def _unwrap(
        self,
        method: str,
        path: str,
        json: Any | None = None,
    ) -> Any:
        headers = {"Authorization": self._auth, "Accept": "application/json"}
        if method == "GET":
            res = self._client.get(self._base + path, headers=headers)
        elif method == "POST":
            res = self._client.post(self._base + path, headers=headers, json=json)
        else:
            raise ValueError(f"unsupported method: {method}")
        _raise_for_error(method, path, res)
        return _unwrap_data(res.json())


# ── Async client ──────────────────────────────────────────────────────────


class AsyncEnrollmentClient:
    """Async httpx-backed client. Same surface as :class:`EnrollmentClient`."""

    def __init__(
        self,
        registry_url: str,
        token: str,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not registry_url:
            raise ValueError("registry_url is required")
        if not token:
            raise ValueError("token is required")
        self._base = registry_url.rstrip("/")
        self._auth = _build_auth_header(token)
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> AsyncEnrollmentClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def get_scopes(self) -> ScopesResponse:
        return _scopes_from_json(await self._unwrap("GET", "/v1/enrollment/scopes"))

    async def submit(self, signed_manifest: dict[str, Any]) -> SubmitResponse:
        return _submit_from_json(
            await self._unwrap(
                "POST", "/v1/enrollment/submit", json={"manifest": signed_manifest}
            )
        )

    async def status(self, session_id: str) -> StatusResponse:
        return _status_from_json(
            await self._unwrap("GET", f"/v1/enrollment/{session_id}/status")
        )

    async def _unwrap(
        self,
        method: str,
        path: str,
        json: Any | None = None,
    ) -> Any:
        headers = {"Authorization": self._auth, "Accept": "application/json"}
        if method == "GET":
            res = await self._client.get(self._base + path, headers=headers)
        elif method == "POST":
            res = await self._client.post(self._base + path, headers=headers, json=json)
        else:
            raise ValueError(f"unsupported method: {method}")
        _raise_for_error(method, path, res)
        return _unwrap_data(res.json())
