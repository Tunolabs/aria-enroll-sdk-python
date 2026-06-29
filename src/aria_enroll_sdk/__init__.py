"""aria-registry — non-custodial agent enrollment for the ARIA Protocol.

Public API mirrors @aria-registry/enroll-sdk-node:

    from aria_enroll_sdk import enroll, fetch_available_scopes

    result = enroll(
        token="<22-char base64url>",
        agent_name="my-agent",
        scopes=["data:public:read", "communication:human:read"],
        registry_url="http://localhost:3001",
    )
    print(result.aid_did)

Both ``enroll`` (sync) and ``aenroll`` (async) are exposed; pick the one
that matches the agent's runtime model. The PEM files land in
``~/.aria/agents/<name>.pem`` and ``<name>.mldsa65.pem`` — the private
keys never leave the local process.
"""

# __version__ is declared BEFORE the re-exports so submodules can
# import it from `aria_enroll_sdk` without triggering a circular import
# (enroll.py reads SDK_VERSION = aria_enroll_sdk.__version__ to populate
# the manifest's sdk_attestation block).
__version__ = "1.2.0"

from aria_enroll_sdk.client import (
    DEFAULT_REGISTRY_URL,
    EnrollmentHTTPError,
    ScopesResponse,
    StatusResponse,
    SubmitResponse,
)
from aria_enroll_sdk.enroll import EnrollOptions, EnrollResult, aenroll, enroll
from aria_enroll_sdk.manifest import build_manifest, compute_identity_commitment
from aria_enroll_sdk.signer import CompositeKeyPair, generate_keypair
from aria_enroll_sdk.storage import store_keypair

__all__ = [
    "DEFAULT_REGISTRY_URL",
    "CompositeKeyPair",
    "EnrollmentHTTPError",
    "EnrollOptions",
    "EnrollResult",
    "ScopesResponse",
    "StatusResponse",
    "SubmitResponse",
    "aenroll",
    "build_manifest",
    "compute_identity_commitment",
    "enroll",
    "fetch_available_scopes",
    "generate_keypair",
    "store_keypair",
]

# Re-exported lazily to avoid pulling httpx at import time when only the
# pure-crypto helpers are needed.
def fetch_available_scopes(token: str, registry_url: str = DEFAULT_REGISTRY_URL) -> ScopesResponse:
    """Fetch the catalog of scopes the registry will accept for this enrollment.

    Use this before calling :func:`enroll` to surface the available scopes
    to whoever is provisioning the agent. ``enroll`` itself rejects unknown
    scopes and refuses to default to "all" — over-permissioned agents are
    a security liability the admin can't easily catch at review.
    """
    from aria_enroll_sdk.client import EnrollmentClient

    with EnrollmentClient(registry_url, token) as client:
        return client.get_scopes()
