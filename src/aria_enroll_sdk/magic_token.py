"""Magic-token helpers — hash + length validation.

The plaintext magic token is a 22-character base64url string of 16
random bytes. aria-core stores its SHA-256(decoded-bytes) under
``enrollment:token:<hash>`` in Redis; we recompute the same hash for
the manifest's ``enrollment_token_hash`` field so the registry can
match on /submit.

The plaintext is NEVER persisted anywhere by this SDK — the only
on-disk artifacts after enrollment are the two PEM files containing
the holder keypair.
"""

from __future__ import annotations

import base64
import hashlib

MAGIC_TOKEN_LENGTH = 22
"""Exact length of the 22-character base64url plaintext."""


def hash_magic_token(plaintext: str) -> str:
    """Return the lowercase-hex SHA-256 of the base64url-decoded token.

    Identical to ``hashMagicToken()`` in @aria-registry/enroll-sdk-node and
    ``HashMagicToken()`` in aria-bootstrap. Used to populate the
    manifest's ``enrollment_token_hash`` field; the registry verifies
    that the hash derived from the Authorization header matches.

    Raises ``ValueError`` if the token isn't exactly 22 valid base64url
    characters.
    """
    if len(plaintext) != MAGIC_TOKEN_LENGTH:
        raise ValueError(
            f"Magic token must be {MAGIC_TOKEN_LENGTH} base64url characters (got {len(plaintext)})"
        )
    try:
        # base64.urlsafe_b64decode requires padding; restore it.
        padded = plaintext + "=" * (-len(plaintext) % 4)
        raw = base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Magic token is not valid base64url: {exc}") from exc
    if len(raw) != 16:
        raise ValueError(f"Decoded magic token must be 16 bytes (got {len(raw)})")
    return hashlib.sha256(raw).hexdigest()
