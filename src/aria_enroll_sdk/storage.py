"""Persist the holder keypair to disk in the same PEM format as the
Node SDK and the Go bootstrap binary.

Layout (mirrors @aria-registry/enroll-sdk-node and aria-bootstrap):

    ~/.aria/agents/<name>.pem          PKCS8 Ed25519 (loadable by openssl)
    ~/.aria/agents/<name>.mldsa65.pem  custom "ARIA MLDSA65 PRIVATE KEY"

Files are created with ``0o600`` permissions and ``O_EXCL`` semantics:
refusing to overwrite an existing key file (silent overwrite would
destroy the only copy of a holder private key).
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from pathlib import Path

from aria_enroll_sdk.signer import CompositeKeyPair

_PEM_WRAP = 64
"""Standard PEM line width in characters."""


@dataclass
class StoredPaths:
    """Paths the keypair was written to. Returned by :func:`store_keypair`."""

    ed25519_path: Path
    mldsa65_path: Path
    out_dir: Path


def store_keypair(
    keypair: CompositeKeyPair,
    agent_name: str,
    out_dir: Path | None = None,
    mode: int = 0o600,
) -> StoredPaths:
    """Write both halves of the keypair to disk.

    Returns the resolved paths. The caller is expected to invoke
    ``keypair.zeroize()`` AFTER this returns successfully — not before,
    or we'd write zeros.

    Raises ``FileExistsError`` if either output path already exists.
    """
    if not agent_name:
        raise ValueError("agent_name is required")

    if out_dir is None:
        out_dir = Path.home() / ".aria" / "agents"
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    safe = _sanitize_filename(agent_name)
    ed_path = out_dir / f"{safe}.pem"
    mldsa_path = out_dir / f"{safe}.mldsa65.pem"

    # Pre-check existence so the error surfaces both paths at once.
    for path in (ed_path, mldsa_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing file: {path}")

    # Ed25519 PEM via cryptography's PKCS8 emitter — produces the same
    # RFC 8410 envelope the Node SDK builds inline.
    ed_pem = keypair.ed25519_pkcs8_pem()

    # ML-DSA-65 has no standardised PKCS8 wrapping yet, so we use a
    # clearly non-standard label to signal "ARIA-specific format" to
    # anyone inspecting the file. Loaders must understand the label;
    # standard openssl will refuse to touch it (correct: there's no
    # public PKCS-style mapping for ML-DSA private keys).
    mldsa_pem = _pem_wrap(
        base64.b64encode(bytes(keypair.mldsa65_private_bytes)).decode("ascii"),
        "ARIA MLDSA65 PRIVATE KEY",
    )

    _write_exclusive(ed_path, ed_pem, mode)
    _write_exclusive(mldsa_path, mldsa_pem, mode)
    return StoredPaths(ed25519_path=ed_path, mldsa65_path=mldsa_path, out_dir=out_dir)


def _write_exclusive(path: Path, content: str, mode: int) -> None:
    """``open(path, 'x', ...)`` with explicit mode + ``fsync`` on close.

    The O_EXCL flag (``'x'``) makes the open atomic w.r.t. another
    process racing past our existence check — without it, two
    concurrent ``store_keypair`` calls could both pass the pre-check
    and one would silently clobber the other.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        # Best-effort cleanup of a partial write.
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _pem_wrap(base64_payload: str, label: str) -> str:
    """Wrap a base64 string into a PEM block with 64-column lines."""
    lines = [base64_payload[i : i + _PEM_WRAP] for i in range(0, len(base64_payload), _PEM_WRAP)]
    body = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _sanitize_filename(name: str) -> str:
    """Strip filename-unsafe chars. aria-core's manifest validator
    already enforces alphanumeric + hyphen, so this is defence in depth."""
    return _SAFE_FILENAME_RE.sub("_", name)
