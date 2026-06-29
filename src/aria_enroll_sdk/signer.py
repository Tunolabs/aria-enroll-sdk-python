"""Composite keypair generation + signing.

Generates a fresh Ed25519 keypair (via ``cryptography``) and an
ML-DSA-65 keypair (FIPS 204, via ``pqcrypto``). Mirrors the Node SDK
and the Go bootstrap binary byte-for-byte on the public-key
multibase encoding (z-prefixed base58btc), so the manifest's
``holder_public_key`` block is interchangeable across clients.

The private halves NEVER leave this process. After PEM serialisation
the caller is expected to call :meth:`CompositeKeyPair.zeroize` to
overwrite the in-memory buffers — best-effort, the Python GC may
have moved bytes elsewhere, but the original slices are wiped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# pqcrypto ships several ML-DSA variants. We pin to the 65 (a.k.a.
# Dilithium3 / FIPS 204 ML-DSA-65) used throughout the protocol.
from pqcrypto.sign import ml_dsa_65

# ── Multibase / base58btc ─────────────────────────────────────────────────

_BASE58_ALPHABET: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
"""Bitcoin base58 alphabet — matches @scure/base and our Go impl."""


def _base58_encode(raw: bytes) -> str:
    """Encode ``raw`` as base58btc, no checksum.

    Matches ``@scure/base``'s ``base58.encode`` and the Go binary's
    inline encoder. Leading zero bytes map to leading '1' chars.
    """
    if not raw:
        return ""
    zeros = 0
    for b in raw:
        if b != 0:
            break
        zeros += 1

    # Convert big-endian bytes to base 58 via repeated division.
    num = int.from_bytes(raw, byteorder="big")
    digits: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        digits.append(_BASE58_ALPHABET[rem])
    digits.reverse()

    return "1" * zeros + "".join(digits)


# ── Keypair ───────────────────────────────────────────────────────────────


@dataclass
class CompositeKeyPair:
    """Composite keypair holding both halves + their public multibase forms.

    Layout matches the Node SDK's :class:`CompositeKeyPair` so PEM
    files written by either SDK are interchangeable.
    """

    ed25519_private_seed: bytearray  # 32 bytes — RFC 8032 § 3.2 seed
    ed25519_public_bytes: bytes  # 32 bytes — raw public key
    ed25519_multibase: str  # "z" + base58btc(public)

    mldsa65_private_bytes: bytearray
    mldsa65_public_bytes: bytes
    mldsa65_multibase: str

    # Internal: typed handles kept around for signing.
    _ed_private: Ed25519PrivateKey | None = field(repr=False, default=None)

    # ── Signing ─────────────────────────────────────────────────────────

    def sign_ed25519(self, payload: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over ``payload`` (RFC 8032)."""
        if self._ed_private is None:
            raise RuntimeError("keypair has been zeroized — cannot sign")
        return self._ed_private.sign(payload)

    def sign_mldsa65(self, payload: bytes) -> bytes:
        """Return the ML-DSA-65 (FIPS 204) signature over ``payload``.

        Hedged-randomness mode under pqcrypto — multiple calls with the
        same input produce different but equally valid signatures.
        That's fine: aria-core verifies, never compares.
        """
        if not self.mldsa65_private_bytes:
            raise RuntimeError("keypair has been zeroized — cannot sign")
        return ml_dsa_65.sign(bytes(self.mldsa65_private_bytes), payload)

    # ── Lifecycle ───────────────────────────────────────────────────────

    def zeroize(self) -> None:
        """Best-effort overwrite of the private buffers in place.

        Call after the keypair has been serialised to PEM and the file
        flushed. The Python GC may have moved the bytes elsewhere, but
        overwriting the original ``bytearray`` shortens the dwell time
        of the secret in process memory.
        """
        # bytearray supports in-place mutation; bytes does not, which is
        # why both private fields are typed as bytearray above.
        for i in range(len(self.ed25519_private_seed)):
            self.ed25519_private_seed[i] = 0
        for i in range(len(self.mldsa65_private_bytes)):
            self.mldsa65_private_bytes[i] = 0
        self._ed_private = None

    # ── Convenience accessors for the storage layer ─────────────────────

    def ed25519_pkcs8_pem(self) -> str:
        """Serialise the Ed25519 private key as a PKCS8 PEM string.

        Uses ``cryptography``'s built-in PEM emitter — produces the
        same RFC 8410 envelope the Node SDK and Go binary use, so the
        file is loadable by ``openssl pkey -in agent.pem`` and any
        PKCS8-aware tool.
        """
        if self._ed_private is None:
            raise RuntimeError("keypair has been zeroized — cannot serialize")
        pem_bytes = self._ed_private.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return pem_bytes.decode("ascii")


# ── Factory ───────────────────────────────────────────────────────────────


def generate_keypair() -> CompositeKeyPair:
    """Sample fresh randomness from the OS CSPRNG and return a new keypair.

    Performance — observed on an M1 MacBook Air:

    * Ed25519 keygen ~0.5 ms
    * ML-DSA-65 keygen ~3 ms

    Negligible relative to the wall clock of the enrollment flow
    (admin 2FA, AID signing on aria-core, network round-trips).
    """
    ed_private = Ed25519PrivateKey.generate()
    ed_seed = ed_private.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    ed_public_obj: Ed25519PublicKey = ed_private.public_key()
    ed_public = ed_public_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)

    mldsa_public, mldsa_private = ml_dsa_65.generate_keypair()

    return CompositeKeyPair(
        ed25519_private_seed=bytearray(ed_seed),
        ed25519_public_bytes=bytes(ed_public),
        ed25519_multibase="z" + _base58_encode(ed_public),
        mldsa65_private_bytes=bytearray(mldsa_private),
        mldsa65_public_bytes=bytes(mldsa_public),
        mldsa65_multibase="z" + _base58_encode(mldsa_public),
        _ed_private=ed_private,
    )
