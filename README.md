# `aria-enroll-sdk` (Python)

`aria-enroll-sdk` — non-custodial agent enrollment for the ARIA Protocol from Python.

Generates a composite ML-DSA-65 + Ed25519 keypair on the agent's machine, builds and self-signs the enrollment manifest conforming to the ARIA v1.2 schema, and submits it to a registry. **The registry never sees the private key.**

Built and maintained by **[Tunolabs](https://tunolabs.com)**. The ARIA Protocol — the AID contract, schemas, and canonical format — is an open standard governed by the **TrustLayer Foundation A.C.** (CC-BY-4.0, see [aria.bar/spec](https://aria.bar/spec)). Enrollment is Tunolabs' implementation on top of that contract; the spec defines the AID, not how you produce it. Tunolabs does not modify the contract — these SDKs emit manifests that conform to the published ARIA v1.2 schema. Any registry implementing ARIA v1.2 can verify them; the reference deployment we run is [registry.aria.bar](https://registry.aria.bar).

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/aria-enroll-sdk)](https://pypi.org/project/aria-enroll-sdk/)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.10-brightgreen)](https://www.python.org/)

---

## Install

```sh
pip install aria-enroll-sdk
```

Requires Python 3.10 or later.

The package depends on:
- `cryptography` — Ed25519 keygen, signing, and PKCS8 PEM serialisation
- `pqcrypto` — ML-DSA-65 (FIPS 204) via Open Quantum Safe bindings. Wheels include `liboqs` precompiled for `linux` / `macos` / `win` × `amd64` / `arm64`.
- `httpx` — sync and async HTTP client
- `click` — CLI ergonomics

## Library

Synchronous:

```python
from aria_enroll_sdk import enroll, EnrollOptions

result = enroll(EnrollOptions(
    token="<22-char base64url magic token>",
    agent_name="ordering-agent",
    scopes=["commerce:catalog:read", "commerce:order:write"],
    registry_url="https://core.aria.bar",
))
print(result.aid_did)
```

Asynchronous (for asyncio-based agent frameworks — LangGraph, FastAPI bots, asyncio worker pools):

```python
import asyncio
from aria_enroll_sdk import aenroll, EnrollOptions

async def main() -> None:
    result = await aenroll(EnrollOptions(
        token="<22-char base64url magic token>",
        agent_name="ordering-agent",
        scopes=["commerce:catalog:read", "commerce:order:write"],
        registry_url="https://core.aria.bar",
    ))
    print(result.aid_did)

asyncio.run(main())
```

## CLI

The package installs an `aria-enroll` binary.

```sh
# 1. Discover the catalog of scopes the registry will accept for this magic token.
aria-enroll scopes --token=<MAGIC_TOKEN> --registry=https://core.aria.bar

# 2. Enroll the agent with an explicit scope subset (no default-to-all).
aria-enroll enroll \
    --token=<MAGIC_TOKEN> \
    --name=ordering-agent \
    --scopes=commerce:catalog:read,commerce:order:write \
    --registry=https://core.aria.bar
```

On success:
- The Ed25519 private key lands in `~/.aria/agents/<name>.pem` (PKCS8, loadable by `openssl pkey`).
- The ML-DSA-65 private key lands in `~/.aria/agents/<name>.mldsa65.pem` (custom ARIA-labelled PEM block).
- File permissions are `0o600`.

## When to use this SDK vs. its siblings

Tunolabs publishes three implementations of the ARIA v1.2 enrollment client. Pick by runtime, not by capability — they are functionally identical:

- **This package** (`aria-enroll-sdk`) — for agents written in Python (incl. LangGraph, FastAPI bots, asyncio worker pools). Exposes both sync `enroll()` and async `aenroll()` and an `aria-enroll` CLI for one-shot scripts.
- [`@aria-registry/enroll-sdk-node`](https://github.com/Tunolabs/aria-enroll-sdk-node) (TypeScript) — for agents that run in Node.js or Bun. Same flow, ESM-first.
- [`aria-enroll-bootstrap`](https://github.com/Tunolabs/aria-enroll-bootstrap) (Go binary) — for environments without Python or Node — CI runners, scratch / distroless containers, minimal VMs, embedded devices. A single statically-linked binary, ~6 MB.

Because the ARIA v1.2 schema defines a single canonical output, the three implementations are byte-for-byte interchangeable — any conforming client produces an identical manifest. The golden vectors in `tests/testdata/golden-vectors.json` verify that this implementation conforms to the ARIA v1.2 canonical format defined by TLF; they are conformance fixtures, not a Tunolabs-defined format.

## Non-custodial guarantee

- The composite keypair is generated on the agent's machine using OS randomness via Python's `secrets` module (transitively, through `cryptography` and `pqcrypto`).
- Both private halves are written to disk **only** at the end of a successful enrollment, with `0o600` permissions, and zeroised in memory before the function returns.
- The registry receives only the public halves embedded in the signed manifest. It signs the issued AID with its **own** composite keypair (a different key entirely) and stores no private agent material.
- A leaked AID is not sufficient to impersonate the agent without the holder secret — this is the cryptographic binding introduced in ARIA Protocol v1.2.

## How the flow works

```
1. POST /v1/enrollment/request        ← human (or API) requests an enrollment slot
                                         registry issues a magic token (one-shot, 15 min)
2. SDK fetches /v1/enrollment/scopes  ← discover what scopes are eligible
3. SDK generates composite keypair    ← LOCAL: Ed25519 + ML-DSA-65, never leaves the machine
4. SDK builds the manifest             ← JCS-canonical JSON, identity commitment over the manifest
5. SDK self-signs                      ← BOTH halves of the composite key sign the manifest
6. POST /v1/enrollment/submit          ← carries the magic token; registry validates 10-step sequence
7. Admin confirms with email OTP       ← out-of-band 2FA on the human side
8. Registry mints AID v1.2             ← embedded holderKey is the public key we generated in step 3
```

This SDK handles steps 2 through 6 and polls until the issuance completes.

## Specification & related work

- ARIA Protocol v1.2 specification (TLF): <https://aria.bar/spec>
- Verifier SDK (offline AID verification, separate work): [`@aria-registry/verify`](https://www.npmjs.com/package/@aria-registry/verify)
- Node sibling: [`@aria-registry/enroll-sdk-node`](https://github.com/Tunolabs/aria-enroll-sdk-node) — same Tunolabs implementation, Node / Bun runtime.
- Go binary sibling: [`aria-enroll-bootstrap`](https://github.com/Tunolabs/aria-enroll-bootstrap) — same Tunolabs implementation, statically-linked binary.

## License

Apache 2.0 — see [LICENSE](LICENSE). Copyright Tunolabs.

The ARIA Protocol specification it implements is published by the TrustLayer Foundation A.C. under CC-BY-4.0.
