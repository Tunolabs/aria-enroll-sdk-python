"""Canonical JSON serialisation — byte-identical to the TS SDKs' canonicalJson().

aria-core's manifest validator recomputes ``identity_commitment`` from
the manifest's canonical JSON server-side and rejects any divergence,
so this module's output MUST match the TS SDKs' down to the last byte.
The fixture ``tests/testdata/golden-vectors.json`` is the contract;
running pytest after any edit catches drift immediately.

The rule is simple: sort object keys lexicographically at every level,
emit values without whitespace, never HTML-escape, never \\uXXXX-encode
non-ASCII. The manifest only contains strings, string lists, and
nested objects — no numbers / booleans / nulls — so the simplified
"sort keys" canonicalisation is sufficient. If a future manifest
revision introduces numeric fields, this module must move to a full
RFC 8785 JCS implementation.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialise ``value`` to canonical JSON.

    Object keys are sorted lexicographically at every level. Output has
    no whitespace separators and no HTML-escape escaping. Non-ASCII
    characters are emitted verbatim (matches JavaScript's
    ``JSON.stringify`` default behavior — the TS SDKs rely on this).
    """
    return json.dumps(
        value,
        sort_keys=True,
        # JSON.stringify in JavaScript emits no whitespace by default;
        # Python's json.dumps adds spaces unless overridden.
        separators=(",", ":"),
        # Python's json defaults to ASCII-only output (escapes non-ASCII
        # as \\uXXXX). JavaScript's JSON.stringify does NOT. The
        # manifest values are all ASCII today, but we set this flag so
        # the rule still holds if someone adds a non-ASCII string.
        ensure_ascii=False,
        # Python doesn't HTML-escape by default; nothing to disable.
    )
