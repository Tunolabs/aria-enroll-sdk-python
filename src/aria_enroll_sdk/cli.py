"""``aria-enroll`` command-line entry point.

Two subcommands:

* ``aria-enroll scopes --token=…``  — list the catalog the registry will
  accept for this enrollment. Use this first to pick what the agent
  actually needs.
* ``aria-enroll enroll --token=… --name=… --scopes=A,B,C``  — run the
  full enrollment flow. Refuses to default to "all scopes" so the
  caller must enumerate explicitly.

All commands print a structured JSON payload to stdout (so callers
can pipe into ``jq``); progress logs go to stderr.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

import click

from aria_enroll_sdk import __version__
from aria_enroll_sdk.client import (
    DEFAULT_REGISTRY_URL,
    EnrollmentClient,
    EnrollmentHTTPError,
)
from aria_enroll_sdk.enroll import EnrollOptions, enroll


@click.group(help="aria-enroll — non-custodial agent enrollment for the ARIA Protocol.")
@click.version_option(__version__, "-V", "--version")
def main() -> None:
    """Top-level dispatcher (no flags at this level)."""


@main.command("scopes")
@click.option(
    "--token", required=True, help="22-char base64url magic token from the admin's enrollment portal."
)
@click.option(
    "--registry",
    default=DEFAULT_REGISTRY_URL,
    show_default=True,
    help="ARIA core base URL. Override for staging / dev.",
)
def scopes_cmd(token: str, registry: str) -> None:
    """Print the catalog of scopes the registry will accept for this enrollment."""
    try:
        with EnrollmentClient(registry, token) as client:
            catalog = client.get_scopes()
    except EnrollmentHTTPError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    click.echo(json.dumps(asdict(catalog), indent=2))


@main.command("enroll")
@click.option(
    "--token", required=True, help="22-char base64url magic token from the admin's enrollment portal."
)
@click.option(
    "--name",
    "agent_name",
    required=True,
    help="Human-readable agent name. 1-64 alphanumeric characters or hyphens.",
)
@click.option(
    "--scopes",
    required=True,
    help="Comma-separated subset of the registry's scope catalog (no default-to-all).",
)
@click.option(
    "--registry",
    default=DEFAULT_REGISTRY_URL,
    show_default=True,
    help="ARIA core base URL.",
)
@click.option(
    "--hitl",
    default="",
    help="Comma-separated subset of --scopes that requires human-in-the-loop approval at runtime.",
)
@click.option("--domain", default=None, help="Target FQDN for the DNS proof (L1+ orgs).")
@click.option(
    "--region",
    "region_hint",
    default=None,
    help="Optional region hint (e.g. 'aws:eu-west-1') surfaced to the admin in the review screen.",
)
@click.option(
    "--poll-timeout",
    default=30 * 60,
    show_default=True,
    type=int,
    help="Seconds to wait for the admin to confirm the OTP before giving up.",
)
def enroll_cmd(
    token: str,
    agent_name: str,
    scopes: str,
    registry: str,
    hitl: str,
    domain: str | None,
    region_hint: str | None,
    poll_timeout: int,
) -> None:
    """Run the full enrollment flow. Prints a JSON result on completion."""
    scope_list = _parse_list(scopes)
    hitl_list = _parse_list(hitl)
    if not scope_list:
        click.echo(
            "error: --scopes must be non-empty. Run `aria-enroll scopes --token=...` to discover the catalog.",
            err=True,
        )
        sys.exit(2)

    opts = EnrollOptions(
        token=token,
        agent_name=agent_name,
        scopes=scope_list,
        registry_url=registry,
        hitl=hitl_list,
        target_domain=domain,
        region_hint=region_hint,
        poll_timeout_seconds=float(poll_timeout),
    )

    try:
        click.echo("[aria-enroll] fetching catalog and generating keypair…", err=True)
        result = enroll(opts)
    except EnrollmentHTTPError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — surface CLI-friendly errors
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    payload = {
        "session_id": result.session_id,
        "status": result.status,
        "visual_hash": result.visual_hash,
        "manifest_hash": result.manifest_hash,
    }
    if result.aid_did:
        payload["aid_did"] = result.aid_did
    if result.credential_id:
        payload["credential_id"] = result.credential_id
    if result.pem_paths is not None:
        payload["pem"] = {
            "ed25519": str(result.pem_paths.ed25519_path),
            "mldsa65": str(result.pem_paths.mldsa65_path),
            "out_dir": str(result.pem_paths.out_dir),
        }
    click.echo(json.dumps(payload, indent=2))


def _parse_list(raw: str) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


if __name__ == "__main__":
    main()
