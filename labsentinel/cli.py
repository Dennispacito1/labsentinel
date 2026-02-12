"""CLI entrypoint for LabSentinel."""

from __future__ import annotations

import json as json_lib
from typing import List, Optional

import typer

from labsentinel.runner import run_scan
from labsentinel import __version__
from labsentinel.ui import render_non_json_report

app = typer.Typer(
    help="Secure-by-default posture scanner for Proxmox home labs.",
    no_args_is_help=True,
)


def _parse_lan_ports(value: Optional[str]) -> Optional[List[int]]:
    if not value:
        return None
    parts = [item.strip() for item in value.split(",") if item.strip()]
    if not parts:
        return None
    parsed: List[int] = []
    for part in parts:
        try:
            port = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid port value '{part}' in --lan-ports.") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"Port '{port}' out of range in --lan-ports.")
        parsed.append(port)
    return parsed


@app.command("scan")
def scan(
    mode: str = typer.Option(
        ...,
        "--mode",
        "-m",
        help="Scan mode: local or api.",
        case_sensitive=False,
    ),
    host: Optional[str] = typer.Option(
        None,
        "--host",
        "-h",
        help="Proxmox host/IP for API mode.",
    ),
    user: Optional[str] = typer.Option(
        None,
        "--user",
        "-u",
        help="Proxmox username (supports user@realm).",
    ),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        "-p",
        help="Proxmox password.",
    ),
    realm: Optional[str] = typer.Option(
        None,
        "--realm",
        help="Optional Proxmox realm when --user does not include @realm.",
    ),
    otp: Optional[str] = typer.Option(
        None,
        "--otp",
        help="Optional one-time password (TOTP) for 2FA.",
    ),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="Skip TLS certificate verification for API requests.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "--json-output",
        help="Output structured JSON.",
    ),
    timeout: int = typer.Option(
        3,
        "--timeout",
        help="HTTP timeout in seconds for API checks.",
        min=1,
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Include additional API debug details in JSON output.",
    ),
    lan_scan: bool = typer.Option(
        True,
        "--lan-scan/--no-lan-scan",
        help="Enable/disable LAN port exposure scan in API mode.",
    ),
    lan_ports: Optional[str] = typer.Option(
        None,
        "--lan-ports",
        help="Comma-separated port list override for LAN scan (e.g. 22,80,443,8006).",
    ),
) -> None:
    """Run a LabSentinel scan."""
    try:
        parsed_lan_ports = _parse_lan_ports(lan_ports)
        result = run_scan(
            mode=mode,
            host=host,
            user=user,
            password=password,
            realm=realm,
            otp=otp,
            insecure=insecure,
            timeout=timeout,
            debug=debug,
            lan_scan=lan_scan,
            lan_ports=parsed_lan_ports,
        )
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    except Exception as exc:  # pragma: no cover - defensive handling
        typer.secho(f"Scan failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(json_lib.dumps(result, indent=2))
        return

    typer.echo(render_non_json_report(result, version=__version__))


if __name__ == "__main__":
    app()
