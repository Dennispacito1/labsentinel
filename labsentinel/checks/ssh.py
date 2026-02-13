"""Local SSH hardening checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")


def _strip_inline_comment(line: str) -> str:
    in_quotes = False
    escaped = False
    output: List[str] = []
    for char in line:
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            output.append(char)
            continue
        if char == '"':
            in_quotes = not in_quotes
            output.append(char)
            continue
        if char == "#" and not in_quotes:
            break
        output.append(char)
    return "".join(output).strip()


def _get_effective_value(config_text: str, key: str) -> Optional[str]:
    """Return the last effective value for a key in sshd_config."""
    value: Optional[str] = None
    for raw_line in config_text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0].lower() == key.lower():
            value = " ".join(parts[1:]).strip()
    return value


def check_local_ssh_config() -> List[Dict[str, Any]]:
    """Check local sshd_config for insecure SSH options."""
    findings: List[Dict[str, Any]] = []

    try:
        config_text = SSHD_CONFIG_PATH.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        # Future improvement: support distro-specific include paths and merged configs.
        findings.append(
            {
                "id": "SSH_CONFIG_MISSING",
                "severity": "WARNING",
                "title": "SSH Config Unavailable",
                "message": f"Could not read {SSHD_CONFIG_PATH}.",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )
        return findings
    except OSError as exc:
        findings.append(
            {
                "id": "SSH_CONFIG_READ_ERROR",
                "severity": "WARNING",
                "title": "SSH Config Read Error",
                "message": f"Failed to read {SSHD_CONFIG_PATH}: {exc}",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )
        return findings

    password_auth = (_get_effective_value(config_text, "PasswordAuthentication") or "").lower()
    permit_root_login = (_get_effective_value(config_text, "PermitRootLogin") or "").lower()
    pubkey_auth = (_get_effective_value(config_text, "PubkeyAuthentication") or "").lower()

    if password_auth == "yes":
        findings.append(
            {
                "id": "SSH_PASSWORD_AUTH_ENABLED",
                "severity": "CRITICAL",
                "title": "PasswordAuthentication Enabled",
                "message": "PasswordAuthentication is set to yes in sshd_config.",
                "category": "Authentication Hardening",
                "impact": 70,
            }
        )

    if permit_root_login == "yes":
        findings.append(
            {
                "id": "SSH_ROOT_LOGIN_ENABLED",
                "severity": "CRITICAL",
                "title": "PermitRootLogin Enabled",
                "message": "PermitRootLogin is set to yes in sshd_config.",
                "category": "Authentication Hardening",
                "impact": 70,
            }
        )
    elif permit_root_login in {"prohibit-password", "without-password"}:
        findings.append(
            {
                "id": "SSH_ROOT_LOGIN_KEY_ONLY",
                "severity": "WARNING",
                "title": "PermitRootLogin Allows Key-Only Root Login",
                "message": (
                    "PermitRootLogin is set to prohibit-password/without-password. "
                    "Consider disabling direct root SSH login."
                ),
                "category": "Authentication Hardening",
                "impact": 30,
            }
        )

    if pubkey_auth == "no":
        findings.append(
            {
                "id": "SSH_PUBKEY_AUTH_DISABLED",
                "severity": "CRITICAL",
                "title": "PubkeyAuthentication Disabled",
                "message": "PubkeyAuthentication is set to no in sshd_config.",
                "category": "Authentication Hardening",
                "impact": 70,
            }
        )

    return findings
