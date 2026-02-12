"""Local SSH hardening checks."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")


def _get_effective_value(config_text: str, key: str) -> Optional[str]:
    """Return the last effective value for a key in sshd_config."""
    value: Optional[str] = None
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0].lower() == key.lower():
            value = parts[1]
    return value


def check_local_ssh_config() -> List[Dict[str, str]]:
    """Check local sshd_config for insecure SSH options."""
    findings: List[Dict[str, str]] = []

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

    password_auth = _get_effective_value(config_text, "PasswordAuthentication")
    permit_root_login = _get_effective_value(config_text, "PermitRootLogin")

    if (password_auth or "").lower() == "yes":
        findings.append(
            {
                "id": "SSH_PASSWORD_AUTH_ENABLED",
                "severity": "CRITICAL",
                "title": "PasswordAuthentication Enabled",
                "message": "PasswordAuthentication is set to yes in sshd_config.",
                "category": "Authentication Hardening",
                "impact": 60,
            }
        )

    if (permit_root_login or "").lower() == "yes":
        findings.append(
            {
                "id": "SSH_ROOT_LOGIN_ENABLED",
                "severity": "CRITICAL",
                "title": "PermitRootLogin Enabled",
                "message": "PermitRootLogin is set to yes in sshd_config.",
                "category": "Authentication Hardening",
                "impact": 40,
            }
        )

    return findings
