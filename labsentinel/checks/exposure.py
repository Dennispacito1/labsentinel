"""Authenticated Proxmox API exposure checks."""

from __future__ import annotations

from typing import Any, Dict, List

from labsentinel.exceptions import ProxmoxApiError, ProxmoxAuthError, ProxmoxConnectionError
from labsentinel.proxmox.client import ProxmoxClient


def check_api_exposure(client: ProxmoxClient) -> Dict[str, Any]:
    """Attempt authenticated Proxmox API access and return findings + version."""
    findings: List[Dict[str, str]] = []
    version: Dict[str, Any] = {}
    try:
        client.login()
        version_data = client.get("/version")
        if isinstance(version_data, dict):
            version = version_data
        findings.append(
            {
                "id": "PROXMOX_API_AUTHENTICATED",
                "severity": "INFO",
                "title": "Proxmox API Authenticated",
                "message": "Proxmox API is reachable and authentication succeeded.",
            }
        )
    except ProxmoxAuthError as exc:
        findings.append(
            {
                "id": "PROXMOX_API_AUTH_FAILED",
                "severity": "CRITICAL",
                "title": "Proxmox API Auth Failed",
                "message": f"{exc} Hint: try user@realm format or pass --realm/--otp.",
            }
        )
    except ProxmoxConnectionError as exc:
        findings.append(
            {
                "id": "PROXMOX_API_UNREACHABLE",
                "severity": "WARNING",
                "title": "Proxmox API Unreachable",
                "message": str(exc),
            }
        )
    except ProxmoxApiError as exc:
        findings.append(
            {
                "id": "PROXMOX_API_ERROR",
                "severity": "WARNING",
                "title": "Proxmox API Error",
                "message": str(exc),
            }
        )

    return {"findings": findings, "version": version}
