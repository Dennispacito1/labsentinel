"""Authentication hardening checks for Proxmox API mode."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from labsentinel.exceptions import ProxmoxApiError
from labsentinel.proxmox.client import ProxmoxClient


def _extract_realm(username: str, realm: Optional[str]) -> Optional[str]:
    if realm:
        return realm
    if "@" in username:
        return username.split("@", 1)[1]
    return None


def check_auth_hardening(
    client: ProxmoxClient, *, username: str, realm: Optional[str] = None
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    if username.lower().startswith("root@"):
        findings.append(
            {
                "id": "AUTH_ROOT_API_USER",
                "severity": "WARNING",
                "title": "Root API User in Use",
                "message": "Using root for API access; create a least-privilege scanner user.",
                "category": "Authentication Hardening",
                "impact": 15,
            }
        )
    else:
        findings.append(
            {
                "id": "AUTH_NON_ROOT_API_USER",
                "severity": "INFO",
                "title": "Non-root API User",
                "message": "API access is not using root.",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )

    selected_realm = _extract_realm(username, realm)
    try:
        domains = client.get("/access/domains")
    except ProxmoxApiError:
        findings.append(
            {
                "id": "AUTH_TFA_STATUS_UNKNOWN",
                "severity": "INFO",
                "title": "2FA Status Unknown",
                "message": "Unable to determine whether realm enforces TFA (unknown/defaults).",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )
        return findings

    realm_info: Optional[Dict[str, Any]] = None
    if isinstance(domains, list):
        for item in domains:
            if not isinstance(item, dict):
                continue
            domain_name = str(item.get("realm") or item.get("domain") or "")
            if selected_realm and domain_name == selected_realm:
                realm_info = item
                break

    if not realm_info:
        findings.append(
            {
                "id": "AUTH_TFA_STATUS_UNKNOWN",
                "severity": "INFO",
                "title": "2FA Status Unknown",
                "message": "Unable to determine whether realm enforces TFA (unknown/defaults).",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )
        return findings

    tfa_value = realm_info.get("tfa")
    if tfa_value in (None, "", 0, "0", False):
        findings.append(
            {
                "id": "AUTH_TFA_NOT_ENFORCED",
                "severity": "WARNING",
                "title": "2FA Enforcement Not Detected",
                "message": f"Realm '{selected_realm}' does not show enforced TFA in API data.",
                "category": "Authentication Hardening",
                "impact": 20,
            }
        )
    else:
        findings.append(
            {
                "id": "AUTH_TFA_DETECTED",
                "severity": "INFO",
                "title": "2FA Configuration Detected",
                "message": f"Realm '{selected_realm}' reports TFA-related configuration.",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )

    return findings

