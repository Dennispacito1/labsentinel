"""Inventory-based service exposure hints."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

KEYWORD_RULES: List[Tuple[Tuple[str, ...], str, int, str]] = [
    (
        ("proxy", "reverseproxy", "traefik", "nginx", "caddy"),
        "WARNING",
        5,
        "Reverse proxy detected; ensure TLS, auth, and WAF/rate limit if internet-facing.",
    ),
    (
        ("nextcloud",),
        "WARNING",
        5,
        "Nextcloud detected; ensure MFA, updates, backups, and restrict admin interfaces.",
    ),
    (
        ("jellyfin", "plex", "servarr", "radarr", "sonarr"),
        "INFO",
        0,
        "Media stack often exposed; verify access controls and no public admin panels.",
    ),
    (
        ("n8n",),
        "WARNING",
        5,
        "Automation platform detected; ensure auth, secrets management, and restrict editor access.",
    ),
    (
        ("cockpit",),
        "WARNING",
        5,
        "Cockpit admin panel detected; ensure it is not exposed beyond management network.",
    ),
    (
        ("dc", "domaincontroller", "ad", "dc01"),
        "INFO",
        0,
        "Directory services detected; ensure isolation and patch hygiene.",
    ),
]


def _normalize_guest(guest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": guest.get("id") or guest.get("vmid"),
        "name": str(guest.get("name") or ""),
        "status": str(guest.get("status") or ""),
    }


def check_service_hints(vms: List[Dict[str, Any]], cts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate service exposure hints from guest names."""
    findings: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()

    guests = [_normalize_guest(g) for g in (vms + cts)]
    running = [g for g in guests if g["status"].lower() == "running"]
    targets = running if running else [g for g in guests if g["name"]]

    for guest in targets:
        name = guest["name"].lower()
        guest_id = str(guest["id"]) if guest["id"] is not None else "unknown"

        if not name:
            continue

        for keywords, severity, impact, message in KEYWORD_RULES:
            if not any(keyword in name for keyword in keywords):
                continue

            finding_id = f"SERVICE_HINT_{keywords[0].upper()}_{guest_id}"
            if finding_id in seen_ids:
                continue
            seen_ids.add(finding_id)

            findings.append(
                {
                    "id": finding_id,
                    "severity": severity,
                    "title": "Service Exposure Hint",
                    "message": f"{message} Guest: {guest['name']} (id={guest_id}).",
                    "category": "Remote Exposure",
                    "impact": impact,
                }
            )

    return findings
