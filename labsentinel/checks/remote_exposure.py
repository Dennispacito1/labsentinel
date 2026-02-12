"""Remote exposure checks derived from LAN and optional WAN probes."""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional


def _tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_remote_exposure(
    lan_findings: List[Dict[str, Any]],
    *,
    wan_probe: bool = False,
    wan_target: Optional[str] = None,
    timeout: float = 1.0,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    open_lan_ids = {str(f.get("id", "")) for f in lan_findings}

    if "LAN_PORT_22_OPEN" in open_lan_ids:
        findings.append(
            {
                "id": "REMOTE_SSH_LAN_OPEN",
                "severity": "WARNING",
                "title": "SSH Exposed on LAN",
                "message": "SSH port 22 is open on LAN; restrict access and harden authentication.",
                "category": "Remote Exposure",
                "impact": 20,
            }
        )

    if "LAN_PORT_8006_OPEN" in open_lan_ids:
        findings.append(
            {
                "id": "REMOTE_PROXMOX_UI_LAN_OPEN",
                "severity": "INFO",
                "title": "Proxmox UI Reachable on LAN",
                "message": "Proxmox UI/API port 8006 is reachable on LAN.",
                "category": "Remote Exposure",
                "impact": 0,
            }
        )

    if wan_probe:
        if not wan_target:
            raise ValueError("WAN probe requires --wan-target.")

        note = " WAN probe result depends on vantage point."
        wan_8006 = _tcp_open(wan_target, 8006, timeout=timeout)
        wan_22 = _tcp_open(wan_target, 22, timeout=timeout)

        if wan_8006:
            findings.append(
                {
                    "id": "WAN_PORT_8006_REACHABLE",
                    "severity": "CRITICAL",
                    "title": "Proxmox UI Reachable from WAN Target",
                    "message": f"WAN target {wan_target}:8006 is reachable.{note}",
                    "category": "Remote Exposure",
                    "impact": 80,
                }
            )
        else:
            findings.append(
                {
                    "id": "WAN_PORT_8006_NOT_REACHABLE",
                    "severity": "INFO",
                    "title": "Proxmox UI Not Reachable from WAN Target",
                    "message": f"WAN target {wan_target}:8006 is not reachable.{note}",
                    "category": "Remote Exposure",
                    "impact": 0,
                }
            )

        if wan_22:
            findings.append(
                {
                    "id": "WAN_PORT_22_REACHABLE",
                    "severity": "CRITICAL",
                    "title": "SSH Reachable from WAN Target",
                    "message": f"WAN target {wan_target}:22 is reachable.{note}",
                    "category": "Remote Exposure",
                    "impact": 40,
                }
            )
        else:
            findings.append(
                {
                    "id": "WAN_PORT_22_NOT_REACHABLE",
                    "severity": "INFO",
                    "title": "SSH Not Reachable from WAN Target",
                    "message": f"WAN target {wan_target}:22 is not reachable.{note}",
                    "category": "Remote Exposure",
                    "impact": 0,
                }
            )

    return findings

