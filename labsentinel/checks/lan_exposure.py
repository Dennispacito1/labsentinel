"""LAN TCP port exposure checks for the Proxmox host."""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional

DEFAULT_LAN_PORTS = [22, 80, 443, 8006, 111, 2049, 445, 3389, 5900, 8080, 8443]


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_lan_ports(
    host: str, ports: Optional[List[int]] = None, timeout: float = 0.5
) -> List[Dict[str, Any]]:
    """Scan selected TCP ports on the target host from LAN perspective."""
    findings: List[Dict[str, Any]] = []
    scan_ports = ports if ports is not None else DEFAULT_LAN_PORTS

    for port in scan_ports:
        if not _is_open(host, port, timeout):
            continue

        if port == 8006:
            findings.append(
                {
                    "id": "LAN_PORT_8006_OPEN",
                    "severity": "INFO",
                    "title": "Proxmox API Port Open",
                    "message": (
                        "Proxmox UI/API reachable on LAN (8006). Ensure it is restricted to a management network/VLAN."
                    ),
                    "category": "Remote Exposure",
                    "impact": 0,
                }
            )
            continue

        if port in {22, 3389, 5900}:
            findings.append(
                {
                    "id": f"LAN_PORT_{port}_OPEN",
                    "severity": "WARNING",
                    "title": "Remote Admin Port Open",
                    "message": (
                        f"Remote admin port open on LAN ({port}). Ensure access is restricted "
                        "(firewall/VLAN/VPN) and hardened."
                    ),
                    "category": "Remote Exposure",
                    "impact": 5,
                }
            )
            continue

        if port in {445, 111, 2049}:
            findings.append(
                {
                    "id": f"LAN_PORT_{port}_OPEN",
                    "severity": "WARNING",
                    "title": "Storage/File Service Port Open",
                    "message": "File-sharing/storage port open on host. Verify necessity and restrict to storage network.",
                    "category": "Remote Exposure",
                    "impact": 5,
                }
            )
            continue

        findings.append(
            {
                "id": f"LAN_PORT_{port}_OPEN",
                "severity": "INFO",
                "title": "Service Port Open",
                "message": f"Service port open on LAN ({port}). Review necessity and network restrictions.",
                "category": "Remote Exposure",
                "impact": 0,
            }
        )

    return findings
