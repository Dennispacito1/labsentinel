"""Guest-level firewall checks for VM/CT network devices and rule presence."""

from __future__ import annotations

from typing import Any, Dict, List

from labsentinel.exceptions import ProxmoxApiError
from labsentinel.proxmox.client import ProxmoxClient


def _normalize_guest_id(guest: Dict[str, Any]) -> str:
    guest_id = guest.get("id")
    return str(guest_id) if guest_id is not None else "unknown"


def _rules_path(guest: Dict[str, Any]) -> str:
    guest_type = str(guest.get("type") or "").lower()
    node = str(guest.get("node") or "")
    guest_id = _normalize_guest_id(guest)
    if guest_type == "lxc":
        return f"/nodes/{node}/lxc/{guest_id}/firewall/rules"
    return f"/nodes/{node}/qemu/{guest_id}/firewall/rules"


def check_guest_firewall(client: ProxmoxClient, guests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for guest in guests:
        guest_id = _normalize_guest_id(guest)
        guest_name = str(guest.get("name") or guest_id)
        running = str(guest.get("status") or "").lower() == "running"
        nics = guest.get("network_summary", []) or []

        firewall_enabled_nics = 0
        for nic in nics:
            if not isinstance(nic, dict):
                continue
            net_name = str(nic.get("net") or "net?")
            nic_firewall = nic.get("firewall")
            if nic_firewall is True:
                firewall_enabled_nics += 1
            else:
                findings.append(
                    {
                        "id": f"GUEST_NIC_FIREWALL_DISABLED_{guest_id}_{net_name}",
                        "severity": "WARNING",
                        "title": "Guest NIC Firewall Flag Disabled",
                        "message": (
                            f"Guest network device firewall flag not enabled ({net_name}) on {guest_name}. "
                            "Proxmox firewall rules won't apply unless enabled per NIC."
                        ),
                        "category": "Network Segmentation",
                        "impact": 10,
                    }
                )

        if not running or firewall_enabled_nics == 0:
            continue

        path = _rules_path(guest)
        try:
            rules_data = client.get(path)
        except ProxmoxApiError:
            findings.append(
                {
                    "id": f"GUEST_FIREWALL_RULES_STATUS_UNKNOWN_{guest_id}",
                    "severity": "INFO",
                    "title": "Guest Firewall Rules Unknown",
                    "message": f"Unable to verify firewall rules for running guest {guest_name}.",
                    "category": "Network Segmentation",
                    "impact": 0,
                }
            )
            continue

        rules = rules_data if isinstance(rules_data, list) else []
        if not rules:
            findings.append(
                {
                    "id": f"GUEST_FIREWALL_RULES_EMPTY_{guest_id}",
                    "severity": "WARNING",
                    "title": "Guest Firewall Rules Missing",
                    "message": f"Running guest {guest_name} has firewall-enabled NICs but no firewall rules.",
                    "category": "Network Segmentation",
                    "impact": 10,
                }
            )
        else:
            findings.append(
                {
                    "id": f"GUEST_FIREWALL_RULES_PRESENT_{guest_id}",
                    "severity": "INFO",
                    "title": "Guest Firewall Rules Present",
                    "message": f"Firewall rules detected for running guest {guest_name}.",
                    "category": "Network Segmentation",
                    "impact": 0,
                }
            )

    return findings

