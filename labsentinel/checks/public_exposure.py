"""Best-effort public exposure checks without external internet calls."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Set

from labsentinel.exceptions import ProxmoxApiError
from labsentinel.proxmox.client import ProxmoxClient

HEURISTIC_PUBLIC_BRIDGE_KEYWORDS = ("wan", "public", "dmz", "edge")


def _normalize_guest_id(guest: Dict[str, Any]) -> str:
    guest_id = guest.get("id")
    return str(guest_id) if guest_id is not None else "unknown"


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_link_local or ip.is_loopback or ip.is_private or ip.is_multicast or ip.is_unspecified:
        return False
    if getattr(ip, "is_reserved", False):
        return False
    return True


def _parse_ips_from_qemu_agent(payload: Any) -> List[str]:
    ips: List[str] = []
    if not isinstance(payload, list):
        return ips
    for iface in payload:
        if not isinstance(iface, dict):
            continue
        entries = iface.get("ip-addresses")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ip_text = str(entry.get("ip-address") or "").strip()
            if not ip_text:
                continue
            if ip_text.startswith("169.254.") or ip_text.lower().startswith("fe80:"):
                continue
            ips.append(ip_text)
    return ips


def check_public_exposure(
    client: ProxmoxClient,
    guests: List[Dict[str, Any]],
    *,
    public_bridges: Optional[List[str]] = None,
    guest_ip_map: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    explicit_public_bridges: Set[str] = {item.strip() for item in (public_bridges or []) if item.strip()}

    for guest in guests:
        guest_id = _normalize_guest_id(guest)
        guest_name = str(guest.get("name") or guest_id)
        guest_type = str(guest.get("type") or "").lower()
        guest_status = str(guest.get("status") or "").lower()
        nic_entries = [nic for nic in (guest.get("network_summary") or []) if isinstance(nic, dict)]

        explicit_hits: List[Dict[str, str]] = []
        heuristic_hits: List[Dict[str, str]] = []
        for nic in nic_entries:
            bridge = str(nic.get("bridge") or "")
            net_name = str(nic.get("net") or "net?")
            if not bridge:
                continue
            if bridge in explicit_public_bridges:
                explicit_hits.append({"bridge": bridge, "net": net_name})
            elif not explicit_public_bridges and any(keyword in bridge.lower() for keyword in HEURISTIC_PUBLIC_BRIDGE_KEYWORDS):
                heuristic_hits.append({"bridge": bridge, "net": net_name})

        if explicit_hits:
            hit = explicit_hits[0]
            findings.append(
                {
                    "id": f"PUBLIC_BRIDGE_GUEST_{guest_id}",
                    "severity": "CRITICAL",
                    "title": "Guest Attached to Declared Public Bridge",
                    "message": (
                        f"Guest NIC attached to public bridge '{hit['bridge']}' ({hit['net']}). "
                        "Confirm firewalling and exposure."
                    ),
                    "category": "Remote Exposure",
                    "impact": 70,
                }
            )
        elif heuristic_hits:
            hit = heuristic_hits[0]
            running = guest_status == "running"
            findings.append(
                {
                    "id": f"PUBLIC_BRIDGE_GUEST_{guest_id}",
                    "severity": "CRITICAL" if running else "WARNING",
                    "title": "Guest Attached to Suspected Public Bridge",
                    "message": (
                        f"Guest uses bridge '{hit['bridge']}' ({hit['net']}) which looks public-facing by name."
                    ),
                    "category": "Remote Exposure",
                    "impact": 50 if running else 20,
                }
            )

        if guest_type == "qemu":
            agent_enabled = bool(guest.get("agent_enabled"))
            if not agent_enabled:
                findings.append(
                    {
                        "id": f"GUEST_IP_UNKNOWN_{guest_id}",
                        "severity": "INFO",
                        "title": "Guest IP Unknown",
                        "message": f"Guest agent not enabled for {guest_name}; cannot determine guest IPs.",
                        "category": "Remote Exposure",
                        "impact": 0,
                    }
                )
                continue

            node = str(guest.get("node") or "")
            try:
                payload = client.get(f"/nodes/{node}/qemu/{guest_id}/agent/network-get-interfaces")
                ips = _parse_ips_from_qemu_agent(payload)
            except ProxmoxApiError:
                findings.append(
                    {
                        "id": f"GUEST_IP_UNKNOWN_{guest_id}",
                        "severity": "INFO",
                        "title": "Guest IP Unknown",
                        "message": f"Guest agent not available for {guest_name}; cannot determine guest IPs.",
                        "category": "Remote Exposure",
                        "impact": 0,
                    }
                )
                continue

            public_ips = [ip for ip in ips if _is_public_ip(ip)]
            if public_ips:
                findings.append(
                    {
                        "id": f"PUBLIC_IP_GUEST_{guest_id}",
                        "severity": "CRITICAL",
                        "title": "Public Guest IP Detected",
                        "message": f"Guest {guest_name} has public IP(s): {', '.join(public_ips[:3])}.",
                        "category": "Remote Exposure",
                        "impact": 70,
                    }
                )
            elif not ips:
                findings.append(
                    {
                        "id": f"GUEST_IP_UNKNOWN_{guest_id}",
                        "severity": "INFO",
                        "title": "Guest IP Unknown",
                        "message": f"No guest IPs returned by guest agent for {guest_name}.",
                        "category": "Remote Exposure",
                        "impact": 0,
                    }
                )
        elif guest_type == "lxc":
            mapped_ips = []
            if guest_ip_map is not None:
                mapped_ips = guest_ip_map.get(str(guest_id), [])
                if not isinstance(mapped_ips, list):
                    mapped_ips = []
            if guest_ip_map is None or not mapped_ips:
                findings.append(
                    {
                        "id": f"GUEST_IP_UNKNOWN_{guest_id}",
                        "severity": "INFO",
                        "title": "Guest IP Unknown",
                        "message": f"LXC guest IPs unknown for {guest_name}; provide --guest-ip-map to evaluate.",
                        "category": "Remote Exposure",
                        "impact": 0,
                    }
                )
            else:
                public_ips = [ip for ip in mapped_ips if isinstance(ip, str) and _is_public_ip(ip)]
                if public_ips:
                    findings.append(
                        {
                            "id": f"PUBLIC_IP_GUEST_{guest_id}",
                            "severity": "CRITICAL",
                            "title": "Public Guest IP Detected",
                            "message": f"Guest {guest_name} has public IP(s): {', '.join(public_ips[:3])}.",
                            "category": "Remote Exposure",
                            "impact": 70,
                        }
                    )

    return findings

