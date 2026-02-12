"""Network segmentation posture checks."""

from __future__ import annotations

from typing import Any, Dict, List, Set


def _iter_nics(guests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nics: List[Dict[str, Any]] = []
    for guest in guests:
        for nic in guest.get("network_summary", []) or []:
            if not isinstance(nic, dict):
                continue
            nics.append(
                {
                    "guest_id": guest.get("id"),
                    "guest_name": guest.get("name"),
                    "net": nic.get("net"),
                    "bridge": nic.get("bridge"),
                    "tag": nic.get("tag"),
                    "firewall": nic.get("firewall"),
                }
            )
    return nics


def check_network_segmentation(guests: List[Dict[str, Any]], mgmt_bridge: str = "vmbr0") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    nics = _iter_nics(guests)
    bridges: Set[str] = {str(nic.get("bridge")) for nic in nics if nic.get("bridge")}
    has_vlan = any(nic.get("tag") not in (None, "", "0") for nic in nics)

    if nics and not has_vlan and len(bridges) <= 1:
        findings.append(
            {
                "id": "NETWORK_SEGMENTATION_NO_VLAN_SINGLE_BRIDGE",
                "severity": "WARNING",
                "title": "Limited Network Segmentation",
                "message": (
                    "No VLAN tagging detected and single bridge in use; "
                    "consider segmenting management/services."
                ),
                "category": "Network Segmentation",
                "impact": 25,
            }
        )
    else:
        findings.append(
            {
                "id": "NETWORK_SEGMENTATION_VLAN_PRESENT",
                "severity": "INFO",
                "title": "VLAN Tags Detected",
                "message": "VLAN tagging detected in guest network configuration.",
                "category": "Network Segmentation",
                "impact": 0,
            }
        )

    mgmt_hits = [nic for nic in nics if str(nic.get("bridge") or "") == mgmt_bridge]
    if mgmt_hits:
        findings.append(
            {
                "id": "NETWORK_SEGMENTATION_MGMT_BRIDGE_SHARED",
                "severity": "WARNING",
                "title": "Management Bridge Shared",
                "message": (
                    f"Guest NICs detected on management bridge '{mgmt_bridge}'. "
                    "Separate management traffic from workload networks."
                ),
                "category": "Network Segmentation",
                "impact": 15,
            }
        )
    else:
        findings.append(
            {
                "id": "NETWORK_SEGMENTATION_MGMT_BRIDGE_ISOLATED",
                "severity": "INFO",
                "title": "Management Bridge Isolation",
                "message": f"No guest NICs were detected on management bridge '{mgmt_bridge}'.",
                "category": "Network Segmentation",
                "impact": 0,
            }
        )

    return findings

