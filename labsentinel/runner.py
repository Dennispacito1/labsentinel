"""Scan runner that orchestrates checks and scoring."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from labsentinel.checks.agent_checks import check_agent_facts
from labsentinel.checks.auth_hardening import check_auth_hardening
from labsentinel.checks.exposure import check_api_exposure
from labsentinel.checks.firewall import check_datacenter_firewall, check_node_firewall
from labsentinel.checks.guest_firewall import check_guest_firewall
from labsentinel.checks.lan_exposure import check_lan_ports
from labsentinel.checks.network_segmentation import check_network_segmentation
from labsentinel.checks.public_exposure import check_public_exposure
from labsentinel.checks.remote_exposure import check_remote_exposure
from labsentinel.checks.service_hints import check_service_hints
from labsentinel.checks.ssh import check_local_ssh_config
from labsentinel.proxmox.client import ProxmoxClient
from labsentinel.proxmox.discovery import list_lxc_cts, list_nodes, list_qemu_vms
from labsentinel.scoring import CATEGORY_WEIGHTS, calculate_weighted_score


def _normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(finding)
    normalized.setdefault("id", "UNKNOWN_FINDING")
    normalized.setdefault("severity", "INFO")
    normalized.setdefault("title", "Finding")
    normalized.setdefault("message", "")

    category = str(normalized.get("category", "")).strip()
    if category not in CATEGORY_WEIGHTS:
        normalized["category"] = "Remote Exposure"

    impact = normalized.get("impact", 0)
    if not isinstance(impact, (int, float)):
        normalized["impact"] = 0
    else:
        normalized["impact"] = max(0, min(100, int(impact)))
    return normalized


def _network_inventory_summary(guests: List[Dict[str, Any]]) -> Dict[str, Any]:
    firewall_enabled_nics = 0
    vlan_tagged_nics = 0
    bridges_seen: set[str] = set()
    for guest in guests:
        for nic in guest.get("network_summary", []) or []:
            if not isinstance(nic, dict):
                continue
            if nic.get("firewall") is True:
                firewall_enabled_nics += 1
            tag = nic.get("tag")
            if tag not in (None, "", "0"):
                vlan_tagged_nics += 1
            bridge = nic.get("bridge")
            if bridge:
                bridges_seen.add(str(bridge))
    return {
        "num_firewall_enabled_nics": firewall_enabled_nics,
        "num_vlan_tagged_nics": vlan_tagged_nics,
        "bridges_seen": sorted(bridges_seen),
    }


def run_scan(
    mode: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    realm: Optional[str] = None,
    otp: Optional[str] = None,
    insecure: bool = False,
    timeout: int = 5,
    debug: bool = False,
    lan_scan: bool = True,
    lan_ports: Optional[List[int]] = None,
    mgmt_bridge: str = "vmbr0",
    wan_probe: bool = False,
    wan_target: Optional[str] = None,
    agent_facts: Optional[Dict[str, Any]] = None,
    update_stale_days: int = 14,
    public_bridges: Optional[List[str]] = None,
    guest_ip_map: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    """Run checks by mode and return a result payload."""
    normalized_mode = mode.strip().lower()
    findings: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {
        "mode": normalized_mode,
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": {},
        "debug": debug,
        "lan_scan": lan_scan,
        "mgmt_bridge": mgmt_bridge,
        "wan_probe": wan_probe,
        "wan_target": wan_target,
        "update_stale_days": update_stale_days,
        "public_bridges": public_bridges or [],
        "guest_ip_map_supplied": guest_ip_map is not None,
    }
    if agent_facts is not None:
        meta["agent_facts"] = agent_facts
    inventory: Dict[str, Any] = {"nodes": [], "vms": [], "cts": []}
    debug_payload: Dict[str, Any] = {"datacenter_firewall_options": None, "node_firewall_options": {}}

    if normalized_mode == "local":
        findings.extend(check_local_ssh_config())
    elif normalized_mode == "api":
        if not host:
            raise ValueError("API mode requires --host.")
        if not user:
            raise ValueError("API mode requires --user.")
        if not password:
            raise ValueError("API mode requires --password.")
        if wan_probe and not wan_target:
            raise ValueError("WAN probe requires --wan-target.")

        client = ProxmoxClient(
            host=host,
            user=user,
            password=password,
            realm=realm,
            otp=otp,
            verify_tls=not insecure,
            timeout=timeout,
        )
        exposure = check_api_exposure(client)
        findings.extend(exposure.get("findings", []))
        meta["version"] = exposure.get("version", {}) or {}

        auth_ok = any(f.get("id") == "PROXMOX_API_AUTHENTICATED" for f in findings)
        if auth_ok:
            findings.extend(check_auth_hardening(client, username=user, realm=realm))

            nodes = list_nodes(client)
            inventory["nodes"] = nodes

            dc_findings, dc_raw = check_datacenter_firewall(client)
            findings.extend(dc_findings)

            debug_node_options: Dict[str, Any] = {}
            for node in nodes:
                node_name = node.get("name")
                if not node_name:
                    continue
                inventory["vms"].extend(list_qemu_vms(client, str(node_name)))
                inventory["cts"].extend(list_lxc_cts(client, str(node_name)))
                node_findings, node_raw = check_node_firewall(client, str(node_name))
                findings.extend(node_findings)
                if debug:
                    debug_node_options[str(node_name)] = node_raw

            guests = list(inventory["vms"]) + list(inventory["cts"])
            findings.extend(check_network_segmentation(guests, mgmt_bridge=mgmt_bridge))
            findings.extend(check_guest_firewall(client, guests))
            findings.extend(check_service_hints(inventory["vms"], inventory["cts"]))
            findings.extend(
                check_public_exposure(
                    client,
                    guests,
                    public_bridges=public_bridges,
                    guest_ip_map=guest_ip_map,
                )
            )

            lan_findings: List[Dict[str, Any]] = []
            if lan_scan:
                lan_findings = check_lan_ports(host=host, ports=lan_ports)
                findings.extend(lan_findings)

            findings.extend(
                check_remote_exposure(
                    lan_findings=lan_findings,
                    wan_probe=wan_probe,
                    wan_target=wan_target,
                )
            )

            if debug:
                debug_payload = {
                    "datacenter_firewall_options": dc_raw,
                    "node_firewall_options": debug_node_options,
                }
    else:
        raise ValueError("Mode must be 'local' or 'api'.")

    if agent_facts is not None:
        findings.extend(check_agent_facts(agent_facts, update_stale_days=update_stale_days))

    normalized_findings = [_normalize_finding(item) for item in findings]
    scoring = calculate_weighted_score(normalized_findings)
    meta["scoring"] = {
        "weights": scoring["weights"],
        "category_health": scoring["category_health"],
        "category_score_contrib": scoring["category_score_contrib"],
    }

    guest_inventory = list(inventory.get("vms", [])) + list(inventory.get("cts", []))
    inventory["network_summary"] = _network_inventory_summary(guest_inventory)

    result: Dict[str, Any] = {
        "mode": normalized_mode,
        "score": scoring["score"],
        "findings": normalized_findings,
        "meta": meta,
        "inventory": inventory,
        "summary": {
            "nodes": len(inventory["nodes"]),
            "vms": len(inventory["vms"]),
            "cts": len(inventory["cts"]),
            "num_firewall_enabled_nics": inventory["network_summary"]["num_firewall_enabled_nics"],
            "num_vlan_tagged_nics": inventory["network_summary"]["num_vlan_tagged_nics"],
            "bridges_seen": inventory["network_summary"]["bridges_seen"],
        },
    }
    if normalized_mode == "api" and debug:
        result["debug"] = debug_payload
    return result

