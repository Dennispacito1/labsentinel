"""Scan runner that orchestrates checks and scoring."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from labsentinel.checks.exposure import check_api_exposure
from labsentinel.checks.firewall import check_datacenter_firewall, check_node_firewall
from labsentinel.checks.lan_exposure import check_lan_ports
from labsentinel.checks.service_hints import check_service_hints
from labsentinel.checks.ssh import check_local_ssh_config
from labsentinel.proxmox.client import ProxmoxClient
from labsentinel.proxmox.discovery import list_lxc_cts, list_nodes, list_qemu_vms
from labsentinel.scoring import calculate_score


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
    }
    inventory: Dict[str, List[Dict[str, Any]]] = {"nodes": [], "vms": [], "cts": []}

    if normalized_mode == "local":
        findings.extend(check_local_ssh_config())
    elif normalized_mode == "api":
        if not host:
            raise ValueError("API mode requires --host.")
        if not user:
            raise ValueError("API mode requires --user.")
        if not password:
            raise ValueError("API mode requires --password.")

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

            findings.extend(check_service_hints(inventory["vms"], inventory["cts"]))

            if lan_scan:
                findings.extend(check_lan_ports(host=host, ports=lan_ports))

            if debug:
                meta_debug: Dict[str, Any] = {
                    "datacenter_firewall_options": dc_raw,
                    "node_firewall_options": debug_node_options,
                }
    else:
        raise ValueError("Mode must be 'local' or 'api'.")

    score = calculate_score(findings)
    result: Dict[str, Any] = {
        "mode": normalized_mode,
        "score": score,
        "findings": findings,
        "meta": meta,
        "inventory": inventory,
        "summary": {
            "nodes": len(inventory["nodes"]),
            "vms": len(inventory["vms"]),
            "cts": len(inventory["cts"]),
        },
    }
    if normalized_mode == "api" and debug:
        result["debug"] = meta_debug if "meta_debug" in locals() else {
            "datacenter_firewall_options": None,
            "node_firewall_options": {},
        }
    return result
