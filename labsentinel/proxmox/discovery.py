"""Inventory discovery helpers using the Proxmox API."""

from __future__ import annotations

from typing import Any, Dict, List

from labsentinel.proxmox.client import ProxmoxClient


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def list_nodes(client: ProxmoxClient) -> List[Dict[str, Any]]:
    """Return normalized node records."""
    raw_nodes = _as_list(client.get("/nodes"))
    nodes: List[Dict[str, Any]] = []
    for item in raw_nodes:
        nodes.append(
            {
                "id": item.get("node") or item.get("id"),
                "name": item.get("node") or item.get("name"),
                "status": item.get("status"),
            }
        )
    return nodes


def list_qemu_vms(client: ProxmoxClient, node: str) -> List[Dict[str, Any]]:
    """Return normalized QEMU VM records for a node."""
    raw_vms = _as_list(client.get(f"/nodes/{node}/qemu"))
    vms: List[Dict[str, Any]] = []
    for item in raw_vms:
        vms.append(
            {
                "id": item.get("vmid"),
                "name": item.get("name"),
                "status": item.get("status"),
            }
        )
    return vms


def list_lxc_cts(client: ProxmoxClient, node: str) -> List[Dict[str, Any]]:
    """Return normalized LXC container records for a node."""
    raw_cts = _as_list(client.get(f"/nodes/{node}/lxc"))
    cts: List[Dict[str, Any]] = []
    for item in raw_cts:
        cts.append(
            {
                "id": item.get("vmid"),
                "name": item.get("name"),
                "status": item.get("status"),
            }
        )
    return cts

