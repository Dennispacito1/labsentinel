"""Inventory discovery helpers using the Proxmox API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from labsentinel.exceptions import ProxmoxApiError
from labsentinel.proxmox.client import ProxmoxClient


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _parse_kv_blob(blob: str) -> Dict[str, str]:
    parts = [part.strip() for part in str(blob).split(",") if part.strip()]
    parsed: Dict[str, str] = {}
    for index, part in enumerate(parts):
        if "=" not in part:
            parsed[f"raw{index}"] = part
            continue
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _to_bool_flag(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


def parse_qemu_net(conf_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    nets: List[Dict[str, Any]] = []
    for key, value in conf_dict.items():
        if not str(key).startswith("net"):
            continue
        if value is None:
            continue
        raw = _parse_kv_blob(str(value))

        mac: Optional[str] = None
        for model in ("virtio", "e1000", "rtl8139", "vmxnet3"):
            if model in raw:
                mac = raw.get(model)
                break
        if mac is None and "raw0" in raw and "=" in raw["raw0"]:
            mac = raw["raw0"].split("=", 1)[1]

        nets.append(
            {
                "net": str(key),
                "bridge": raw.get("bridge"),
                "tag": raw.get("tag"),
                "firewall": _to_bool_flag(raw.get("firewall")),
                "mac": mac,
            }
        )
    return nets


def parse_lxc_net(conf_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    nets: List[Dict[str, Any]] = []
    for key, value in conf_dict.items():
        if not str(key).startswith("net"):
            continue
        if value is None:
            continue
        raw = _parse_kv_blob(str(value))
        nets.append(
            {
                "net": str(key),
                "bridge": raw.get("bridge"),
                "tag": raw.get("tag"),
                "firewall": _to_bool_flag(raw.get("firewall")),
                "hwaddr": raw.get("hwaddr"),
            }
        )
    return nets


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
    """Return normalized QEMU VM records with network summary."""
    raw_vms = _as_list(client.get(f"/nodes/{node}/qemu"))
    vms: List[Dict[str, Any]] = []
    for item in raw_vms:
        vmid = item.get("vmid")
        config: Dict[str, Any] = {}
        if vmid is not None:
            try:
                config_data = client.get(f"/nodes/{node}/qemu/{vmid}/config")
                if isinstance(config_data, dict):
                    config = config_data
            except ProxmoxApiError:
                config = {}
        agent_raw = str(config.get("agent", "")).strip().lower()
        agent_enabled = agent_raw in {"1", "yes", "on", "true"} or agent_raw.startswith("enabled=1")
        vms.append(
            {
                "node": node,
                "type": "qemu",
                "id": vmid,
                "name": item.get("name"),
                "status": item.get("status"),
                "network_summary": parse_qemu_net(config),
                "agent_enabled": agent_enabled,
            }
        )
    return vms


def list_lxc_cts(client: ProxmoxClient, node: str) -> List[Dict[str, Any]]:
    """Return normalized LXC container records with network summary."""
    raw_cts = _as_list(client.get(f"/nodes/{node}/lxc"))
    cts: List[Dict[str, Any]] = []
    for item in raw_cts:
        vmid = item.get("vmid")
        config: Dict[str, Any] = {}
        if vmid is not None:
            try:
                config_data = client.get(f"/nodes/{node}/lxc/{vmid}/config")
                if isinstance(config_data, dict):
                    config = config_data
            except ProxmoxApiError:
                config = {}
        cts.append(
            {
                "node": node,
                "type": "lxc",
                "id": vmid,
                "name": item.get("name"),
                "status": item.get("status"),
                "network_summary": parse_lxc_net(config),
            }
        )
    return cts
