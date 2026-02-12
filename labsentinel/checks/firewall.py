"""Read-only firewall posture checks via Proxmox API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from labsentinel.exceptions import ProxmoxApiError
from labsentinel.proxmox.client import ProxmoxClient


def _is_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", ""}
    return False


def _normalize_node_id(node_name: str) -> str:
    return (
        str(node_name)
        .replace(" ", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )


def _get_enable_value(options: Dict[str, Any]) -> Any:
    if "enable" in options:
        return options.get("enable")
    if "enabled" in options:
        return options.get("enabled")
    return None


def _firewall_check_failed_message(path: str, status_code: Any, details: str) -> str:
    code_text = status_code if status_code is not None else "n/a"
    if status_code in (401, 403):
        permission_hint = " Check API permissions for firewall option endpoints."
    else:
        permission_hint = ""
    return (
        f"Firewall check failed for path '{path}' (HTTP {code_text}). "
        f"Response: {details or 'no response body'}."
        f"{permission_hint}"
    )


def check_datacenter_firewall(client: ProxmoxClient) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    raw_options: Optional[Dict[str, Any]] = None
    path = "/cluster/firewall/options"
    try:
        options = client.get(path)
        if isinstance(options, dict):
            raw_options = options
        if not isinstance(options, dict):
            findings.append(
                {
                    "id": "FIREWALL_CHECK_FAILED_DATACENTER",
                    "severity": "WARNING",
                    "title": "Firewall Check Failed",
                    "message": _firewall_check_failed_message(path, 200, "invalid response shape"),
                    "impact": 0,
                }
            )
            return findings, raw_options

        enable_value = _get_enable_value(options)
        if enable_value is not None:
            enabled = _is_enabled(enable_value)
            if not enabled:
                findings.append(
                    {
                        "id": "FIREWALL_DATACENTER_DISABLED",
                        "severity": "CRITICAL",
                        "title": "Datacenter Firewall Disabled",
                        "message": "Proxmox datacenter firewall is disabled. Enable it to enforce host/guest rules.",
                        "impact": 10,
                    }
                )
            else:
                findings.append(
                    {
                        "id": "FIREWALL_DATACENTER_ENABLED",
                        "severity": "INFO",
                        "title": "Datacenter Firewall Enabled",
                        "message": "Datacenter firewall is enabled.",
                        "impact": 0,
                    }
                )
            return findings, raw_options

        findings.append(
            {
                "id": "FIREWALL_DATACENTER_STATUS_UNKNOWN",
                "severity": "INFO",
                "title": "Datacenter Firewall Status Unknown",
                "message": (
                    "Firewall options are not explicitly set (defaults in effect). "
                    "Unable to determine if firewall is enabled via API. "
                    "Verify in Proxmox UI: Datacenter -> Firewall."
                ),
                "impact": 0,
            }
        )
    except ProxmoxApiError as exc:
        findings.append(
            {
                "id": "FIREWALL_CHECK_FAILED_DATACENTER",
                "severity": "WARNING",
                "title": "Firewall Check Failed",
                "message": _firewall_check_failed_message(exc.path or path, exc.status_code, exc.details),
                "impact": 0,
            }
        )
    return findings, raw_options


def check_node_firewall(
    client: ProxmoxClient, node_name: str
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    raw_options: Optional[Dict[str, Any]] = None
    path = f"/nodes/{node_name}/firewall/options"
    normalized_node = _normalize_node_id(node_name)
    try:
        options = client.get(path)
        if isinstance(options, dict):
            raw_options = options
        if not isinstance(options, dict):
            findings.append(
                {
                    "id": f"FIREWALL_CHECK_FAILED_NODE_{normalized_node}",
                    "severity": "WARNING",
                    "title": "Firewall Check Failed",
                    "message": _firewall_check_failed_message(path, 200, "invalid response shape"),
                    "impact": 0,
                }
            )
            return findings, raw_options

        enable_value = _get_enable_value(options)
        if enable_value is not None:
            enabled = _is_enabled(enable_value)
            if not enabled:
                findings.append(
                    {
                        "id": f"FIREWALL_NODE_DISABLED_{normalized_node}",
                        "severity": "CRITICAL",
                        "title": "Node Firewall Disabled",
                        "message": f"Firewall is disabled on node '{node_name}'. Enable to apply rules on this node.",
                        "impact": 10,
                    }
                )
            else:
                findings.append(
                    {
                        "id": f"FIREWALL_NODE_ENABLED_{normalized_node}",
                        "severity": "INFO",
                        "title": "Node Firewall Enabled",
                        "message": f"Firewall is enabled on node '{node_name}'.",
                        "impact": 0,
                    }
                )
            return findings, raw_options

        findings.append(
            {
                "id": f"FIREWALL_NODE_STATUS_UNKNOWN_{normalized_node}",
                "severity": "INFO",
                "title": "Node Firewall Status Unknown",
                "message": (
                    "Firewall options are not explicitly set (defaults in effect). "
                    "Unable to determine if firewall is enabled via API. "
                    f"Verify in Proxmox UI: Node '{node_name}' -> Firewall."
                ),
                "impact": 0,
            }
        )
    except ProxmoxApiError as exc:
        findings.append(
            {
                "id": f"FIREWALL_CHECK_FAILED_NODE_{normalized_node}",
                "severity": "WARNING",
                "title": "Firewall Check Failed",
                "message": _firewall_check_failed_message(exc.path or path, exc.status_code, exc.details),
                "impact": 0,
            }
        )
    return findings, raw_options
