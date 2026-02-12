"""Checks that consume optional agent-provided host facts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def check_agent_facts(agent_facts: Dict[str, Any], *, update_stale_days: int = 14) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    updates = agent_facts.get("updates", {}) if isinstance(agent_facts, dict) else {}
    tls = agent_facts.get("tls", {}) if isinstance(agent_facts, dict) else {}
    zfs = agent_facts.get("zfs", {}) if isinstance(agent_facts, dict) else {}

    pending = updates.get("pending_updates_count")
    if isinstance(pending, int) and pending > 0:
        findings.append(
            {
                "id": "AGENT_UPDATES_PENDING",
                "severity": "WARNING",
                "title": "Pending OS Updates",
                "message": f"{pending} pending package updates detected on Proxmox host.",
                "category": "Update Hygiene",
                "impact": 40,
            }
        )
    else:
        findings.append(
            {
                "id": "AGENT_UPDATES_PENDING_NONE_OR_UNKNOWN",
                "severity": "INFO",
                "title": "Pending Updates Check",
                "message": "No pending package updates detected or unavailable from agent facts.",
                "category": "Update Hygiene",
                "impact": 0,
            }
        )

    last_update = _parse_timestamp(updates.get("last_apt_update"))
    if last_update is not None:
        age_days = (datetime.now(timezone.utc) - last_update).days
        if age_days > int(update_stale_days):
            findings.append(
                {
                    "id": "AGENT_APT_UPDATE_STALE",
                    "severity": "WARNING",
                    "title": "APT Metadata Stale",
                    "message": f"Last apt update is {age_days} days old (threshold: {update_stale_days}).",
                    "category": "Update Hygiene",
                    "impact": 30,
                }
            )
        else:
            findings.append(
                {
                    "id": "AGENT_APT_UPDATE_RECENT",
                    "severity": "INFO",
                    "title": "APT Metadata Fresh",
                    "message": f"Last apt update is {age_days} days old.",
                    "category": "Update Hygiene",
                    "impact": 0,
                }
            )
    else:
        findings.append(
            {
                "id": "AGENT_APT_UPDATE_TIMESTAMP_UNKNOWN",
                "severity": "INFO",
                "title": "APT Update Timestamp Unknown",
                "message": "Unable to determine last apt update timestamp from agent facts.",
                "category": "Update Hygiene",
                "impact": 0,
            }
        )

    self_signed = tls.get("self_signed")
    if self_signed is True:
        findings.append(
            {
                "id": "AGENT_TLS_SELF_SIGNED",
                "severity": "WARNING",
                "title": "Self-Signed TLS Certificate",
                "message": "Proxmox TLS certificate appears self-signed.",
                "category": "Authentication Hardening",
                "impact": 10,
            }
        )
    elif self_signed is False:
        findings.append(
            {
                "id": "AGENT_TLS_NOT_SELF_SIGNED",
                "severity": "INFO",
                "title": "TLS Certificate Chain Check",
                "message": "Proxmox TLS certificate does not appear self-signed.",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )
    else:
        findings.append(
            {
                "id": "AGENT_TLS_STATUS_UNKNOWN",
                "severity": "INFO",
                "title": "TLS Certificate Status Unknown",
                "message": "Unable to determine TLS self-signed status from agent facts.",
                "category": "Authentication Hardening",
                "impact": 0,
            }
        )

    zfs_present = zfs.get("present")
    any_encrypted = zfs.get("any_encrypted_dataset")
    if zfs_present is False:
        findings.append(
            {
                "id": "AGENT_ZFS_NOT_PRESENT",
                "severity": "INFO",
                "title": "ZFS Not Detected",
                "message": "ZFS not detected on this host.",
                "category": "Backup Protection",
                "impact": 0,
            }
        )
    elif zfs_present is True and any_encrypted is False:
        findings.append(
            {
                "id": "AGENT_ZFS_NOT_ENCRYPTED",
                "severity": "WARNING",
                "title": "ZFS Encryption Not Enabled",
                "message": "ZFS datasets detected but encryption appears disabled.",
                "category": "Backup Protection",
                "impact": 20,
            }
        )
    elif zfs_present is True and any_encrypted is True:
        findings.append(
            {
                "id": "AGENT_ZFS_ENCRYPTION_ENABLED",
                "severity": "INFO",
                "title": "ZFS Encryption Detected",
                "message": "At least one ZFS dataset reports encryption enabled.",
                "category": "Backup Protection",
                "impact": 0,
            }
        )
    else:
        findings.append(
            {
                "id": "AGENT_ZFS_STATUS_UNKNOWN",
                "severity": "INFO",
                "title": "ZFS Encryption Status Unknown",
                "message": "Unable to determine ZFS encryption status from agent facts.",
                "category": "Backup Protection",
                "impact": 0,
            }
        )

    return findings

