"""Read-only backup posture checks via Proxmox API."""

from __future__ import annotations

from typing import Any, Dict, List

from labsentinel.exceptions import ProxmoxApiError
from labsentinel.proxmox.client import ProxmoxClient


def _job_display_name(job: Dict[str, Any], index: int) -> str:
    schedule = str(job.get("schedule", "")).strip()
    mode = str(job.get("mode", "")).strip()
    vmid = str(job.get("vmid", "")).strip()
    label_parts = [f"job #{index}"]
    if schedule:
        label_parts.append(f"schedule='{schedule}'")
    if mode:
        label_parts.append(f"mode='{mode}'")
    if vmid:
        label_parts.append(f"vmid='{vmid}'")
    return ", ".join(label_parts)


def check_backup_jobs(client: ProxmoxClient) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    path = "/cluster/backup"
    try:
        jobs = client.get(path)
    except ProxmoxApiError as exc:
        code = exc.status_code if exc.status_code is not None else "n/a"
        findings.append(
            {
                "id": "BACKUP_CONFIG_UNKNOWN",
                "severity": "INFO",
                "title": "Backup Configuration Unknown",
                "message": (
                    f"Backup config unknown via API (path '{exc.path or path}', HTTP {code})."
                ),
                "category": "Backup Protection",
                "impact": 0,
            }
        )
        return findings

    if not isinstance(jobs, list):
        findings.append(
            {
                "id": "BACKUP_CONFIG_UNKNOWN",
                "severity": "INFO",
                "title": "Backup Configuration Unknown",
                "message": (
                    f"Backup config unknown via API (path '{path}', unexpected response shape)."
                ),
                "category": "Backup Protection",
                "impact": 0,
            }
        )
        return findings

    if not jobs:
        findings.append(
            {
                "id": "BACKUP_JOBS_NONE",
                "severity": "WARNING",
                "title": "No Backup Jobs Detected",
                "message": (
                    "No scheduled cluster backup jobs (vzdump) detected. "
                    "Configure backups for running guests."
                ),
                "category": "Backup Protection",
                "impact": 60,
            }
        )
        return findings

    findings.append(
        {
            "id": "BACKUP_JOBS_PRESENT",
            "severity": "INFO",
            "title": "Backup Jobs Detected",
            "message": f"Detected {len(jobs)} scheduled cluster backup job(s).",
            "category": "Backup Protection",
            "impact": 0,
        }
    )

    jobs_missing_storage = [
        (idx, job)
        for idx, job in enumerate(jobs, start=1)
        if isinstance(job, dict) and not str(job.get("storage", "")).strip()
    ]
    if jobs_missing_storage:
        examples = ", ".join(
            _job_display_name(job, idx) for idx, job in jobs_missing_storage[:3]
        )
        findings.append(
            {
                "id": "BACKUP_JOB_STORAGE_MISSING",
                "severity": "WARNING",
                "title": "Backup Job Storage Not Set",
                "message": (
                    "One or more backup jobs have no explicit target storage configured. "
                    f"Examples: {examples}."
                ),
                "category": "Backup Protection",
                "impact": 20,
            }
        )
    else:
        findings.append(
            {
                "id": "BACKUP_JOB_STORAGE_CONFIGURED",
                "severity": "INFO",
                "title": "Backup Job Storage Configured",
                "message": "All detected backup jobs include a target storage.",
                "category": "Backup Protection",
                "impact": 0,
            }
        )

    return findings
