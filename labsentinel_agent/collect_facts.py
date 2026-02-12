#!/usr/bin/env python3
"""Collect local host facts for LabSentinel (manual, read-only)."""

from __future__ import annotations

import datetime as dt
import json
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _run(cmd: List[str]) -> Optional[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _iso_from_mtime(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    try:
        ts = path.stat().st_mtime
    except OSError:
        return None
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()


def _collect_updates() -> Dict[str, Any]:
    pending_updates_count: Optional[int] = None
    sim = _run(["apt-get", "-s", "upgrade"])
    if sim is not None:
        pending_updates_count = sum(1 for line in sim.splitlines() if line.startswith("Inst "))

    last_apt_update = _iso_from_mtime(Path("/var/lib/apt/periodic/update-success-stamp"))

    last_apt_upgrade: Optional[str] = None
    history = Path("/var/log/apt/history.log")
    if history.exists():
        try:
            content = history.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            content = ""
        lines = [line.strip() for line in content.splitlines() if line.strip().startswith("End-Date:")]
        if lines:
            # End-Date: 2026-02-08  20:50:44
            last_apt_upgrade = lines[-1].split("End-Date:", 1)[1].strip()

    return {
        "pending_updates_count": pending_updates_count,
        "last_apt_update": last_apt_update,
        "last_apt_upgrade": last_apt_upgrade,
    }


def _collect_tls() -> Dict[str, Any]:
    cert_candidates = [
        Path("/etc/pve/local/pveproxy-ssl.pem"),
        Path("/etc/pve/pveproxy-ssl.pem"),
        Path("/etc/pve/local/pve-ssl.pem"),
    ]
    cert_path = next((p for p in cert_candidates if p.exists()), None)

    data: Dict[str, Any] = {
        "cert_path": str(cert_path) if cert_path else None,
        "self_signed": None,
        "not_after": None,
        "subject": None,
        "issuer": None,
        "fingerprint": None,
    }
    if cert_path is None:
        return data

    if shutil.which("openssl") is None:
        return data

    output = _run(
        [
            "openssl",
            "x509",
            "-in",
            str(cert_path),
            "-noout",
            "-subject",
            "-issuer",
            "-dates",
            "-fingerprint",
        ]
    )
    if output is None:
        return data

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            data["subject"] = line.split("subject=", 1)[1].strip()
        elif line.startswith("issuer="):
            data["issuer"] = line.split("issuer=", 1)[1].strip()
        elif line.startswith("notAfter="):
            data["not_after"] = line.split("notAfter=", 1)[1].strip()
        elif "Fingerprint=" in line:
            data["fingerprint"] = line.split("Fingerprint=", 1)[1].strip()

    if data["subject"] is not None and data["issuer"] is not None:
        data["self_signed"] = data["subject"] == data["issuer"]

    return data


def _collect_zfs() -> Dict[str, Any]:
    if shutil.which("zfs") is None:
        return {"present": False, "any_encrypted_dataset": None}

    output = _run(
        [
            "zfs",
            "get",
            "-H",
            "-o",
            "name,property,value",
            "encryption",
            "-t",
            "filesystem,volume",
        ]
    )
    if output is None:
        return {"present": True, "any_encrypted_dataset": None}

    any_encrypted = False
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            parts = line.split()
            if len(parts) < 3:
                continue
            value = parts[2]
        else:
            value = parts[2]
        if str(value).strip().lower() not in {"off", "-", ""}:
            any_encrypted = True
            break

    return {"present": True, "any_encrypted_dataset": any_encrypted}


def _host_info() -> Dict[str, Any]:
    pve_version = _run(["pveversion", "-v"])
    if pve_version:
        pve_version = pve_version.splitlines()[0]
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "pve_version": pve_version,
    }


def main() -> None:
    payload = {
        "agent_version": "0.1",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": _host_info(),
        "updates": _collect_updates(),
        "tls": _collect_tls(),
        "zfs": _collect_zfs(),
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
