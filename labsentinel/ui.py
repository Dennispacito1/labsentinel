"""Terminal presentation helpers for LabSentinel."""

from __future__ import annotations

import textwrap
from typing import Any, Dict, Iterable, List, Set, Tuple

from labsentinel.scoring import CATEGORY_WEIGHTS

LINE_WIDTH = 90


def classify_risk(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 65:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"


def _wrap(text: str, *, initial: str = "", subsequent: str = "") -> str:
    return textwrap.fill(
        text.strip(),
        width=LINE_WIDTH,
        initial_indent=initial,
        subsequent_indent=subsequent,
        break_long_words=False,
    )


def _compact_guest_ref(message: str) -> str:
    message = message.replace("(id=", "(ID ")
    message = message.replace(").", ").")
    return message


def format_finding_line(finding: Dict[str, Any]) -> str:
    title = str(finding.get("title", "Finding")).strip()
    message = _compact_guest_ref(str(finding.get("message", "")).strip())
    if title == "Service Exposure Hint":
        text = message
    else:
        text = f"{title}: {message}" if message else title
    return _wrap(text, initial="- ", subsequent="  ")


def _finding_weighted_loss(finding: Dict[str, Any], weights: Dict[str, int]) -> float:
    impact = finding.get("impact", 0)
    if not isinstance(impact, (int, float)):
        return 0.0
    category = str(finding.get("category", ""))
    weight = float(weights.get(category, 0))
    return float(impact) * (weight / 100.0)


def _top_risks(findings: List[Dict[str, Any]], weights: Dict[str, int]) -> List[Dict[str, Any]]:
    scored = [f for f in findings if isinstance(f.get("impact"), (int, float)) and int(f["impact"]) > 0]
    return sorted(
        scored,
        key=lambda item: (-_finding_weighted_loss(item, weights), -int(item.get("impact", 0)), str(item.get("id", ""))),
    )[:3]


def _has_prefix(ids: Set[str], prefix: str) -> bool:
    return any(item.startswith(prefix) for item in ids)


def _has_any(ids: Set[str], exact_ids: Iterable[str]) -> bool:
    exact = set(exact_ids)
    return any(item in exact for item in ids)


def derive_next_steps(findings: List[Dict[str, Any]], max_steps: int = 5) -> List[str]:
    ids = {str(f.get("id", "")) for f in findings}
    critical_ids = {str(f.get("id", "")) for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"}

    rules: List[Tuple[int, bool, str]] = [
        (
            1,
            _has_prefix(ids, "FIREWALL_DATACENTER_DISABLED") or _has_prefix(ids, "FIREWALL_NODE_DISABLED_"),
            "Enable Proxmox firewall controls (datacenter and nodes) and apply baseline deny rules.",
        ),
        (
            2,
            _has_any(ids, {"LAN_PORT_22_OPEN"}),
            "Restrict SSH (22) to mgmt VLAN/VPN; disable password auth.",
        ),
        (
            2,
            _has_any(ids, {"LAN_PORT_3389_OPEN", "LAN_PORT_5900_OPEN"}),
            "Restrict remote admin ports (RDP/VNC) to management paths only.",
        ),
        (
            3,
            _has_any(ids, {"LAN_PORT_111_OPEN", "LAN_PORT_2049_OPEN", "LAN_PORT_445_OPEN"}),
            "Investigate rpcbind/NFS/SMB exposure; keep storage protocols on isolated networks.",
        ),
        (
            3,
            _has_prefix(ids, "SERVICE_HINT_PROXY_"),
            "Ensure reverse proxy enforces TLS + auth; consider rate limiting.",
        ),
        (
            3,
            _has_prefix(ids, "SERVICE_HINT_N8N_"),
            "Lock down n8n editor access, isolate workloads, and rotate secrets.",
        ),
        (
            4,
            _has_prefix(ids, "FIREWALL_DATACENTER_STATUS_UNKNOWN")
            or _has_prefix(ids, "FIREWALL_NODE_STATUS_UNKNOWN_"),
            "Verify Proxmox firewall settings in UI (Datacenter/Node) where API defaults are not explicit.",
        ),
        (
            4,
            _has_any(ids, {"LAN_PORT_8006_OPEN"}),
            "Keep Proxmox UI/API (8006) on a dedicated management network/VLAN.",
        ),
    ]

    prioritized: List[Tuple[int, str]] = []
    for priority, matched, step in rules:
        if matched:
            prioritized.append((priority, step))

    # Prefer steps tied to current critical findings.
    prioritized.sort(key=lambda item: (item[0], item[1]))
    ordered_steps: List[str] = []
    seen: Set[str] = set()
    for _, step in prioritized:
        if step in seen:
            continue
        seen.add(step)
        ordered_steps.append(step)
        if len(ordered_steps) >= max_steps:
            break

    if not ordered_steps and critical_ids:
        ordered_steps.append("Address critical findings first, then reassess network exposure controls.")

    return ordered_steps


def render_non_json_report(result: Dict[str, Any], version: str) -> str:
    score = int(result.get("score", 0))
    findings: List[Dict[str, Any]] = list(result.get("findings", []))
    risk = classify_risk(score)
    scoring_meta = result.get("meta", {}).get("scoring", {})
    weights = scoring_meta.get("weights", CATEGORY_WEIGHTS)
    category_health = scoring_meta.get("category_health", {})
    category_contrib = scoring_meta.get("category_score_contrib", {})
    top = _top_risks(findings, weights)
    top_ids = {str(item.get("id", "")) for item in top}

    version_label = version
    if version.count(".") == 2 and version.endswith(".0"):
        version_label = version.rsplit(".", 1)[0]

    lines: List[str] = []
    lines.append(f"LabSentinel v{version_label}")
    lines.append("=" * 64)
    lines.append(f"Score: {score}/100")
    lines.append(f"Risk Level: {risk}")
    lines.append("=" * 64)
    lines.append("Category Breakdown")
    for category in CATEGORY_WEIGHTS:
        health = float(category_health.get(category, 100.0))
        contrib = float(category_contrib.get(category, 0.0))
        weight = int(weights.get(category, CATEGORY_WEIGHTS[category]))
        lines.append(
            _wrap(
                f"{category}: health {health:.1f}/100, weight {weight}, score contrib {contrib:.2f}",
                initial="- ",
                subsequent="  ",
            )
        )
    lines.append("-" * 64)

    lines.append("Top Risks")
    if not top:
        lines.append("- None")
    else:
        for finding in top:
            impact = int(finding.get("impact", 0))
            weighted_loss = _finding_weighted_loss(finding, weights)
            sev = str(finding.get("severity", "INFO")).upper()
            head = f"[{sev}] weighted loss {weighted_loss:.2f} (impact {impact}) - "
            text = format_finding_line(finding)[2:]
            lines.append(_wrap(text, initial=f"- {head}", subsequent="  "))
    lines.append("-" * 64)

    lines.append("Findings")
    if not findings:
        lines.append("- No findings.")
    else:
        severity_order = ["CRITICAL", "WARNING", "INFO"]
        for severity in severity_order:
            scoped = [f for f in findings if str(f.get("severity", "")).upper() == severity]
            if not scoped:
                continue
            lines.append(f"{severity}")
            if severity == "WARNING":
                deduped = [f for f in scoped if str(f.get("id", "")) not in top_ids]
                repeated = len(scoped) - len(deduped)
                if repeated > 0:
                    lines.append(
                        _wrap(
                            f"{repeated} warning finding(s) already listed in Top Risks; showing remaining warnings.",
                            initial="  Note: ",
                            subsequent="        ",
                        )
                    )
                scoped = deduped
            if not scoped:
                lines.append("  - None")
                continue
            for finding in scoped:
                lines.append("  " + format_finding_line(finding))
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
    lines.append("-" * 64)

    steps = derive_next_steps(findings, max_steps=5)
    lines.append("Recommended Next Steps")
    if not steps:
        lines.append("- Continue periodic scans and review any new exposed services.")
    else:
        for step in steps:
            lines.append(_wrap(step, initial="- ", subsequent="  "))
    lines.append("-" * 64)
    lines.append("Tip: use --json to export results")
    return "\n".join(lines)
