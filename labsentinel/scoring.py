"""Basic scoring engine for LabSentinel findings."""

from __future__ import annotations

from typing import Any, Dict, List

SEVERITY_PENALTIES = {
    "CRITICAL": 30,
    "WARNING": 10,
}


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """Compute a 0-100 security score from findings."""
    score = 100
    for finding in findings:
        impact = finding.get("impact")
        if isinstance(impact, (int, float)):
            penalty = int(impact)
        else:
            penalty = SEVERITY_PENALTIES.get(str(finding.get("severity", "")).upper(), 0)
        score -= penalty

    # Future improvement: tune weights and add confidence-based scoring.
    return max(score, 0)
