"""Category-weighted scoring engine for LabSentinel."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

CATEGORY_WEIGHTS: Dict[str, int] = {
    "Remote Exposure": 30,
    "Authentication Hardening": 25,
    "Network Segmentation": 20,
    "Update Hygiene": 15,
    "Backup Protection": 10,
}

RISK_LEVELS: List[Tuple[int, str]] = [
    (85, "Low"),
    (65, "Moderate"),
    (40, "High"),
    (0, "Critical"),
]


def classify_risk_level(score: int) -> str:
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label
    return "Critical"


def calculate_weighted_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute weighted score and category breakdown from findings."""
    category_health: Dict[str, float] = {name: 100.0 for name in CATEGORY_WEIGHTS}

    for finding in findings:
        category = str(finding.get("category", "")).strip()
        if category not in category_health:
            continue
        impact = finding.get("impact", 0)
        if not isinstance(impact, (int, float)):
            continue
        category_health[category] = max(0.0, category_health[category] - float(impact))

    category_score_contrib: Dict[str, float] = {}
    total_score = 0.0
    for category, weight in CATEGORY_WEIGHTS.items():
        contrib = category_health[category] * (float(weight) / 100.0)
        category_score_contrib[category] = round(contrib, 2)
        total_score += contrib

    score = int(round(max(0.0, min(100.0, total_score))))
    return {
        "score": score,
        "risk_level": classify_risk_level(score),
        "weights": dict(CATEGORY_WEIGHTS),
        "category_health": {k: round(v, 2) for k, v in category_health.items()},
        "category_score_contrib": category_score_contrib,
    }


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """Backward-compatible score accessor."""
    return int(calculate_weighted_score(findings)["score"])
