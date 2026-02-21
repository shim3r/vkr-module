from __future__ import annotations

from typing import Any, Dict, Tuple

# Source criticality weights (scale 1-10) per TO-BE architecture
SOURCE_CRITICALITY = {
    "firewall": 10,
    "av": 8,
    "edr": 6,
    "iam": 5,
    "arm": 4,
}

# Weighted formula coefficients
W_SOURCE = 0.4
W_ASSET = 0.3
W_SEVERITY = 0.3


def _get_source_criticality(source_type: str) -> float:
    """Return source criticality on scale 1-10."""
    src = (source_type or "unknown").lower()
    return float(SOURCE_CRITICALITY.get(src, 3))


def _get_asset_criticality(payload: Dict[str, Any]) -> float:
    """Return asset criticality on scale 1-10 (CMDB stores 1-5, normalized *2)."""
    crit = None
    # Direct field
    if payload.get("asset_criticality") is not None:
        crit = payload.get("asset_criticality")
    else:
        # Pull from enriched asset objects
        for k in ("dst_asset", "host_asset", "src_asset"):
            a = payload.get(k)
            if isinstance(a, dict) and a.get("criticality") is not None:
                crit = a.get("criticality")
                break

    if crit is None:
        return 2.0  # default low criticality

    try:
        c = int(crit)
    except Exception:
        return 2.0

    c = max(1, min(5, c))
    return float(c * 2)  # normalize 1-5 -> 2-10


def _get_event_severity(payload: Dict[str, Any]) -> float:
    """Return event severity on scale 1-10."""
    try:
        s = int(payload.get("severity") or 1)
    except Exception:
        s = 1
    return float(max(1, min(10, s)))


def score(payload: Dict[str, Any]) -> Tuple[float, str, bool]:
    """Compute risk score using the TO-BE weighted formula.

    risk = (source_criticality * 0.4) + (asset_criticality * 0.3) + (event_severity * 0.3)

    Scale: 1.0 - 10.0

    Thresholds:
      > 8.5 -> CRITICAL
      > 7.0 -> HIGH
      > 4.0 -> MEDIUM
      <= 4.0 -> LOW

    Returns (risk_score, priority, is_critical).
    """
    source_crit = _get_source_criticality(payload.get("source_type", ""))
    asset_crit = _get_asset_criticality(payload)
    event_sev = _get_event_severity(payload)

    risk = (source_crit * W_SOURCE) + (asset_crit * W_ASSET) + (event_sev * W_SEVERITY)
    risk = round(risk, 2)

    if risk > 8.5:
        priority = "CRITICAL"
    elif risk > 7.0:
        priority = "HIGH"
    elif risk > 4.0:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    is_critical = priority in ("HIGH", "CRITICAL")
    return risk, priority, is_critical
