from __future__ import annotations

from typing import Any, Dict, Tuple

# Source trust coefficients for calculating Risk Score
SOURCE_TRUST = {
    "firewall": 2.0,
    "av": 1.5,
    "edr": 1.5,
    "iam": 1.0,
    "arm": 0.5,
}


def _get_source_trust(source_type: str) -> float:
    """Return source trust coefficient (0.5 to 2.0)."""
    src = (source_type or "unknown").lower()
    return float(SOURCE_TRUST.get(src, 1.0))


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
        return 1.0  # default low criticality

    try:
        c = int(crit)
    except Exception:
        return 1.0

    c = max(1, min(5, c))
    return float(c)  # return 1-5 unmodified


def _get_event_severity(payload: Dict[str, Any]) -> float:
    """Return event severity on scale 1-10."""
    try:
        s = int(payload.get("severity") or 1)
    except Exception:
        s = 1
    return float(max(1, min(10, s)))


def score(payload: Dict[str, Any]) -> Tuple[float, str, bool]:
    """Compute risk score (0-100) for noise reduction.

    Формула: Risk = (Criticality Актива) * (Severity Атаки) * (Доверие Источника)
    
    Max Risk: 5 * 10 * 2.0 = 100.
    
    Шкалы:
    - Asset Criticality: 1..5
    - Event Severity: 1..10
    - Source Trust: 0.5..2.0

    Thresholds:
      > 70 -> CRITICAL
      > 40 -> HIGH
      > 20 -> MEDIUM
      <= 20 -> LOW
    """
    trust_coeff = _get_source_trust(payload.get("source_type", ""))
    asset_crit = _get_asset_criticality(payload)
    event_sev = _get_event_severity(payload)

    risk = asset_crit * event_sev * trust_coeff
    risk = round(min(100.0, risk), 2)

    if risk > 70.0:
        priority = "CRITICAL"
    elif risk > 40.0:
        priority = "HIGH"
    elif risk > 20.0:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    is_critical = priority in ("HIGH", "CRITICAL")
    return risk, priority, is_critical
