from __future__ import annotations

from typing import Any, Dict, Tuple

# Weight of the telemetry source (coarse trust/importance signal)
SOURCE_WEIGHT = {"firewall": 10, "av": 8, "edr": 6, "iam": 5, "arm": 3}

# Text markers that should increase risk when found in raw/normalized text (MVP heuristic)
CRITICAL_MARKERS = [
    "VPN_LOGIN_FAIL",
    "PORTSCAN",
    "AV_DETECT",
    "MALWARE_DETECT",
    "credential_dumping",
    "ransom",
    "C2",
    "4688",
    "4697",
    "GROUP_ADD",
    "ACCOUNT_LOCK",
]


def _as_text(data: Any) -> str:
    if isinstance(data, dict):
        return " ".join(map(str, data.values()))
    if isinstance(data, (list, tuple)):
        return " ".join(map(str, data))
    return str(data or "")


def _severity_score(sev: Any) -> int:
    """Normalize severity (expected 1..10) into 0..40 points."""
    try:
        s = int(sev)
    except Exception:
        s = 0
    s = max(0, min(10, s))
    return int(round(s * 4))


def _asset_criticality_score(crit: Any) -> int:
    """Normalize asset criticality (expected 1..5) into 0..25 points."""
    try:
        c = int(crit)
    except Exception:
        c = 0
    c = max(0, min(5, c))
    return int(round(c * 5))


def _ioc_score(ioc_hits: Any) -> int:
    """IOC hits (list or dict) -> 0..30 points."""
    if not ioc_hits:
        return 0
    # If list, count items. If dict, count keys/entries.
    if isinstance(ioc_hits, list):
        n = len(ioc_hits)
    elif isinstance(ioc_hits, dict):
        n = len(ioc_hits)
    else:
        n = 1
    return min(30, n * 10)


def _marker_score(text: str) -> int:
    hits = sum(1 for m in CRITICAL_MARKERS if m.lower() in text.lower())
    return min(30, hits * 12)


def score(payload: Dict[str, Any]) -> Tuple[int, str, bool]:
    """Compute risk score and priority.

    Supports both the legacy ingest payload (source_type + data) and
    enriched normalized events (source_type + severity + *_asset + ioc_hits + tags).
    """
    src = (payload.get("source_type") or "unknown").lower()
    base = SOURCE_WEIGHT.get(src, 2)

    # Legacy field (raw ingest) OR normalized event fields
    data = payload.get("data")
    message = payload.get("message")

    text = " ".join(
        t
        for t in (
            _as_text(data),
            _as_text(message),
            _as_text(payload.get("event_type")),
            _as_text(payload.get("action")),
            _as_text(payload.get("status")),
            _as_text(payload.get("tags")),
        )
        if t
    )

    # Enrichment-aware signals
    sev_points = _severity_score(payload.get("severity"))

    # Pull asset criticality from the best available enriched field
    # (dst_asset is usually the protected target, host_asset is the generating host)
    crit = None
    for k in ("dst_asset", "host_asset", "src_asset"):
        a = payload.get(k)
        if isinstance(a, dict) and a.get("criticality") is not None:
            crit = a.get("criticality")
            break
    asset_points = _asset_criticality_score(crit)

    ioc_points = _ioc_score(payload.get("ioc_hits"))
    marker_points = _marker_score(text)

    # Base source weight contributes up to ~30 points
    base_points = min(30, base * 3)

    # Total risk (0..100)
    risk = min(100, base_points + sev_points + asset_points + ioc_points + marker_points)

    if risk >= 70:
        priority = "critical"
    elif risk >= 45:
        priority = "high"
    elif risk >= 25:
        priority = "medium"
    else:
        priority = "low"

    return risk, priority, priority in ("high", "critical")
