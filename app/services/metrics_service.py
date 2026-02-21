"""
Metrics service — business logic for computing SIEM dashboard metrics.

Extracted from ui.py to keep controllers free of business logic (TO-BE requirement).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.services.events_store import list_events, count_events
from app.services.alerts_store import list_alerts, count_alerts
from app.services.incidents_store import list_incidents, count_incidents

try:
    from app.services.aggregates_store import list_aggregates, count_aggregates
except ImportError:
    list_aggregates = None
    count_aggregates = None


ASSETS_PATHS: List[Path] = [
    Path("data/cmdb/assets.json"),
    Path("data/assets.json"),
]


def _load_assets() -> List[Dict[str, Any]]:
    """Load assets from CMDB JSON (best-effort)."""
    for p in ASSETS_PATHS:
        try:
            if not p.exists():
                continue
            raw = p.read_text(encoding="utf-8").strip()
            if not raw:
                continue
            data = json.loads(raw)
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
        except Exception:
            continue
    return []


def _safe_count(fn: Optional[Callable[[], int]], fallback_list_fn: Optional[Callable] = None) -> int:
    if callable(fn):
        try:
            return int(fn())
        except Exception:
            return 0
    if callable(fallback_list_fn):
        try:
            data = fallback_list_fn(10_000)
            return len(data) if isinstance(data, list) else len(list(data))
        except Exception:
            return 0
    return 0


def _safe_list(fn: Optional[Callable], limit: int) -> list:
    if not callable(fn):
        return []
    try:
        data = fn(limit)
        return data if isinstance(data, list) else list(data)
    except Exception:
        return []


def _count_by(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        v = it.get(key)
        if v is None:
            v = "unknown"
        v = str(v)
        out[v] = out.get(v, 0) + 1
    return out


def _top_by(items: List[Dict[str, Any]], key: str, limit: int = 10) -> List[Dict[str, Any]]:
    counts = _count_by(items, key)
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"key": k, "count": c} for k, c in top]


def compute_metrics() -> Dict[str, Any]:
    """Compute all dashboard metrics."""
    events_raw = _safe_count(count_events, list_events)
    events_aggregated = _safe_count(count_aggregates, None)
    alerts_total = _safe_count(count_alerts, list_alerts)
    incidents_total = _safe_count(count_incidents, list_incidents)

    events_sample = _safe_list(list_events, 10_000)
    alerts_sample = _safe_list(list_alerts, 10_000)
    incidents_sample = _safe_list(list_incidents, 10_000)

    # Per-source counters
    by_source: Dict[str, int] = {"firewall": 0, "av": 0, "edr": 0, "iam": 0, "endpoints": 0}
    for e in events_sample:
        if not isinstance(e, dict):
            continue
        st = str(e.get("source_type") or e.get("source") or "").lower()
        if st in ("iam/ad", "iam", "ad", "active_directory"):
            st = "iam"
        if st in ("antivirus", "av"):
            st = "av"
        if st in ("edr", "edr_system"):
            st = "edr"
        if st in ("endpoint", "endpoints", "os", "os_logs"):
            st = "endpoints"
        if st in by_source:
            by_source[st] += 1

    alerts_by_priority = _count_by(alerts_sample, "priority")
    incidents_by_severity = _count_by(incidents_sample, "severity")
    incidents_by_status = _count_by(incidents_sample, "status")

    top_event_types = _top_by(events_sample, "event_type", limit=10)
    top_src_ip = _top_by(events_sample, "src_ip", limit=10)
    top_dst_ip = _top_by(events_sample, "dst_ip", limit=10)
    top_users = _top_by(events_sample, "user", limit=10)
    top_assets = _top_by(events_sample, "asset_id", limit=10)

    assets_count = len(_load_assets())

    return {
        "events_raw": events_raw,
        "events_aggregated": events_aggregated,
        "alerts": alerts_total,
        "incidents": incidents_total,
        "by_source": by_source,
        "breakdowns": {
            "alerts_by_priority": alerts_by_priority,
            "incidents_by_severity": incidents_by_severity,
            "incidents_by_status": incidents_by_status,
        },
        "tops": {
            "event_types": top_event_types,
            "src_ip": top_src_ip,
            "dst_ip": top_dst_ip,
            "users": top_users,
            "assets": top_assets,
        },
        "cmdb": {
            "assets_count": assets_count,
            "paths": [str(p) for p in ASSETS_PATHS],
        },
    }


def get_assets() -> List[Dict[str, Any]]:
    """Return all CMDB assets."""
    return _load_assets()


def search_assets(query: str) -> List[Dict[str, Any]]:
    """Search assets by hostname, name, asset_id, or IP."""
    qn = (query or "").strip().lower()
    assets = _load_assets()
    if not qn:
        return assets

    def _hit(a: Dict[str, Any]) -> bool:
        host = str(a.get("host") or "").lower()
        name = str(a.get("name") or "").lower()
        asset_id = str(a.get("asset_id") or a.get("id") or "").lower()
        ips = a.get("ips") or []
        if isinstance(ips, str):
            ips_list = [ips]
        elif isinstance(ips, list):
            ips_list = [str(x) for x in ips]
        else:
            ips_list = []
        return (
            qn in host
            or qn in name
            or qn in asset_id
            or any(qn in ip.lower() for ip in ips_list)
        )

    return [a for a in assets if _hit(a)]
