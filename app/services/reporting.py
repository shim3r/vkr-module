"""
Reporting module for SOC-level metrics (TO-BE requirement).

Provides:
  - incidents_count by time period
  - FP-rate (resolved as false_positive / total resolved)
  - mean_time_to_resolve (MTTR)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.services.incidents_store import list_incidents


def _parse_dt(ts: Any) -> Optional[datetime]:
    """Parse ISO timestamp best-effort."""
    if not ts:
        return None
    if isinstance(ts, datetime):
        return ts
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def incidents_count(period_hours: int = 24) -> Dict[str, Any]:
    """Count incidents created within the given time period."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=period_hours)
    all_inc = list_incidents(limit=10_000)

    total = 0
    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_type: Dict[str, int] = {}

    for inc in all_inc:
        created = _parse_dt(inc.get("created_at"))
        if created and created < cutoff:
            continue
        total += 1

        sev = str(inc.get("severity", "unknown")).lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

        status = str(inc.get("status", "unknown"))
        by_status[status] = by_status.get(status, 0) + 1

        itype = str(inc.get("type", "unknown"))
        by_type[itype] = by_type.get(itype, 0) + 1

    return {
        "period_hours": period_hours,
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
    }


def fp_rate() -> Dict[str, Any]:
    """Calculate False Positive rate.

    FP-rate = resolved_as_false_positive / total_resolved

    A resolved incident is considered FP if:
      - status == "Resolved" and comment contains "false positive" / "fp" / "ложное"
    """
    all_inc = list_incidents(limit=10_000)

    resolved = [
        inc for inc in all_inc
        if str(inc.get("status", "")).lower() == "resolved"
    ]

    total_resolved = len(resolved)
    if total_resolved == 0:
        return {
            "total_resolved": 0,
            "false_positives": 0,
            "fp_rate": 0.0,
            "note": "No resolved incidents yet",
        }

    fp_keywords = {"false positive", "fp", "ложное срабатывание", "ложное", "false_positive"}
    false_positives = 0
    for inc in resolved:
        comment = str(inc.get("comment", "")).lower().strip()
        if any(kw in comment for kw in fp_keywords):
            false_positives += 1

    rate = round(false_positives / total_resolved, 4) if total_resolved > 0 else 0.0

    return {
        "total_resolved": total_resolved,
        "false_positives": false_positives,
        "fp_rate": rate,
        "fp_rate_pct": round(rate * 100, 2),
    }


def mean_time_to_resolve() -> Dict[str, Any]:
    """Calculate Mean Time To Resolve (MTTR) for resolved incidents.

    Uses created_at and updated_at (last status change) as proxy.
    """
    all_inc = list_incidents(limit=10_000)

    resolved = [
        inc for inc in all_inc
        if str(inc.get("status", "")).lower() == "resolved"
    ]

    if not resolved:
        return {
            "resolved_count": 0,
            "mttr_minutes": 0.0,
            "mttr_hours": 0.0,
            "note": "No resolved incidents yet",
        }

    durations: List[float] = []
    for inc in resolved:
        created = _parse_dt(inc.get("created_at"))
        updated = _parse_dt(inc.get("updated_at"))
        if created and updated and updated > created:
            delta = (updated - created).total_seconds()
            durations.append(delta)

    if not durations:
        return {
            "resolved_count": len(resolved),
            "mttr_minutes": 0.0,
            "mttr_hours": 0.0,
            "note": "Could not compute durations",
        }

    avg_seconds = sum(durations) / len(durations)
    return {
        "resolved_count": len(resolved),
        "mttr_seconds": round(avg_seconds, 1),
        "mttr_minutes": round(avg_seconds / 60, 2),
        "mttr_hours": round(avg_seconds / 3600, 2),
    }


def mean_time_to_acknowledge() -> Dict[str, Any]:
    """Calculate Mean Time To Acknowledge (MTTA).

    MTTA = time from incident created_at to first status transition to 'In Progress'.
    Computed from incident timeline entries.
    """
    all_inc = list_incidents(limit=10_000)

    acknowledged = [
        inc for inc in all_inc
        if str(inc.get("status", "")) in ("In Progress", "Resolved", "Closed")
    ]

    if not acknowledged:
        return {
            "acknowledged_count": 0,
            "mtta_minutes": 0.0,
            "mtta_hours": 0.0,
            "note": "No acknowledged incidents yet",
        }

    durations: list[float] = []
    for inc in acknowledged:
        created = _parse_dt(inc.get("created_at"))
        if not created:
            continue
        # Find first 'In Progress' entry in timeline
        timeline = inc.get("timeline") or []
        ack_time = None
        for entry in sorted(timeline, key=lambda e: e.get("timestamp", "")):
            detail = str(entry.get("detail", "")).lower()
            if "in progress" in detail and entry.get("action") == "status_change":
                ack_time = _parse_dt(entry.get("timestamp"))
                break
        # Fallback: use updated_at as proxy
        if not ack_time:
            ack_time = _parse_dt(inc.get("updated_at"))
        if ack_time and ack_time > created:
            durations.append((ack_time - created).total_seconds())

    if not durations:
        return {
            "acknowledged_count": len(acknowledged),
            "mtta_minutes": 0.0,
            "mtta_hours": 0.0,
            "note": "Could not compute MTTA durations",
        }

    avg_seconds = sum(durations) / len(durations)
    return {
        "acknowledged_count": len(acknowledged),
        "mtta_seconds": round(avg_seconds, 1),
        "mtta_minutes": round(avg_seconds / 60, 2),
        "mtta_hours": round(avg_seconds / 3600, 2),
    }


def full_report(period_hours: int = 24) -> Dict[str, Any]:
    """Generate a complete SOC-level report (TO-BE required metrics)."""
    from app.services.events_store import count_events

    total_events = 0
    try:
        total_events = count_events()
    except Exception:
        pass

    aggregated_events = 0
    try:
        from app.services.aggregates_store import count_aggregates
        aggregated_events = count_aggregates()
    except Exception:
        pass

    return {
        "total_events": total_events,
        "aggregated_events": aggregated_events,
        "incidents": incidents_count(period_hours=period_hours),
        "fp_rate": fp_rate(),
        "mttr": mean_time_to_resolve(),
        "mtta": mean_time_to_acknowledge(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
