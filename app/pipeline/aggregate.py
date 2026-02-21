

from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from app.services.aggregates_store import get_aggregate, upsert_aggregate

BUCKET_SECONDS = 300  # 5 minutes

# Priority ordering (higher is worse)
PRIORITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_iso(ts: Any) -> Optional[datetime]:
    """Parse ISO8601 timestamps like 2026-01-28T20:11:48.356556Z (best-effort)."""
    if not ts:
        return None
    s = str(ts).strip()
    if not s:
        return None
    try:
        # Handle trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def bucket_start(dt: datetime) -> datetime:
    """Floor datetime to BUCKET_SECONDS boundary (UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    epoch = int(dt.timestamp())
    start_epoch = epoch - (epoch % BUCKET_SECONDS)
    return datetime.fromtimestamp(start_epoch, tz=timezone.utc)


def _bucket_range(ts_iso: Any) -> tuple[str, str]:
    dt = _parse_iso(ts_iso) or datetime.now(timezone.utc)
    start = bucket_start(dt)
    end = start + timedelta(seconds=BUCKET_SECONDS)
    return start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")


def build_group_key(event: Dict[str, Any]) -> str:
    """Build a stable grouping key (dedup key) from important fields."""
    # Use the normalized fields that exist in your pipeline
    parts = [
        str(event.get("source_type") or ""),
        str(event.get("event_type") or ""),
        str(event.get("src_ip") or ""),
        str(event.get("dst_ip") or ""),
        str(event.get("host") or ""),
        str(event.get("user") or ""),
        str(event.get("asset_id") or ""),
    ]
    # Normalize whitespace/lower for host/user/source
    norm = [p.strip() for p in parts]
    return "|".join(norm)


def aggregate_id_for(event: Dict[str, Any]) -> str:
    """aggregate_id = sha1(bucket_start + group_key)."""
    bucket_s, _ = _bucket_range(event.get("received_at") or event.get("received_at_iso") or event.get("parsed_at"))
    gk = build_group_key(event)
    raw = f"{bucket_s}|{gk}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()


def _max_priority(p1: Any, p2: Any) -> str:
    a = str(p1 or "low").lower()
    b = str(p2 or "low").lower()
    return a if PRIORITY_RANK.get(a, 1) >= PRIORITY_RANK.get(b, 1) else b


def update_aggregate(event: Dict[str, Any]) -> Dict[str, Any]:
    """Update/create aggregate for a single enriched+scored event."""

    # Use received_at as the primary clock
    received_ts = event.get("received_at") or event.get("received_at_iso") or event.get("parsed_at")
    bucket_s, bucket_e = _bucket_range(received_ts)

    gk = build_group_key(event)
    agg_id = hashlib.sha1(f"{bucket_s}|{gk}".encode("utf-8")).hexdigest()

    existing = get_aggregate(agg_id)

    # Event timestamps for first/last
    ev_ts = _parse_iso(received_ts)
    ev_iso = (
        ev_ts.isoformat().replace("+00:00", "Z")
        if ev_ts
        else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    # Pull key fields for visibility in UI
    src_type = event.get("source_type")
    event_type = event.get("event_type")
    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip")
    host = event.get("host")
    user = event.get("user")
    asset_id = event.get("asset_id")

    # Risk/priority
    try:
        risk = int(event.get("risk") or 0)
    except Exception:
        risk = 0
    priority = str(event.get("priority") or "low").lower()

    if not existing:
        agg = {
            "aggregate_id": agg_id,
            "bucket_start": bucket_s,
            "bucket_end": bucket_e,
            "group_key": gk,
            "first_seen": ev_iso,
            "last_seen": ev_iso,
            "count": 1,
            "source_type": src_type,
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "host": host,
            "user": user,
            "asset_id": asset_id,
            "max_risk": risk,
            "max_priority": priority,
        }
        return upsert_aggregate(agg)

    # Update existing aggregate
    agg = dict(existing)
    agg["last_seen"] = ev_iso
    agg["count"] = int(agg.get("count") or 0) + 1

    # Keep earliest first_seen
    first_seen = _parse_iso(agg.get("first_seen"))
    if first_seen and ev_ts and ev_ts < first_seen:
        agg["first_seen"] = ev_iso

    agg["max_risk"] = max(int(agg.get("max_risk") or 0), risk)
    agg["max_priority"] = _max_priority(agg.get("max_priority"), priority)

    return upsert_aggregate(agg)