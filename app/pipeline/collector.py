"""
Collector module — raw event ingestion entry point.

In the TO-BE architecture, the collector only handles:
  1) Raw event storage (forensic archive)
  2) Pushing to the async pipeline queue

All normalization, enrichment, scoring, aggregation, correlation
are handled by downstream pipeline stages.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.pipeline.normalize import normalize
from app.pipeline.enrich import enrich_dict
from app.pipeline.scoring import score
from app.pipeline.aggregate import update_aggregate
from app.pipeline.correlate import run_correlation

from app.services.alerts_store import add_alert
from app.services.events_store import add_event

from app.config import (
    RAW_DIR,
    NORMALIZED_DIR,
    RAW_RETENTION_DAYS,
    RAW_MAX_FILES,
    RAW_CLEANUP_EVERY,
)


_raw_ingest_count = 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _raw_cleanup() -> None:
    """Очистка хранилища сырых событий (архив/форензика): по сроку хранения и лимиту файлов."""
    if not RAW_DIR.exists():
        return
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RAW_RETENTION_DAYS)
    cutoff_ts = cutoff.timestamp()
    files: list[tuple[Path, float]] = []
    for p in RAW_DIR.glob("*.json"):
        try:
            mtime = p.stat().st_mtime
            if mtime < cutoff_ts:
                try:
                    p.unlink()
                except OSError:
                    pass
            else:
                files.append((p, mtime))
        except OSError:
            pass
    if len(files) <= RAW_MAX_FILES:
        return
    files.sort(key=lambda x: x[1])
    for p, _ in files[: len(files) - RAW_MAX_FILES]:
        try:
            p.unlink()
        except OSError:
            pass


async def ingest_event(payload: dict) -> dict:
    """
    Ingest a raw event through the async pipeline.

    Tries to use the Pipeline (queue-based) if started,
    otherwise falls back to synchronous processing.
    """
    from app.pipeline.pipeline import get_pipeline

    pipeline = get_pipeline()

    # If pipeline workers are running, use async queue path
    if pipeline._running:
        result = await pipeline.push_raw(payload)
        # Periodic raw cleanup
        global _raw_ingest_count
        _raw_ingest_count += 1
        if _raw_ingest_count % RAW_CLEANUP_EVERY == 0:
            _raw_cleanup()
        return result

    # Fallback: synchronous processing (when pipeline not started)
    return await _ingest_sync(payload)


async def _ingest_sync(payload: dict) -> dict:
    """Synchronous fallback — direct function call chain (legacy mode)."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)

    raw_id = str(uuid4())

    record = {
        "raw_id": raw_id,
        "received_at": _utc_now_iso(),
        "payload": payload,
    }

    # 1) Raw Events Store
    out_path = RAW_DIR / f"{raw_id}.json"
    out_path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    global _raw_ingest_count
    _raw_ingest_count += 1
    if _raw_ingest_count % RAW_CLEANUP_EVERY == 0:
        _raw_cleanup()

    # 2) Normalize
    normalized = normalize(
        payload=payload,
        raw_id=raw_id,
        received_at_iso=record["received_at"],
    )

    normalized_dict = normalized.model_dump(mode="json")

    # 3) Enrich
    normalized_dict = enrich_dict(normalized_dict)

    # 4) Score
    risk, priority, is_critical = score(normalized_dict)
    normalized_dict["risk"] = risk
    normalized_dict["priority"] = priority

    # 5) Aggregate
    update_aggregate(normalized_dict)

    # 6) Store event
    add_event(normalized_dict)

    # Save normalized event to disk
    normalized_path = NORMALIZED_DIR / f"{raw_id}.json"
    normalized_path.write_text(
        json.dumps(normalized_dict, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )

    result = {
        "raw_id": raw_id,
        "stored_to": str(out_path),
        "normalized_stored_to": str(normalized_path),
        "risk": risk,
        "priority": priority,
        "normalized_event": normalized_dict,
    }

    # 7) Alerts for critical events
    if is_critical:
        add_alert({
            "alert_id": f"AL-{uuid4().hex[:12].upper()}",
            "raw_id": raw_id,
            "priority": priority,
            "risk": risk,
            "source_type": normalized_dict.get("source_type") or payload.get("source_type"),
            "format": normalized_dict.get("format") or payload.get("format"),
            "received_at": record["received_at"],
            "event_type": normalized_dict.get("event_type"),
            "src_ip": normalized_dict.get("src_ip"),
            "dst_ip": normalized_dict.get("dst_ip"),
            "user": normalized_dict.get("user"),
            "snippet": str(payload.get("data", ""))[:200],
        })

    # 8) Correlation
    incidents = run_correlation()
    result["correlation_incidents"] = incidents
    print(
        f"[INGEST] raw_id={raw_id} "
        f"type={normalized_dict.get('event_type')} "
        f"src={normalized_dict.get('src_ip')} "
        f"user={normalized_dict.get('user')} "
        f"risk={risk} priority={priority}"
    )

    if incidents:
        print(f"[CORRELATION] incidents={incidents}")
    return result
