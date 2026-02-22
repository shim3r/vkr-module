"""
Collector module — single entry point for raw event ingestion.

TO-BE architecture:
  1) Persist raw event to disk (forensic archive, immutable).
  2) Push to async pipeline queue.

All downstream processing (normalize, enrich, score, aggregate,
correlate, incident) is handled EXCLUSIVELY by pipeline.py workers.
No business logic here.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    """Remove stale raw events by retention period and file count limit."""
    if not RAW_DIR.exists():
        return
    now = datetime.now(timezone.utc)
    cutoff_ts = (now - timedelta(days=RAW_RETENTION_DAYS)).timestamp()
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

    - If pipeline workers are running: push to async queue (non-blocking).
    - If pipeline is not started: delegate to Pipeline._ingest_sync()
      which runs the full chain synchronously as a safe fallback.
    """
    from app.pipeline.pipeline import get_pipeline

    pipeline = get_pipeline()

    global _raw_ingest_count
    _raw_ingest_count += 1
    if _raw_ingest_count % RAW_CLEANUP_EVERY == 0:
        _raw_cleanup()

    if pipeline._running:
        # Async path — raw store + queue push happen inside push_raw()
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
        return await pipeline.push_raw(payload)

    # Sync fallback — full pipeline chain is in Pipeline._ingest_sync()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
    return await pipeline._ingest_sync(payload)
