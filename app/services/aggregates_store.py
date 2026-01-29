

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# In-memory aggregates store + best-effort persistence to disk.
# MVP goal: keep last aggregates for UI "Aggregated" tab and metrics.

AGG_DIR = Path("data/aggregated")
AGG_FILE = AGG_DIR / "aggregates.jsonl"

# aggregate_id -> aggregate dict
_AGG: Dict[str, Dict[str, Any]] = {}


def _ensure_dir() -> None:
    try:
        AGG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        # ignore filesystem errors in MVP
        pass


def _append_jsonl(obj: Dict[str, Any]) -> None:
    """Append a snapshot of the aggregate to disk (best-effort)."""
    try:
        _ensure_dir()
        with AGG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        # ignore persistence errors in MVP
        pass


def upsert_aggregate(agg: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
    """Insert/update aggregate by aggregate_id."""
    agg_id = str(agg.get("aggregate_id") or "").strip()
    if not agg_id:
        raise ValueError("aggregate_id is required")

    _AGG[agg_id] = agg
    if persist:
        _append_jsonl(agg)
    return agg


def get_aggregate(aggregate_id: str) -> Optional[Dict[str, Any]]:
    return _AGG.get(aggregate_id)


def list_aggregates(limit: int = 50) -> List[Dict[str, Any]]:
    """List aggregates sorted by last_seen desc."""
    lim = int(limit or 50)
    items = list(_AGG.values())
    items.sort(key=lambda x: str(x.get("last_seen") or ""), reverse=True)
    return items[:lim]


def count_aggregates() -> int:
    return len(_AGG)


def reset_aggregates(purge_file: bool = False) -> None:
    """Reset in-memory aggregates. Optionally purge the persisted file."""
    _AGG.clear()
    if purge_file:
        try:
            if AGG_FILE.exists():
                AGG_FILE.unlink()
        except Exception:
            pass