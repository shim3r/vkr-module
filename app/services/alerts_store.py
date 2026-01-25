from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Optional

import json
from pathlib import Path

# Preferred (SIEM-style) path comes from config; fallback keeps old layout working.
try:
    from app.config import ALERTS_DIR
except Exception:
    ALERTS_DIR = Path("data/alerts")

# In-memory store for alerts (demo/SOC UI)
_ALERTS: Deque[Dict] = deque(maxlen=500)


def _ensure_alerts_dir() -> None:
    try:
        ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Do not break the app if filesystem is read-only or path is invalid
        pass


def _persist_alert(alert: Dict) -> Optional[Path]:
    """Persist a single alert to disk as JSON (SIEM-style)."""
    _ensure_alerts_dir()

    alert_id = str(alert.get("alert_id") or alert.get("id") or "")
    if not alert_id:
        return None

    # Keep filenames predictable; add prefix if missing
    if not alert_id.startswith("AL-"):
        filename = f"AL-{alert_id}.json"
    else:
        filename = f"{alert_id}.json"

    path = ALERTS_DIR / filename
    try:
        path.write_text(
            json.dumps(alert, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path
    except Exception:
        # Never fail alert creation due to IO
        return None


def add_alert(alert: Dict) -> Dict:
    """Add alert to in-memory store and persist to disk (best-effort)."""
    _ALERTS.appendleft(alert)
    _persist_alert(alert)
    return alert


def list_alerts(limit: int = 50) -> List[Dict]:
    return list(_ALERTS)[:limit]


def clear_alerts() -> None:
    """Clear all stored alerts (in-memory and on disk)."""
    _ALERTS.clear()

    # Best-effort: clear persisted files
    _ensure_alerts_dir()
    try:
        for p in ALERTS_DIR.glob("AL-*.json"):
            try:
                p.unlink()
            except Exception:
                pass
    except Exception:
        pass


def count_alerts() -> int:
    return len(_ALERTS)