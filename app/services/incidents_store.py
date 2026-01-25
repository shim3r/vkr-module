from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional

import json
from pathlib import Path

try:
    # Preferred (SIEM-style) path
    from app.config import INCIDENTS_DIR
except Exception:
    # Fallback for older layouts
    INCIDENTS_DIR = Path("data/incidents")


# In-memory store for incidents (demo mode)
_INCIDENTS: Deque[Dict] = deque(maxlen=200)


def _ensure_incidents_dir() -> None:
    try:
        INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Do not break the app if filesystem is read-only
        pass


def _persist_incident(incident: Dict) -> None:
    """Persist a single incident to disk as JSON (SIEM-style)."""
    _ensure_incidents_dir()
    incident_id = str(incident.get("incident_id", ""))
    if not incident_id:
        return
    path = INCIDENTS_DIR / f"{incident_id}.json"
    try:
        path.write_text(
            json.dumps(incident, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        # Never fail incident creation due to IO
        pass


def _delete_incident_file(incident_id: str) -> None:
    _ensure_incidents_dir()
    path = INCIDENTS_DIR / f"{incident_id}.json"
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_id() -> str:
    # simple deterministic-ish id for demo
    return f"INC-{int(datetime.now(timezone.utc).timestamp()*1000)}"


def _sla_by_severity(sev: str) -> int:
    s = (sev or "").lower()
    if "crit" in s:
        return 60
    if "high" in s:
        return 240
    if "med" in s:
        return 480
    return 1440


def add_incident(inc: Dict) -> Dict:
    """Add a new incident to the store.

    Enriches incident with:
      - incident_id
      - status
      - created_at / updated_at
      - sla_minutes
      - assignee / comment (optional)

    Returns the stored incident.
    """
    stored = dict(inc)

    stored.setdefault("incident_id", _gen_id())
    stored.setdefault("status", "New")

    # Use existing timestamps if provided, otherwise set
    stored.setdefault("created_at", stored.get("first_seen") or _now())
    stored.setdefault("updated_at", _now())

    # SLA
    stored.setdefault("sla_minutes", _sla_by_severity(str(stored.get("severity", ""))))

    # Optional workflow fields
    stored.setdefault("assignee", "")
    stored.setdefault("comment", "")

    _INCIDENTS.appendleft(stored)
    _persist_incident(stored)
    return stored


def list_incidents(limit: int = 50) -> List[Dict]:
    """Return latest incidents (most recent first)."""
    return list(_INCIDENTS)[:limit]


def get_incident(incident_id: str) -> Optional[Dict]:
    for inc in _INCIDENTS:
        if inc.get("incident_id") == incident_id:
            return inc
    return None


def update_incident(
    incident_id: str,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    comment: Optional[str] = None,
) -> Optional[Dict]:
    """Update incident fields in-place. Returns updated incident or None."""
    inc = get_incident(incident_id)
    if not inc:
        return None

    if status is not None:
        inc["status"] = status
    if assignee is not None:
        inc["assignee"] = assignee
    if comment is not None:
        inc["comment"] = comment

    inc["updated_at"] = _now()
    _persist_incident(inc)
    return inc


def count_incidents() -> int:
    return len(_INCIDENTS)


def clear_incidents() -> None:
    """Clear all stored incidents (in-memory and on disk)."""
    # Clear memory
    _INCIDENTS.clear()

    # Best-effort: clear persisted files
    _ensure_incidents_dir()
    try:
        for p in INCIDENTS_DIR.glob("INC-*.json"):
            try:
                p.unlink()
            except Exception:
                pass
    except Exception:
        pass
