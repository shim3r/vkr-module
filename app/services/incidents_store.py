from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional

try:
    from app.config import INCIDENTS_DIR, WEBHOOK_URL
except Exception:
    INCIDENTS_DIR = Path("data/incidents")
    WEBHOOK_URL = None


# In-memory store for incidents (demo mode)
_INCIDENTS: Deque[Dict] = deque(maxlen=200)

# Valid status transitions (TO-BE: New → In Progress → Resolved → Closed)
VALID_TRANSITIONS = {
    "New": {"In Progress", "Resolved", "Closed"},
    "In Progress": {"Resolved", "Closed"},
    "Resolved": {"Closed"},
    "Closed": set(),  # terminal state
}


def _ensure_incidents_dir() -> None:
    try:
        INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
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
            json.dumps(incident, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception:
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


def _send_webhook(incident: Dict) -> None:
    """Delegate webhook notification to the integrations layer."""
    try:
        from app.integrations import send_webhook as _send
        _send(incident)
    except Exception:
        pass


def _compute_total_risk(related_events: List[Dict]) -> float:
    """Compute total_risk_score from related events (max of all risk scores)."""
    if not related_events:
        return 0.0
    risks = []
    for e in related_events:
        r = e.get("risk")
        if r is not None:
            try:
                risks.append(float(r))
            except (TypeError, ValueError):
                pass
    return max(risks) if risks else 0.0


def _add_timeline_entry(incident: Dict, action: str, actor: str = "system", detail: str = "") -> None:
    """Append an entry to the incident timeline."""
    timeline = incident.setdefault("timeline", [])
    timeline.append({
        "timestamp": _now(),
        "action": action,
        "actor": actor,
        "detail": detail,
    })


def add_incident(inc: Dict) -> Dict:
    """Add a new incident to the store.

    Enriches incident with TO-BE required fields:
      - incident_id
      - status (New)
      - related_events[] — full event objects from evidence
      - total_risk_score — max risk from related events
      - timeline[] — chronological audit trail
      - created_at / updated_at
      - sla_minutes
      - assignee / comment
    """
    stored = dict(inc)

    stored.setdefault("incident_id", _gen_id())
    stored.setdefault("status", "New")

    # Timestamps
    stored.setdefault("created_at", stored.get("first_seen") or _now())
    stored.setdefault("updated_at", _now())

    # SLA
    stored.setdefault("sla_minutes", _sla_by_severity(str(stored.get("severity", ""))))

    # Optional workflow fields
    stored.setdefault("assignee", "")
    stored.setdefault("comment", "")
    # Active Response: список действий реагирования по данному инциденту
    stored.setdefault("response_actions", [])

    # TO-BE: related_events — hydrate full event objects from events store
    if "related_events" not in stored or not stored["related_events"]:
        evidence_ids = set(stored.get("evidence_event_ids") or [])
        if evidence_ids:
            try:
                from app.services.events_store import all_events
                related = [e for e in all_events() if e.get("event_id") in evidence_ids]
                stored["related_events"] = related
            except Exception:
                stored["related_events"] = []
        else:
            stored["related_events"] = []

    # TO-BE: total_risk_score (computed from related events or incident risk)
    if "total_risk_score" not in stored:
        related = stored.get("related_events", [])
        if related:
            stored["total_risk_score"] = _compute_total_risk(related)
        else:
            try:
                stored["total_risk_score"] = float(stored.get("risk", 0))
            except (TypeError, ValueError):
                stored["total_risk_score"] = 0.0

    # TO-BE: timeline (audit trail)
    if "timeline" not in stored:
        stored["timeline"] = []
    _add_timeline_entry(stored, action="created", detail=f"Incident created: {stored.get('title', '')}")

    _INCIDENTS.appendleft(stored)
    _persist_incident(stored)
    _send_webhook(stored)
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
    """Update incident fields in-place with status transition enforcement.

    Valid transitions: New -> In Progress -> Resolved
    """
    inc = get_incident(incident_id)
    if not inc:
        return None

    if status is not None:
        current_status = inc.get("status", "New")
        allowed = VALID_TRANSITIONS.get(current_status, set())
        if status not in allowed and status != current_status:
            # Return with error info but don't block (prototype grace)
            inc["_last_transition_error"] = (
                f"Invalid transition: {current_status} -> {status}. "
                f"Allowed: {sorted(allowed)}"
            )
        else:
            old_status = current_status
            inc["status"] = status
            _add_timeline_entry(
                inc,
                action="status_change",
                actor=assignee or inc.get("assignee", "system"),
                detail=f"Status changed: {old_status} -> {status}",
            )

    if assignee is not None:
        inc["assignee"] = assignee
        _add_timeline_entry(
            inc,
            action="assigned",
            actor=assignee,
            detail=f"Assigned to {assignee}",
        )

    if comment is not None:
        inc["comment"] = comment
        _add_timeline_entry(
            inc,
            action="comment",
            actor=assignee or inc.get("assignee", "system"),
            detail=comment,
        )

    inc["updated_at"] = _now()
    _persist_incident(inc)
    return inc


def count_incidents() -> int:
    return len(_INCIDENTS)


def clear_incidents() -> None:
    """Clear all stored incidents (in-memory and on disk)."""
    _INCIDENTS.clear()
    _ensure_incidents_dir()
    try:
        for p in INCIDENTS_DIR.glob("INC-*.json"):
            try:
                p.unlink()
            except Exception:
                pass
    except Exception:
        pass
