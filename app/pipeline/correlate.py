from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from app.services.alerts_store import add_alert
from app.services.events_store import all_events
from datetime import datetime
from app.services.incidents_store import add_incident

def _to_dt(x):
    if isinstance(x, datetime):
        return x
    s = str(x)
    # Python 3.9 не парсит ISO с 'Z' → заменяем на +00:00
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)

def correlate_bruteforce_vpn(window_seconds: int = 120, threshold: int = 5) -> Tuple[bool, Dict]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    events = all_events()

    candidates = []
    for e in events:
        ra = e.get("received_at")
        if not ra:
            continue
        try:
            ra_dt = _to_dt(ra)
        except Exception:
            continue

        if ra_dt < window_start:
            continue

        if e.get("event_type") != "VPN_LOGIN_FAIL":
            continue

        src_ip = e.get("src_ip")
        if not src_ip:
            continue

        candidates.append(e)

    if not candidates:
        return False, {}

    by_src: Dict[str, List[Dict]] = {}
    for e in candidates:
        by_src.setdefault(e["src_ip"], []).append(e)

    for src, group in by_src.items():
        if len(group) >= threshold:
            users = sorted({g.get("user") for g in group if g.get("user")})
            dsts = sorted({g.get("dst_ip") for g in group if g.get("dst_ip")})

            incident = {
                "type": "BRUTEFORCE_VPN",
                "title": f"Possible VPN bruteforce from {src}",
                "src_ip": src,
                "users": users,
                "dst_ips": dsts,
                "count": len(group),
                "window_seconds": window_seconds,
                "first_seen": min(_to_dt(g["received_at"]) for g in group).isoformat(),
                "last_seen": max(_to_dt(g["received_at"]) for g in group).isoformat(),
                "severity": "critical",
                "evidence_event_ids": [g.get("event_id") for g in group if g.get("event_id")],
            }
            return True, incident

    return False, {}

def run_correlation() -> List[Dict]:
    incidents: List[Dict] = []

    found, inc = correlate_bruteforce_vpn()
    if found:
        incidents.append(inc)
        
        add_incident(inc)
        
        # Добавляем корреляционный алерт
        add_alert({
            "raw_id": None,
            "priority": "critical",
            "risk": 95,
            "source_type": "correlation",
            "format": "rule",
            "received_at": datetime.now(timezone.utc).isoformat(),
            "event_type": inc["type"],
            "src_ip": inc.get("src_ip"),
            "dst_ip": ",".join(inc.get("dst_ips", [])),
            "user": ",".join(inc.get("users", [])),
            "snippet": inc["title"],
        })

    return incidents
