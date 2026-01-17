
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from app.services.alerts_store import add_alert
from app.services.events_store import all_events
from app.services.incidents_store import add_incident

# -------------------------------------------------
# Simple dedup for correlation incidents (TTL cache)
# -------------------------------------------------
_SEEN: Dict[str, datetime] = {}
SEEN_TTL_SECONDS = 300


def _seen(key: str) -> bool:
    now = datetime.now(timezone.utc)
    # cleanup
    for k, ts in list(_SEEN.items()):
        if (now - ts).total_seconds() > SEEN_TTL_SECONDS:
            _SEEN.pop(k, None)
    if key in _SEEN:
        return True
    _SEEN[key] = now
    return False


def _to_dt(x):
    if x is None:
        return None
    if isinstance(x, datetime):
        return x
    s = str(x)
    # Python 3.9 не парсит ISO с 'Z' → заменяем на +00:00
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


# -------------------------------------------------
# 1) VPN brute force (already exists)
# -------------------------------------------------

def correlate_bruteforce_vpn(window_seconds: int = 120, threshold: int = 5) -> Tuple[bool, Dict]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    events = all_events()

    candidates: List[Dict] = []
    for e in events:
        ra = e.get("received_at")
        if not ra:
            continue
        try:
            ra_dt = _to_dt(ra)
        except Exception:
            continue

        if ra_dt is None or ra_dt < window_start:
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
            key = f"BRUTEFORCE_VPN:{src}:{window_seconds}:{threshold}"
            if _seen(key):
                return False, {}

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
                "asset_id": group[0].get("asset_id"),
                "asset_criticality": group[0].get("asset_criticality"),
                "asset_owner": group[0].get("asset_owner"),
                "asset_zone": group[0].get("asset_zone"),
                "evidence_event_ids": [g.get("event_id") for g in group if g.get("event_id")],
            }
            return True, incident

    return False, {}


# -------------------------------------------------
# 2) Port scan (src_ip -> many ports within window)
# -------------------------------------------------

def correlate_portscan(window_seconds: int = 120, ports_threshold: int = 10) -> Tuple[bool, Dict]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)
    events = all_events()

    scans: List[Dict] = []
    for e in events:
        ra = e.get("received_at")
        if not ra:
            continue
        try:
            ra_dt = _to_dt(ra)
        except Exception:
            continue
        if ra_dt is None or ra_dt < window_start:
            continue

        if e.get("event_type") != "PORTSCAN":
            continue

        if not e.get("src_ip"):
            continue

        scans.append(e)

    if not scans:
        return False, {}

    by_src: Dict[str, List[Dict]] = {}
    for e in scans:
        by_src.setdefault(e["src_ip"], []).append(e)

    for src, group in by_src.items():
        ports = sorted({g.get("dst_port") for g in group if g.get("dst_port") is not None})
        dsts = sorted({g.get("dst_ip") for g in group if g.get("dst_ip")})
        if len(ports) >= ports_threshold:
            key = f"PORTSCAN:{src}:{window_seconds}:{len(ports)}"
            if _seen(key):
                return False, {}

            incident = {
                "type": "PORT_SCAN",
                "title": f"Port scan from {src} (ports={len(ports)})",
                "src_ip": src,
                "dst_ips": dsts,
                "ports": ports,
                "count": len(group),
                "window_seconds": window_seconds,
                "first_seen": min(_to_dt(g["received_at"]) for g in group).isoformat(),
                "last_seen": max(_to_dt(g["received_at"]) for g in group).isoformat(),
                "severity": "high",
                "asset_id": group[0].get("asset_id"),
                "asset_criticality": group[0].get("asset_criticality"),
                "asset_owner": group[0].get("asset_owner"),
                "asset_zone": group[0].get("asset_zone"),
                "evidence_event_ids": [g.get("event_id") for g in group if g.get("event_id")],
            }
            return True, incident

    return False, {}


# -------------------------------------------------
# 3) Malware detected (AV_DETECT / MALWARE_DETECT)
# -------------------------------------------------

def correlate_malware(window_seconds: int = 300) -> Tuple[bool, Dict]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)
    events = all_events()

    det: List[Dict] = []
    for e in events:
        ra = e.get("received_at")
        if not ra:
            continue
        try:
            ra_dt = _to_dt(ra)
        except Exception:
            continue
        if ra_dt is None or ra_dt < window_start:
            continue

        if e.get("event_type") in ("AV_DETECT", "MALWARE_DETECT"):
            det.append(e)

    if not det:
        return False, {}

    by_host: Dict[str, List[Dict]] = {}
    for e in det:
        host = e.get("host") or "unknown"
        by_host.setdefault(host, []).append(e)

    for host, group in by_host.items():
        key = f"MALWARE:{host}:{window_seconds}"
        if _seen(key):
            return False, {}

        users = sorted({g.get("user") for g in group if g.get("user")})

        incident = {
            "type": "MALWARE_DETECTED",
            "title": f"Malware detected on host {host}",
            "host": host,
            "users": users,
            "count": len(group),
            "window_seconds": window_seconds,
            "first_seen": min(_to_dt(g["received_at"]) for g in group).isoformat(),
            "last_seen": max(_to_dt(g["received_at"]) for g in group).isoformat(),
            "severity": "critical",
            "asset_id": group[0].get("asset_id"),
            "asset_criticality": group[0].get("asset_criticality"),
            "asset_owner": group[0].get("asset_owner"),
            "asset_zone": group[0].get("asset_zone"),
            "evidence_event_ids": [g.get("event_id") for g in group if g.get("event_id")],
        }
        return True, incident

    return False, {}


# -------------------------------------------------
# 4) Lateral movement (IAM success -> EDR activity on another host)
# -------------------------------------------------

def correlate_lateral_movement(window_seconds: int = 300) -> Tuple[bool, Dict]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)
    events = all_events()

    def _norm(s: Any) -> str:
        return str(s or "").strip()

    def _lower(s: Any) -> str:
        return _norm(s).lower()

    def _pick_host(evt: Dict) -> str:
        # Try canonical host first, then fallbacks from fields
        h = _norm(evt.get("host"))
        if h:
            return h
        f = evt.get("fields") or {}
        for k in ("host", "hostname", "computer", "workstation", "device", "endpoint", "src_host", "dst_host"):
            v = _norm(f.get(k))
            if v:
                return v
        return ""

    def _pick_user(evt: Dict) -> str:
        u = _norm(evt.get("user"))
        if u:
            return u
        f = evt.get("fields") or {}
        for k in ("user", "username", "account", "subject_user", "target_user"):
            v = _norm(f.get(k))
            if v:
                return v
        return ""

    auth_success: List[Dict] = []
    edr_activity: List[Dict] = []

    AUTH_SUCCESS_TYPES = {
        "login_success",
        "ad_login_success",
        "iam_login_success",
        "4624",  # windows logon success sometimes mapped as ID
    }

    EDR_TYPES = {
        "process_start",
        "process_create",
        "4688",  # windows process create sometimes mapped as ID
        "network_connection",
        "suspicious_script",
        "credential_dumping",
        "remote_exec",
    }

    for e in events:
        ra = e.get("received_at")
        if not ra:
            continue
        try:
            ra_dt = _to_dt(ra)
        except Exception:
            continue
        if ra_dt is None or ra_dt < window_start:
            continue

        et_l = _lower(e.get("event_type"))
        st_l = _lower(e.get("source_type"))

        # 1) auth success (IAM/AD/Windows)
        if et_l in AUTH_SUCCESS_TYPES:
            user = _pick_user(e)
            host = _pick_host(e)
            if user and host:
                e2 = dict(e)
                e2["_lm_user"] = user
                e2["_lm_host"] = host
                auth_success.append(e2)

        # 2) EDR activity (case-insensitive + allow other source_type values)
        if st_l in ("edr", "endpoint", "agent") and et_l in EDR_TYPES:
            host = _pick_host(e)
            if host:
                e2 = dict(e)
                e2["_lm_host"] = host
                e2["_lm_user"] = _pick_user(e)  # may be empty
                edr_activity.append(e2)

    if not auth_success or not edr_activity:
        return False, {}

    # Heuristic:
    # same user logs in successfully on one host, then within window shows EDR activity on another host
    for a in auth_success:
        user = a.get("_lm_user")
        src_host = a.get("_lm_host")
        if not user or not src_host:
            continue

        candidates = []
        for x in edr_activity:
            dst_host = x.get("_lm_host")
            if not dst_host or dst_host == src_host:
                continue
            # If EDR provides user, match it; otherwise allow empty user
            x_user = x.get("_lm_user")
            if x_user and _lower(x_user) != _lower(user):
                continue
            candidates.append(x)

        if not candidates:
            continue

        dst_hosts = sorted({c.get("_lm_host") for c in candidates if c.get("_lm_host")})
        key = f"LATERAL:{_lower(user)}:{_lower(src_host)}:{','.join(map(_lower, dst_hosts))}:{window_seconds}"
        if _seen(key):
            return False, {}

        incident = {
            "type": "LATERAL_MOVEMENT",
            "title": f"Possible lateral movement for user {user}: {src_host} -> {', '.join(dst_hosts)}",
            "user": user,
            "src_host": src_host,
            "dst_hosts": dst_hosts,
            "count": len(candidates),
            "window_seconds": window_seconds,
            "first_seen": min(_to_dt(c["received_at"]) for c in candidates).isoformat(),
            "last_seen": max(_to_dt(c["received_at"]) for c in candidates).isoformat(),
            "severity": "high",
            "asset_id": candidates[0].get("asset_id"),
            "asset_criticality": candidates[0].get("asset_criticality"),
            "asset_owner": candidates[0].get("asset_owner"),
            "asset_zone": candidates[0].get("asset_zone"),
            "evidence_event_ids": [c.get("event_id") for c in candidates if c.get("event_id")],
            "debug": {
                "auth_success_seen": len(auth_success),
                "edr_activity_seen": len(edr_activity),
            },
        }
        return True, incident

    return False, {}


# -------------------------------------------------
# Runner: execute all correlation rules
# -------------------------------------------------

def _store_incident_and_alert(inc: Dict, priority: str, risk: int, src_ip: str = "", dst_ip: str = "", user: str = "") -> None:
    add_incident(inc)
    add_alert({
        "raw_id": None,
        "priority": priority,
        "risk": risk,
        "source_type": "correlation",
        "format": "rule",
        "received_at": datetime.now(timezone.utc).isoformat(),
        "event_type": inc.get("type", "CORRELATED"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": user,
        "snippet": inc.get("title", "Correlation incident"),
    })


def run_correlation() -> List[Dict]:
    incidents: List[Dict] = []

    found, inc = correlate_bruteforce_vpn()
    if found:
        incidents.append(inc)
        _store_incident_and_alert(
            inc,
            priority="critical",
            risk=95,
            src_ip=inc.get("src_ip", ""),
            dst_ip=",".join(inc.get("dst_ips", [])),
            user=",".join(inc.get("users", [])),
        )

    found, inc = correlate_portscan()
    if found:
        incidents.append(inc)
        _store_incident_and_alert(
            inc,
            priority="high",
            risk=80,
            src_ip=inc.get("src_ip", ""),
            dst_ip=",".join(inc.get("dst_ips", [])),
            user="",
        )

    found, inc = correlate_malware()
    if found:
        incidents.append(inc)
        _store_incident_and_alert(
            inc,
            priority="critical",
            risk=95,
            src_ip="",
            dst_ip=inc.get("host", ""),
            user=",".join(inc.get("users", [])),
        )

    found, inc = correlate_lateral_movement()
    if found:
        incidents.append(inc)
        _store_incident_and_alert(
            inc,
            priority="high",
            risk=85,
            src_ip="",
            dst_ip=",".join(inc.get("dst_hosts", [])),
            user=inc.get("user", ""),
        )

    return incidents
