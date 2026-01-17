from datetime import datetime, timezone
from typing import Dict, Any, Tuple
import re

from app.schemas.event import NormalizedEvent

# ----------------------------
# Canonical mappings
# ----------------------------

EVENT_TYPE_MAP = {
    "firewall": {
        "VPN_LOGIN_FAIL": ("authentication", 7),
        "VPN_LOGIN_SUCCESS": ("authentication", 4),
        "PORTSCAN": ("network", 8),
    },
    "av": {
        "AV_DETECT": ("malware", 9),
        "MALWARE_DETECT": ("malware", 9),
    },
    "edr": {
        "PROCESS_START": ("process", 4),
        "NETWORK_CONNECTION": ("network", 5),
        "CREDENTIAL_DUMP": ("process", 9),
    },
    "iam": {
        "LOGIN_FAIL": ("authentication", 6),
        "LOGIN_SUCCESS": ("authentication", 3),
        "ACCOUNT_LOCK": ("account", 8),
    },
}

# ----------------------------
# CEF parsing
# ----------------------------

CEF_RE = re.compile(
    r"^CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<event_id>[^|]*)\|(?P<signature>[^|]*)\|(?P<severity>\d+)\|(?P<ext>.*)$"
)

KV_RE = re.compile(r"(\w+)=([^\s]+)")

def parse_cef(text: str) -> Dict[str, Any]:
    m = CEF_RE.match(text.strip())
    if not m:
        return {}

    try:
        sev = int(m.group("severity"))
    except Exception:
        sev = 1

    fields = {
        "vendor": m.group("vendor"),
        "product": m.group("product"),
        "event_type": m.group("signature") or "UNKNOWN",
        "severity": sev,
    }

    ext = m.group("ext") or ""
    for k, v in KV_RE.findall(ext):
        fields[k] = v

    return fields

def parse_csv(text: str) -> Dict[str, Any]:
    parts = [p.strip() for p in text.strip().split(",") if p.strip()]
    if len(parts) < 3:
        return {}

    ts, user, event_type = parts[0], parts[1], parts[2]
    fields: Dict[str, Any] = {
        "timestamp": ts,
        "user": user,
        "event_type": event_type,
    }

    for part in parts[3:]:
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields

# ----------------------------
# Helpers
# ----------------------------

def to_int(value: Any) -> int | None:
    """Best-effort conversion to int. Returns None if conversion fails."""
    if value is None:
        return None
    try:
        # Handle strings like "443" or "443," etc.
        if isinstance(value, str):
            value = value.strip().rstrip(",")
        return int(value)
    except Exception:
        return None

def to_utc(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def map_event(source: str, raw_type: str) -> Tuple[str, int]:
    mapping = EVENT_TYPE_MAP.get(source, {})
    category, sev = mapping.get(raw_type, ("unknown", 1))
    return category, sev

# ----------------------------
# Source-specific normalizers
# ----------------------------

def normalize_firewall(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": data.get("event_type") or data.get("signature") or "UNKNOWN",
        "src_ip": data.get("src") or data.get("src_ip"),
        "dst_ip": data.get("dst") or data.get("dst_ip"),
        "src_port": to_int(data.get("spt") or data.get("src_port")),
        "dst_port": to_int(data.get("dpt") or data.get("dst_port")),
        "user": data.get("suser"),
        "host": data.get("shost") or data.get("dhost"),
        "vendor": data.get("vendor"),
        "product": data.get("product"),
    }

def normalize_av(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": data.get("event_type") or "AV_DETECT",
        "host": data.get("host"),
        "user": data.get("user"),
        "vendor": data.get("vendor"),
        "product": data.get("product"),
    }

def normalize_edr(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": data.get("event_type") or data.get("action") or "UNKNOWN",
        "host": data.get("host"),
        "user": data.get("user"),
        "src_ip": data.get("src_ip"),
        "dst_ip": data.get("dst_ip"),
        "src_port": to_int(data.get("src_port") or data.get("spt")),
        "dst_port": to_int(data.get("dst_port") or data.get("dpt")),
    }

def normalize_iam(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": data.get("event_type") or data.get("action") or "UNKNOWN",
        "user": data.get("user"),
        "host": data.get("host"),
        "src_ip": data.get("ip"),
    }

# ----------------------------
# Main dispatcher
# ----------------------------

def normalize(payload: Dict[str, Any], raw_id: str, received_at_iso: str) -> NormalizedEvent:
    source = (payload.get("source_type") or "unknown").lower()
    fmt = (payload.get("format") or "unknown").lower()
    raw_data = payload.get("data")

    fields: Dict[str, Any] = {}
    base: Dict[str, Any] = {}
    tags: list[str] = []

    if isinstance(raw_data, str) and fmt == "cef":
        fields = parse_cef(raw_data)
        if not fields:
            tags.append("parse_failed:cef")
    elif isinstance(raw_data, str) and fmt == "csv":
        fields = parse_csv(raw_data)
        if not fields:
            tags.append("parse_failed:csv")
    elif isinstance(raw_data, dict):
        fields = dict(raw_data)
    else:
        tags.append(f"unknown_format:{fmt}")

    if source == "firewall":
        base = normalize_firewall(fields)
    elif source == "av":
        base = normalize_av(fields)
    elif source == "edr":
        base = normalize_edr(fields)
    elif source == "iam":
        base = normalize_iam(fields)
    else:
        base = {}

    raw_event_type = base.get("event_type", "UNKNOWN")
    category, severity = map_event(source, raw_event_type)

    return NormalizedEvent(
        event_id=raw_id,
        received_at=to_utc(received_at_iso),
        parsed_at=datetime.now(timezone.utc),
        source_type=source,
        format=fmt,
        event_type=raw_event_type,
        event_category=category,
        severity=severity,
        src_ip=base.get("src_ip"),
        dst_ip=base.get("dst_ip"),
        src_port=to_int(base.get("src_port")),
        dst_port=to_int(base.get("dst_port")),
        host=base.get("host"),
        user=base.get("user"),
        vendor=base.get("vendor"),
        product=base.get("product"),
        message=str(raw_data),
        fields=fields,
        tags=tags,
    )
