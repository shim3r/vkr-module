from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
from uuid import uuid4
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
        "AV_QUARANTINE": ("malware", 6),
        "AV_CLEAN_FAIL": ("malware", 8),
        "AV_DISABLED": ("defense_evasion", 9),
    },
    "edr": {
        "PROCESS_START": ("process", 4),
        "NETWORK_CONNECTION": ("network", 5),
        "CREDENTIAL_DUMP": ("process", 9),
        "EDR_SUSPICIOUS_PROCESS": ("process", 7),
        "EDR_CREDENTIAL_DUMP": ("process", 9),
        "EDR_LATERAL_TOOL": ("lateral_movement", 8),
        "EDR_REMOTE_SERVICE_CREATE": ("lateral_movement", 8),
        "EDR_RANSOMWARE_BEHAVIOR": ("malware", 9),
        "EDR_BLOCK": ("edr", 7),
    },
    "iam": {
        "LOGIN_FAIL": ("authentication", 6),
        "LOGIN_SUCCESS": ("authentication", 3),
        "ACCOUNT_LOCK": ("account", 8),
    },
    # Windows Event Logs / ARM (Azure Resource Manager / Windows logs)
    "arm": {
        "4624": ("authentication", 3),   # Logon Success
        "4625": ("authentication", 7),   # Logon Failure
        "4648": ("authentication", 6),   # Logon with explicit credentials
        "4672": ("privilege", 6),        # Special privileges assigned
        "4688": ("process", 4),          # Process creation
        "4698": ("persistence", 8),      # Scheduled task created
        "4720": ("account", 7),          # User account created
        "4726": ("account", 8),          # User account deleted
        "4769": ("authentication", 5),   # Kerberos TGS request
        "4776": ("authentication", 6),   # NTLM authentication attempt
        "7045": ("persistence", 8),      # New service installed
        "LOGON_SUCCESS": ("authentication", 3),
        "LOGON_FAILURE": ("authentication", 7),
        "PROCESS_CREATE": ("process", 4),
        "SERVICE_INSTALL": ("persistence", 8),
    },
}

# ----------------------------
# CEF parsing
# ----------------------------

CEF_RE = re.compile(
    r"^CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<event_id>[^|]*)\|(?P<signature>[^|]*)\|(?P<severity>\d+)\|(?P<ext>.*)$"
)

# Supports both key=value and key="value with spaces"
KV_RE = re.compile(r"(\w+)=\"([^\"]*)\"|(\w+)=([^\s]+)")

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
    for m2 in KV_RE.finditer(ext):
        if m2.group(1):
            # quoted: key="value with spaces"
            k, v = m2.group(1), m2.group(2)
        else:
            # unquoted: key=value
            k, v = m2.group(3), m2.group(4)
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

def to_int(value: Any) -> Optional[int]:
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
        "host": data.get("host") or data.get("dhost") or data.get("shost"),
        "user": data.get("suser") or data.get("user"),
        "vendor": data.get("vendor"),
        "product": data.get("product"),
        # keep extra useful fields in base when present
        "file": data.get("file"),
        "malware": data.get("malware"),
        "action": data.get("action"),
        "reason": data.get("reason"),
    }

def normalize_edr(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": data.get("event_type") or data.get("action") or "UNKNOWN",
        "host": data.get("host") or data.get("dhost") or data.get("shost"),
        "user": data.get("suser") or data.get("user"),
        "src_ip": data.get("src") or data.get("src_ip"),
        "dst_ip": data.get("dst") or data.get("dst_ip"),
        "src_port": to_int(data.get("src_port") or data.get("spt")),
        "dst_port": to_int(data.get("dst_port") or data.get("dpt")),
        # extra EDR context
        "process": data.get("process"),
        "cmd": data.get("cmd") or data.get("cmdline"),
        "tool": data.get("tool"),
        "technique": data.get("technique"),
        "action": data.get("action"),
        "dhost": data.get("dhost"),
    }

def normalize_iam(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_type": data.get("event_type") or data.get("action") or "UNKNOWN",
        "user": data.get("user"),
        "host": data.get("host"),
        "src_ip": data.get("ip"),
    }


def normalize_arm(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Windows Event Logs (ARM/Azure Resource Manager).

    Supports both:
      - Structured JSON (from Windows Security event log collector)
      - Key-value flat format: EventID, Computer, SubjectUserName, IpAddress, etc.
    """
    event_id = str(data.get("EventID") or data.get("event_id") or "")
    event_type = data.get("event_type")
    if not event_type:
        # Map numeric Windows Event IDs to canonical type names
        _win_type_map = {
            "4624": "LOGON_SUCCESS",
            "4625": "LOGON_FAILURE",
            "4648": "LOGON_EXPLICIT_CREDS",
            "4672": "SPECIAL_PRIVILEGES",
            "4688": "PROCESS_CREATE",
            "4698": "SCHEDULED_TASK_CREATED",
            "4720": "ACCOUNT_CREATED",
            "4726": "ACCOUNT_DELETED",
            "4769": "KERBEROS_TGS",
            "4776": "NTLM_AUTH",
            "7045": "SERVICE_INSTALL",
        }
        event_type = _win_type_map.get(event_id, event_id or "UNKNOWN")

    return {
        "event_type": event_type,
        "host": (
            data.get("host") or data.get("Computer")
            or data.get("WorkstationName") or data.get("hostname")
        ),
        "user": (
            data.get("user") or data.get("SubjectUserName")
            or data.get("TargetUserName") or data.get("username")
        ),
        "src_ip": (
            data.get("src_ip") or data.get("IpAddress")
            or data.get("ClientAddress")
        ),
        "dst_ip": data.get("dst_ip"),
        "process": data.get("NewProcessName") or data.get("ProcessName"),
        "windows_event_id": event_id,
        "logon_type": data.get("LogonType"),
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
    elif source == "arm":
        base = normalize_arm(fields)
    else:
        base = {}

    raw_event_type = base.get("event_type", "UNKNOWN")
    category, severity = map_event(source, raw_event_type)

    # quick tags for filtering
    if source in {"av", "edr"}:
        act = str(base.get("action") or "").lower()
        if act:
            tags.append(f"action:{act}")
        if base.get("malware"):
            tags.append("marker:malware")
        if base.get("tool"):
            tags.append(f"tool:{str(base.get('tool')).lower()}")
        if base.get("technique"):
            tags.append(f"tech:{str(base.get('technique')).lower()}")

    received_dt = to_utc(received_at_iso)
    dst_ip_val = base.get("dst_ip")

    return NormalizedEvent(
        id=str(uuid4()),
        raw_event_id=raw_id,
        event_id=raw_id,
        timestamp_utc=received_dt,
        received_at=received_dt,
        parsed_at=datetime.now(timezone.utc),
        source_type=source,
        format=fmt,
        event_type=raw_event_type,
        event_category=category,
        severity=severity,
        src_ip=base.get("src_ip"),
        dst_ip=dst_ip_val,
        dest_ip=dst_ip_val,
        src_port=to_int(base.get("src_port")),
        dst_port=to_int(base.get("dst_port")),
        host=base.get("host"),
        user=base.get("user"),
        vendor=base.get("vendor"),
        product=base.get("product"),
        message=str(raw_data),
        fields={**fields, **{k: v for k, v in base.items() if k not in {"event_type", "src_ip", "dst_ip", "src_port", "dst_port", "host", "user", "vendor", "product"} and v is not None}},
        tags=tags,
    )
