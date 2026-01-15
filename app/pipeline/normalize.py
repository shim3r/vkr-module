import re
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from app.schemas.event import NormalizedEvent

# CEF:0|Vendor|Product|Version|EventID|Signature|Severity| key=val key=val
CEF_RE = re.compile(
    r"^CEF:(?P<ver>\d+)\|(?P<device_vendor>[^|]*)\|(?P<device_product>[^|]*)\|(?P<device_version>[^|]*)\|"
    r"(?P<event_id>[^|]*)\|(?P<signature>[^|]*)\|(?P<severity>\d+)\|(?P<ext>.*)$"
)

KV_RE = re.compile(r"(\w+)=([^\s]+)")

def _parse_cef(text: str) -> Tuple[Dict[str, Any], str, int, str]:
    """
    Возвращает (fields, event_type, severity, message)
    """
    text = text.strip()
    m = CEF_RE.match(text)
    if not m:
        return {}, "UNKNOWN", 1, text

    fields: Dict[str, Any] = {
        "cef_version": m.group("ver"),
        "device_vendor": m.group("device_vendor"),
        "device_product": m.group("device_product"),
        "device_version": m.group("device_version"),
        "cef_event_id": m.group("event_id"),
    }
    event_type = m.group("signature") or "UNKNOWN"
    try:
        severity = int(m.group("severity"))
    except Exception:
        severity = 1

    ext = m.group("ext") or ""
    for k, v in KV_RE.findall(ext):
        fields[k] = v

    return fields, event_type, max(1, min(10, severity)), text


def normalize(payload: Dict[str, Any], raw_id: str, received_at_iso: str) -> NormalizedEvent:
    source_type = (payload.get("source_type") or "unknown").lower()
    fmt = (payload.get("format") or "unknown").lower()
    data = payload.get("data")

    fields: Dict[str, Any] = {}
    event_type = "UNKNOWN"
    severity = 1
    message = None

    if isinstance(data, dict):
        fields = dict(data)
        message = str(data.get("message") or data.get("msg") or "")
        event_type = str(data.get("event_type") or data.get("signature") or "UNKNOWN")
        try:
            severity = int(data.get("severity", 1))
        except Exception:
            severity = 1
    else:
        text = str(data or "")
        message = text
        if fmt == "cef" and text.startswith("CEF:"):
            fields, event_type, severity, message = _parse_cef(text)

    # Вытаскиваем типовые поля из extensions (как в твоём raw: src/dst/suser)
    src_ip = fields.get("src") or fields.get("src_ip")
    dst_ip = fields.get("dst") or fields.get("dst_ip")
    host = fields.get("host") or fields.get("dhost") or fields.get("shost")
    user = fields.get("suser") or fields.get("user")

    received_at = datetime.fromisoformat(received_at_iso)
    parsed_at = datetime.now(timezone.utc)

    return NormalizedEvent(
        event_id=raw_id,
        received_at=received_at,
        parsed_at=parsed_at,
        source_type=source_type,
        format=fmt,
        event_type=event_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        host=host,
        user=user,
        message=message,
        fields=fields,
        tags=[],
    )
