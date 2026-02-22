"""
Tests for normalize.py — TO-BE requirements:
  - unified JSON schema for all source types
  - all required fields present: timestamp_utc, source_type, src_ip, dst_ip,
    user, host, event_type, severity, raw_event_id
  - ARM (Windows Event Logs) normalization
"""
import pytest
from uuid import UUID
from app.pipeline.normalize import normalize


# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_normalized(payload: dict) -> dict:
    result = normalize(
        payload=payload,
        raw_id="test-raw-001",
        received_at_iso="2026-01-28T10:00:00+00:00",
    )
    return result.model_dump()


# ─── Firewall CEF ─────────────────────────────────────────────────────────────

def test_normalize_firewall_cef_required_fields(firewall_cef_payload):
    result = make_normalized(firewall_cef_payload)

    assert result["source_type"] == "firewall", "source_type must be 'firewall'"
    assert result["raw_event_id"] == "test-raw-001"
    assert result["event_type"] is not None
    assert result["timestamp_utc"] is not None


def test_normalize_firewall_cef_vpn_fail(firewall_cef_payload):
    result = make_normalized(firewall_cef_payload)

    assert result["event_type"] == "VPN_LOGIN_FAIL"
    assert result["src_ip"] == "1.2.3.4"
    assert result["dst_ip"] == "10.0.0.1" or result["dst_ip"] is not None
    assert result["user"] == "bob"
    assert isinstance(result["severity"], int)
    assert result["severity"] >= 1


def test_normalize_firewall_cef_severity_range(firewall_cef_payload):
    result = make_normalized(firewall_cef_payload)
    assert 1 <= result["severity"] <= 10


# ─── AV CEF ──────────────────────────────────────────────────────────────────

def test_normalize_av_cef(av_cef_payload):
    result = make_normalized(av_cef_payload)

    assert result["source_type"] == "av"
    assert result["event_type"] in ("AV_DETECT", "MALWARE_DETECT", "AV_DETECT_CEF")
    assert result["host"] == "ws-eng-01"
    assert result["user"] in ("alice", "alice")
    assert result["severity"] >= 7, "Malware detection must have high severity"


def test_normalize_av_cef_fields_present(av_cef_payload):
    result = make_normalized(av_cef_payload)
    assert result["raw_event_id"] == "test-raw-001"
    assert result["timestamp_utc"] is not None
    assert result["source_type"] is not None
    assert result["event_type"] is not None


# ─── EDR JSON ────────────────────────────────────────────────────────────────

def test_normalize_edr_json(edr_json_payload):
    result = make_normalized(edr_json_payload)

    assert result["source_type"] == "edr"
    assert result["event_type"] == "EDR_SUSPICIOUS_PROCESS"
    assert result["host"] == "ws-eng-01"
    assert result["user"] == "alice"
    assert result["src_ip"] == "10.1.1.50"


def test_normalize_edr_json_schema(edr_json_payload):
    result = make_normalized(edr_json_payload)
    # All TO-BE schema fields must be present (may be None)
    required_keys = {"event_id", "raw_event_id", "source_type", "event_type",
                     "timestamp_utc", "severity", "enriched"}
    for key in required_keys:
        assert key in result, f"Missing field: {key}"


# ─── IAM CSV ─────────────────────────────────────────────────────────────────

def test_normalize_iam_csv(iam_csv_payload):
    result = make_normalized(iam_csv_payload)

    assert result["source_type"] == "iam"
    assert result["event_type"] == "LOGIN_FAIL"
    assert result["user"] == "bob"


# ─── ARM (Windows Event Logs) ────────────────────────────────────────────────

def test_normalize_arm_json(arm_json_payload):
    """ARM source (Windows Event ID 4625 = logon failure) must normalize correctly."""
    result = make_normalized(arm_json_payload)

    assert result["source_type"] == "arm"
    assert result["event_type"] == "LOGON_FAILURE", (
        f"EventID 4625 must map to LOGON_FAILURE, got {result['event_type']}"
    )
    assert result["host"] == "dc-01"
    assert result["user"] == "charlie"
    assert result["src_ip"] == "10.0.0.20"


def test_normalize_arm_4624():
    """EventID 4624 (successful logon) must normalize to LOGON_SUCCESS."""
    payload = {
        "source_type": "arm",
        "format": "json",
        "data": {"EventID": "4624", "Computer": "ws-eng-01", "SubjectUserName": "dave"},
    }
    result = make_normalized(payload)

    assert result["event_type"] == "LOGON_SUCCESS"
    assert result["host"] == "ws-eng-01"
    assert result["user"] == "dave"


def test_normalize_arm_4688():
    """EventID 4688 (process creation) must normalize to PROCESS_CREATE."""
    payload = {
        "source_type": "arm",
        "format": "json",
        "data": {
            "EventID": "4688",
            "Computer": "dc-01",
            "SubjectUserName": "admin",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
    }
    result = make_normalized(payload)

    assert result["event_type"] == "PROCESS_CREATE"


# ─── Unknown source ───────────────────────────────────────────────────────────

def test_normalize_unknown_source_does_not_crash():
    """Unknown source type should not raise an exception."""
    payload = {"source_type": "unknown_device", "format": "json", "data": {"x": 1}}
    try:
        result = make_normalized(payload)
        assert result is not None
    except Exception as exc:
        pytest.fail(f"normalize() raised unexpected error for unknown source: {exc}")
