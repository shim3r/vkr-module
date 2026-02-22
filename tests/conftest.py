"""
Pytest fixtures for SIEM module tests.
"""
import pytest
from app.services.events_store import clear_events
from app.services.alerts_store import clear_alerts
from app.services.incidents_store import clear_incidents
from app.services.aggregates_store import reset_aggregates


@pytest.fixture(autouse=True)
def clear_stores():
    """Clear all in-memory stores before each test to ensure isolation."""
    clear_events()
    clear_alerts()
    clear_incidents()
    reset_aggregates()
    yield
    clear_events()
    clear_alerts()
    clear_incidents()
    reset_aggregates()


# ─── Sample payloads ─────────────────────────────────────────────────────────

@pytest.fixture
def firewall_cef_payload():
    return {
        "source_type": "firewall",
        "format": "cef",
        "data": (
            "CEF:0|CheckPoint|VPN-1|R77|VPN_LOGIN_FAIL|VPN login failure|7|"
            "src=1.2.3.4 dst=10.0.0.1 spt=54321 dpt=443 suser=bob"
        ),
    }


@pytest.fixture
def av_cef_payload():
    return {
        "source_type": "av",
        "format": "cef",
        "data": (
            "CEF:0|Kaspersky|AV|9.0|AV_DETECT|Malware detected|9|"
            "host=ws-eng-01 suser=alice file=evil.exe malware=Trojan.Generic"
        ),
    }


@pytest.fixture
def edr_json_payload():
    return {
        "source_type": "edr",
        "format": "json",
        "data": {
            "event_type": "EDR_SUSPICIOUS_PROCESS",
            "host": "ws-eng-01",
            "user": "alice",
            "src_ip": "10.1.1.50",
            "process": "powershell.exe",
        },
    }


@pytest.fixture
def iam_csv_payload():
    return {
        "source_type": "iam",
        "format": "csv",
        "data": "2026-01-28T10:00:00,bob,LOGIN_FAIL,ip=1.2.3.4",
    }


@pytest.fixture
def arm_json_payload():
    return {
        "source_type": "arm",
        "format": "json",
        "data": {
            "EventID": "4625",
            "Computer": "dc-01",
            "SubjectUserName": "charlie",
            "IpAddress": "10.0.0.20",
            "LogonType": "3",
        },
    }
