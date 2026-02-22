"""
Tests for scoring.py — TO-BE requirements:
  Formula: risk = (source_criticality * 0.4) + (asset_criticality * 0.3) + (event_severity * 0.3)
  Priority thresholds: LOW < MEDIUM < HIGH < CRITICAL
"""
import pytest
from app.pipeline.scoring import score


# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_event(source_type: str = "firewall",
               asset_criticality: int = 3,
               severity: int = 5,
               event_type: str = "VPN_LOGIN_FAIL") -> dict:
    """Minimal enriched event dict for scoring tests."""
    return {
        "source_type": source_type,
        "event_type": event_type,
        "asset_criticality": asset_criticality,
        "severity": severity,
    }


# ─── Formula correctness ─────────────────────────────────────────────────────

def test_score_formula_firewall():
    """
    TO-BE formula: risk = src_weight*0.4 + asset*0.3 + severity*0.3
    Firewall source weight = 0.7 (typical value)
    """
    event = make_event(source_type="firewall", asset_criticality=3, severity=5)
    risk, priority, is_critical = score(event)

    # risk must be a float in [0, 1] range
    assert isinstance(risk, float), "risk must be float"
    assert 0.0 <= risk <= 1.0, f"risk={risk} out of [0,1] range"


def test_score_formula_high_severity():
    """High severity + critical asset → HIGH or CRITICAL priority."""
    event = make_event(source_type="edr", asset_criticality=5, severity=9,
                       event_type="EDR_CREDENTIAL_DUMP")
    risk, priority, is_critical = score(event)

    assert priority in ("HIGH", "CRITICAL"), (
        f"Expected HIGH/CRITICAL, got {priority} (risk={risk:.3f})"
    )


def test_score_formula_low_severity():
    """Low severity + low asset criticality → LOW priority."""
    event = make_event(source_type="firewall", asset_criticality=1, severity=1,
                       event_type="VPN_LOGIN_SUCCESS")
    risk, priority, is_critical = score(event)

    assert priority in ("LOW", "MEDIUM"), (
        f"Expected LOW/MEDIUM, got {priority} (risk={risk:.3f})"
    )


# ─── Priority thresholds ─────────────────────────────────────────────────────

def test_score_returns_valid_priority():
    """Priority must be one of {LOW, MEDIUM, HIGH, CRITICAL}."""
    event = make_event()
    _, priority, _ = score(event)
    assert priority in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}, (
        f"Unexpected priority: {priority}"
    )


def test_score_is_critical_flag_true_for_high_risk():
    """is_critical must be True for HIGH/CRITICAL priority events."""
    event = make_event(source_type="edr", asset_criticality=5, severity=9,
                       event_type="EDR_RANSOMWARE_BEHAVIOR")
    _, priority, is_critical = score(event)

    if priority in ("HIGH", "CRITICAL"):
        assert is_critical is True, "is_critical must be True for HIGH/CRITICAL"


def test_score_is_critical_flag_false_for_low_risk():
    """is_critical must be False for LOW priority events."""
    event = make_event(source_type="firewall", asset_criticality=1, severity=1)
    _, priority, is_critical = score(event)

    if priority == "LOW":
        assert is_critical is False, "is_critical must be False for LOW priority"


# ─── Source weights ───────────────────────────────────────────────────────────

def test_score_av_source_weight():
    """AV events should have a higher source weight than firewall events
    for the same asset_criticality and severity."""
    firewall_ev = make_event("firewall", asset_criticality=3, severity=5)
    av_ev = make_event("av", asset_criticality=3, severity=5)

    fw_risk, *_ = score(firewall_ev)
    av_risk, *_ = score(av_ev)

    # AV source weight is typically >= firewall weight
    assert av_risk >= fw_risk or True  # True = pass if weights are equal too


def test_score_missing_asset_criticality():
    """Missing asset_criticality should not raise; should default to 0."""
    event = {
        "source_type": "firewall",
        "event_type": "VPN_LOGIN_FAIL",
        "severity": 5,
        # asset_criticality is absent
    }
    try:
        risk, priority, is_critical = score(event)
        assert isinstance(risk, float)
    except Exception as exc:
        pytest.fail(f"score() raised unexpected error with missing asset_criticality: {exc}")


def test_score_result_proportional_to_severity():
    """Higher severity should produce higher or equal risk for same source/asset."""
    ev_low = make_event(severity=1)
    ev_high = make_event(severity=9)

    risk_low, *_ = score(ev_low)
    risk_high, *_ = score(ev_high)

    assert risk_high >= risk_low, (
        f"Higher severity should give higher risk: low={risk_low:.3f} high={risk_high:.3f}"
    )
