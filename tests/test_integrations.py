"""
Tests for integrations.py — TO-BE requirements:
  - Integration layer must be separate from business logic
  - send_webhook() dispatches POST request
  - test_webhook() returns success/failure synchronously
  - send_notification() logs structured messages
"""
import pytest
from unittest.mock import patch, MagicMock
from app.integrations import (
    send_webhook,
    test_webhook,
    send_notification,
    configure,
    get_config,
)


# ─── Configuration ───────────────────────────────────────────────────────────

def test_get_config_returns_config():
    cfg = get_config()
    assert cfg is not None
    assert hasattr(cfg, "webhook_url")
    assert hasattr(cfg, "timeout_seconds")
    assert hasattr(cfg, "enabled")


def test_configure_updates_settings():
    configure(webhook_url="http://test-hook.local/events", timeout=5.0, enabled=True)
    cfg = get_config()
    assert cfg.webhook_url == "http://test-hook.local/events"
    assert cfg.timeout_seconds == 5.0
    assert cfg.enabled is True


# ─── send_webhook — fire-and-forget ──────────────────────────────────────────

def test_send_webhook_dispatches_to_url():
    """send_webhook must POST the payload to the target URL in a background thread."""
    payload = {"incident_id": "INC-TEST-001", "severity": "HIGH"}

    with patch("app.integrations.threading.Thread") as mock_thread_cls:
        mock_thread = MagicMock()
        mock_thread_cls.return_value = mock_thread

        configure(webhook_url="http://webhook.test/hook", enabled=True)
        send_webhook(payload)

        mock_thread_cls.assert_called_once()
        mock_thread.start.assert_called_once()


def test_send_webhook_no_op_when_disabled():
    """send_webhook must not dispatch when enabled=False."""
    configure(webhook_url="http://hook.test/disabled", enabled=False)

    with patch("app.integrations.threading.Thread") as mock_thread_cls:
        send_webhook({"test": "data"})
        mock_thread_cls.assert_not_called()


def test_send_webhook_no_op_when_no_url():
    """send_webhook must not dispatch when webhook_url is None."""
    configure(webhook_url=None, enabled=True)

    with patch("app.integrations.threading.Thread") as mock_thread_cls:
        send_webhook({"test": "data"})
        mock_thread_cls.assert_not_called()


# ─── test_webhook — synchronous ──────────────────────────────────────────────

def test_test_webhook_success():
    """test_webhook must return success dict on 2xx response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.is_success = True

    with patch("app.integrations.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response

        result = test_webhook("http://hook.test/success")

        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["error"] is None


def test_test_webhook_failure():
    """test_webhook must return failure dict on connection error."""
    with patch("app.integrations.httpx") as mock_httpx:
        mock_httpx.Client.return_value.__enter__ = MagicMock(
            side_effect=Exception("Connection refused")
        )

        result = test_webhook("http://hook.test/unreachable")

        assert result["success"] is False
        assert result["error"] is not None
        assert "Connection refused" in result["error"] or result["error"]


def test_test_webhook_returns_correct_structure():
    """test_webhook must always return dict with success, status_code, error keys."""
    with patch("app.integrations.httpx") as mock_httpx:
        mock_httpx.Client.return_value.__enter__ = MagicMock(
            side_effect=Exception("timeout")
        )

        result = test_webhook("http://any-url.test")

        assert "success" in result
        assert "status_code" in result
        assert "error" in result


# ─── send_notification ───────────────────────────────────────────────────────

def test_send_notification_does_not_crash():
    """send_notification must not raise for any level."""
    configure(webhook_url=None, enabled=False)  # disable webhook for pure unit test

    for level in ("debug", "info", "warning", "error", "critical"):
        try:
            send_notification(f"Test {level} notification", level=level)
        except Exception as exc:
            pytest.fail(f"send_notification raised for level={level}: {exc}")


def test_send_notification_with_context():
    """send_notification must handle context dict."""
    configure(webhook_url=None, enabled=False)
    try:
        send_notification(
            "Incident created",
            level="warning",
            context={"incident_id": "INC-001", "severity": "HIGH"},
        )
    except Exception as exc:
        pytest.fail(f"send_notification with context raised: {exc}")
