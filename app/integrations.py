"""
Integration layer — outbound notifications and webhook dispatch.

TO-BE requirement: dedicated integration module, separate from business logic.

Supports:
  - Webhook (HTTP POST to configurable URL)
  - Notification messages (log + future channels)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("siem.integrations")

try:
    from app.config import WEBHOOK_URL as _DEFAULT_WEBHOOK_URL
except Exception:
    _DEFAULT_WEBHOOK_URL = None


@dataclass
class IntegrationConfig:
    webhook_url: Optional[str] = field(default_factory=lambda: _DEFAULT_WEBHOOK_URL)
    timeout_seconds: float = 10.0
    enabled: bool = True


# Module-level config (can be overridden at runtime)
_config = IntegrationConfig()


def get_config() -> IntegrationConfig:
    return _config


def configure(webhook_url: Optional[str] = None, timeout: float = 10.0, enabled: bool = True) -> None:
    """Update integration settings at runtime."""
    global _config
    _config = IntegrationConfig(
        webhook_url=webhook_url or _DEFAULT_WEBHOOK_URL,
        timeout_seconds=timeout,
        enabled=enabled,
    )


def send_webhook(payload: Dict[str, Any], url: Optional[str] = None) -> None:
    """
    Send JSON payload to a webhook URL asynchronously (fire-and-forget).

    Used for: incident creation notifications, alert escalations, etc.
    """
    cfg = _config
    target_url = url or cfg.webhook_url
    if not target_url or not cfg.enabled:
        return

    def _post() -> None:
        try:
            import httpx
            with httpx.Client(timeout=cfg.timeout_seconds) as client:
                resp = client.post(target_url, json=payload)
                logger.info(
                    "[INTEGRATIONS] Webhook sent to %s status=%d",
                    target_url,
                    resp.status_code,
                )
        except Exception as exc:
            logger.warning("[INTEGRATIONS] Webhook failed: %s", exc)

    t = threading.Thread(target=_post, daemon=True)
    t.start()


def send_notification(message: str, level: str = "info", context: Optional[Dict[str, Any]] = None) -> None:
    """
    Send a structured notification message.

    Currently: structured log output.
    Future: Telegram, email, ServiceDesk integration via channel adapters.
    """
    payload: Dict[str, Any] = {
        "message": message,
        "level": level.upper(),
        "context": context or {},
    }

    log_fn = {
        "debug": logger.debug,
        "info": logger.info,
        "warning": logger.warning,
        "error": logger.error,
        "critical": logger.critical,
    }.get(level.lower(), logger.info)

    log_fn("[NOTIFICATION] %s | %s", level.upper(), message)

    # Also dispatch to webhook if configured
    if _config.webhook_url and _config.enabled:
        send_webhook(payload)


def test_webhook(url: str) -> Dict[str, Any]:
    """
    Synchronously test a webhook endpoint.
    Returns {"success": bool, "status_code": int | None, "error": str | None}
    """
    try:
        import httpx
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json={"event": "webhook_test", "source": "siem"})
            return {"success": resp.is_success, "status_code": resp.status_code, "error": None}
    except Exception as exc:
        return {"success": False, "status_code": None, "error": str(exc)}
