"""
Integrations API router.

Endpoints:
  POST /api/webhooks/test        — test a webhook endpoint synchronously
  GET  /api/integrations/status  — current integration configuration status
"""

from fastapi import APIRouter, Body
from typing import Optional

router = APIRouter(tags=["integrations"])


@router.post("/webhooks/test")
def test_webhook(payload: dict = Body(...)):
    """
    Test a webhook endpoint synchronously.

    Body: {"url": "http://...", "message": "optional test message"}

    Returns: {"success": bool, "status_code": int|null, "error": str|null}
    """
    from app.integrations import test_webhook as _test
    url = payload.get("url", "")
    if not url:
        return {"success": False, "status_code": None, "error": "url is required"}
    return _test(url)


@router.get("/integrations/status")
def integration_status():
    """
    Return current integration configuration status.
    """
    from app.integrations import get_config
    cfg = get_config()
    return {
        "enabled": cfg.enabled,
        "webhook_url": cfg.webhook_url or None,
        "timeout_seconds": cfg.timeout_seconds,
    }
