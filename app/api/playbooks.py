from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.pipeline.playbooks import _DB

logger = logging.getLogger("siem.api.playbooks")

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


class PlaybookToggleRequest(BaseModel):
    enabled: bool


@router.get("/")
def get_playbooks():
    """Возвращает список всех плейбуков SOAR."""
    return {"items": _DB.get_all()}


@router.patch("/{pb_id}")
def toggle_playbook(pb_id: str, req: PlaybookToggleRequest):
    """Включить или выключить плейбук."""
    for pb in _DB.get_all():
        if pb.get("id") == pb_id:
            _DB.update(pb_id, {"enabled": req.enabled})
            return {"status": "ok", "enabled": req.enabled}
    raise HTTPException(status_code=404, detail="Playbook not found")
