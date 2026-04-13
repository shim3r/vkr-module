from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.pipeline.playbooks import _DB

logger = logging.getLogger("siem.api.playbooks")

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


# ---------------------------------------------------------------------------
# Pydantic models for validation
# ---------------------------------------------------------------------------

class PlaybookCondition(BaseModel):
    type_in: List[str] = Field(default_factory=list, description="Типы инцидентов для срабатывания")
    severity_in: List[str] = Field(default_factory=list, description="Уровни severity для срабатывания")


class PlaybookAction(BaseModel):
    type: Literal["block_ip", "isolate_host", "disable_user"] = Field(..., description="Тип действия")
    target_field: Literal["src_ip", "host", "user"] = Field(..., description="Поле инцидента с целью")


class PlaybookCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Название плейбука")
    description: str = Field("", max_length=1000, description="Описание")
    enabled: bool = Field(True, description="Включен ли плейбук")
    condition: PlaybookCondition = Field(default_factory=PlaybookCondition)
    actions: List[PlaybookAction] = Field(default_factory=list, description="Список действий")


class PlaybookUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    enabled: Optional[bool] = None
    condition: Optional[PlaybookCondition] = None
    actions: Optional[List[PlaybookAction]] = None


class PlaybookToggleRequest(BaseModel):
    enabled: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def get_playbooks():
    """Возвращает список всех плейбуков SOAR."""
    return {"items": _DB.get_all()}


@router.get("/{pb_id}")
def get_playbook(pb_id: str):
    """Возвращает один плейбук по ID."""
    for pb in _DB.get_all():
        if pb.get("id") == pb_id:
            return pb
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.post("/")
def create_playbook(req: PlaybookCreateRequest):
    """Создать новый плейбук SOAR."""
    pb_id = f"pb_{uuid4().hex[:8]}"
    pb = {
        "id": pb_id,
        "name": req.name,
        "description": req.description,
        "enabled": req.enabled,
        "condition": req.condition.model_dump(),
        "actions": [a.model_dump() for a in req.actions],
    }
    _DB.add(pb)
    logger.info("[PLAYBOOKS] Created playbook %s: %s", pb_id, req.name)
    return {"status": "created", "playbook": pb}


@router.put("/{pb_id}")
def update_playbook(pb_id: str, req: PlaybookUpdateRequest):
    """Полное обновление плейбука (имя, описание, условия, действия, enabled)."""
    for pb in _DB.get_all():
        if pb.get("id") == pb_id:
            updates: Dict[str, Any] = {}
            if req.name is not None:
                updates["name"] = req.name
            if req.description is not None:
                updates["description"] = req.description
            if req.enabled is not None:
                updates["enabled"] = req.enabled
            if req.condition is not None:
                updates["condition"] = req.condition.model_dump()
            if req.actions is not None:
                updates["actions"] = [a.model_dump() for a in req.actions]

            _DB.update(pb_id, updates)
            logger.info("[PLAYBOOKS] Updated playbook %s", pb_id)
            # Return updated playbook
            for p in _DB.get_all():
                if p.get("id") == pb_id:
                    return {"status": "updated", "playbook": p}
            return {"status": "updated"}
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.patch("/{pb_id}")
def toggle_playbook(pb_id: str, req: PlaybookToggleRequest):
    """Включить или выключить плейбук."""
    for pb in _DB.get_all():
        if pb.get("id") == pb_id:
            _DB.update(pb_id, {"enabled": req.enabled})
            return {"status": "ok", "enabled": req.enabled}
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.delete("/{pb_id}")
def delete_playbook(pb_id: str):
    """Удалить плейбук."""
    for pb in _DB.get_all():
        if pb.get("id") == pb_id:
            _DB.delete(pb_id)
            logger.info("[PLAYBOOKS] Deleted playbook %s", pb_id)
            return {"status": "deleted", "id": pb_id}
    raise HTTPException(status_code=404, detail="Playbook not found")
