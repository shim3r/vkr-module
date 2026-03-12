"""
API роутер — активное реагирование (Active Response).

Эндпоинты:
  GET  /api/response/actions          — журнал всех действий
  GET  /api/response/status           — текущие блокировки (IP/хосты/пользователи)
  POST /api/response/block-ip         — ручная блокировка IP
  POST /api/response/isolate-host     — ручная изоляция хоста
  POST /api/response/disable-user     — ручная деактивация пользователя
  DELETE /api/response/actions/{id}   — отзыв действия (снятие блокировки)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.response_engine import (
    list_actions,
    get_block_status,
    manually_block_ip,
    manually_isolate_host,
    manually_disable_user,
    revoke_action,
)

router = APIRouter(prefix="/api/response", tags=["response"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = "manual"
    actor: Optional[str] = "analyst"


class IsolateHostRequest(BaseModel):
    host: str
    reason: Optional[str] = "manual"
    actor: Optional[str] = "analyst"


class DisableUserRequest(BaseModel):
    user: str
    reason: Optional[str] = "manual"
    actor: Optional[str] = "analyst"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/actions")
def get_actions(limit: int = 100):
    """Вернуть журнал последних действий реагирования."""
    return {"actions": list_actions(limit=limit)}


@router.get("/status")
def get_status():
    """Вернуть текущий статус блокировок (IP, хосты, пользователи)."""
    return get_block_status()


@router.post("/block-ip", status_code=201)
def block_ip(req: BlockIPRequest):
    """Ручная блокировка IP-адреса."""
    if not req.ip:
        raise HTTPException(status_code=400, detail="ip is required")
    action = manually_block_ip(ip=req.ip, reason=req.reason or "manual", actor=req.actor or "analyst")
    return {"status": "ok", "action": action}


@router.post("/isolate-host", status_code=201)
def isolate_host(req: IsolateHostRequest):
    """Ручная изоляция хоста."""
    if not req.host:
        raise HTTPException(status_code=400, detail="host is required")
    action = manually_isolate_host(host=req.host, reason=req.reason or "manual", actor=req.actor or "analyst")
    return {"status": "ok", "action": action}


@router.post("/disable-user", status_code=201)
def disable_user(req: DisableUserRequest):
    """Ручная деактивация учётной записи пользователя."""
    if not req.user:
        raise HTTPException(status_code=400, detail="user is required")
    action = manually_disable_user(user=req.user, reason=req.reason or "manual", actor=req.actor or "analyst")
    return {"status": "ok", "action": action}


@router.delete("/actions/{action_id}")
def revoke(action_id: str):
    """Отозвать действие реагирования (снять блокировку/изоляцию)."""
    action = revoke_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    return {"status": "revoked", "action": action}
