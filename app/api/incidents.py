from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.services.incidents_store import list_incidents, get_incident, update_incident

router = APIRouter(tags=["incidents"])

@router.get("/incidents")
def get_incidents(limit: int = 50) -> dict:
    return {"items": list_incidents(limit=limit)}


@router.get("/incidents/{incident_id}")
def get_incident_by_id(incident_id: str):
    inc = get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    return inc


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    comment: Optional[str] = None


@router.patch("/incidents/{incident_id}")
def patch_incident(incident_id: str, payload: IncidentUpdate):
    updated = update_incident(
        incident_id,
        status=payload.status,
        assignee=payload.assignee,
        comment=payload.comment,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="incident not found")
    return updated
