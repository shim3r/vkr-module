from fastapi import APIRouter
from app.services.incidents_store import list_incidents

router = APIRouter(tags=["incidents"])

@router.get("/incidents")
def get_incidents(limit: int = 50):
    return {"items": list_incidents(limit=limit)}
