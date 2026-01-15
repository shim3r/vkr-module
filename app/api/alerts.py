from fastapi import APIRouter
from app.services.alerts_store import list_alerts

router = APIRouter(tags=["alerts"])

@router.get("/alerts")
def get_alerts(limit: int = 50):
    return {"items": list_alerts(limit=limit)}
