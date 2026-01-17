from fastapi import APIRouter

from app.services.events_store import count_events
from app.services.alerts_store import list_alerts, count_alerts
from app.services.incidents_store import count_incidents

router = APIRouter(tags=["alerts"])

@router.get("/alerts")
def get_alerts(limit: int = 50):
    return {"items": list_alerts(limit=limit)}

@router.get("/metrics")
def get_metrics():
    return {
        "events": count_events(),
        "alerts": count_alerts(),
        "incidents": count_incidents(),
    }