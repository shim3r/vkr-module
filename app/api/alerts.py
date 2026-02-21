from fastapi import APIRouter, Query

from app.services.events_store import count_events
from app.services.alerts_store import list_alerts, count_alerts
from app.services.incidents_store import count_incidents
from app.services.reporting import full_report, incidents_count, fp_rate, mean_time_to_resolve

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

@router.get("/reports")
def get_reports(period_hours: int = Query(24, ge=1, le=8760)):
    """SOC-level reporting: incident counts, FP-rate, MTTR."""
    return full_report(period_hours=period_hours)

@router.get("/reports/incidents")
def get_report_incidents(period_hours: int = Query(24, ge=1, le=8760)):
    return incidents_count(period_hours=period_hours)

@router.get("/reports/fp-rate")
def get_report_fp_rate():
    return fp_rate()

@router.get("/reports/mttr")
def get_report_mttr():
    return mean_time_to_resolve()
