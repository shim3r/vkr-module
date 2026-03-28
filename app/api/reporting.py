"""
Reporting API router.

Endpoints:
  GET /api/report               — full SOC report (MTTA, MTTR, FP-rate, counts)
  GET /api/aggregates           — list aggregated event buckets
"""

from fastapi import APIRouter
from typing import Optional

router = APIRouter(tags=["reporting"])


@router.get("/report")
def get_report(period_hours: int = 24):
    """
    Full SOC-level report.

    Returns: incidents_count, MTTA, MTTR, FP-rate, total_events, aggregated_events.
    """
    from app.services.reporting import full_report
    return full_report(period_hours=period_hours)


@router.get("/aggregates")
def get_aggregates(limit: int = 100):
    """
    List aggregated event buckets (5-minute windows with deduplication counts).
    """
    try:
        from app.services.aggregates_store import list_aggregates
        items = list_aggregates(limit=limit)
    except Exception:
        items = []
    return {"items": items, "total": len(items)}


@router.get("/gossopka/{incident_id}")
def generate_gossopka_report(incident_id: str):
    """
    Generate an incident report in a simplified NCKI / GosSOPKA format.
    """
    from app.services.incidents_store import get_incident
    from fastapi import HTTPException
    
    inc = get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Формируем структуру по ГОСТ/НКЦКИ (упрощенную)
    report = {
        "report_id": f"GOST-{incident_id}",
        "organization": "ПАО ТЭК-Энерго",
        "created_at": inc.get("created_at"),
        "incident_details": {
            "title": inc.get("title"),
            "severity": inc.get("severity"),
            "status": inc.get("status"),
            "vector": inc.get("type"),
        },
        "indicators": {
            "source_ip": inc.get("src_ip") or "unknown",
            "target_host": inc.get("host") or "unknown",
            "target_asset_id": inc.get("asset_id") or "unknown",
            "compromised_users": inc.get("users") or ([inc.get("user")] if inc.get("user") else []),
        },
        "response_actions": inc.get("response_actions", []),
        "timeline": inc.get("timeline", []),
    }
    
    return report

