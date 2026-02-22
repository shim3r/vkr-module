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
