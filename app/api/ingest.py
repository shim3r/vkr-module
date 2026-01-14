from fastapi import APIRouter, Body
from app.pipeline.collector import ingest_event

router = APIRouter(tags=["ingest"])


@router.post("/ingest")
async def ingest(payload: dict = Body(...)):
    """
    Универсальная точка входа.
    Пример payload:
      {
        "source_type": "firewall",
        "format": "cef",
        "data": "CEF:0|..."
      }
    """
    result = await ingest_event(payload)
    return {"status": "ok", "result": result}
