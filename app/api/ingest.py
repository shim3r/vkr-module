from fastapi import APIRouter, Body, UploadFile, File
from app.pipeline.collector import ingest_event

router = APIRouter(tags=["ingest"])


@router.post("/ingest")
async def ingest(payload: dict = Body(...)):
    """
    Универсальная точка входа для одиночных событий (JSON).
    """
    result = await ingest_event(payload)
    return {"status": "ok", "result": result}


@router.post("/ingest-file")
async def ingest_file(
    source_type: str,
    format: str,
    file: UploadFile = File(...)
):
    """
    Загрузка файла логов (для стенда и ВКР).
    source_type: firewall|av|edr|iam|arm
    format: cef|syslog|json|csv|text
    """
    content = (await file.read()).decode("utf-8", errors="replace")

    payload = {
        "source_type": source_type,
        "format": format,
        "filename": file.filename,
        "data": content,
    }

    result = await ingest_event(payload)
    return {"status": "ok", "result": result}
