from fastapi import APIRouter, Body, UploadFile, File, HTTPException
from app.pipeline.collector import ingest_event

router = APIRouter(tags=["ingest"])

ALLOWED_SOURCES = {"firewall", "av", "edr", "iam", "arm", "endpoints"}
ALLOWED_FORMATS = {"cef", "syslog", "json", "csv", "text"}

SOURCE_ALIASES = {
    # IAM/AD aliases
    "ad": "iam",
    "iam/ad": "iam",
    "active_directory": "iam",
    # Endpoints/OS logs aliases
    "endpoint": "endpoints",
    "os": "endpoints",
    "os_logs": "endpoints",
    "windows": "endpoints",
    "linux": "endpoints",
}


def normalize_source_type(source_type: str) -> str:
    s = (source_type or "").strip().lower()
    return SOURCE_ALIASES.get(s, s)

def _validate_source_and_format(source_type: str, fmt: str) -> None:
    if source_type not in ALLOWED_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unsupported source_type: {source_type}")
    if fmt not in ALLOWED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")


@router.post("/ingest")
async def ingest(payload: dict = Body(...)):
    """
    Универсальная точка входа для одиночных событий (JSON).
    """
    source_type = normalize_source_type(payload.get("source_type") or "")
    fmt = (payload.get("format") or "").lower()
    _validate_source_and_format(source_type, fmt)
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
    source_type: firewall|av|edr|iam|arm|endpoints
    format: cef|syslog|json|csv|text
    """
    source_type = normalize_source_type(source_type)
    format = format.lower()
    _validate_source_and_format(source_type, format)

    content = (await file.read()).decode("utf-8", errors="replace")

    payload = {
        "source_type": source_type,
        "format": format,
        "filename": file.filename,
        "data": content,
    }

    result = await ingest_event(payload)
    return {"status": "ok", "result": result}
