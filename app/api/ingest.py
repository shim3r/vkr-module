import json

from fastapi import APIRouter, Body, UploadFile, File, HTTPException

from app.config import RAW_DIR
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


@router.get("/raw")
async def list_raw(limit: int = 100):
    """
    Список сырых событий (архив/форензика). Возвращает raw_id и received_at.
    """
    if not RAW_DIR.exists():
        return {"items": [], "total": 0}
    items = []
    for p in sorted(RAW_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            items.append({
                "raw_id": data.get("raw_id", p.stem),
                "received_at": data.get("received_at"),
            })
        except Exception:
            continue
        if len(items) >= limit:
            break
    return {"items": items, "total": len(items)}


@router.get("/raw/{raw_id}")
async def get_raw(raw_id: str):
    """
    Одно сырое событие по raw_id (для форензики).
    """
    if not raw_id.replace("-", "").replace("_", "").isalnum() or len(raw_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid raw_id")
    path = RAW_DIR / f"{raw_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Raw event not found")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
