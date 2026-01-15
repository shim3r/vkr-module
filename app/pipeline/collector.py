import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.pipeline.scoring import score
from app.services.alerts_store import add_alert

RAW_DIR = Path("data/raw")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ingest_event(payload: dict) -> dict:
    """
    Центральная функция приёма и первичной обработки события.
    """
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    raw_id = str(uuid4())

    record = {
        "raw_id": raw_id,
        "received_at": _utc_now_iso(),
        "payload": payload,
    }

    # 1. Сохраняем сырое событие
    out_path = RAW_DIR / f"{raw_id}.json"
    out_path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    # 2. Скоринг и приоритизация
    risk, priority, is_critical = score(payload)

    result = {
        "raw_id": raw_id,
        "stored_to": str(out_path),
        "risk": risk,
        "priority": priority,
    }

    # 3. Если критическое — добавляем в alerts
    if is_critical:
        add_alert({
            "raw_id": raw_id,
            "priority": priority,
            "risk": risk,
            "source_type": payload.get("source_type"),
            "format": payload.get("format"),
            "received_at": record["received_at"],
            "snippet": str(payload.get("data", ""))[:200],
        })

    return result
