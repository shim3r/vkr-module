import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)


async def ingest_event(payload: dict) -> dict:
    raw_id = str(uuid4())
    received_at = datetime.now(timezone.utc).isoformat()

    record = {
        "raw_id": raw_id,
        "received_at": received_at,
        "payload": payload,
    }

    # На первом этапе — просто сохраняем “сырые” события (raw store)
    (RAW_DIR / f"{raw_id}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

    return {"raw_id": raw_id, "stored_to": str(RAW_DIR / f"{raw_id}.json")}
