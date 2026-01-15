import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.pipeline.normalize import normalize
from app.pipeline.scoring import score
from app.pipeline.correlate import run_correlation

from app.services.alerts_store import add_alert
from app.services.events_store import add_event

RAW_DIR = Path("data/raw")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ingest_event(payload: dict) -> dict:
    """
    Центральная функция приёма и первичной обработки события:
      1) сохраняем raw (для аудита/форензики)
      2) нормализуем в единую модель NormalizedEvent
      3) сохраняем нормализованное событие в events store (для корреляции)
      4) считаем риск/приоритет
      5) если событие критичное — добавляем в alerts feed
      6) запускаем корреляцию (правила) и возвращаем найденные инциденты
    """
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    raw_id = str(uuid4())

    record = {
        "raw_id": raw_id,
        "received_at": _utc_now_iso(),
        "payload": payload,
    }

    # 1) Raw Events Store
    out_path = RAW_DIR / f"{raw_id}.json"
    out_path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    # 2) Нормализация (CEF/CSV/JSON/text → NormalizedEvent)
    normalized = normalize(
        payload=payload,
        raw_id=raw_id,
        received_at_iso=record["received_at"],
    )

    normalized_dict = normalized.model_dump(mode="json") # Pydantic v2

    # 3) Сохраняем нормализованное событие для последующей корреляции
    add_event(normalized_dict)

    # 4) Скоринг / приоритизация
    risk, priority, is_critical = score(payload)

    result = {
        "raw_id": raw_id,
        "stored_to": str(out_path),
        "risk": risk,
        "priority": priority,
        "normalized_event": normalized_dict,
    }

    # 5) Критические события — в ленту alerts
    if is_critical:
        add_alert({
            "raw_id": raw_id,
            "priority": priority,
            "risk": risk,
            "source_type": payload.get("source_type"),
            "format": payload.get("format"),
            "received_at": record["received_at"],
            "event_type": normalized_dict.get("event_type"),
            "src_ip": normalized_dict.get("src_ip"),
            "dst_ip": normalized_dict.get("dst_ip"),
            "user": normalized_dict.get("user"),
            "snippet": str(payload.get("data", ""))[:200],
        })

    # 6) Корреляция (правила SOC-подобного уровня)
    incidents = run_correlation()
    result["correlation_incidents"] = incidents
    print(
    f"[INGEST] raw_id={raw_id} "
    f"type={normalized_dict.get('event_type')} "
    f"src={normalized_dict.get('src_ip')} "
    f"user={normalized_dict.get('user')} "
    f"risk={risk} priority={priority}"
    )

    if incidents:
        print(f"[CORRELATION] incidents={incidents}")
    return result
