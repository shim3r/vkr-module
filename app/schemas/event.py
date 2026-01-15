from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

class NormalizedEvent(BaseModel):
    event_id: str

    # Времена
    received_at: datetime
    parsed_at: datetime

    # Источник
    source_type: str
    format: str

    # Тип/важность
    event_type: str = Field(default="UNKNOWN")
    severity: int = Field(default=1, ge=1, le=10)

    # Ключевые сущности
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None

    # Текст и поля
    message: Optional[str] = None
    fields: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
