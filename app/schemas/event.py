from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class NormalizedEvent(BaseModel):
    # ----------------------------
    # Identifiers
    # ----------------------------
    event_id: str

    # ----------------------------
    # Timestamps
    # ----------------------------
    received_at: datetime
    parsed_at: datetime

    # ----------------------------
    # Source metadata
    # ----------------------------
    source_type: str                     # firewall / edr / av / iam
    format: str                          # cef / json / csv / text
    vendor: Optional[str] = None
    product: Optional[str] = None

    # ----------------------------
    # Classification
    # ----------------------------
    event_type: str = Field(default="UNKNOWN")
    event_category: str = Field(default="unknown")
    severity: int = Field(default=1, ge=1, le=10)

    # ----------------------------
    # Network context
    # ----------------------------
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # ----------------------------
    # Identity / asset context
    # ----------------------------
    host: Optional[str] = None
    user: Optional[str] = None

    # Asset enrichment (CMDB/Asset DB)
    asset_id: Optional[str] = None
    asset_criticality: Optional[int] = Field(default=None, ge=1, le=5)
    asset_owner: Optional[str] = None
    asset_zone: Optional[str] = None

    # ----------------------------
    # Raw / additional data
    # ----------------------------
    message: Optional[str] = None
    fields: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
