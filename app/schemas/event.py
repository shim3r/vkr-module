from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from uuid import uuid4


class NormalizedEvent(BaseModel):
    # ----------------------------
    # Identifiers (TO-BE schema)
    # ----------------------------
    id: str = Field(default_factory=lambda: str(uuid4()))
    raw_event_id: str  # reference to raw event store
    event_id: str = ""  # backward compat alias (= raw_event_id)

    # ----------------------------
    # Timestamps
    # ----------------------------
    timestamp_utc: datetime  # explicit UTC timestamp (TO-BE requirement)
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
    dest_ip: Optional[str] = None  # alias for dst_ip (TO-BE compliance)
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

    # Enrichment fields
    enriched: bool = False
    src_asset: Optional[Dict[str, Any]] = None
    dst_asset: Optional[Dict[str, Any]] = None
    host_asset: Optional[Dict[str, Any]] = None
    src_geo: Optional[str] = None
    dst_geo: Optional[str] = None
    ioc_hits: Optional[List[Dict[str, Any]]] = None

    # TO-BE required enrichment fields
    network_zone: Optional[str] = None          # e.g. "dmz", "internal", "external", "ics"
    geoip: Optional[Dict[str, str]] = None      # {"country_code": "RU", "country": "Russia", "city": "Moscow"}
    ti_match: bool = False                       # True if IOC match found in TI database
