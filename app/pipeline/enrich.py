from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

ASSETS_PATH = Path("data/cmdb/assets.json")


class AssetDB:
    def __init__(self, assets_path: Path):
        self.assets_path = assets_path
        self._by_host: Dict[str, Dict[str, Any]] = {}
        self._by_ip: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        self._by_host.clear()
        self._by_ip.clear()

        if not self.assets_path.exists():
            return

        raw = self.assets_path.read_text(encoding="utf-8").strip()
        if not raw:
            return

        try:
            data = json.loads(raw)
        except Exception:
            return

        if not isinstance(data, list):
            return

        for a in data:
            if not isinstance(a, dict):
                continue

            host = (a.get("host") or a.get("hostname") or "").strip().lower()
            if host:
                self._by_host[host] = a

            ips = a.get("ips")
            if isinstance(ips, str):
                ips = [ips]
            if isinstance(ips, list):
                for ip in ips:
                    if isinstance(ip, str) and ip.strip():
                        self._by_ip[ip.strip()] = a

            ip_single = a.get("ip")
            if isinstance(ip_single, str) and ip_single.strip():
                self._by_ip[ip_single.strip()] = a

    def find(self, host: str = "", ip: str = "") -> Optional[Dict[str, Any]]:
        if host:
            hit = self._by_host.get(host.strip().lower())
            if hit:
                return hit
        if ip:
            hit = self._by_ip.get(ip.strip())
            if hit:
                return hit
        return None


_DB = AssetDB(ASSETS_PATH)


def enrich_dict(normalized: Dict[str, Any]) -> Dict[str, Any]:
    host = str(normalized.get("host") or "")
    dst_ip = str(normalized.get("dst_ip") or "")
    src_ip = str(normalized.get("src_ip") or "")

    asset = _DB.find(host=host)
    if not asset and dst_ip:
        asset = _DB.find(ip=dst_ip)
    if not asset and src_ip:
        asset = _DB.find(ip=src_ip)

    if not asset:
        return normalized

    normalized["asset_id"] = asset.get("asset_id") or asset.get("id")
    normalized["asset_name"] = asset.get("name") or asset.get("host")
    normalized["asset_criticality"] = int(asset.get("criticality") or 0) or None
    normalized["asset_owner"] = asset.get("owner")
    normalized["asset_zone"] = asset.get("zone")
    normalized["asset_tags"] = asset.get("tags") or []

    return normalized