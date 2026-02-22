from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# Support both legacy and simplified paths so the module works regardless of where you keep CMDB files.
ASSETS_PATHS: List[Path] = [
    Path("data/cmdb/assets.json"),
    Path("data/assets.json"),
]
IOCS_PATHS: List[Path] = [
    Path("data/cmdb/ti_iocs.json")
]

# ---------------------------------------------------------------------------
# Mock GeoIP table — maps IP address prefixes to country/city.
# In production replace with MaxMind GeoLite2 or similar database.
# Format: {"prefix": ("country_code", "country", "city")}
# ---------------------------------------------------------------------------
_MOCK_GEOIP: dict = {
    # RFC-1918 private ranges → internal
    "10.": ("RU", "Internal", "LAN"),
    "192.168.": ("RU", "Internal", "LAN"),
    "172.16.": ("RU", "Internal", "LAN"),
    "127.": ("RU", "Internal", "Localhost"),
    # Common external ranges (illustrative — NOT real GeoIP)
    "1.2.3.": ("CN", "China", "Beijing"),
    "5.188.": ("RU", "Russia", "Moscow"),
    "45.83.": ("NL", "Netherlands", "Amsterdam"),
    "46.166.": ("RU", "Russia", "Saint Petersburg"),
    "77.88.": ("RU", "Russia", "Moscow"),
    "80.90.": ("UA", "Ukraine", "Kyiv"),
    "91.108.": ("RU", "Russia", "Moscow"),
    "185.220.": ("DE", "Germany", "Frankfurt"),
    "194.165.": ("NL", "Netherlands", "Amsterdam"),
    "8.8.": ("US", "United States", "Mountain View"),
    "1.1.": ("AU", "Australia", "Sydney"),
}


def _geoip_lookup(ip: str) -> Optional[dict]:
    """Return GeoIP dict for an IP address using prefix matching."""
    ip = (ip or "").strip()
    if not ip:
        return None
    for prefix, (code, country, city) in _MOCK_GEOIP.items():
        if ip.startswith(prefix):
            return {"country_code": code, "country": country, "city": city}
    # Unknown external IP
    try:
        import ipaddress as _ia
        if not _ia.ip_address(ip).is_private:
            return {"country_code": "XX", "country": "Unknown", "city": "Unknown"}
    except Exception:
        pass
    return None


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _first_existing(paths: List[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists() and p.read_text(encoding="utf-8").strip():
            return p
    return None


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _geo_tag(ip: str) -> Optional[str]:
    ip = (ip or "").strip()
    if not ip:
        return None
    return "internal" if _is_private_ip(ip) else "external"


def _ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


class AssetDB:
    def __init__(self, assets_paths: List[Path]):
        self.assets_paths = assets_paths
        self.assets_path: Optional[Path] = None
        self._by_host: Dict[str, Dict[str, Any]] = {}
        self._by_ip: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        self._by_host.clear()
        self._by_ip.clear()

        self.assets_path = _first_existing(self.assets_paths)
        if not self.assets_path:
            return

        data = _read_json(self.assets_path)
        if not isinstance(data, list):
            return

        for a in data:
            if not isinstance(a, dict):
                continue

            host = (a.get("host") or a.get("hostname") or "").strip().lower()
            if host:
                self._by_host[host] = a

            # Accept both ips=[...] and ip="..."
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
        host = (host or "").strip().lower()
        ip = (ip or "").strip()

        if host:
            hit = self._by_host.get(host)
            if hit:
                return hit
        if ip:
            hit = self._by_ip.get(ip)
            if hit:
                return hit
        return None


class IOCDB:
    def __init__(self, iocs_paths: List[Path]):
        self.iocs_paths = iocs_paths
        self.iocs_path: Optional[Path] = None
        self.bad_ips: set[str] = set()
        self.bad_users: set[str] = set()
        self.bad_hashes: set[str] = set()
        self.reload()

    def reload(self) -> None:
        self.bad_ips.clear()
        self.bad_users.clear()
        self.bad_hashes.clear()

        self.iocs_path = _first_existing(self.iocs_paths)
        if not self.iocs_path:
            return

        data = _read_json(self.iocs_path)
        if not isinstance(data, dict):
            return

        self.bad_ips = set(str(x).strip() for x in _ensure_list(data.get("bad_ips")) if str(x).strip())
        self.bad_users = set(str(x).strip() for x in _ensure_list(data.get("bad_users")) if str(x).strip())
        self.bad_hashes = set(str(x).strip() for x in _ensure_list(data.get("bad_hashes")) if str(x).strip())


_DB = AssetDB(ASSETS_PATHS)
_IOC = IOCDB(IOCS_PATHS)


def reload_enrichment() -> None:
    """Call this after you update assets/iocs files to refresh caches."""
    _DB.reload()
    _IOC.reload()


def enrich_dict(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich normalized event dict with CMDB context + IOC hits + simple geo tags.

    This function is intentionally side-effect free except for mutating `normalized`.
    """

    host = str(normalized.get("host") or normalized.get("hostname") or "").strip()
    dst_ip = str(normalized.get("dst_ip") or "").strip()
    src_ip = str(normalized.get("src_ip") or "").strip()
    user = str(normalized.get("user") or normalized.get("suser") or "").strip()

    tags: List[str] = list(normalized.get("tags") or [])
    ioc_hits: List[Dict[str, Any]] = list(normalized.get("ioc_hits") or [])

    # --- Geo (GeoIP: country/city from mock table, fallback internal/external)
    if src_ip:
        geo = _geoip_lookup(src_ip)
        if geo:
            normalized["src_geo"] = geo["country_code"].lower() if geo["country_code"] not in ("XX",) else "external"
            normalized["geoip"] = geo
        else:
            normalized["src_geo"] = _geo_tag(src_ip)
        if _geo_tag(src_ip) == "external":
            tags.append("geo:external_src")
    if dst_ip:
        normalized["dst_geo"] = _geo_tag(dst_ip)

    # --- IOC enrichment
    if src_ip and src_ip in _IOC.bad_ips:
        ioc_hits.append({"type": "ip", "value": src_ip})
    if user and user in _IOC.bad_users:
        ioc_hits.append({"type": "user", "value": user})

    if ioc_hits:
        normalized["ioc_hits"] = ioc_hits
        tags.append("enrich:ioc_hit")

    # ti_match: True if ANY IOC hit found (TO-BE required field)
    normalized["ti_match"] = bool(ioc_hits)

    # --- Asset (CMDB) lookup: host -> dst_ip -> src_ip
    asset = _DB.find(host=host)
    if not asset and dst_ip:
        asset = _DB.find(ip=dst_ip)
    if not asset and src_ip:
        asset = _DB.find(ip=src_ip)

    # Keep your existing flattened asset_* fields for compatibility
    if asset:
        normalized["asset_id"] = asset.get("asset_id") or asset.get("id")
        normalized["asset_name"] = asset.get("name") or asset.get("host")
        try:
            crit_val = int(asset.get("criticality") or 0)
        except Exception:
            crit_val = 0
        normalized["asset_criticality"] = crit_val or None
        normalized["asset_owner"] = asset.get("owner")
        normalized["asset_zone"] = asset.get("zone")
        # TO-BE: explicit network_zone field (was only in asset_zone before)
        normalized["network_zone"] = asset.get("zone") or asset.get("network_zone") or "unknown"
        normalized["asset_tags"] = asset.get("tags") or []
        tags.append("enrich:asset")

        # Also provide richer nested asset objects for scoring/UI going forward
        normalized.setdefault("dst_asset", asset if dst_ip else None)
        normalized.setdefault("host_asset", asset if host else None)
    else:
        # No CMDB hit — derive network_zone from GeoIP
        if src_ip:
            normalized.setdefault("network_zone", "internal" if _is_private_ip(src_ip) else "external")
        else:
            normalized.setdefault("network_zone", "unknown")

    # Finalize tags
    if tags:
        normalized["tags"] = sorted(set(str(t) for t in tags if t))

    normalized["enriched"] = True
    return normalized