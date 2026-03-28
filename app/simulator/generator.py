import asyncio
import random
from datetime import datetime, timezone
from pathlib import Path
import httpx

from app.config import SIMULATOR_DIR

LIVE_DIR = SIMULATOR_DIR / "synthetic_logs_live"
LIVE_DIR.mkdir(parents=True, exist_ok=True)

RUNNING = False

# ─── Real CMDB hostnames (synced with assets.json) ───────────────────────────
_CMDB_WORKSTATIONS = [
    "ws-user-01", "ws-user-02", "ws-user-03",
    "ws-user-04", "ws-user-05", "ws-eng-01", "ws-admin-01",
]
_CMDB_SERVERS = ["fileserver-01", "webportal-01", "mailsrv-01", "dbsrv-01"]
_CMDB_DC = ["dc-01", "dc-02"]
_CMDB_VPN_IP = "10.0.0.5"   # vpn-gw-01
_CMDB_FW_IP  = "10.0.0.1"   # fw-perimeter-01
_CMDB_ALL_IPS = [
    "10.1.2.10", "10.1.2.11", "10.1.2.12", "10.1.2.13", "10.1.2.14",
    "10.1.1.50", "10.0.0.20",
]

def _utc_iso():
    return datetime.now(timezone.utc).isoformat()

def _rand_internal_ip():
    return random.choice(_CMDB_ALL_IPS)

def _rand_workstation():
    return random.choice(_CMDB_WORKSTATIONS)

def gen_firewall_event():
    critical = random.random() < 0.2
    etype = "VPN_LOGIN_FAIL" if critical else "ALLOW"
    src = f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}"
    dst = _CMDB_VPN_IP if critical else _CMDB_FW_IP
    msg = f"CEF:0|NGFW|Vendor|1.0|100|{etype}|8|src={src} dst={dst} suser=user{random.randint(1,5)}"
    return {"source_type": "firewall", "format": "cef", "data": msg}

def gen_av_event():
    critical = random.random() < 0.1
    etype = "AV_DETECT" if critical else "AV_OK"
    host = _rand_workstation()
    msg = f"CEF:0|EndpointAV|Vendor|1.0|200|{etype}|7|host={host} file=sample.exe action=quarantine"
    return {"source_type": "av", "format": "cef", "data": msg}

def gen_iam_event():
    critical = random.random() < 0.1
    etype = "GROUP_ADD" if critical else "LOGIN_SUCCESS"
    host = random.choice(_CMDB_DC)
    ip = _rand_internal_ip()
    msg = f"{_utc_iso()},user{random.randint(1,5)},{etype},host={host},ip={ip}"
    return {"source_type": "iam", "format": "csv", "data": msg}

def gen_edr_event():
    host = _rand_workstation()
    user = f"user{random.randint(1, 5)}"
    etype = random.choice(["EDR_SUSPICIOUS_PROCESS", "PROCESS_START", "NETWORK_CONNECTION"])
    sev = 7 if etype == "EDR_SUSPICIOUS_PROCESS" else 4
    msg = (
        f"CEF:0|EDR|Vendor|1.0|300|{etype}|{sev}|"
        f"host={host} suser={user} process=powershell.exe"
    )
    return {"source_type": "edr", "format": "cef", "data": msg}

def pick_event():
    r = random.random()
    if r < 0.50:
        return gen_firewall_event()
    if r < 0.70:
        return gen_av_event()
    if r < 0.85:
        return gen_iam_event()
    return gen_edr_event()

def append_to_live_file(payload: dict):
    src = payload["source_type"]
    p = LIVE_DIR / src
    p.mkdir(parents=True, exist_ok=True)
    out = p / "live.log"
    line = payload["data"].replace("\n", "\\n")
    with out.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

async def run_generator(target_url: str, eps: float = 1.0):
    global RUNNING
    RUNNING = True
    async with httpx.AsyncClient(timeout=10) as client:
        while RUNNING:
            payload = pick_event()
            append_to_live_file(payload)
            try:
                await client.post(f"{target_url}/api/ingest", json=payload)
            except Exception:
                pass
            await asyncio.sleep(1.0 / max(eps, 0.1))

def stop():
    global RUNNING
    RUNNING = False
