import asyncio
import random
from datetime import datetime, timezone
from pathlib import Path
import httpx

LIVE_DIR = Path("synthetic_logs_live")
LIVE_DIR.mkdir(parents=True, exist_ok=True)

RUNNING = False

def _utc_iso():
    return datetime.now(timezone.utc).isoformat()

def _rand_ip():
    return f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}"

def gen_firewall_event():
    critical = random.random() < 0.2
    etype = "VPN_LOGIN_FAIL" if critical else "ALLOW"
    msg = f"CEF:0|NGFW|Vendor|1.0|100|{etype}|8|src={_rand_ip()} dst=10.0.0.1 suser=user{random.randint(1,5)}"
    return {"source_type": "firewall", "format": "cef", "data": msg}

def gen_av_event():
    critical = random.random() < 0.1
    etype = "AV_DETECT" if critical else "AV_OK"
    msg = f"CEF:0|EndpointAV|Vendor|1.0|200|{etype}|7|host=pc{random.randint(1,30)} file=sample.exe action=quarantine"
    return {"source_type": "av", "format": "cef", "data": msg}

def gen_iam_event():
    critical = random.random() < 0.1
    etype = "GROUP_ADD" if critical else "LOGIN_SUCCESS"
    msg = f"{_utc_iso()},user{random.randint(1,5)},{etype},ip={_rand_ip()}"
    return {"source_type": "iam", "format": "csv", "data": msg}

def pick_event():
    r = random.random()
    if r < 0.55:
        return gen_firewall_event()
    if r < 0.8:
        return gen_av_event()
    return gen_iam_event()

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
