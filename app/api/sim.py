import asyncio
import random
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.pipeline.collector import ingest_event
from app.simulator.attack_catalog import ATTACKS
from app.simulator.generator import run_generator, stop, RUNNING
from app.services.alerts_store import clear_alerts
from app.services.incidents_store import clear_incidents
from app.services.events_store import clear_events

router = APIRouter(tags=["sim"])

# Background task for continuous random generation (/sim/start)
_task: Optional[asyncio.Task] = None

# Background task for one-shot demo attacks (/sim/attack)
_attack_task: Optional[asyncio.Task] = None
_last_attack: Optional[str] = None


@router.post("/sim/start")
async def sim_start(eps: float = 1.0, target_url: str = "http://127.0.0.1:8000"):
    """Start continuous random generator (pushes events to the API target)."""
    global _task

    if _task and not _task.done():
        return {"status": "already_running"}

    _task = asyncio.create_task(run_generator(target_url=target_url, eps=eps))
    return {"status": "started", "eps": eps, "target_url": target_url}


@router.post("/sim/stop")
async def sim_stop():
    """Stop continuous generator."""
    stop()
    return {"status": "stopping"}


@router.get("/sim/status")
async def sim_status():
    """Status of the continuous generator."""
    return {"running": RUNNING}


async def _run_attack(mode: str):
    """Run a demo attack continuously until stopped."""
    global _last_attack

    if mode not in ATTACKS:
        raise HTTPException(status_code=400, detail=f"Unknown mode: {mode}")

    _last_attack = mode

    try:
        while True:
            # Each item is (payload_dict, delay_seconds_after)
            seq = ATTACKS[mode]()
            for payload, delay_s in seq:
                await ingest_event(payload)
                await asyncio.sleep(float(delay_s))
            await asyncio.sleep(0.5)
    except asyncio.CancelledError:
        return


@router.post("/sim/attack")
async def attack(mode: str):
    """Start a demo attack (runs until stopped)."""
    global _attack_task

    if _attack_task and not _attack_task.done():
        return {"status": "busy", "detail": "attack already running"}

    _attack_task = asyncio.create_task(_run_attack(mode))
    return {"status": "started", "mode": mode}


@router.post("/sim/attack-random")
async def attack_random():
    """Start a random one-shot demo attack."""
    mode = random.choice(list(ATTACKS.keys()))
    global _attack_task
    if _attack_task and not _attack_task.done():
        _attack_task.cancel()
        await asyncio.sleep(0)
    _attack_task = asyncio.create_task(_run_attack(mode))
    return {"status": "started", "mode": mode}


@router.get("/sim/attack-status")
def attack_status():
    """Return attack task status and available modes."""
    running = _attack_task is not None and not _attack_task.done()
    return {
        "running": running,
        "last": _last_attack,
        "modes": list(ATTACKS.keys()),
        "server_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
@router.post("/sim/attack-stop")
async def attack_stop():
    global _attack_task
    if _attack_task and not _attack_task.done():
        _attack_task.cancel()
        return {"status": "stopping"}
    return {"status": "not_running"}


@router.post("/sim/reset")
async def reset_demo_state():
    clear_events()
    clear_alerts()
    clear_incidents()
    return {"status": "ok"}
