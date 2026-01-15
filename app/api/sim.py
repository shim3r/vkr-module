import asyncio
from typing import Optional
from fastapi import APIRouter
from app.simulator.generator import run_generator, stop, RUNNING

router = APIRouter(tags=["sim"])

_task: Optional[asyncio.Task] = None


@router.post("/sim/start")
async def sim_start(eps: float = 1.0, target_url: str = "http://127.0.0.1:8000"):
    global _task
    if _task and not _task.done():
        return {"status": "already_running"}
    _task = asyncio.create_task(run_generator(target_url=target_url, eps=eps))
    return {"status": "started", "eps": eps, "target_url": target_url}


@router.post("/sim/stop")
async def sim_stop():
    stop()
    return {"status": "stopping"}


@router.get("/sim/status")
async def sim_status():
    return {"running": RUNNING}
