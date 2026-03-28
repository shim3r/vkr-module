from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app.api.ingest import router as ingest_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.sim import router as sim_router
from app.api.ui import router as ui_router
from app.api.reporting import router as reporting_router
from app.api.integrations import router as integrations_router
from app.api.response import router as response_router
from app.api.playbooks import router as playbooks_router
from app.pipeline.pipeline import get_pipeline
from app.config import ALLOWED_ORIGINS


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: launch async pipeline workers
    pipeline = get_pipeline()
    await pipeline.start()
    yield
    # Shutdown: gracefully stop pipeline workers
    await pipeline.stop()


app = FastAPI(title="VKR SIEM Module (Prototype)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# UI at site root (/)
app.include_router(ui_router)

# APIs under /api
app.include_router(ingest_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(sim_router, prefix="/api")
app.include_router(reporting_router, prefix="/api")
app.include_router(integrations_router, prefix="/api")
app.include_router(playbooks_router)
app.include_router(response_router)


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)
