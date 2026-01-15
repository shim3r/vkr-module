from fastapi import FastAPI

from app.api.ingest import router as ingest_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.sim import router as sim_router
from app.api.ui import router as ui_router

app = FastAPI(title="VKR SIEM Module (Prototype)")

# UI at site root (/)
app.include_router(ui_router)

# APIs under /api
app.include_router(ingest_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(sim_router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
