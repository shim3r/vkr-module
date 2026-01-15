from fastapi import FastAPI
from app.api.ingest import router as ingest_router
from app.api.alerts import router as alerts_router
from app.api.sim import router as sim_router


app = FastAPI(title="VKR SIEM Module (Prototype)")

app.include_router(ingest_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(sim_router, prefix="/api")

@app.get("/health")
def health():
    return {"status": "ok"}
