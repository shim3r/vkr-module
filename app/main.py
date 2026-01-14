from fastapi import FastAPI
from app.api.ingest import router as ingest_router

app = FastAPI(title="VKR SIEM Module (prototype)")

app.include_router(ingest_router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
