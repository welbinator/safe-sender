"""
Sender Safety API.
Sprint 1 stub — health check only. Full routes come in Sprint 3.
"""
from fastapi import FastAPI

app = FastAPI(title="Sender Safety API", version="0.1.0")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
