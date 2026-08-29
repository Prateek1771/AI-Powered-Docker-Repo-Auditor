import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import scans, ws
from app.config.api import CORS_ORIGINS, DEV_AUTH

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

app = FastAPI(title="Docker Repo Auditor", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(scans.router)
app.include_router(ws.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if DEV_AUTH:
    from fastapi import APIRouter

    from app.dev.keys import jwks

    dev = APIRouter(prefix="/dev", tags=["dev"])

    @dev.get("/.well-known/jwks.json")
    def dev_jwks() -> dict:
        return jwks()

    app.include_router(dev)

    logger.warning("DEV_AUTH enabled: local JWKS is being served")
