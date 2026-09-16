import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import images, scans, ws
from app.config.api import CORS_ORIGINS, DEV_AUTH, assert_production_auth
from app.telemetry import setup

# Runs once per uvicorn worker process, because uvicorn imports this module in
# each child. That is deliberate: both workers push OTLP, so neither owns the
# metrics and there is no in-process registry to scrape inconsistently.
_TELEMETRY = setup("api")

logger = logging.getLogger(__name__)

# Here rather than in the config module, because this is the process that
# trusts tokens. The worker imports app.config.api for REDIS_URL and verifies
# nothing, so asserting at config import refused to start the one service that
# has no auth surface at all.
assert_production_auth()

app = FastAPI(title="Docker Repo Auditor", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    # Without this a browser cannot read Content-Disposition, so an
    # export downloads under a generated filename instead of its own.
    expose_headers=["Content-Disposition"],
)

app.include_router(images.router)
app.include_router(scans.router)
app.include_router(ws.router)

if _TELEMETRY:
    # After the routers, so every route is covered. Traces only; the metrics
    # this project cares about are domain events, not request counts.
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app, excluded_urls="health")


@app.get("/health")
def health() -> dict:
    """Report that the process is up, for load balancers and ECS."""
    return {"status": "ok"}


if DEV_AUTH:
    from fastapi import APIRouter

    from app.dev.keys import jwks, mint_token

    dev = APIRouter(prefix="/dev", tags=["dev"])

    @dev.get("/.well-known/jwks.json")
    def dev_jwks() -> dict:
        return jwks()

    # Hands a valid token for ANY tenant to ANY caller. That is exactly as
    # dangerous as it sounds, which is why it lives inside the gate - the
    # browser needs a token and Cognito does not arrive until Phase 12.
    @dev.get("/token")
    def dev_token(tenant_id: str = "demo-tenant") -> dict:
        return {
            "token": mint_token(tenant_id),
            "tenant_id": tenant_id,
            "expires_in": 3600,
        }

    app.include_router(dev)

    logger.warning("DEV_AUTH enabled: local JWKS and /dev/token are being served")
