import os

DEV_AUTH = os.environ.get("DEV_AUTH", "0") == "1"

JWKS_URL = os.environ.get(
    "JWKS_URL",
    "http://localhost:8080/dev/.well-known/jwks.json",
)

TOKEN_AUDIENCE = os.environ.get("TOKEN_AUDIENCE", "local-client-id")

EXPECTED_TOKEN_USE = "id"

JWKS_CACHE_SECONDS = 600

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

SCAN_LIMIT = 5

SCAN_WINDOW_SECONDS = 3600

CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000",
).split(",")
