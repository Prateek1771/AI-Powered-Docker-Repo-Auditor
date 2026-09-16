import os

DEV_AUTH = os.environ.get("DEV_AUTH", "0") == "1"

# The dev issuer. Cognito's is
# https://cognito-idp.<region>.amazonaws.com/<pool-id> and must be set
# explicitly in any deployment - see _assert_production_auth() below.
DEV_ISSUER = "http://localhost:8080/dev"

JWKS_URL = os.environ.get(
    "JWKS_URL",
    "http://localhost:8080/dev/.well-known/jwks.json",
)

TOKEN_AUDIENCE = os.environ.get("TOKEN_AUDIENCE", "local-client-id")

TOKEN_ISSUER = os.environ.get("TOKEN_ISSUER", DEV_ISSUER)

EXPECTED_TOKEN_USE = "id"

JWKS_CACHE_SECONDS = 600

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Kept out of REDIS_URL deliberately. Deployed, the URL is a plain ECS
# environment value - console-readable - while this arrives through the
# `secrets` block, which the agent resolves at task start. Putting the
# credential in the URL would have made the whole URL a secret.
# See docs/audits/audit-01-backend.md P4-3.
#
# `or None` rather than a default of "": redis-py skips AUTH entirely for None,
# where an empty string would send an empty AUTH that a server with no
# requirepass rejects. So an unset variable means exactly "no password".
#
# Note the precedence if anyone ever puts credentials in REDIS_URL instead:
# redis-py's from_url lets URL options win over explicit kwargs, so the URL
# would take over. Sane, and worth knowing before debugging it.
REDIS_PASSWORD: str | None = os.environ.get("REDIS_PASSWORD") or None

SCAN_LIMIT = 5

SCAN_WINDOW_SECONDS = 3600

CORS_ORIGINS = [
    # Stripped: "a, b".split(",") yields " b", which matches no browser Origin
    # and fails as a CORS error nobody can find. Empties dropped for the same
    # reason a trailing comma should not create a phantom origin.
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]


class InsecureAuthConfig(RuntimeError):
    """Raised at import when a deployment would accept dev-minted tokens."""


def assert_production_auth() -> None:
    """Refuse to start with dev auth settings outside a local run.

    Every value here has a working local default, which is what makes the
    project pleasant to run and dangerous to deploy: forgetting one
    variable does not fail, it silently trusts the local dev issuer, and
    /dev/token hands a token for ANY tenant to ANY caller.

    The CI smoke test asserts /dev/token returns 404, which catches
    DEV_AUTH but not a JWKS_URL nobody set. This catches both.

    Called from app/api/main.py, NOT at import of this module. The worker
    imports this file for REDIS_URL alone and verifies no tokens at all -
    asserting here would refuse to start the one process that has no
    opinion about auth, which is exactly what happened the first time.

    Opt out with AUTH_ALLOW_DEV_DEFAULTS=1 for a deployment that genuinely
    wants the dev issuer.
    """
    if os.environ.get("AUTH_ALLOW_DEV_DEFAULTS") == "1" or DEV_AUTH:
        return

    problems = []

    if JWKS_URL == "http://localhost:8080/dev/.well-known/jwks.json":
        problems.append("JWKS_URL is unset and points at the local dev issuer")

    if not JWKS_URL.startswith("https://"):
        problems.append(f"JWKS_URL is not https: {JWKS_URL}")

    if TOKEN_AUDIENCE == "local-client-id":
        problems.append("TOKEN_AUDIENCE is unset and still the dev placeholder")

    if TOKEN_ISSUER == DEV_ISSUER:
        problems.append("TOKEN_ISSUER is unset and still the dev issuer")

    if problems:
        raise InsecureAuthConfig(
            "Refusing to start: this configuration accepts dev-minted tokens. "
            + "; ".join(problems)
            + ". Set these, or set AUTH_ALLOW_DEV_DEFAULTS=1 if that is intended."
        )
