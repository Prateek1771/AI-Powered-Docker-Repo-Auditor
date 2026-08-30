import logging
import time

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from jose.jwk import construct as jwk_construct
from pydantic import BaseModel

from app.config.api import (
    EXPECTED_TOKEN_USE,
    JWKS_CACHE_SECONDS,
    JWKS_URL,
    TOKEN_AUDIENCE,
)

logger = logging.getLogger(__name__)

security = HTTPBearer()

_jwks_cache: dict = {"keys": [], "fetched_at": 0.0}


class Principal(BaseModel):
    tenant_id: str
    email: str


def _fetch_jwks(force: bool = False) -> list[dict]:
    """Return the identity provider's signing keys, cached for a window.

    `force` skips the cache, which is how a key rotation is picked up
    without waiting out JWKS_CACHE_SECONDS.
    """
    age = time.time() - _jwks_cache["fetched_at"]

    if not force and _jwks_cache["keys"] and age < JWKS_CACHE_SECONDS:
        return _jwks_cache["keys"]

    with httpx.Client(timeout=10.0) as client:
        resp = client.get(JWKS_URL)
        resp.raise_for_status()

        keys = resp.json()["keys"]

    _jwks_cache["keys"] = keys
    _jwks_cache["fetched_at"] = time.time()

    return keys


def _find_key(kid: str | None) -> dict:
    """Find the signing key a token's `kid` names, refreshing once if new.

    The single forced refresh is the rotation path: a key minted after our
    last fetch is unknown until we look again, and only then is it absent.
    """
    key = next(
        (k for k in _fetch_jwks() if k["kid"] == kid),
        None,
    )

    if key is not None:
        return key

    logger.info("Unknown kid %s, refreshing JWKS", kid)

    key = next(
        (k for k in _fetch_jwks(force=True) if k["kid"] == kid),
        None,
    )

    if key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signing key not found",
        )

    return key


def verify_token(token: str) -> dict:
    """Verify a JWT's signature, audience, expiry and type, and return it.

    Raises 401 for every failure mode. token_use is checked explicitly:
    an access token and an id token are both validly signed by the same
    pool, and only one of them identifies a user.
    """
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token",
        ) from exc

    key = _find_key(header.get("kid"))

    try:
        claims = jwt.decode(
            token,
            jwk_construct(key),
            algorithms=["RS256"],
            audience=TOKEN_AUDIENCE,
            options={"verify_exp": True, "verify_aud": True},
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
        ) from exc

    if claims.get("token_use") != EXPECTED_TOKEN_USE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
        )

    return claims


# Deliberately sync, not async. _fetch_jwks uses a blocking httpx client, and
# an async dependency would run it ON the event loop - which self-deadlocks a
# single-worker uvicorn when JWKS_URL points back at this same app, and blocks
# the loop on every request even when it points at Cognito. FastAPI runs sync
# dependencies in a threadpool, which is what this needs.
def current_principal(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Principal:
    """Resolve the caller from the bearer token, for use as a dependency."""
    claims = verify_token(credentials.credentials)

    return Principal(
        tenant_id=claims["sub"],
        email=claims.get("email", ""),
    )
