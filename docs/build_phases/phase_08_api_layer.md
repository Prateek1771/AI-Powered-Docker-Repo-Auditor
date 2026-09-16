# Phase 8 — The API Layer: Verifying Tokens, Limiting Cost & Object-Level Authorization

The producer needs an HTTP front door. The moment it has one, every request is hostile until proven otherwise.

```text
        request
           │
           ▼
   ┌───────────────┐
   │  VERIFY JWT   │   check the RS256 signature
   │  JWKS + kid   │   against the issuer's public key
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │  RATE LIMIT   │   six model calls per scan
   │  sliding win  │   is real money
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │  AUTHORIZE    │   authenticated is not
   │  own the row  │   the same as allowed
   └───────┬───────┘
           ▼
      enqueue_scan
           │
           ▼
    202 { job_id }
```

The rule for this phase:

```text
authentication answers "who are you"
authorization answers "is this yours"
answering only the first is the most
common serious bug in web APIs
```

Redis runs in Docker. Tokens are signed by a local issuer you build in section 3, so still no AWS account.

---

# 1. One package, two processes

The reference implementation keeps `backend/` and `worker/` as separate projects, each with its own copy of the persistence layer. Look at what that produced:

```text
backend/app/services/dynamodb.py    get_latest_scan, get_scan_history
worker/app/services/dynamodb.py     store_scan_result, get_previous_scan
```

Two files, same name, different functions, and different attribute names for the same data — one uses `repo_id`, the other `repoId`. They drifted because nothing forced them to agree.

We keep one package and run two entrypoints:

```text
python -m app.main        → the worker, polls the queue
uvicorn app.api.main:app  → the API, serves HTTP
```

Shared storage code, imported by both, impossible to drift. In Phase 11 you build two images from one context with different commands.

```powershell
mkdir app\api
mkdir app\core
mkdir app\dev
New-Item app\api\__init__.py, app\core\__init__.py, app\dev\__init__.py -ItemType File
```

```powershell
uv add fastapi "uvicorn[standard]" "python-jose[cryptography]" redis
```

```powershell
uv add --dev httpx
```

---

# 2. Run Redis

```powershell
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

```powershell
docker exec redis redis-cli ping
```

Expect `PONG`.

---

# 3. A local token issuer

Verifying tokens properly needs a real issuer with a real JWKS endpoint. You don't have Cognito yet, and a dev bypass that skips verification would mean the code you test is not the code you ship.

So build a small issuer that signs real RS256 tokens and serves a real JWKS document. The verification code then exercises its production path from day one.

Create:

```text
app/dev/keys.py
```

```python
import base64
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

KEY_PATH = Path(".dev-keys/private.pem")

KID = "local-dev-key-1"


@lru_cache(maxsize=1)
def _private_key():
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(
            KEY_PATH.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    KEY_PATH.parent.mkdir(exist_ok=True)

    KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return key


def _b64(value: int) -> str:
    length = (value.bit_length() + 7) // 8

    raw = value.to_bytes(length, "big")

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwks() -> dict:
    numbers = _private_key().public_key().public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": KID,
                "use": "sig",
                "alg": "RS256",
                "n": _b64(numbers.n),
                "e": _b64(numbers.e),
            }
        ]
    }


def mint_token(
    tenant_id: str,
    email: str = "dev@example.com",
    audience: str = "local-client-id",
    ttl_minutes: int = 60,
    token_use: str = "id",
) -> str:
    now = datetime.now(timezone.utc)

    pem = _private_key().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        {
            "sub": tenant_id,
            "email": email,
            "aud": audience,
            "token_use": token_use,
            "iat": now,
            "exp": now + timedelta(minutes=ttl_minutes),
            "jti": str(uuid.uuid4()),
        },
        pem.decode(),
        algorithm="RS256",
        headers={"kid": KID},
    )
```

Add `.dev-keys/` to `.gitignore`.

The `token_use` claim matters. Cognito issues both ID tokens and access tokens from the same pool, and they carry different claims. Minting it here means you can test that your verifier rejects the wrong kind.

---

# 4. Configuration

Create:

```text
app/config/api.py
```

```python
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
```

In AWS, `JWKS_URL` becomes the Cognito URL and `DEV_AUTH` stays unset. Nothing else changes.

---

# 5. Verify, don't decode

The single most common auth bug is reading a token's payload and believing it.

```text
jwt.get_unverified_claims(token)["sub"]
        ↓
anyone can forge that in ten seconds
```

A JWT is three base64 segments. The payload is not encrypted, just encoded. Only the **signature** proves the issuer minted it.

Create:

```text
app/core/auth.py
```

```python
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


async def current_principal(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Principal:
    claims = verify_token(credentials.credentials)

    return Principal(
        tenant_id=claims["sub"],
        email=claims.get("email", ""),
    )
```

Walk the flow: read `kid` from the unverified header, find the matching public key in the JWKS, verify the RS256 signature with it, check audience and expiry, then check the token type.

Two improvements over the reference implementation, both about key rotation.

It caches the JWKS with `@lru_cache(maxsize=1)`, which never expires. When the issuer rotates signing keys, every request fails with "Signing key not found" until someone restarts every task. Ours has a ten-minute TTL **and** force-refreshes on an unknown `kid`, so a rotation self-heals within one request instead of one deploy.

It also omits the `token_use` check. That happens to be safe there, because access tokens have no `aud` claim and would fail audience validation anyway — but it's safe by accident. Being explicit about which token type you accept is one line and removes a whole class of confusion.

**`algorithms=["RS256"]` is not optional.** Omit it and a library may accept a token whose header says `alg: none`, or one signed with HMAC using the public key as the secret. Always pin the algorithm.

---

# 6. The rate limiter

Every scan is six model calls. Unlimited scans is an unlimited bill.

Create:

```text
app/core/ratelimit.py
```

```python
import logging
import time

from fastapi import Depends, HTTPException

from app.config.api import REDIS_URL, SCAN_LIMIT, SCAN_WINDOW_SECONDS
from app.core.auth import Principal, current_principal

logger = logging.getLogger(__name__)

_client = None


def _redis():
    global _client

    if _client is None:
        try:
            import redis

            _client = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_timeout=2,
            )
        except Exception as exc:
            logger.warning("Redis unavailable: %s", exc)

            return None

    return _client


def check_limit(
    tenant_id: str,
    action: str,
    limit: int,
    window_seconds: int,
) -> None:
    client = _redis()

    if client is None:
        return

    key = f"ratelimit:{action}:{tenant_id}"

    now = time.time()

    try:
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zcard(key)
        pipe.expire(key, window_seconds)

        count = pipe.execute()[1]

        if count >= limit:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded: {limit} {action}s "
                    f"per {window_seconds // 3600}h"
                ),
                headers={"Retry-After": str(window_seconds)},
            )

        client.zadd(key, {f"{now}:{action}": now})

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Rate limit check failed, allowing: %s", exc)


def scan_rate_limit(
    principal: Principal = Depends(current_principal),
) -> Principal:
    check_limit(
        principal.tenant_id,
        "scan",
        SCAN_LIMIT,
        SCAN_WINDOW_SECONDS,
    )

    return principal
```

This is a **sliding window over a Redis sorted set**, and it's a pattern worth owning.

```text
zremrangebyscore   drop entries older than the window
zcard              count what remains
zadd               record this request
expire             let the key die if the tenant goes quiet
```

Timestamps are the sort scores, so trimming the window is one range delete and counting is O(1). The pipeline sends it as a single round trip.

One change from the reference version. It calls `zadd` *before* `zcard`, so a rejected request still consumes quota. A client retrying on 429 then keeps its own window permanently full and can never recover. Ours counts first and only records the request if it was allowed.

---

# 7. Fail open or fail closed

Look at what happens when Redis is down:

```python
if client is None:
    return          # allow the request
```

And what happens when the JWKS fetch fails: an exception propagates and the request gets a 500.

That asymmetry is deliberate and correct.

```text
rate limiter broken   →  fail OPEN
                         worst case: a surprising bill

authenticator broken  →  fail CLOSED
                         worst case if open: anyone
                         reads anyone's data
```

The question to ask for any check: **what does an attacker gain if this check silently stops running?** For a rate limiter, money. For an authenticator, everything.

Write that decision down in a comment. Six months later someone will "fix" the inconsistency in the wrong direction.

---

# 8. Request and response models

Create:

```text
app/api/models.py
```

```python
from pydantic import BaseModel, ConfigDict, Field


class StartScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=300)


class ScanAccepted(BaseModel):
    job_id: str
    status: str
    repo_id: str
    enqueued_at: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    current_step: str
    started_at: str
    updated_at: str
```

Notice what `StartScanRequest` does **not** have: a `tenant_id` or `user_id` field.

```text
tenant_id comes from the verified token
never from the request body
```

Accept it from the body and any authenticated user can scan as anyone, write into anyone's partition, and read the results back. Your Phase 6 tenant isolation becomes decorative — the keys are still scoped, they're just scoped by an attacker-supplied string.

`extra="forbid"` means a client sending `{"repo_id": "x", "target": "y", "tenant_id": "victim"}` gets a 422 instead of having the field quietly ignored. Loud is better.

---

# 9. Object-level authorization

Here is the bug in the reference implementation, in full:

```python
@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(
    scan_id: str,
    user: dict = Depends(get_current_user),
) -> ScanResult:
    item = await get_scan_result(scan_id)

    if not item:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResult(**item)
```

`get_current_user` runs, so the request is authenticated. `user` is then never used.

```text
any valid token
    +
any job_id
    ↓
somebody else's scan results
```

The scan record does contain `user_id`. The check is one comparison. It just isn't there.

This class of bug has a name — Broken Object Level Authorization — and it has sat at the top of the OWASP API Security Top 10 since the list existed. It is common because authentication *feels* like the hard part, so once the token check passes the work seems done.

```text
authenticated  →  I know who you are
authorized     →  this specific row is yours
```

The two sibling endpoints get it right, because they pass `user["user_id"]` into a query that scopes by it. The single-item fetch has no query to scope, so the check has to be explicit — and that's exactly where it gets forgotten.

Create the guard:

```text
app/api/deps.py
```

```python
from fastapi import Depends, HTTPException

from app.core.auth import Principal, current_principal
from app.storage.results import ScanSummary, get_summary


def owned_scan(
    job_id: str,
    principal: Principal = Depends(current_principal),
) -> ScanSummary:
    summary = get_summary(job_id)

    if summary is None or summary.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    return summary
```

Two details.

The missing case and the forbidden case return the **same 404**. Returning 403 for "exists but not yours" leaks existence: an attacker can enumerate job IDs and learn which ones are real. Same status, same body, same timing.

Making it a dependency means the check happens before your handler body runs. A handler that forgets to call a helper is a bug waiting to happen; a handler that can't receive its argument without the check having passed is not.

---

# 10. The routes

Create:

```text
app/api/scans.py
```

```python
import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import owned_scan
from app.api.models import (
    JobStatusResponse,
    ScanAccepted,
    StartScanRequest,
)
from app.core.auth import Principal, current_principal
from app.core.ratelimit import scan_rate_limit
from app.queue.producer import enqueue_scan
from app.storage.jobs import get_job
from app.storage.results import (
    ScanSummary,
    get_full_report,
    scan_history,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("", response_model=ScanAccepted, status_code=202)
def start_scan(
    request: StartScanRequest,
    principal: Principal = Depends(scan_rate_limit),
) -> ScanAccepted:
    message = enqueue_scan(
        principal.tenant_id,
        request.repo_id,
        request.target,
    )

    return ScanAccepted(
        job_id=message.job_id,
        status="queued",
        repo_id=message.repo_id,
        enqueued_at=message.enqueued_at,
    )


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
def job_status(
    job_id: str,
    principal: Principal = Depends(current_principal),
) -> JobStatusResponse:
    job = get_job(job_id)

    if job is None or job.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        current_step=job.current_step,
        started_at=job.started_at,
        updated_at=job.updated_at,
    )


@router.get("/history/{repo_id}", response_model=list[ScanSummary])
def history(
    repo_id: str,
    principal: Principal = Depends(current_principal),
    limit: int = Query(default=30, ge=1, le=100),
) -> list[ScanSummary]:
    return scan_history(principal.tenant_id, repo_id, limit=limit)


@router.get("/{job_id}", response_model=ScanSummary)
def scan_summary(summary: ScanSummary = Depends(owned_scan)) -> ScanSummary:
    return summary


@router.get("/{job_id}/report")
def scan_report(summary: ScanSummary = Depends(owned_scan)) -> dict:
    report = get_full_report(summary.job_id)

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    return report
```

`status_code=202` rather than 200. The work has been accepted, not completed. Returning 200 for queued work tells clients something finished that hasn't.

`Query(default=30, ge=1, le=100)` bounds the limit. Without it, `?limit=1000000` is a free denial-of-service against your own database.

Two of these handlers take `summary: ScanSummary = Depends(owned_scan)` and have no body worth speaking of. That's the point — the authorization is structural.

---

# 11. Side effects after the point of no return

The reference implementation's start endpoint does this:

```python
job = await dispatch_scan_job(...)
await send_scan_started_email(user["email"], request.repo_id, job.jobId)
return job
```

The message is on the queue. The scan is going to run. Then an email is sent, inline, in the request path.

If SES is slow, the client waits. If SES throws, the client gets a 500 — for a scan that is already queued and will complete normally. The client concludes it failed and retries, and now two scans run.

```text
enqueue succeeds  ← point of no return
       ↓
email fails
       ↓
500 to the client
       ↓
client retries
       ↓
duplicate scan
```

Two rules follow:

```text
1. nothing after the point of no return
   may fail the request

2. notifications belong to the process
   that knows the outcome, not the one
   that started the work
```

The email belongs in the worker, after the scan completes. It knows whether it succeeded, and its failures are already retryable through the queue.

If you do want something in the request path, isolate it:

```python
try:
    send_started_notification(principal.email, message.job_id)
except Exception:
    logger.warning("Notification failed for %s", message.job_id, exc_info=True)
```

Never let a nice-to-have take down a must-have.

---

# 12. Assemble the app

Create:

```text
app/api/main.py
```

```python
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import scans
from app.config.api import CORS_ORIGINS, DEV_AUTH

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Docker Repo Auditor", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(scans.router)


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

    logging.warning("DEV_AUTH enabled: local JWKS is being served")
```

`allow_origins` is an explicit list, never `["*"]`. With `allow_credentials=True` the browser rejects a wildcard anyway, but the real reason is that a wildcard means any site can call your API with a user's token.

`allow_headers` is narrowed to what the frontend actually sends. The reference uses `["*"]`, which is not exploitable on its own but is a habit worth not forming.

The dev router only mounts when `DEV_AUTH=1`, and it logs a warning when it does. Anything that weakens security in development should be noisy about it.

---

# 13. Tests

Create `tests/test_api.py`:

```python
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.dev.keys import mint_token
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.storage.results import store_result

pytestmark = pytest.mark.integration

client = TestClient(app)


def _auth(tenant: str) -> dict:
    return {"Authorization": f"Bearer {mint_token(tenant)}"}


def _stored(tenant: str, repo: str = "repo-a") -> str:
    job_id = str(uuid.uuid4())

    store_result(
        job_id,
        tenant,
        repo,
        ScanOutcome(
            target="alpine:3.20",
            outcomes=[
                AgentOutcome(agent="cve_analyst", status="analysed", findings=[])
            ],
        ),
    )

    return job_id


def test_health_needs_no_token() -> None:
    assert client.get("/health").status_code == 200


def test_missing_token_is_rejected() -> None:
    resp = client.post(
        "/api/v1/scans",
        json={"repo_id": "r", "target": "alpine:3.20"},
    )

    assert resp.status_code == 403


def test_forged_token_is_rejected() -> None:
    forged = (
        "eyJhbGciOiJub25lIiwia2lkIjoibG9jYWwtZGV2LWtleS0xIn0"
        ".eyJzdWIiOiJhdHRhY2tlciJ9."
    )

    resp = client.get(
        "/api/v1/scans/history/repo-a",
        headers={"Authorization": f"Bearer {forged}"},
    )

    assert resp.status_code == 401


def test_wrong_token_use_is_rejected(tenant: str) -> None:
    token = mint_token(tenant, token_use="access")

    resp = client.get(
        "/api/v1/scans/history/repo-a",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 401


def test_start_scan_returns_202(tenant: str) -> None:
    resp = client.post(
        "/api/v1/scans",
        json={"repo_id": "repo-a", "target": "alpine:3.20"},
        headers=_auth(tenant),
    )

    assert resp.status_code == 202
    assert resp.json()["status"] == "queued"


def test_tenant_id_in_body_is_rejected(tenant: str) -> None:
    resp = client.post(
        "/api/v1/scans",
        json={
            "repo_id": "repo-a",
            "target": "alpine:3.20",
            "tenant_id": "victim",
        },
        headers=_auth(tenant),
    )

    assert resp.status_code == 422


def test_owner_can_read_their_scan(tenant: str) -> None:
    job_id = _stored(tenant)

    resp = client.get(f"/api/v1/scans/{job_id}", headers=_auth(tenant))

    assert resp.status_code == 200
    assert resp.json()["job_id"] == job_id


def test_other_tenant_gets_404_not_403(tenant: str) -> None:
    job_id = _stored(tenant)

    attacker = f"{tenant}-attacker"

    resp = client.get(f"/api/v1/scans/{job_id}", headers=_auth(attacker))

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_history_is_scoped_to_the_caller(tenant: str) -> None:
    other = f"{tenant}-other"

    _stored(tenant, "nginx")
    _stored(other, "nginx")

    resp = client.get("/api/v1/scans/history/nginx", headers=_auth(tenant))

    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_limit_is_bounded(tenant: str) -> None:
    resp = client.get(
        "/api/v1/scans/history/repo-a?limit=999999",
        headers=_auth(tenant),
    )

    assert resp.status_code == 422


def test_rate_limit_returns_429(tenant: str) -> None:
    body = {"repo_id": "repo-a", "target": "alpine:3.20"}

    codes = [
        client.post("/api/v1/scans", json=body, headers=_auth(tenant)).status_code
        for _ in range(7)
    ]

    assert codes.count(202) == 5
    assert codes[-1] == 429
```

```powershell
$env:DEV_AUTH = "1"
uv run pytest tests/test_api.py -v
```

`test_other_tenant_gets_404_not_403` is the one that matters. Delete the `summary.tenant_id != principal.tenant_id` comparison and it goes red. That single assertion is the difference between this API and the reference implementation's.

`test_forged_token_is_rejected` uses a token with `alg: none` and an empty signature. Drop `algorithms=["RS256"]` from `jwt.decode` and some libraries will happily accept it.

`test_tenant_id_in_body_is_rejected` guards `extra="forbid"`. Remove it and the field is silently ignored — safe today, but it stops being safe the moment someone adds `request.tenant_id or principal.tenant_id` as a "convenience".

---

# 14. Run it

Four containers and two processes.

```powershell
docker start dynamodb-local elasticmq redis
```

Terminal one, the API:

```powershell
$env:DEV_AUTH = "1"
$env:DYNAMODB_ENDPOINT_URL = "http://localhost:8000"
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
uv run uvicorn app.api.main:app --port 8080 --reload
```

Terminal two, the worker:

```powershell
$env:DYNAMODB_ENDPOINT_URL = "http://localhost:8000"
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
uv run python -m app.main
```

Terminal three. Mint a token:

```powershell
$env:TOKEN = uv run python -c "from app.dev.keys import mint_token; print(mint_token('demo-tenant'))"
```

Start a scan:

```powershell
curl.exe -X POST http://localhost:8080/api/v1/scans `
  -H "Authorization: Bearer $env:TOKEN" `
  -H "Content-Type: application/json" `
  -d '{\"repo_id\":\"python\",\"target\":\"python:3.8\"}'
```

Watch the worker pick it up. Poll the job:

```powershell
curl.exe http://localhost:8080/api/v1/scans/jobs/PASTE_JOB_ID -H "Authorization: Bearer $env:TOKEN"
```

Then prove the authorization works. Mint a second token for a different tenant and try to read the first tenant's scan:

```powershell
$env:ATTACKER = uv run python -c "from app.dev.keys import mint_token; print(mint_token('other-tenant'))"
```

```powershell
curl.exe http://localhost:8080/api/v1/scans/PASTE_JOB_ID -H "Authorization: Bearer $env:ATTACKER"
```

You should get a 404 with no hint that the scan exists.

Interactive docs are at `http://localhost:8080/docs`. Paste a token into the Authorize box and you can drive the whole API from the browser.

---

# 15. Quality gate

```powershell
uv run ruff check .
```

```powershell
uv run ruff format --check .
```

```powershell
uv run mypy app eval
```

```powershell
uv run pytest -m "not eval and not integration" -v
```

```powershell
uv run pytest -m integration -v
```

You should have:

```text
✓ RS256 signature verified against a JWKS, algorithm pinned
✓ JWKS cached with a TTL and refreshed on unknown kid
✓ token_use checked explicitly
✓ tenant_id from the token only, extra body fields rejected
✓ Every single-object read behind an ownership dependency
✓ Not-yours and not-found both return 404
✓ Sliding-window limiter that does not charge rejected requests
✓ Rate limiter fails open, authenticator fails closed
✓ 202 for accepted work, bounded query parameters
```

---

# 16. Where this sits

```text
 Phases 1-5      Phase 6        Phase 7         Phase 8  ◄── here
┌───────────┐  ┌──────────┐  ┌───────────┐  ┌──────────────┐
│ measurable│→ │ storage  │→ │ queue +   │→ │ HTTP front   │
│ AI system │  │          │  │ worker    │  │ door + authz │
└───────────┘  └──────────┘  └───────────┘  └──────────────┘
                                                    │
                                                    ▼
                                           ┌──────────────┐
                                           │   Phase 9    │
                                           │  real-time   │
                                           └──────────────┘
```

The API is a thin layer. It verifies, limits, authorizes, and enqueues — and does no work of its own. That thinness is what lets it scale to many small tasks while the workers scale independently on their own resource profile.

---

## Next: Phase 9 — Real-Time Progress

Polling `/jobs/{job_id}` every two seconds works, and it is the wrong shape. A ninety-second scan means forty-five requests per client, most returning the same bytes.

```text
  THE NAIVE VERSION              THE ONE THAT SCALES

  browser ──ws──→ task A         browser ──ws──→ gateway
                    │                                │
             dict in memory                    connection id
                    │                            in a table
                    ▼                                │
              worker pushes                          ▼
              to... which task?               any worker can
                                              push to any browser
```

We build the in-memory `ConnectionManager` first, watch it fail behind two tasks, then move the registry into DynamoDB.

```text
1. why a dict of connections and horizontal
   scaling are mutually exclusive

2. why the reference implementation still
   ships that dead ConnectionManager, fully
   wired into main.py and never used

3. why WebSocket auth puts the token in the
   query string, and what that costs you
   in access logs
```

Making that mistake once, deliberately, is worth more than reading about it.