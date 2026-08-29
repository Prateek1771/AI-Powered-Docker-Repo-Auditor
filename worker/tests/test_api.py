import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.dev.keys import mint_token
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.storage.results import store_result

pytestmark = pytest.mark.integration

client = TestClient(app)


@pytest.fixture(autouse=True)
def _serve_jwks(jwks_server):
    """Every authed test needs the JWKS endpoint reachable over HTTP."""


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

    # FastAPI >= 0.112 returns 401 here, not the 403 older versions used.
    assert resp.status_code == 401


def test_forged_token_is_rejected() -> None:
    forged = (
        "eyJhbGciOiJub25lIiwia2lkIjoibG9jYWwtZGV2LWtleS0xIn0.eyJzdWIiOiJhdHRhY2tlciJ9."
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


def test_a_started_scan_is_readable_before_a_worker_runs(tenant: str) -> None:
    """202 must not hand back a job_id that GET immediately 404s.

    Nothing consumes the queue in this test, so the row can only exist if
    start_scan wrote it. Before that fix this window lasted until a worker
    picked the message up, and the client had no way to wait it out.
    """
    job_id = client.post(
        "/api/v1/scans",
        json={"repo_id": "repo-a", "target": "alpine:3.20"},
        headers=_auth(tenant),
    ).json()["job_id"]

    resp = client.get(f"/api/v1/scans/jobs/{job_id}", headers=_auth(tenant))

    assert resp.status_code == 200
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
