"""Every export format, fetched from the live API and parsed for real.

The unit tests prove the renderers are correct. This proves the route
reaches them: auth, the 404, the policy application and the response
headers are all things that only exist at this layer.
"""

import csv
import io
import json
import uuid
from xml.etree import ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.dev.keys import mint_token
from app.models.findings import CVEFinding
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.policy.store import Policy, Suppression, save_policy
from app.processors.packages import Package
from app.storage.results import store_result

pytestmark = pytest.mark.integration

client = TestClient(app)


@pytest.fixture(autouse=True)
def _serve_jwks(jwks_server):
    """Every authed test needs the JWKS endpoint reachable over HTTP."""


def _auth(tenant: str) -> dict:
    return {"Authorization": f"Bearer {mint_token(tenant)}"}


def _stored(tenant: str) -> str:
    job_id = str(uuid.uuid4())

    store_result(
        job_id,
        tenant,
        "repo-exports",
        ScanOutcome(
            target="alpine:3.20",
            outcomes=[
                AgentOutcome(
                    agent="cve_analyst",
                    status="analysed",
                    findings=[
                        CVEFinding(
                            severity="critical",
                            title="OpenSSL RCE",
                            impact="Remote code execution",
                            fix="Upgrade",
                            effort="trivial",
                            priority=99,
                            vulnerability_id="CVE-2022-3602",
                            exploitability="likely",
                            package="openssl",
                            fingerprint="fp-export-1",
                        )
                    ],
                )
            ],
            packages=[
                Package(name="openssl", version="3.0.2", purl="pkg:apk/openssl@3.0.2")
            ],
        ),
    )

    return job_id


def test_json_is_still_the_default(tenant: str) -> None:
    """The existing contract, untouched. Nothing that reads it today breaks."""
    job_id = _stored(tenant)

    default = client.get(f"/api/v1/scans/{job_id}/report", headers=_auth(tenant))
    explicit = client.get(
        f"/api/v1/scans/{job_id}/report?format=json", headers=_auth(tenant)
    )

    assert default.status_code == 200
    assert default.content == explicit.content
    assert default.json()["target"] == "alpine:3.20"


@pytest.mark.parametrize(
    ("fmt", "media_type", "parse"),
    [
        ("sarif", "application/sarif+json", json.loads),
        ("cyclonedx", "application/vnd.cyclonedx+json", json.loads),
        ("csv", "text/csv", lambda t: list(csv.DictReader(io.StringIO(t)))),
        ("junit", "application/xml", ET.fromstring),
    ],
)
def test_every_format_parses_with_a_real_parser(
    tenant: str, fmt: str, media_type: str, parse
) -> None:
    job_id = _stored(tenant)

    resp = client.get(
        f"/api/v1/scans/{job_id}/report?format={fmt}", headers=_auth(tenant)
    )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith(media_type)

    # Named after the scan, so a downloads folder full of these is legible.
    assert job_id in resp.headers["content-disposition"]

    assert parse(resp.text) is not None


def test_an_unknown_format_is_rejected(tenant: str) -> None:
    job_id = _stored(tenant)

    resp = client.get(
        f"/api/v1/scans/{job_id}/report?format=pdf", headers=_auth(tenant)
    )

    assert resp.status_code == 422


def test_exports_inherit_404_not_403(tenant: str) -> None:
    """Another tenant's scan is not found, not forbidden - no id oracle."""
    job_id = _stored(tenant)

    resp = client.get(
        f"/api/v1/scans/{job_id}/report?format=sarif",
        headers=_auth(f"other-{uuid.uuid4()}"),
    )

    assert resp.status_code == 404


def test_policy_is_applied_on_read(tenant: str) -> None:
    """Suppress after the scan, and the stored report is unchanged."""
    job_id = _stored(tenant)

    save_policy(
        tenant,
        Policy(
            suppressions=[
                Suppression(vulnerability_id="CVE-2022-3602", reason="Accepted")
            ]
        ),
    )

    resp = client.get(
        f"/api/v1/scans/{job_id}/report?format=sarif", headers=_auth(tenant)
    )

    result = json.loads(resp.text)["runs"][0]["results"][0]

    # Still reported, and reported as accepted rather than quietly dropped.
    assert result["ruleId"] == "cve/CVE-2022-3602"
    assert result["suppressions"][0]["justification"] == "Accepted"

    save_policy(tenant, Policy())
