"""Cover the auth and input-validation properties the audit found unguarded.

Every test here fails against the code as it was before the fix. That is the
point of the module: the previous suite asserted `alg: none` was rejected and
then stopped, so a missing issuer check and an unvalidated image reference both
passed review.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.main import app
from app.api.models import StartScanRequest
from app.config.api import DEV_ISSUER
from app.dev.keys import mint_token

client = TestClient(app)


# ---------------------------------------------------------------- argv safety


@pytest.mark.parametrize(
    "target",
    [
        # The whole reason `--` was added to every scanner argv. Trivy and the
        # docker CLI both parse flags positionally-anywhere, so a target that
        # starts with a dash is a flag, not an image.
        "--server=https://attacker.example",
        "-v/:/host",
        "--config=/etc/passwd",
        # Newline: Python's `$` matches before a trailing newline, so an
        # unanchored pattern would let this through.
        "alpine:3.20\n--server=https://attacker.example",
        "alpine:3.20 --output=/data/blobs/x",
        "alpine;whoami",
        "alpine$(whoami)",
        "alpine`whoami`",
        "",
    ],
)
def test_hostile_targets_are_refused(target: str) -> None:
    with pytest.raises(ValidationError):
        StartScanRequest(repo_id="r", target=target)


@pytest.mark.parametrize(
    "target",
    [
        "alpine",
        "alpine:3.20",
        "python:3.12-slim",
        "ghcr.io/owner/image:tag",
        "registry.example.com:5000/team/app:v1.2.3",
        "alpine@sha256:" + "a" * 64,
        "upload://abc-123_DEF.tar",
    ],
)
def test_real_references_still_pass(target: str) -> None:
    assert StartScanRequest(repo_id="r", target=target).target == target


# --------------------------------------------------------------- token claims


@pytest.mark.integration
def test_token_from_another_issuer_is_rejected(jwks_server) -> None:
    """The gap that made a mis-set JWKS_URL a full bypass.

    This token is correctly signed by the key the JWKS serves and carries
    the right audience and token_use. Only `iss` is wrong. Before
    verify_iss it was accepted.
    """
    token = mint_token("attacker", issuer="https://cognito-idp.example/other-pool")

    resp = client.get(
        "/api/v1/scans/history/repo-a",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 401


@pytest.mark.integration
def test_matching_issuer_is_accepted(jwks_server) -> None:
    """The other half: the fix must not reject the issuer we do expect."""
    resp = client.get(
        "/api/v1/scans/history/repo-a",
        headers={"Authorization": f"Bearer {mint_token('t', issuer=DEV_ISSUER)}"},
    )

    assert resp.status_code == 200


@pytest.mark.integration
def test_expired_token_is_rejected(jwks_server) -> None:
    token = mint_token("t", ttl_minutes=-5)

    resp = client.get(
        "/api/v1/scans/history/repo-a",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 401


@pytest.mark.integration
def test_wrong_audience_is_rejected(jwks_server) -> None:
    token = mint_token("t", audience="some-other-client")

    resp = client.get(
        "/api/v1/scans/history/repo-a",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 401


# ------------------------------------------------------- production fail-fast


@pytest.fixture
def reload_config(monkeypatch):
    """Reload app.config.api under altered env, then always put it back.

    The restore is a fixture rather than a trailing line because these
    tests deliberately make the reload raise, and a module left
    half-initialised would break every test that imports it afterwards.
    """
    import importlib

    import app.config.api as api_config

    def reload():
        return importlib.reload(api_config)

    yield reload

    monkeypatch.undo()
    importlib.reload(api_config)


def test_dev_defaults_are_refused_outside_a_local_run(
    monkeypatch, reload_config
) -> None:
    """A deploy that forgets JWKS_URL must not silently trust the dev issuer."""
    monkeypatch.setenv("DEV_AUTH", "0")
    monkeypatch.delenv("AUTH_ALLOW_DEV_DEFAULTS", raising=False)
    monkeypatch.delenv("JWKS_URL", raising=False)
    monkeypatch.delenv("TOKEN_AUDIENCE", raising=False)
    monkeypatch.delenv("TOKEN_ISSUER", raising=False)

    config = reload_config()

    # RuntimeError, not InsecureAuthConfig: reload() rebuilds the module's
    # classes, so the name captured before the reload is a different object
    # from the one actually raised.
    with pytest.raises(RuntimeError) as exc:
        config.assert_production_auth()

    assert "JWKS_URL" in str(exc.value)
    assert "TOKEN_ISSUER" in str(exc.value)


def test_real_settings_start_cleanly(monkeypatch, reload_config) -> None:
    monkeypatch.setenv("DEV_AUTH", "0")
    monkeypatch.delenv("AUTH_ALLOW_DEV_DEFAULTS", raising=False)
    monkeypatch.setenv(
        "JWKS_URL", "https://cognito-idp.example/pool/.well-known/jwks.json"
    )
    monkeypatch.setenv("TOKEN_AUDIENCE", "real-client-id")
    monkeypatch.setenv("TOKEN_ISSUER", "https://cognito-idp.example/pool")

    config = reload_config()

    config.assert_production_auth()

    assert config.TOKEN_ISSUER == "https://cognito-idp.example/pool"


def test_the_worker_starts_without_any_auth_settings(monkeypatch) -> None:
    """The worker imports this module for REDIS_URL and verifies no tokens.

    Importing config must therefore never assert. This is the regression
    test for a guard that refused to start the worker in compose.
    """
    import importlib

    monkeypatch.setenv("DEV_AUTH", "0")
    monkeypatch.delenv("AUTH_ALLOW_DEV_DEFAULTS", raising=False)
    monkeypatch.delenv("JWKS_URL", raising=False)

    import app.config.api as api_config

    importlib.reload(api_config)  # must not raise

    assert api_config.REDIS_URL

    monkeypatch.undo()
    importlib.reload(api_config)


def test_cors_origins_are_stripped(monkeypatch, reload_config) -> None:
    """`"a, b".split(",")` yields " b", which matches no browser Origin."""
    monkeypatch.setenv("AUTH_ALLOW_DEV_DEFAULTS", "1")
    monkeypatch.setenv("CORS_ORIGINS", "http://a.example, http://b.example,")

    config = reload_config()

    assert config.CORS_ORIGINS == ["http://a.example", "http://b.example"]
