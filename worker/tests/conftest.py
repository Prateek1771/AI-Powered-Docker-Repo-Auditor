import os
import socket
import uuid

import pytest

os.environ.setdefault("DYNAMODB_ENDPOINT_URL", "http://localhost:8000")
os.environ.setdefault("SQS_ENDPOINT_URL", "http://localhost:9324")
# Same literal as docker-compose and CI. Three different defaults is how you
# get a green CI and a broken laptop. setdefault, not assignment, so CI's own
# value wins. app.config.api reads this at import, hence up here.
os.environ.setdefault("REDIS_PASSWORD", "localdev")
# The dev JWKS router only mounts when this is on, and app.config.api reads
# it at import time - so it has to be set before any app module loads.
os.environ.setdefault("DEV_AUTH", "1")

# Assignment, not setdefault: this one has to be forced OFF.
#
# app/telemetry/setup.py says the test suite runs with no endpoint configured,
# and that was true only because the .env loader had never worked. Once it did,
# tests inherited OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 from
# the project .env - a hostname that resolves inside the compose network and
# nowhere else - and every suite spent its time retrying DNS failures and
# printing export warnings between assertions.
#
# Tests should not emit telemetry to a real collector in any case. This is the
# documented behaviour, now actually enforced rather than accidental.
os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = ""


def _free_port() -> int:
    """Ask the OS for a port nothing is using."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))

        return int(probe.getsockname()[1])


# The JWKS server used to bind a hardcoded 8080, which made the whole session
# fail whenever anything else on the machine held that port - and worse, it
# failed confusingly: `localhost` resolves to ::1 first, so a container
# publishing [::]:8080 answered the JWKS fetch with its own 404 while our
# uvicorn sat unreachable on 127.0.0.1.
#
# A port the OS picked cannot collide, and 127.0.0.1 in the URL cannot be
# hijacked by something listening on ::1.
JWKS_PORT = int(os.environ.get("JWKS_TEST_PORT") or _free_port())

os.environ.setdefault(
    "JWKS_URL",
    f"http://127.0.0.1:{JWKS_PORT}/dev/.well-known/jwks.json",
)


@pytest.fixture(scope="session")
def tables() -> None:
    # ponytail: not autouse - an autouse session fixture would drag DynamoDB
    # Local into the free `-m "not integration"` suite too.
    from app.scripts.create_tables import main

    main()


@pytest.fixture
def tenant(tables: None) -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def jwks_server():
    """Serve the dev JWKS over real HTTP on the port JWKS_URL points at.

    app.core.auth fetches the JWKS with httpx, so TestClient alone is not
    enough - it never binds a port. Running uvicorn here keeps the verifier
    on its production path (real fetch, real cache, real kid lookup) instead
    of stubbing the part this phase exists to test.
    """
    import threading
    import time

    import uvicorn

    from app.api.main import app

    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=JWKS_PORT, log_level="warning")
    )

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError(f"dev JWKS server did not start on 127.0.0.1:{JWKS_PORT}")

    yield

    server.should_exit = True
    thread.join(timeout=5)
