import os
import uuid

import pytest

os.environ.setdefault("DYNAMODB_ENDPOINT_URL", "http://localhost:8000")
os.environ.setdefault("SQS_ENDPOINT_URL", "http://localhost:9324")
# The dev JWKS router only mounts when this is on, and app.config.api reads
# it at import time - so it has to be set before any app module loads.
os.environ.setdefault("DEV_AUTH", "1")


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
        uvicorn.Config(app, host="127.0.0.1", port=8080, log_level="warning")
    )

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("dev JWKS server did not start on 127.0.0.1:8080")

    yield

    server.should_exit = True
    thread.join(timeout=5)
