import os
import uuid

import pytest

os.environ.setdefault("DYNAMODB_ENDPOINT_URL", "http://localhost:8000")
os.environ.setdefault("SQS_ENDPOINT_URL", "http://localhost:9324")


@pytest.fixture(scope="session")
def tables() -> None:
    # ponytail: not autouse - an autouse session fixture would drag DynamoDB
    # Local into the free `-m "not integration"` suite too.
    from app.scripts.create_tables import main

    main()


@pytest.fixture
def tenant(tables: None) -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"
