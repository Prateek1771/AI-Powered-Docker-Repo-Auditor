from functools import lru_cache
from typing import Any

import boto3

from app.config.storage import (
    AWS_REGION,
    DYNAMODB_ENDPOINT_URL,
    SCAN_JOBS_TABLE,
    SCAN_RESULTS_TABLE,
)

_TABLES = {
    "scan_jobs": SCAN_JOBS_TABLE,
    "scan_results": SCAN_RESULTS_TABLE,
}


@lru_cache(maxsize=1)
def get_resource() -> Any:
    """Build the DynamoDB resource, pointed at Local when configured.

    With DYNAMODB_ENDPOINT_URL unset boto3 finds the real service, which
    is what makes the same code run on a laptop and in AWS.

    Cached: constructing a boto3 resource parses the service JSON model,
    which is not cheap, and this was being rebuilt twice per GET /report.
    Every input is a module-level constant read at import, so there is
    nothing for the cache to go stale against. See docs/audits/audit-01-backend.md P3-10.
    """
    kwargs: dict[str, Any] = {"region_name": AWS_REGION}

    if DYNAMODB_ENDPOINT_URL:
        kwargs.update(
            endpoint_url=DYNAMODB_ENDPOINT_URL,
            aws_access_key_id="local",
            aws_secret_access_key="local",
        )

    return boto3.resource("dynamodb", **kwargs)


def table(name: str) -> Any:
    """Return one of the two tables by its logical name."""
    return get_resource().Table(_TABLES[name])
