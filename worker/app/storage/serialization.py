import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from pydantic import BaseModel


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(UTC).isoformat()


def ttl_epoch(days: int) -> int:
    """Return a Unix timestamp `days` from now, for DynamoDB's TTL.

    An integer epoch, because that is the only thing DynamoDB will expire
    on - a declared TTL over an ISO string silently deletes nothing.
    """
    expiry = datetime.now(UTC) + timedelta(days=days)

    return int(expiry.timestamp())


def to_item(model: BaseModel) -> dict:
    """Convert a Pydantic model into a DynamoDB-safe item.

    The round trip through JSON is what turns floats into Decimals, which
    boto3 requires and which json.dumps alone will not produce.
    """
    return json.loads(
        model.model_dump_json(),
        parse_float=Decimal,
    )


def to_item_dict(payload: dict) -> dict:
    """Convert a plain dict into a DynamoDB-safe item."""
    return json.loads(
        json.dumps(payload),
        parse_float=Decimal,
    )


def item_size(item: Any) -> int:
    """Measure an item's encoded size in bytes.

    Used to refuse a write before DynamoDB does, so an oversized report
    fails with our message rather than a 400 from the SDK.
    """
    return len(json.dumps(item, default=str).encode())
