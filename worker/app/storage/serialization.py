import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from pydantic import BaseModel


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def ttl_epoch(days: int) -> int:
    expiry = datetime.now(UTC) + timedelta(days=days)

    return int(expiry.timestamp())


def to_item(model: BaseModel) -> dict:
    return json.loads(
        model.model_dump_json(),
        parse_float=Decimal,
    )


def to_item_dict(payload: dict) -> dict:
    return json.loads(
        json.dumps(payload),
        parse_float=Decimal,
    )


def item_size(item: Any) -> int:
    return len(json.dumps(item, default=str).encode())
