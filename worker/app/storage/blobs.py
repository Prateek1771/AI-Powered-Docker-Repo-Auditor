import json
from pathlib import Path
from typing import Any

import boto3

from app.config.storage import AWS_REGION, BLOB_DIR, REPORTS_BUCKET


def _client() -> Any:
    return boto3.client("s3", region_name=AWS_REGION)


def _path(key: str) -> Path:
    path = Path(BLOB_DIR) / f"{key}.json"

    path.parent.mkdir(parents=True, exist_ok=True)

    return path


def put_blob(key: str, payload: dict) -> str:
    if not REPORTS_BUCKET:
        _path(key).write_text(json.dumps(payload, default=str))

        return key

    _client().put_object(
        Bucket=REPORTS_BUCKET,
        Key=f"{key}.json",
        Body=json.dumps(payload, default=str).encode(),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    return key


def get_blob(key: str) -> dict | None:
    if not REPORTS_BUCKET:
        path = _path(key)

        if not path.exists():
            return None

        return json.loads(path.read_text())

    client = _client()

    try:
        resp = client.get_object(Bucket=REPORTS_BUCKET, Key=f"{key}.json")
    # NoSuchKey is only raised for get_object; a missing report is a normal
    # answer here, not an error worth propagating to the API layer.
    except client.exceptions.NoSuchKey:
        return None

    return json.loads(resp["Body"].read())
