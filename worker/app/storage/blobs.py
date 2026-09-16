import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

import boto3

from app.config.storage import AWS_REGION, BLOB_DIR, REPORTS_BUCKET

# Every segment of a blob key comes from outside: the tenant id from a token
# claim, the job id from a path parameter. The same pattern images.py applies
# to upload paths, and for the same reason - it had the guard, this did not,
# so with DEV_AUTH=1 a token minted for tenant "../../.." produced a report
# key that escaped BLOB_DIR entirely. See docs/audits/audit-01-backend.md P3-10.
_SAFE_SEGMENT = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")


class BlobKeyError(ValueError):
    """Raised when a blob key could reach outside the blob directory."""


def safe_segment(value: str) -> str:
    """Return a path segment, refusing anything that could escape the dir."""
    if not _SAFE_SEGMENT.fullmatch(value) or value in {".", ".."}:
        raise BlobKeyError(f"Unusable path segment: {value[:64]!r}")

    return value


def _client() -> Any:
    """Build an S3 client for the configured region."""
    return boto3.client("s3", region_name=AWS_REGION)


def _checked(key: str) -> str:
    """Validate every segment of a blob key.

    Applied to the key itself rather than only to the local path, because
    the S3 branch is just as escapable - `reports/../../other-tenant/x`
    is a perfectly valid S3 key, and reads someone else's report.
    """
    if not key:
        raise BlobKeyError("Empty blob key")

    for segment in key.split("/"):
        safe_segment(segment)

    return key


def _path(key: str) -> Path:
    """Return the local file a blob key maps to, creating its parent."""
    path = Path(BLOB_DIR) / f"{_checked(key)}.json"

    path.parent.mkdir(parents=True, exist_ok=True)

    return path


def put_blob(key: str, payload: dict) -> str:
    """Store a report, in S3 when REPORTS_BUCKET is set and on disk if not.

    Reports are too big for a DynamoDB item, so only the summary goes in
    the table and this holds the body the summary points at.
    """
    body = json.dumps(payload, default=str)

    if not REPORTS_BUCKET:
        path = _path(key)

        # Write-then-rename. A crash partway through a direct write left
        # truncated JSON on disk, which surfaced later as a 500 from
        # json.loads rather than the 404 a missing report is supposed to
        # give. os.replace is atomic within a filesystem, so a reader sees
        # either the old file or the whole new one. See docs/audits/audit-01-backend.md P3-10.
        tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")

        try:
            tmp.write_text(body)

            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)

        return key

    _client().put_object(
        Bucket=REPORTS_BUCKET,
        Key=f"{_checked(key)}.json",
        Body=body.encode(),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    return key


def get_blob(key: str) -> dict | None:
    """Read a report back, or None when there is nothing stored.

    A missing report is a normal answer, not an error: the summary row can
    outlive its body if the two expire on different schedules.
    """
    if not REPORTS_BUCKET:
        path = _path(key)

        if not path.exists():
            return None

        return json.loads(path.read_text())

    client = _client()

    try:
        resp = client.get_object(Bucket=REPORTS_BUCKET, Key=f"{_checked(key)}.json")
    # NoSuchKey is only raised for get_object; a missing report is a normal
    # answer here, not an error worth propagating to the API layer.
    except client.exceptions.NoSuchKey:
        return None

    return json.loads(resp["Body"].read())
