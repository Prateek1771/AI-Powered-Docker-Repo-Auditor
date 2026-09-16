# Phase 6 — Persistence: Hot/Cold Tables, Tenant Keys & the Decimal Problem

Your scans vanish when the process exits. Time to fix that, and to fix three real bugs the reference implementation has in this exact layer.

```text
                      ScanOutcome
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
      ┌───────────────┐        ┌────────────────┐
      │  scan_jobs    │        │  scan_results  │
      │               │        │                │
      │  hot, tiny    │        │  cold, larger  │
      │  written on   │        │  written once  │
      │  every tick   │        │  at the end    │
      │               │        │                │
      │  PK job_id    │        │  PK job_id     │
      │  TTL 30 days  │        │  GSI tenant#repo│
      └───────────────┘        └───────┬────────┘
                                       │
                                       ▼
                              ┌────────────────┐
                              │  BLOB STORE    │
                              │  full findings │
                              │  local → S3    │
                              └────────────────┘
```

The rule for this phase:

```text
the shape of your keys decides
which questions you can answer cheaply
```

Everything runs in Docker. No AWS account until Phase 12 — the only thing that changes then is an endpoint URL.

---

# 1. Run DynamoDB Local

```powershell
docker run -d --name dynamodb-local -p 8000:8000 amazon/dynamodb-local
```

Verify it's up:

```powershell
docker logs dynamodb-local --tail 5
```

This is the real DynamoDB engine, not a mock. Same API, same errors, same key constraints. Anything that works here works in AWS.

Install the SDK:

```powershell
uv add boto3
```

```powershell
uv add --dev boto3-stubs[dynamodb]
```

---

# 2. Why two tables

You could put everything in one table. Don't.

```text
scan_jobs
  written  8+ times per scan (every progress tick)
  size     ~200 bytes
  read     constantly, by the UI polling status

scan_results
  written  once per scan
  size     50-400 KB
  read     rarely, when someone opens a report
```

Put them together and every progress update rewrites the entire findings blob. DynamoDB charges by bytes written, rounded up per KB. A 300 KB item rewritten eight times is 2.4 MB of writes per scan instead of 1.6 KB.

```text
hot and small    →   one table
cold and large   →   another
```

That split is not DynamoDB-specific. It's the same reasoning behind separating a session store from a document store in any database.

---

# 3. Design the keys before writing code

Ask what questions the product needs to answer:

```text
1. what is the status of job X          → PK on job_id
2. what is the latest scan of repo R
   for tenant T                         → needs a composite
3. show tenant T's scan history for R   → same composite, sorted
4. show all of tenant T's recent jobs   → PK tenant, SK time
```

Question 2 is where the reference implementation goes wrong, so look at it closely.

Its table has a GSI keyed on `repo_id` alone, and the query filters by user:

```python
resp = table.query(
    IndexName="RepoIdIndex",
    KeyConditionExpression=Key("repo_id").eq(repo_id),
    FilterExpression=Attr("user_id").eq(user_id),
    ScanIndexForward=False,
    Limit=1,
)
```

In DynamoDB, **`Limit` caps items read, and `FilterExpression` runs after that.**

```text
1. read the 1 most recent item for repo_id "nginx"
2. that item belongs to a different tenant
3. filter removes it
4. return []
```

Two tenants both scanning a repo named `nginx` hide each other's results. The query is not slow or expensive. It is silently wrong.

The fix is to put the tenant in the partition key:

```text
tenant_repo = "{tenant_id}#{repo_id}"
```

Now the question is answerable with a key condition alone. No filter, no post-read discard, and `Limit=1` means what you think it means.

**Any time you see `Limit` and `FilterExpression` on the same query, treat it as a bug until proven otherwise.**

---

# 4. Configuration

Create:

```text
worker/app/config/storage.py
```

```python
import os

DYNAMODB_ENDPOINT_URL = os.environ.get("DYNAMODB_ENDPOINT_URL")

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

SCAN_JOBS_TABLE = os.environ.get(
    "SCAN_JOBS_TABLE",
    "auditor-scan-jobs",
)

SCAN_RESULTS_TABLE = os.environ.get(
    "SCAN_RESULTS_TABLE",
    "auditor-scan-results",
)

BLOB_DIR = os.environ.get("BLOB_DIR", "./.blobs")

JOB_TTL_DAYS = 30

MAX_ITEM_BYTES = 380_000
```

`DYNAMODB_ENDPOINT_URL` is the entire local/cloud switch. Set it locally, leave it unset in AWS, and the same code talks to both.

Set it for your shell:

```powershell
$env:DYNAMODB_ENDPOINT_URL = "http://localhost:8000"
```

---

# 5. The storage client

Create:

```text
worker/app/storage/__init__.py
worker/app/storage/client.py
```

```python
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


def get_resource():
    kwargs: dict = {"region_name": AWS_REGION}

    if DYNAMODB_ENDPOINT_URL:
        kwargs.update(
            endpoint_url=DYNAMODB_ENDPOINT_URL,
            aws_access_key_id="local",
            aws_secret_access_key="local",
        )

    return boto3.resource("dynamodb", **kwargs)


def table(name: str):
    return get_resource().Table(_TABLES[name])
```

DynamoDB Local requires credentials to be present but does not check them, hence the dummy values. In AWS the branch is skipped and boto3 picks up the task role.

---

# 6. Create the tables

Create:

```text
worker/app/scripts/create_tables.py
```

```python
from app.config.storage import SCAN_JOBS_TABLE, SCAN_RESULTS_TABLE
from app.storage.client import get_resource


def main() -> None:
    resource = get_resource()

    existing = {t.name for t in resource.tables.all()}

    if SCAN_JOBS_TABLE not in existing:
        resource.create_table(
            TableName=SCAN_JOBS_TABLE,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[
                {"AttributeName": "job_id", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "job_id", "AttributeType": "S"},
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "started_at", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "TenantIndex",
                    "KeySchema": [
                        {"AttributeName": "tenant_id", "KeyType": "HASH"},
                        {"AttributeName": "started_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        ).wait_until_exists()

        print(f"created {SCAN_JOBS_TABLE}")

    if SCAN_RESULTS_TABLE not in existing:
        resource.create_table(
            TableName=SCAN_RESULTS_TABLE,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[
                {"AttributeName": "job_id", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "job_id", "AttributeType": "S"},
                {"AttributeName": "tenant_repo", "AttributeType": "S"},
                {"AttributeName": "scan_date", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "TenantRepoIndex",
                    "KeySchema": [
                        {"AttributeName": "tenant_repo", "KeyType": "HASH"},
                        {"AttributeName": "scan_date", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        ).wait_until_exists()

        print(f"created {SCAN_RESULTS_TABLE}")

    client = resource.meta.client

    # Re-enabling raises ValidationException, so this has to be idempotent:
    # conftest runs main() once per test session, not once ever.
    status = client.describe_time_to_live(TableName=SCAN_JOBS_TABLE)[
        "TimeToLiveDescription"
    ]["TimeToLiveStatus"]

    if status in ("ENABLED", "ENABLING"):
        print(f"ttl already {status.lower()} on expires_at")

        return

    client.update_time_to_live(
        TableName=SCAN_JOBS_TABLE,
        TimeToLiveSpecification={
            "Enabled": True,
            "AttributeName": "expires_at",
        },
    )

    print("ttl enabled on expires_at")


if __name__ == "__main__":
    main()
```

```powershell
uv run python -m app.scripts.create_tables
```

Note `AttributeDefinitions` only lists attributes used in **keys**. DynamoDB is schemaless everywhere else. Declaring an attribute you don't index is an error, which surprises people coming from SQL.

---

# 7. TTL: the bug that looks like a feature

The reference implementation declares this in Terraform:

```hcl
ttl {
  attribute_name = "expires_at"
  enabled        = true
}
```

and then writes job records like this:

```python
table.put_item(Item={
    "job_id": job_id,
    "user_id": user_id,
    "status": "running",
    "startedAt": now,
    "created_at": now,
    "updatedAt": now,
})
```

No `expires_at`. The TTL is enabled, correctly configured, and does nothing. Job records accumulate forever.

There's a second trap waiting even if you do write it. **DynamoDB TTL requires a Number holding Unix epoch seconds.** Write an ISO-8601 string and DynamoDB accepts the item without complaint and silently ignores the TTL.

```text
expires_at = "2026-09-28T10:00:00Z"   accepted, ignored forever
expires_at = 1790000000                deleted on schedule
```

No error. No warning. A feature that exists in your infrastructure diagram and nowhere in reality.

Create:

```text
worker/app/storage/serialization.py
```

```python
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
```

---

# 8. The Decimal problem

DynamoDB rejects Python floats outright:

```text
TypeError: Float types are not supported. Use Decimal types instead.
```

Your models are full of them — `cvss_score`, `confidence`. So every float in an arbitrarily nested structure has to become a `Decimal` on the way in.

The reference implementation walks the structure by hand:

```python
def _serialize(obj):
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    if isinstance(obj, float):
        from decimal import Decimal
        return Decimal(str(obj))
    return obj
```

That works, though importing `Decimal` inside the function on every float is doing needless work.

The one-liner does the same job:

```python
json.loads(model.model_dump_json(), parse_float=Decimal)
```

Pydantic serialises to JSON, and `parse_float` intercepts every float during parsing at any depth. Tuples, sets, enums, and datetimes are all handled by Pydantic's serialiser rather than by you.

Reading back needs nothing at all. `Model.model_validate(item)` coerces `Decimal` into `float` and `int` fields automatically.

One detail worth internalising: `Decimal(str(x))` not `Decimal(x)`. The float `0.1` is not exactly one tenth in binary, and `Decimal(0.1)` faithfully preserves all the noise:

```text
Decimal(0.1)       0.1000000000000000055511151231257827
Decimal(str(0.1))  0.1
```

`parse_float=Decimal` receives the string token from the JSON text, so it takes the correct path for free.

---

# 9. The 400 KB ceiling

A DynamoDB item cannot exceed 400 KB. A scan with 150 CVE findings, each carrying `title`, `impact`, `fix`, and `evidence`, gets close.

The standard pattern:

```text
DynamoDB   →  the index: scores, counts, metadata, a pointer
blob store →  the payload: full findings, dockerfile diff
```

Create:

```text
worker/app/storage/blobs.py
```

```python
import json
from pathlib import Path

from app.config.storage import BLOB_DIR


def _path(key: str) -> Path:
    path = Path(BLOB_DIR) / f"{key}.json"

    path.parent.mkdir(parents=True, exist_ok=True)

    return path


def put_blob(key: str, payload: dict) -> str:
    _path(key).write_text(json.dumps(payload, default=str))

    return key


def get_blob(key: str) -> dict | None:
    path = _path(key)

    if not path.exists():
        return None

    return json.loads(path.read_text())
```

Add `.blobs/` to `.gitignore`.

Two functions and a key. In Phase 12 the bodies become `s3.put_object` and `s3.get_object` and nothing above this file changes. That is the entire point of putting it behind an interface now, while it costs nothing.

The reference implementation does write both — `store_scan_result` to DynamoDB and `upload_scan_report` to S3 — but writes the *complete* record to both, so DynamoDB still carries the full findings blob and the 400 KB risk with it.

---

# 10. The job repository

Create:

```text
worker/app/storage/jobs.py
```

```python
import logging
from typing import Literal

from boto3.dynamodb.conditions import Key
from pydantic import BaseModel

from app.config.storage import JOB_TTL_DAYS
from app.storage.client import table
from app.storage.serialization import now_iso, to_item, ttl_epoch

logger = logging.getLogger(__name__)

JobStatus = Literal["queued", "running", "completed", "failed"]


class JobRecord(BaseModel):
    job_id: str
    tenant_id: str
    repo_id: str
    target: str
    status: JobStatus
    progress: int = 0
    current_step: str = ""
    started_at: str
    updated_at: str
    expires_at: int


def create_job(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> JobRecord:
    now = now_iso()

    record = JobRecord(
        job_id=job_id,
        tenant_id=tenant_id,
        repo_id=repo_id,
        target=target,
        status="queued",
        progress=0,
        current_step="Queued",
        started_at=now,
        updated_at=now,
        expires_at=ttl_epoch(JOB_TTL_DAYS),
    )

    table("scan_jobs").put_item(Item=to_item(record))

    return record


def update_progress(
    job_id: str,
    status: JobStatus,
    progress: int,
    step: str,
) -> None:
    table("scan_jobs").update_item(
        Key={"job_id": job_id},
        UpdateExpression=(
            "SET #status = :status, "
            "progress = :progress, "
            "current_step = :step, "
            "updated_at = :updated"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":progress": progress,
            ":step": step,
            ":updated": now_iso(),
        },
    )


def get_job(job_id: str) -> JobRecord | None:
    resp = table("scan_jobs").get_item(Key={"job_id": job_id})

    item = resp.get("Item")

    return JobRecord.model_validate(item) if item else None


def recent_jobs(tenant_id: str, limit: int = 20) -> list[JobRecord]:
    resp = table("scan_jobs").query(
        IndexName="TenantIndex",
        KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        ScanIndexForward=False,
        Limit=limit,
    )

    return [
        JobRecord.model_validate(item)
        for item in resp.get("Items", [])
    ]
```

`ExpressionAttributeNames={"#status": "status"}` is not optional. `status` is a DynamoDB reserved word, and using it directly in an `UpdateExpression` fails with a validation error that does not mention reserved words. The list is long and includes `name`, `size`, `count`, `timestamp`, and `year`. When an expression fails for no visible reason, suspect a reserved word first.

`update_item` writes only the named attributes. Using `put_item` for a progress tick would rewrite the whole record and silently drop `expires_at` and `target`, because `put_item` replaces rather than merges.

---

# 11. The result repository

Create:

```text
worker/app/storage/results.py
```

```python
import logging

from boto3.dynamodb.conditions import Key
from pydantic import BaseModel

from app.config.storage import MAX_ITEM_BYTES
from app.models.outcomes import ScanOutcome
from app.storage.blobs import get_blob, put_blob
from app.storage.client import table
from app.storage.serialization import item_size, now_iso, to_item

logger = logging.getLogger(__name__)


def tenant_repo_key(tenant_id: str, repo_id: str) -> str:
    return f"{tenant_id}#{repo_id}"


class ScanSummary(BaseModel):
    job_id: str
    tenant_id: str
    repo_id: str
    tenant_repo: str
    target: str
    scan_date: str
    degraded: bool
    confidence: float = 0.0
    overall: int = 0
    security: int = 0
    efficiency: int = 0
    compliance: int = 0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    report_key: str


def _counts(scan: ScanOutcome) -> tuple[int, int, int]:
    findings = scan.all_findings

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    return len(findings), critical, high


def store_result(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    scan: ScanOutcome,
) -> ScanSummary:
    report_key = f"reports/{tenant_id}/{job_id}"

    put_blob(
        report_key,
        {
            "job_id": job_id,
            "outcomes": [o.model_dump() for o in scan.outcomes],
            "dockerfile": scan.dockerfile.model_dump() if scan.dockerfile else None,
            "risk": scan.risk.model_dump() if scan.risk else None,
            "profile": scan.profile.model_dump() if scan.profile else None,
        },
    )

    total, critical, high = _counts(scan)

    summary = ScanSummary(
        job_id=job_id,
        tenant_id=tenant_id,
        repo_id=repo_id,
        tenant_repo=tenant_repo_key(tenant_id, repo_id),
        target=scan.target,
        scan_date=now_iso(),
        degraded=scan.degraded,
        confidence=scan.risk.confidence if scan.risk else 0.0,
        overall=scan.risk.score.overall if scan.risk else 0,
        security=scan.risk.score.security if scan.risk else 0,
        efficiency=scan.risk.score.efficiency if scan.risk else 0,
        compliance=scan.risk.score.compliance if scan.risk else 0,
        finding_count=total,
        critical_count=critical,
        high_count=high,
        report_key=report_key,
    )

    item = to_item(summary)

    size = item_size(item)

    if size > MAX_ITEM_BYTES:
        raise ValueError(
            f"Summary item is {size} bytes, over the {MAX_ITEM_BYTES} limit"
        )

    table("scan_results").put_item(Item=item)

    logger.info(
        "Stored scan %s: %d findings, %d bytes in dynamo",
        job_id,
        total,
        size,
    )

    return summary


def get_summary(job_id: str) -> ScanSummary | None:
    resp = table("scan_results").get_item(Key={"job_id": job_id})

    item = resp.get("Item")

    return ScanSummary.model_validate(item) if item else None


def get_full_report(job_id: str) -> dict | None:
    summary = get_summary(job_id)

    if summary is None:
        return None

    return get_blob(summary.report_key)


def previous_scan(
    tenant_id: str,
    repo_id: str,
    before_job_id: str | None = None,
) -> ScanSummary | None:
    resp = table("scan_results").query(
        IndexName="TenantRepoIndex",
        KeyConditionExpression=Key("tenant_repo").eq(
            tenant_repo_key(tenant_id, repo_id)
        ),
        ScanIndexForward=False,
        Limit=2,
    )

    for item in resp.get("Items", []):
        summary = ScanSummary.model_validate(item)

        if summary.job_id != before_job_id:
            return summary

    return None


def scan_history(
    tenant_id: str,
    repo_id: str,
    limit: int = 30,
) -> list[ScanSummary]:
    resp = table("scan_results").query(
        IndexName="TenantRepoIndex",
        KeyConditionExpression=Key("tenant_repo").eq(
            tenant_repo_key(tenant_id, repo_id)
        ),
        ScanIndexForward=False,
        Limit=limit,
    )

    return [
        ScanSummary.model_validate(item)
        for item in resp.get("Items", [])
    ]
```

Note what `previous_scan` does and does not do. It queries **`scan_results`**, the table that actually holds scores. It uses a key condition only, so `Limit` is honest. It takes `Limit=2` and skips the current job, because the current scan has usually already been written by the time you ask for the previous one.

The reference implementation's version queries `scan_jobs`, which stores `status`, `progress`, and `currentStep` and nothing else. Its callers then do:

```python
prev_cves = [f.get("title", "") for f in state["previous_scan"].get("findings", [])]
prev_scores = previous_scan.get("scores", {})
```

Neither key exists on that table, so both are always empty. Regression detection and score trends never fire, nothing errors, and the prompts still ask the model to analyse a trend from an empty list.

```text
.get("findings", []) on the wrong table
        ↓
always empty
        ↓
no error, no log
        ↓
a feature that never worked
```

Every `.get(key, default)` is a place where a schema mismatch becomes a plausible-looking empty value instead of a `KeyError` you would have fixed in five minutes.

---

# 12. Wire it into the orchestrator

```python
from app.storage.jobs import create_job, update_progress
from app.storage.results import previous_scan, store_result


async def run_and_store(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> ScanSummary:
    create_job(job_id, tenant_id, repo_id, target)

    try:
        update_progress(job_id, "running", 10, "Fetching image data")

        trivy_raw, history_raw, inspect_raw = await asyncio.gather(
            run_trivy_scan(target),
            run_docker_history(target),
            run_image_inspect(target),
        )

        update_progress(job_id, "running", 40, "Running agents")

        scan = await run_scan_from_raw(
            target, trivy_raw, history_raw, inspect_raw
        )

        update_progress(job_id, "running", 90, "Storing results")

        summary = store_result(job_id, tenant_id, repo_id, scan)

        update_progress(job_id, "completed", 100, "Scan complete")

        return summary

    except Exception as exc:
        logger.exception("Scan %s failed", job_id)

        update_progress(job_id, "failed", 0, str(exc)[:200])

        raise
```

The `except` re-raises after recording the failure. Swallowing it here would make the caller believe the scan succeeded, and in Phase 7 that caller is a queue consumer deciding whether to retry.

```text
record the failure   →  the UI can show it
re-raise             →  the caller can decide
```

Doing only the first is how the reference implementation ends up with a dead-letter queue that never receives anything.

---

# 13. Tests against real DynamoDB Local

Mocks would not catch the reserved-word error, the float rejection, or the `Limit` semantics. Test against the container.

Create `worker/tests/conftest.py`:

```python
import os
import uuid

import pytest

os.environ.setdefault("DYNAMODB_ENDPOINT_URL", "http://localhost:8000")


@pytest.fixture
def tenant(tables) -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def tables():
    # NOT autouse: an autouse session fixture would drag DynamoDB Local
    # into the free `-m "not integration"` suite too. `tenant` depends on
    # this, and every integration test takes `tenant`.
    from app.scripts.create_tables import main

    main()
```

Create `worker/tests/test_storage.py`:

```python
import uuid

import pytest

from app.models.outcomes import AgentOutcome, ScanOutcome
from app.storage.jobs import create_job, get_job, recent_jobs, update_progress
from app.storage.results import (
    get_full_report,
    previous_scan,
    scan_history,
    store_result,
)

pytestmark = pytest.mark.integration


def _scan(target: str = "python:3.8") -> ScanOutcome:
    return ScanOutcome(
        target=target,
        outcomes=[
            AgentOutcome(
                agent="cve_analyst",
                status="analysed",
                findings=[],
            )
        ],
    )


def test_job_roundtrip(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, "repo-a", "python:3.8")

    update_progress(job_id, "running", 40, "Running agents")

    job = get_job(job_id)

    assert job is not None
    assert job.status == "running"
    assert job.progress == 40
    assert job.current_step == "Running agents"


def test_ttl_is_an_integer_epoch(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    record = create_job(job_id, tenant, "repo-a", "python:3.8")

    assert isinstance(record.expires_at, int)
    assert record.expires_at > 1_700_000_000


def test_update_preserves_unnamed_attributes(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, "repo-a", "python:3.8")

    update_progress(job_id, "running", 10, "Working")

    job = get_job(job_id)

    assert job is not None
    assert job.target == "python:3.8"
    assert job.expires_at > 0


def test_floats_survive_the_roundtrip(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    summary = store_result(job_id, tenant, "repo-a", _scan())

    assert isinstance(summary.confidence, float)

    report = get_full_report(job_id)

    assert report is not None
    assert report["job_id"] == job_id


def test_previous_scan_finds_the_prior_run(tenant: str) -> None:
    first = str(uuid.uuid4())
    second = str(uuid.uuid4())

    store_result(first, tenant, "repo-a", _scan())
    store_result(second, tenant, "repo-a", _scan())

    prev = previous_scan(tenant, "repo-a", before_job_id=second)

    assert prev is not None
    assert prev.job_id == first


def test_tenants_do_not_see_each_other(tenant: str) -> None:
    other = f"{tenant}-other"

    mine = str(uuid.uuid4())
    theirs = str(uuid.uuid4())

    store_result(mine, tenant, "nginx", _scan())
    store_result(theirs, other, "nginx", _scan())

    history = scan_history(tenant, "nginx")

    assert [s.job_id for s in history] == [mine]


def test_recent_jobs_are_newest_first(tenant: str) -> None:
    ids = [str(uuid.uuid4()) for _ in range(3)]

    for job_id in ids:
        create_job(job_id, tenant, "repo-a", "python:3.8")

    jobs = recent_jobs(tenant)

    assert [j.job_id for j in jobs] == list(reversed(ids))
```

Add the marker to `pyproject.toml`:

```toml
markers = [
    "eval: hits the real model API, costs money, needs Docker",
    "integration: needs DynamoDB Local on port 8000",
]
```

```powershell
uv run pytest -m integration -v
```

`test_tenants_do_not_see_each_other` is the one that matters. Write it against the old `repo_id`-only key design and it fails. That failing test is the tenancy bug, reproduced in eight lines.

`test_update_preserves_unnamed_attributes` guards the `put_item` versus `update_item` distinction. Swap `update_progress` to use `put_item` and it goes red immediately.

---

# 14. Run it

```powershell
uv run python -m app.scripts.create_tables
```

Create `worker/app/scripts/scan_and_store.py`:

```python
import asyncio
import sys
import uuid

from app.orchestrator import run_and_store
from app.storage.results import get_full_report, scan_history


async def main() -> None:
    target = sys.argv[1]
    tenant = "demo-tenant"
    repo = target.split(":")[0]

    job_id = str(uuid.uuid4())

    summary = await run_and_store(job_id, tenant, repo, target)

    print(f"job:        {summary.job_id}")
    print(f"overall:    {summary.overall}/100")
    print(f"confidence: {summary.confidence:.0%}")
    print(f"findings:   {summary.finding_count}")
    print(f"degraded:   {summary.degraded}")
    print(f"report key: {summary.report_key}")

    print("\nhistory:")

    for entry in scan_history(tenant, repo):
        print(f"  {entry.scan_date}  {entry.overall:3d}/100  {entry.job_id[:8]}")

    report = get_full_report(job_id)

    if report is None:
        print("\nfull report missing")
    else:
        print(f"\nfull report agents: {len(report['outcomes'])}")


if __name__ == "__main__":
    asyncio.run(main())
```

```powershell
uv run python -m app.scripts.scan_and_store python:3.8
```

Run it twice. The second run should list both scans in history, newest first. Then confirm the data actually persisted somewhere real:

```powershell
docker restart dynamodb-local
```

```powershell
uv run python -m app.scripts.scan_and_store python:3.8
```

DynamoDB Local keeps data in memory by default, so a restart clears it. If you want it to survive, mount a volume:

```powershell
docker rm -f dynamodb-local
```

```powershell
docker run --rm -v dynamodb-data:/data alpine chown -R 1000:1000 /data
docker run -d --name dynamodb-local -p 8000:8000 `
  -v dynamodb-data:/home/dynamodblocal/data `
  amazon/dynamodb-local -jar DynamoDBLocal.jar -sharedDb -dbPath /home/dynamodblocal/data
```

---

# 15. Quality gate

```powershell
uv run ruff check .
```

```powershell
uv run ruff format --check .
```

```powershell
uv run mypy app eval
```

```powershell
uv run pytest -m "not eval and not integration" -v
```

```powershell
uv run pytest -m integration -v
```

You should have:

```text
✓ Hot and cold tables separated by write pattern
✓ Tenant in the partition key, no FilterExpression anywhere
✓ TTL written as an integer epoch, verified by a test
✓ Floats converted to Decimal in one line, at any depth
✓ Large payloads in a blob store behind a swappable interface
✓ Item size checked against the 400 KB ceiling
✓ previous_scan reads the table that holds scores
✓ Integration tests against the real engine, not a mock
```

---

# 16. Where this sits

```text
  Phases 1-5                          Phase 6  ◄── here
 ┌──────────────────────┐      ┌──────────────────────┐
 │ measurable AI system │  ──→ │ results that survive │
 │ recall / precision   │      │ a process restart    │
 └──────────────────────┘      └──────────────────────┘
                                          │
                                          ▼
                                 ┌──────────────────────┐
                                 │      Phase 7         │
                                 │  queue + worker loop │
                                 └──────────────────────┘
```

Storage sits behind four small modules. When Phase 12 swaps DynamoDB Local for real DynamoDB, one environment variable changes. When the blob store becomes S3, two function bodies change. Nothing above `app/storage/` knows the difference, which is what an interface is for.

---

# Errata — found while implementing this phase

Three of these stop the phase dead. All are fixed in the code above.

**The volume mount deadlocks DynamoDB Local, and it looks like a network fault.**
`-v dynamodb-data:/data` gives you a root-owned directory while the image runs as uid 1000
`dynamodblocal`. sqlite cannot create its file, so the container logs
`unable to open database file` and retries every three seconds forever. Meanwhile it
reports `Up`, accepts TCP, and answers curl with a 400 — so the port looks healthy and
every boto3 call hangs until read timeout with no useful error. Chown the volume once and
mount it under the user's home:

```powershell
docker run --rm -v dynamodb-data:/data alpine chown -R 1000:1000 /data
```

**`create_tables.py` is not idempotent.** Table creation is guarded by
`if X not in existing`, but `update_time_to_live` is not, and re-enabling TTL raises
`ValidationException: TimeToLive is already enabled`. Since `conftest` calls `main()` once
per test session, every integration run after the first errors out on all seven tests.
Check `describe_time_to_live` first.

**`@pytest.fixture(scope="session", autouse=True)` breaks the free suite.** An autouse
session fixture runs for *every* pytest invocation, so `pytest -m "not eval and not
integration"` would still reach for DynamoDB Local and fail — contradicting the quality
gate in section 15, which runs the fast suite as a separate no-Docker step. Make `tables`
non-autouse and have `tenant` depend on it; all seven integration tests already take
`tenant`, so it runs exactly when needed. Verified: with the container stopped, the fast
suite still runs 40 tests in two seconds.

**Smaller things.** `Optional[X]` trips ruff UP045 and `datetime.now(timezone.utc)` trips
UP017 — use `X | None` and `datetime.now(UTC)`. `get_full_report` returns `dict | None`,
so `report['outcomes']` in `scan_and_store.py` fails `mypy`.

**One caveat on `test_ttl_is_an_integer_epoch`.** It asserts on the record `create_job`
returns, which is the in-memory object — it never proves DynamoDB stored a Number rather
than a String. `test_update_preserves_unnamed_attributes` does round-trip `expires_at`, so
between them the property is covered, but not by the test named for it.

---

## Next: Phase 7 — The Queue & Worker Loop

A scan takes 90 seconds. An HTTP request cannot wait that long — the load balancer times out, the browser gives up, and the retry starts a duplicate scan.

```text
    POST /scans                    worker process
         │                               │
         ▼                               ▼
   mint job_id                    long-poll the queue
         │                               │
         ▼                               ▼
   enqueue message  ──────────────→  receive one
         │                               │
         ▼                               ▼
   return in 50ms                  run_and_store
   { job_id, queued }                    │
                                         ▼
                                  delete on success
```

We run ElasticMQ in Docker as an SQS-compatible queue, so still no AWS account.

The three things this phase actually teaches:

```text
1. why MessageGroupId = repo_id serialises scans of
   one repo while letting different repos run at once

2. why VisibilityTimeout must exceed your worst-case
   runtime — the reference implementation allows 900s
   for a pipeline whose timeouts alone total 840s,
   so a slow scan gets processed twice

3. why catching every exception inside the consumer
   means delete_message always runs, the DLQ stays
   empty forever, and no failure is ever retried
```

Phase 6 already set up the fix for the third one: `run_and_store` records the failure and then re-raises.