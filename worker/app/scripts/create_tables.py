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
