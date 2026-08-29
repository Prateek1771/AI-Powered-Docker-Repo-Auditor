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
