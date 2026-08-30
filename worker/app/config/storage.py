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

# Upper bound on a `docker save` tar the API will accept. Generous, because a
# real image tar is routinely hundreds of megabytes - the point is to stop a
# single request filling the disk, not to be tight.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024**3)))

# Set in AWS, unset locally. Its presence is what switches app/storage/blobs.py
# from the filesystem to S3 - there is no separate mode flag to disagree with.
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET")

JOB_TTL_DAYS = 30

MAX_ITEM_BYTES = 380_000
