import os

SQS_ENDPOINT_URL = os.environ.get("SQS_ENDPOINT_URL")

SCAN_QUEUE_URL = os.environ.get(
    "SCAN_QUEUE_URL",
    "http://localhost:9324/000000000000/scan-jobs.fifo",
)

POLL_WAIT_SECONDS = 20

VISIBILITY_TIMEOUT_SECONDS = 300

HEARTBEAT_INTERVAL_SECONDS = 60

HEARTBEAT_EXTENSION_SECONDS = 300

# How long a worker's claim on a job stays valid without a refresh.
#
# The heartbeat renews it every HEARTBEAT_INTERVAL_SECONDS, so this must be
# comfortably longer than that - three intervals, matching the three strikes
# the heartbeat itself allows before giving up. Shorter and a single slow
# renewal hands a live scan to a second worker; much longer and a genuinely
# dead worker holds the job past the point SQS redelivers it, which is the
# window this exists to close.
JOB_LEASE_SECONDS = HEARTBEAT_INTERVAL_SECONDS * 3

MAX_MESSAGES_PER_POLL = 1

DEDUP_WINDOW_SECONDS = 60
