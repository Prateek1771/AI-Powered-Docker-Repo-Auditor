# Two images, one dependency install. The API and the worker are the same
# package with different entrypoints (Phase 8), so they share a base stage and
# each carries only what it runs.

# Base images are pinned by digest, not tag. `python:3.12-slim` today and next
# month are different images, so a tag lets a rebuild change the runtime with
# no commit of yours. The cost is that patches stop arriving on their own -
# refresh with `docker inspect --format='{{index .RepoDigests 0}}' <tag>` on a
# schedule and land it as a reviewable commit.
FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS deps

# uv is copied in rather than pip-installed: its image is distroless and holds
# a single static binary, so this adds one file and no packages.
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy

WORKDIR /app

# Lockfile only. Dependencies change rarely and source changes on every edit,
# so resolving them in their own stage keeps this layer cached across edits.
COPY pyproject.toml uv.lock ./

# --no-install-project: the uv_build backend would package src/worker, which is
# the untouched uv-init stub. The real package is app/, imported off WORKDIR.
RUN uv sync --frozen --no-dev --no-install-project


FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/app/.venv/bin:$PATH

WORKDIR /app

# Only the resolved environment crosses the stage boundary. uv, the lockfile
# and pyproject are build-time tools, and deleting them in a later layer would
# hide them rather than remove them - a separate stage is the only way they
# genuinely never reach the runtime image.
COPY --from=deps /app/.venv /app/.venv


FROM base AS worker

# The worker shells out to the docker CLI - app/scanners/trivy.py runs Trivy as
# a sibling container, and docker_history.py needs `docker history`. Copying the
# binary from the official CLI image avoids adding an apt repo, and with it
# curl and gnupg, purely to fetch a signing key.
COPY --from=docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe /usr/local/bin/docker /usr/local/bin/docker

RUN useradd --system --uid 1001 --create-home worker \
 && mkdir -p /data/blobs \
 && chown -R worker:worker /data/blobs

COPY --chown=worker:worker app ./app

USER worker

# Not `import app.main`: that drags langchain in and takes ~9s, so it blows a
# 5s timeout and then burns the same 9s every interval forever. The worker has
# no port to probe, so the next best liveness signal is the dependency its poll
# loop actually needs - if the queue is unreachable the worker is not working,
# whatever its PID says.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD ["python", "-c", "from app.config.queue import SCAN_QUEUE_URL; from app.queue.producer import get_client; get_client().get_queue_attributes(QueueUrl=SCAN_QUEUE_URL, AttributeNames=['QueueArn'])"]

CMD ["python", "-m", "app.main"]


# The Fargate target. There is no Docker socket in a Fargate task, and mounting
# one would be a privilege problem even if there were, so this image carries the
# Trivy binary and scans the registry directly - SCANNER_MODE=registry switches
# app/scanners/ over to that path, and layer history then comes out of Trivy's
# own report rather than `docker history`.
#
# It is a separate target rather than a flag on `worker` because the binary is
# 168 MB. Local runs would carry it for nothing.
FROM base AS worker-aws

COPY --from=aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 /usr/local/bin/trivy /usr/local/bin/trivy

ENV SCANNER_MODE=registry \
    TRIVY_CACHE_DIR=/tmp/trivy-cache

RUN useradd --system --uid 1001 --create-home worker

COPY --chown=worker:worker app ./app

USER worker

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD ["python", "-c", "from app.config.queue import SCAN_QUEUE_URL; from app.queue.producer import get_client; get_client().get_queue_attributes(QueueUrl=SCAN_QUEUE_URL, AttributeNames=['QueueArn'])"]

CMD ["python", "-m", "app.main"]


FROM base AS api

# The API lists the daemon's images for the "My images" picker (app/images.py),
# which is a socket-mode-only feature - this binary is dead weight in the
# Fargate path, which builds `worker-aws` and never this stage.
COPY --from=docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe /usr/local/bin/docker /usr/local/bin/docker

# .dev-keys is created here rather than left to app/dev/keys.py: with two
# uvicorn workers, both processes race to generate the RSA key on the first
# /dev/token, and each needs the directory to already be writable.
RUN useradd --system --uid 1001 api \
 && mkdir -p /data/blobs /app/.dev-keys \
 && chown -R api:api /data/blobs /app/.dev-keys

COPY --chown=api:api app ./app

USER api

EXPOSE 8080

# Python is already here. Installing curl for a healthcheck adds a package, and
# every package is attack surface.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health').read()"]

# Two workers is safe now: Phase 9 moved progress routing to Redis, so a socket
# on one process still receives events published by another.
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
