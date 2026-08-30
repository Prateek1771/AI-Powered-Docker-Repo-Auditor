# Phase 11 — Containerisation: Layers, Ghosts & Scanning Your Own Work

Three images from two build contexts. Every line you write here is something your own scanner will grade, which makes this the one phase with an objective pass mark.

```text
   worker/ context      frontend/ context
         │                      │
    ┌────┴────┐                 ▼
    ▼         ▼           ┌───────────┐
 ┌───────┐ ┌───────┐      │ frontend  │
 │worker │ │  api  │      │ npm build │
 │       │ │       │      │     ↓     │
 │docker │ │ slim  │      │ standalone│
 │ CLI   │ │ only  │      │           │
 └───┬───┘ └───┬───┘      └─────┬─────┘
     │         │                │
     └─────────┼────────────────┘
               ▼
      point the auditor at itself
               │
               ▼
        read what it says about you
```

The rule for this phase:

```text
every layer is permanent
deleting a file in a later layer
hides it, it does not remove it
```

---

# 1. The files that must come first

There is no `.dockerignore` in this repository. Check for yourself — there isn't one anywhere.

The first decision is what the build context even is. All the Python lives in `worker/`, and the Next app in `frontend/`, so those are the two contexts. That choice alone does most of the work: `.git` sits at the repository root, outside both, so no image can bake your history even by accident. A root context would have to reach down into `worker/` for `pyproject.toml` and `app/`, and would ship `.git` to the daemon on every build for the privilege.

What is still inside the `worker/` context and must not survive:

```text
.venv/          hundreds of MB of platform-specific binaries
.env            your real OPENAI_API_KEY and GROQ_API_KEY, in plaintext
.dev-keys/      the RSA private key from Phase 8
out.json        49 MB of leftover scan output
.blobs/         stored reports
eval/           fixtures, including a 2.7 GB image definition
__pycache__/    stale bytecode
```

`.env` is the dangerous one, and it is not hypothetical — open it. `app/config/__init__.py` reads `parents[2] / ".env"`, which resolves to `/app/.env` inside the image, so without an ignore file the container would happily read credentials baked into a layer instead of the ones the orchestrator injects. Two different problems, one line of fix.

Create `worker/.dockerignore`:

```text
# Build context is ./worker, so .git is out of reach already. Everything here
# is either a secret, a cache, or weight the image has no use for.

# Secrets. app/config/__init__.py reads parents[2]/.env, which is /app/.env in
# the image - excluding it makes compose the only source of config.
.env
.env.*
.dev-keys

# Environments and caches
.venv
venv
__pycache__
*.pyc
*.pyo
.pytest_cache
.mypy_cache
.ruff_cache

# Local state and scan output
.blobs
out.json
*.trivy.json
eval

# Not shipped: tests, the uv-init stub package, docs
tests
src
*.md
```

And `frontend/.dockerignore`:

```text
node_modules
.next
out
coverage
.env.local
.env*.local
*.tsbuildinfo
```

Two knock-on effects beyond secrets. Build context upload gets faster because the daemon receives megabytes instead of gigabytes — `out.json` alone was 49 MB. And your layer cache stops invalidating on files that have nothing to do with the build.

Write these before your first build, not after. A secret baked into a layer stays there through every subsequent build that reuses the cache.

---

# 2. The worker and API images

Create `worker/Dockerfile`:

```dockerfile
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
```

Three stages, and a target per image. `deps` resolves the environment, `base` receives it, and each leaf adds only what it runs.

The third target, `worker-aws`, arrives in Phase 12: Fargate has no Docker socket, so that image carries the Trivy binary and scans the registry directly instead of launching a sibling container. It is a separate target rather than a flag because the binary is 168 MB and a local run would carry it for nothing. Ignore it until then — `docker compose` builds `worker` and `api`.

---

# 3. Where Trivy actually lives

The obvious move is to `apt-get install trivy` into the worker and bake the vulnerability database in with `trivy image --download-db-only`, so a cold container does not spend four minutes downloading CVE data before its first scan.

Read `app/scanners/trivy.py` before you do that:

```python
def build_command(target: str) -> list[str]:
    return [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy",
        TRIVY_IMAGE,
        "image", ...
    ]
```

Trivy is not a binary this project calls. It is a **sibling container** the worker launches through the host daemon, and `TRIVY_CACHE_VOLUME` is a Docker *named volume* on that host — not a path inside the worker image. Installing Trivy into the worker would add ~180 MB that nothing ever executes, and bake a database into a directory nothing ever reads.

What the worker actually needs is the `docker` CLI, for Trivy and for `docker history` and `docker image inspect` in the other two scanners. One line gets it:

```dockerfile
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
```

No apt repository, no signing key, and therefore no `curl` and no `gnupg` to install and then purge.

The cold-start argument survives, it just moves. The database lives in the `trivy-cache` volume on the host, so warm it once and every container that follows inherits it:

```powershell
docker volume create trivy-cache
docker run --rm -v trivy-cache:/root/.cache/trivy aquasec/trivy:latest image --download-db-only
```

```text
volume warm     ~90 second scan
volume cold     ~4 minute scan, once
```

The trade-off is the same one baking would have had: the database ages. A scheduled refresh of that volume is the production answer, and Phase 12 replaces the whole arrangement with Trivy reading a registry instead of a daemon.

---

# 4. Same layer, or it doesn't count

This is the rule your bloat agent hunts for, and now you're on the other side of it.

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && apt-get purge -y --auto-remove build-essential \
 && rm -rf /var/lib/apt/lists/*
```

One `RUN`. Split it and the cleanup accomplishes nothing:

```dockerfile
RUN apt-get update && apt-get install -y build-essential    # layer 2: +466MB
RUN apt-get purge -y --auto-remove build-essential          # layer 3: +0MB, deletes nothing
```

A Docker image is a stack of read-only layers. Layer 3 records a *whiteout entry* saying the files are gone. Layer 2 still contains them. Your image still ships them. Measured, on this machine:

```text
Dockerfile.ghost   split RUN      644 MB
Dockerfile.clean   single RUN     178 MB
```

466 MB of files that `ls` cannot see inside the running container and that every `docker pull` transfers anyway. Section 13 has both files so you can reproduce that number rather than trust it.

```text
delete in the same layer   →  the bytes never exist
delete in a later layer    →  the bytes are hidden, not removed
```

Those hidden bytes are what Phase 3's bloat prompt calls ghost files, and they're why the prompt says deleting in a later layer only hides the file.

**The same trap applies to your own build tooling.** `uv` and the lockfile are build-time only; an `rm` in the leaf stages would hide them, not remove them, because `COPY /uv` happened in a layer those stages inherit. Only a stage boundary genuinely keeps them out — `COPY --from=deps /app/.venv` brings across the one thing the runtime needs and leaves the rest behind. That is worth 265 MB:

```text
uv in the shared base    worker 695 MB   api 633 MB
uv in its own stage      worker 430 MB   api 368 MB
```

---

# 5. Cache ordering, and no requirements.txt

```dockerfile
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
...
COPY --chown=worker:worker app ./app
```

Dependencies change rarely; your source changes constantly. This order keeps the expensive resolve cached across every code edit. Reverse it and every one-character change to a Python file reinstalls every dependency.

There is no `requirements.txt` in this project and you should not generate one. `uv.lock` already pins the exact resolution, `--frozen` fails the build if it has drifted from `pyproject.toml`, and a hand-written requirements file would list only direct dependencies — which would silently drop `cryptography`, used by `app/dev/keys.py` but reaching you transitively through `python-jose[cryptography]`.

`--no-dev` leaves out pytest, mypy and ruff. `--no-install-project` matters for a subtler reason: the `uv_build` backend would try to package `src/worker`, which is the untouched `uv init` stub. The real package is `app/`, imported off `WORKDIR /app` — the same reason `pyproject.toml` sets `pythonpath = ["."]` for pytest.

Note `COPY app ./app` rather than `COPY . .`. Even with a `.dockerignore`, copying only what you need is better — it's explicit about what belongs in the image, and adding a new top-level directory doesn't silently enlarge your build.

`PYTHONDONTWRITEBYTECODE=1` stops `.pyc` files being written into the image. `PYTHONUNBUFFERED=1` makes logs appear immediately rather than sitting in a buffer, which matters enormously when you're reading CloudWatch and wondering why your worker went quiet.

---

# 6. Non-root, and what it breaks

```dockerfile
RUN useradd --system --uid 1001 --create-home worker \
 && mkdir -p /data/blobs \
 && chown -R worker:worker /data/blobs

USER worker
```

Containers run as root by default. A container escape then means host root.

The part people get wrong is the `chown`, and this codebase has three places that need it — none of them obvious from the Dockerfile alone:

```text
1. anything the process WRITES to  →  needs chown
2. ports below 1024                →  can't bind, use 8080 not 80
3. files copied after USER         →  COPY --chown, or they land as root
```

For rule 1, grep for what runs at runtime rather than guessing. `app/storage/blobs.py` writes `$BLOB_DIR/<key>.json`, and `app/dev/keys.py` writes `.dev-keys/private.pem` **relative to the process CWD**, so under `WORKDIR /app` that is `/app/.dev-keys`. Add `USER` without fixing ownership and both fail with an error that never mentions permissions.

`.dev-keys` is worth pre-creating rather than letting `keys.py` `mkdir` it. With `--workers 2` there are two uvicorn processes, each holding its own `lru_cache` over `_private_key()`, both racing to generate an RSA key on the first `/dev/token`. They agree only because they share a filesystem — and only if the directory is already writable.

`--uid 1001` is explicit rather than letting the system pick. Fixed UIDs matter when you mount volumes, because the host sees numeric IDs and not names — and here both images use 1001, so the shared blob volume is readable from either side.

One thing non-root does not solve on its own. The worker needs `/var/run/docker.sock`, which is root-owned, so a uid 1001 process cannot open it. That gets fixed in compose with `group_add: ["0"]` rather than by dropping back to root — see section 11.

---

# 7. Two images, one package

`base` is shared; `worker` and `api` diverge after it. The API doesn't get the docker CLI and doesn't get the socket. This is what Phase 8's one-package-two-entrypoints decision buys you: shared code, no duplication, each image carrying only what it runs.

Be honest about the size, though. The measured gap is 430 MB against 368 MB, not the fivefold difference you might expect, because there is one lockfile and both images install all of it — the API ships langchain and the OpenAI client it never calls. Splitting that would mean optional dependency groups in `pyproject.toml` and two `uv sync` invocations. It is the correct next step and it is deliberately not taken here; know that it is on the table for when 62 MB stops being the interesting number.

Note `--workers 2`, and remember Phase 9. Each uvicorn worker is a separate process with its own memory. That was fatal for the naive in-memory `ConnectionManager` and is fine now, because progress routing goes through Redis and every worker subscribes.

---

# 8. HEALTHCHECK, and the one that looked right

CIS 4.6 wants a healthcheck, and your own compliance agent checks for it. More practically, an orchestrator without one only knows whether the process is *running*, not whether it's *working*. A worker that has deadlocked looks perfectly healthy — the PID exists.

```text
no healthcheck    →  "is the process alive"
healthcheck       →  "is the process doing its job"
```

The API's is easy, because it has a port. Note that it uses Python's `urllib` rather than `curl`: installing a package purely so a healthcheck can call it adds attack surface for something the runtime already has.

The worker is where the obvious answer fails. This is what you would write first, and it is what the reference does:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import app.main"
```

It looks like a real check, and it marked the container **unhealthy on every single interval**. `app.main` imports the handler, which imports the orchestrator, which imports langchain:

```powershell
docker run --rm auditor-worker:latest python -X importtime -c "import app.main"
```

8.7 seconds. It blows a 5 second timeout, and had the timeout been generous it would have burned 8.7 seconds of CPU every 30 seconds forever to prove nothing except that imports still work.

The worker has no port, so the next best signal is the dependency its poll loop actually needs:

```dockerfile
CMD ["python", "-c", "from app.config.queue import SCAN_QUEUE_URL; from app.queue.producer import get_client; get_client().get_queue_attributes(QueueUrl=SCAN_QUEUE_URL, AttributeNames=['QueueArn'])"]
```

boto3 only, well under a second, and it goes red exactly when the worker genuinely cannot do its job.

`--start-period` is the detail people miss. During it a failing check doesn't count toward `--retries`, which stops a slow-booting container being killed before it finishes starting.

---

# 9. The frontend image

Create `frontend/Dockerfile`:

```dockerfile
# A real multi-stage build: the runner never sees node_modules, the source, or
# the build toolchain. None of it can leak from the image because none of it is
# in the image.

# Base images are pinned by digest, not tag. `python:3.12-slim` today and next
# month are different images, so a tag lets a rebuild change the runtime with
# no commit of yours. The cost is that patches stop arriving on their own -
# refresh with `docker inspect --format='{{index .RepoDigests 0}}' <tag>` on a
# schedule and land it as a reviewable commit.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS deps

WORKDIR /app

COPY package.json package-lock.json ./

# ci, not install: it installs exactly what the lockfile says and fails if the
# lockfile is stale, which is what a build wants.
RUN npm ci


FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder

WORKDIR /app

# NEXT_PUBLIC_ values are inlined into the client bundle at build time, so they
# have to exist during `npm run build` rather than at container start. Anything
# passed this way is visible in `docker history` - URLs yes, keys never.
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL

ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL \
    NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules

COPY . .

RUN npm run build


FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runner

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 --ingroup nodejs nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<400?0:1)).on('error',()=>process.exit(1))"]

CMD ["node", "server.js"]
```

Enable standalone output in `frontend/next.config.ts`:

```typescript
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Traces the modules the server actually imports and emits a self-contained
  // bundle, so the runtime image carries neither node_modules nor the source.
  output: "standalone",
};

export default nextConfig;
```

This is a genuine multi-stage build, and the payoff is large.

```text
builder stage   node_modules, source, build cache   ~1.2 GB
runner stage    standalone bundle + static           300 MB
```

`output: "standalone"` makes Next trace exactly which modules the server actually imports and emit a self-contained bundle. The runner never sees `node_modules`, never sees your source, never sees the build toolchain. None of it can be exfiltrated from the image because none of it is in the image.

Four details. `npm ci`, not `npm install` — `ci` installs exactly what the lockfile says and fails if the lockfile is out of date, which is what a build wants. All three `COPY --from=builder` lines carry `--chown`; miss one and those files land owned by root while their neighbours don't, which bites the moment anything needs to write there. `node:22-alpine`, not `node:20` — Next 16.3.3 sits above Node 20's floor and Node 20 is out of support. And `HOSTNAME=0.0.0.0`, which is easy to forget: the standalone `server.js` binds `localhost` by default, and inside a container that means nothing outside it can connect.

---

# 10. Build args are not secrets

```dockerfile
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
```

`NEXT_PUBLIC_` values get inlined into the JavaScript bundle at build time, so they must be present during `npm run build` rather than at container start. That's why they're build args.

The thing to be clear about: **anything passed as a build arg is visible in the final image.** `docker history` shows every `ARG` and `ENV` value.

```text
safe as a build arg     API URLs, WebSocket URLs, public client IDs
never a build arg       API keys, DB passwords, private keys
```

A Sentry DSN is designed to be public, so passing one this way is fine — but it's the kind of thing that gets copied into a new project where the next variable isn't.

Runtime secrets belong in environment variables injected by the orchestrator, or in a secrets manager. Never in the image.

---

# 11. Compose the whole stack

Create `docker-compose.yml` in the project root:

```yaml
services:
  dynamodb:
    image: amazon/dynamodb-local
    command: -jar DynamoDBLocal.jar -sharedDb -dbPath /data
    user: root
    volumes:
      - dynamodb-data:/data
    ports:
      - "8000:8000"

  elasticmq:
    image: softwaremill/elasticmq-native
    volumes:
      - ./worker/elasticmq.conf:/opt/elasticmq.conf:ro
    ports:
      - "9324:9324"
      - "9325:9325"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 10

  # One shot. DynamoDB Local has no healthcheck of its own, so the loop is the
  # readiness wait - create_tables is already idempotent (it checks for the
  # tables and for an existing TTL setting before touching either).
  bootstrap:
    image: auditor-api:latest
    build:
      context: ./worker
      target: api
    command: ["sh", "-c", "until python -m app.scripts.create_tables; do echo 'waiting for dynamodb'; sleep 2; done"]
    restart: "no"
    # Inherited from the api image, where it curls a port this container never
    # opens. A one-shot job is healthy by exiting 0, not by answering requests.
    healthcheck:
      disable: true
    environment:
      DYNAMODB_ENDPOINT_URL: http://dynamodb:8000
    depends_on:
      - dynamodb

  api:
    image: auditor-api:latest
    build:
      context: ./worker
      target: api
    environment:
      DEV_AUTH: "1"
      DYNAMODB_ENDPOINT_URL: http://dynamodb:8000
      SQS_ENDPOINT_URL: http://elasticmq:9324
      SCAN_QUEUE_URL: http://elasticmq:9324/000000000000/scan-jobs.fifo
      REDIS_URL: redis://redis:6379/0
      BLOB_DIR: /data/blobs
      JWKS_URL: http://127.0.0.1:8080/dev/.well-known/jwks.json
      CORS_ORIGINS: http://localhost:3000
    volumes:
      - blobs:/data/blobs
    ports:
      - "8080:8080"
    depends_on:
      redis:
        condition: service_healthy
      elasticmq:
        condition: service_started
      bootstrap:
        condition: service_completed_successfully

  worker:
    image: auditor-worker:latest
    build:
      context: ./worker
      target: worker
    environment:
      DYNAMODB_ENDPOINT_URL: http://dynamodb:8000
      SQS_ENDPOINT_URL: http://elasticmq:9324
      SCAN_QUEUE_URL: http://elasticmq:9324/000000000000/scan-jobs.fifo
      REDIS_URL: redis://redis:6379/0
      BLOB_DIR: /data/blobs
      OPENAI_API_KEY: ${OPENAI_API_KEY}
    volumes:
      # The worker runs Trivy and `docker history` as sibling containers, so it
      # needs the host daemon. This grants the container root on the host -
      # acceptable for local development, and the reason Phase 12 replaces it
      # with Trivy reading a registry instead of a daemon.
      - /var/run/docker.sock:/var/run/docker.sock
      # Reports are written here by the worker and read back by the API. One
      # volume, both services - without it every /report returns nothing.
      - blobs:/data/blobs
    # The image runs as uid 1001 so it passes its own CIS 4.1 check. The socket
    # is root-owned, so the process needs gid 0 to reach it.
    group_add:
      - "0"
    depends_on:
      redis:
        condition: service_healthy
      elasticmq:
        condition: service_started
      bootstrap:
        condition: service_completed_successfully

  frontend:
    image: auditor-frontend:latest
    build:
      context: ./frontend
      args:
        # Baked into JavaScript that runs in the browser, which is outside this
        # network and cannot resolve `api`. Service names work container to
        # container; browser-facing URLs must be reachable from the host.
        NEXT_PUBLIC_API_URL: http://localhost:8080
        NEXT_PUBLIC_WS_URL: ws://localhost:8080
    ports:
      - "3000:3000"
    depends_on:
      - api

volumes:
  dynamodb-data:
  blobs:
```

```powershell
$env:OPENAI_API_KEY = "sk-..."
docker compose up -d --build --wait
```

Four things worth flagging, three of which are invisible until the stack is actually running.

**The blob volume is load-bearing.** `store_result` writes the full report to `$BLOB_DIR/<key>.json` and only the summary to DynamoDB; `get_full_report` reads that file back. The worker writes it and the API serves it, so in compose they are two containers reaching for one path. Without a shared volume the scan completes, the summary renders, the scores render — and the report body silently comes back empty. It is the most convincing kind of bug: everything looks like it worked.

**Nothing creates the tables.** `app/scripts/create_tables.py` existed for five phases with no caller in the stack. The `bootstrap` service is a one-shot that runs it, and `api` and `worker` wait on `service_completed_successfully`. DynamoDB Local publishes no healthcheck, so the readiness wait is the `until` loop — safe because `create_tables` already checks for existing tables and an existing TTL setting before touching either.

That service also has to *disable* the healthcheck it inherits from the API image, which probes a port a one-shot job never opens. A batch job is healthy by exiting 0, not by answering requests.

**The worker mounts `/var/run/docker.sock`** because it shells out to Trivy and `docker history`. That grants the container root on the host — acceptable for local development you control, and the reason Phase 12 replaces it with Trivy talking to a registry. `group_add: ["0"]` is what lets the uid 1001 process open the root-owned socket without the image dropping back to `USER root`.

**`NEXT_PUBLIC_API_URL` is `http://localhost:8080`, not `http://api:8080`.** The value is baked into JavaScript that runs in your *browser*, which is outside the compose network and cannot resolve `api`. Service names work for container-to-container calls; browser-facing URLs must be reachable from the host. `JWKS_URL` is the mirror image — the API fetches it from itself, so `127.0.0.1` is right and a service name would be a pointless round trip through the network.

---

# 12. Scan your own images

This is the part worth doing slowly. You have a container scanner. You have just written two Dockerfiles. Point one at the other.

Compose already tags the images (`image: auditor-worker:latest` and friends), so no retagging is needed:

```powershell
docker compose exec worker python -m app.scripts.enqueue auditor-api:latest
docker compose exec worker python -m app.scripts.enqueue auditor-worker:latest
docker compose exec worker python -m app.scripts.enqueue auditor-frontend:latest
```

Open each result in the UI from Phase 10.

Here is the real report for `auditor-api:latest`, not an idealised one:

```text
                          overall  sec  eff  comp   findings
auditor-api:latest             25   20   40    50   12  (1 crit, 6 high)
auditor-worker:latest          30   25   40    50    9  (1 crit, 4 high)
auditor-frontend:latest        25   20   30    50   11  (1 crit, 7 high)
```

Nothing you wrote is flagged at high. What is flagged:

```text
CIS 4.1  non-root USER          →  PASS on all three, not flagged
CIS 4.6  HEALTHCHECK            →  PASS on all three, not flagged
CIS 4.10 no secrets in ENV      →  PASS, secrets come from the orchestrator
CIS 5.8  no privileged ports    →  PASS, 8080 and 3000

bloat       build toolchain left in the image        →  HIGH, all three
compliance  standalone apt-get update instruction    →  MEDIUM
compliance  ADD instruction used instead of COPY     →  LOW, frontend only
CVEs        Archive::Tar, SQLite, OpenSSL, Perl, gzip
```

Now read where those come from. Every one is in the base image, not in anything you wrote. The "build toolchain" finding quotes the upstream layer that compiles CPython. The "standalone apt-get update" is upstream's. The CVEs are in Perl and SQLite packages your code never invokes.

The `ADD` finding is the sharpest example, because it is the one control you would swear you passed — there is no `ADD` in either Dockerfile. It comes from `node:22-alpine`, which uses `ADD` to unpack its own tarball. Your compliance agent is reading `docker history`, and history is the whole stack, not your part of it. That is correct behaviour and worth sitting with: **a scan of an image is never a scan of your Dockerfile.**

That is the useful lesson, and it is worth more than a green checkmark would have been. A clean scan is not achievable and was never the goal — every base image carries unpatched CVEs, and the question is whether they're reachable in your runtime path. That's precisely the judgement Phase 2's CVE prompt asks for, which is why it says to weigh actual exploitability rather than the CVSS number.

The one finding that is genuinely actionable is the base image itself: distroless would drop most of the package surface along with the shell you use to debug it. That is a real trade and a real decision, which is what a scanner is for.

---

# 13. Measure the layers yourself

Before trusting the agent, look directly:

```powershell
docker history auditor-worker:latest --no-trunc --format "{{.Size}}`t{{.CreatedBy}}"
```

Then prove the ghost-file rule to yourself. `docs/learning/ghost-demo/Dockerfile.ghost`:

```dockerfile
# Cleanup in a LATER layer. The rm records a whiteout entry; the bytes it
# claims to remove are still in the layer below, and every pull transfers them.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
RUN apt-get purge -y --auto-remove build-essential && rm -rf /var/lib/apt/lists/*
```

And `docs/learning/ghost-demo/Dockerfile.clean`:

```dockerfile
# Same install, same cleanup, one RUN. The bytes never exist in any layer.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && apt-get purge -y --auto-remove build-essential \
 && rm -rf /var/lib/apt/lists/*
```

```powershell
cd docs/learning/ghost-demo
docker build -f Dockerfile.ghost -t ghost-demo .
docker build -f Dockerfile.clean -t clean-demo .
docker images --format "{{.Repository}} {{.Size}}" | Select-String demo
```

```text
ghost-demo   644MB
clean-demo   178MB
```

Identical instructions, identical end state, 466 MB apart. Delete both images afterward.

---

# 14. Pin what you build on

A tag is mutable. `python:3.12-slim` today and next month are different images, so a rebuild can change your runtime without a single line of your code changing. A digest is immutable, and updating it becomes a deliberate commit you can review and roll back.

```powershell
docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
```

```dockerfile
FROM python:3.12-slim@sha256:09f7da3b... AS base
```

Pin the runtime bases, and pin `docker:29-cli` too — its binary ships inside your worker. `uv` does not need pinning past a minor tag, because nothing it produces survives the `deps` stage.

The trade-off is real and it cuts the other way from everything else in this phase: you no longer get security patches automatically, and nothing will remind you. That is the right trade only if the scheduled bump actually happens. A reviewed dependency commit beats a silent change you discover during an incident — but an unreviewed pin nobody touches for a year is worse than a tag.

---

# 15. Quality gate

```powershell
docker compose up -d --build --wait
docker compose ps
```

All seven services should show healthy, running, or — for `bootstrap` — `Exited (0)`. Then run the full flow through containers rather than local processes: open `http://localhost:3000`, start a scan, watch progress stream, confirm results render. Check the findings list specifically, not just the score: that is the blob volume, and it is the one thing that half-works convincingly.

Verify the image hygiene directly:

```powershell
docker run --rm auditor-worker:latest whoami
```

Expect `worker`, not `root`.

```powershell
docker run --rm auditor-api:latest ls -A /app
```

Expect `.dev-keys`, `.venv`, `app` — no `.git`, no tests, no `.env`, and no `uv.lock` or `pyproject.toml` either, because the `deps` stage kept them out.

You should have:

```text
✓ .dockerignore in both contexts before the first build, no .env in any image
✓ Trivy left as a sibling container, cache volume warmed on the host
✓ Build tooling confined to its own stage, verified by size (265 MB)
✓ Dependencies copied before source, cache holds across edits
✓ Non-root in all three images, blob dir and .dev-keys chowned
✓ Socket reachable from uid 1001 via group_add, not by reverting to root
✓ HEALTHCHECK on all three, each one cheap enough to run every 30s
✓ Frontend standalone output, HOSTNAME set, no node_modules in the runtime
✓ Build args carry only public values
✓ Shared blob volume, so the API can serve what the worker wrote
✓ Bootstrap creates the tables, and api/worker wait for it
✓ Bases pinned by digest
✓ All three images scanned by the auditor itself
```

---

# 16. Where this sits

```text
 Phase 9        Phase 10          Phase 11  ◄── here
┌───────────┐ ┌────────────┐ ┌──────────────────┐
│ live      │→│ honest UI  │→│ three images,    │
│ progress  │ │            │ │ scanned by the   │
│           │ │            │ │ tool itself      │
└───────────┘ └────────────┘ └──────────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │    Phase 12      │
                              │  infrastructure  │
                              └──────────────────┘
```

The whole product now runs from `docker compose up`. Nothing about it depends on your laptop's Python version, your Node install, or which containers you remembered to start.

The idea to keep is the one from section 4, and it generalises past Docker: **in an append-only system, removal is a fiction.** Git history, event logs, and container layers all work this way. The only way to not ship something is to never add it — which is why the `deps` stage exists and why an `rm` would not have done.

---

## Next: Phase 12 — Infrastructure

Terraform, and the first thing that matters is the order you build in.

```text
iam         →  roles, OIDC provider          no dependencies
networking  →  VPC, subnets, security groups
ecr         →  image repositories
auth        →  Cognito user pool
secrets     →  Secrets Manager
database    →  DynamoDB tables
storage     →  S3 + lifecycle
queue       →  SQS FIFO + DLQ
cache       →  ElastiCache Redis
api         →  API Gateway WebSocket
monitoring  →  dashboards, alarms
ecs         →  clusters, tasks, services      depends on everything
```

Build infrastructure inside-out. The ECS module is last and largest because it references the VPC, the image URIs, the secret ARNs, the queue URL, the table names, and the Redis endpoint all at once.

```text
1. every local endpoint you've been setting becomes
   a Terraform output — DYNAMODB_ENDPOINT_URL simply
   goes away, and boto3 finds the real thing

2. the blob volume becomes S3, which is where
   BLOB_DIR stops being a filesystem path and the
   worker/API sharing problem solves itself

3. the TTL, tenant-key, and DLQ fixes from Phases 6
   and 7 have to exist in the table and queue
   definitions, not just in your application code
```

This is also where the cost conversation gets real. NAT gateways, ElastiCache, and an always-on Fargate task will run you real money per month whether or not anyone scans anything, so Phase 12 includes a teardown you can actually trust.
