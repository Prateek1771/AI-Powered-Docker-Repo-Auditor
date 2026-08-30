# Phase 13 — CI/CD: OIDC, Matrices, Rollback & the Gate That Matters

The last phase, and the shortest. Most of it is deleting duplication.

```text
   preflight ────┐
   lint ─────────┼──→ eval gate ──→ build ──→ deploy ──→ smoke
   test-python ──┤     (matrix)    (matrix)   (matrix)     │
   test-frontend ┤                                ▲        │
   terraform ────┘                                │        ▼
                                              rollback ← failed
```

The rule for this phase:

```text
a green check must mean
"it is running", not
"the API accepted my request"
```

---

# 1. OIDC: stop storing AWS keys

The reference gets this right, and it's worth understanding why it matters.

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}
    aws-region: us-east-1
```

No access key. No secret key. GitHub mints a short-lived OIDC token describing the workflow, AWS trusts GitHub's OIDC provider, and hands back temporary credentials scoped to one role.

```text
long-lived keys        OIDC
never expire           15 minutes
leak = permanent       leak = useless
rotation is manual     no rotation needed
copyable anywhere      bound to one repo and branch
```

The doc this phase replaces created the provider and the roles with `aws iam` CLI calls and pasted JSON. Phase 12's entire argument is that the security boundary belongs in version control where it can be reviewed and re-applied, so it is a Terraform module instead. Create `terraform/modules/cicd/main.tf`:

```hcl
# GitHub mints a short-lived token describing the workflow, AWS trusts the
# provider, and the pipeline never stores an access key.
#
#   long-lived keys        OIDC
#   never expire           15 minutes
#   leak = permanent       leak = useless
#   copyable anywhere      bound to one repo, and here one branch
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = var.tags
}

# The `sub` condition IS the security boundary, and a too-broad one works
# perfectly - the pipeline goes green and nothing reports that a stranger's
# fork can assume the role too. Build runs on any branch, including pull
# requests, so it gets a wildcard on the ref and nothing more.
data "aws_iam_policy_document" "build_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:*"]
    }
  }
}

# Deploy is StringEquals on one exact ref, not StringLike. A wildcard here
# would let a pull request from a fork deploy to production.
data "aws_iam_policy_document" "deploy_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/${var.deploy_branch}"]
    }
  }
}

resource "aws_iam_role" "build" {
  name               = "${var.name}-github-build"
  assume_role_policy = data.aws_iam_policy_document.build_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "build" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = var.ecr_repository_arns
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "build"
  role   = aws_iam_role.build.id
  policy = data.aws_iam_policy_document.build.json
}

resource "aws_iam_role" "deploy" {
  name               = "${var.name}-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.deploy_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecs:DescribeTaskDefinition",
      "ecs:RegisterTaskDefinition",
    ]
    # Neither call takes a resource; ECS scopes them account-wide. What keeps
    # RegisterTaskDefinition safe is the PassRole statement below.
    resources = ["*"]
  }

  statement {
    actions = [
      "ecs:UpdateService",
      "ecs:DescribeServices",
    ]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.cluster_arn]
    }
  }

  # Scoped to exactly the two task roles. Unscoped, the pipeline could register
  # a task definition using ANY role in the account - an admin role included -
  # and then run a container as it. That turns deploy access into account
  # takeover, and it is the single most common way this role is written wrong.
  statement {
    actions   = ["iam:PassRole"]
    resources = var.task_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
```

Wire it in `main.tf` last — it needs the cluster ARN and the task role ARNs — and add the `github_repository` variable with no default, so `terraform validate` refuses to let you forget it.

---

# 2. The trust policy condition that matters

This is where OIDC setups go badly wrong, and the failure is silent.

The `sub` condition is the entire security boundary. Get it wrong and any GitHub Actions workflow, in anyone's repository, can assume your role.

```text
"sub": "repo:*"                                   catastrophic — the whole of GitHub
missing sub condition entirely                    catastrophic — same
"sub": "repo:YOU/YOUR-REPO:*"                     good — your repo, any branch
"sub": "repo:YOU/YOUR-REPO:ref:refs/heads/main"   better — main only
"sub": "repo:YOU/YOUR-REPO:environment:production" best — gated environment
```

The reason this bites people is that a too-broad condition works perfectly. Your pipeline goes green. Nothing tells you that a stranger's fork can also assume the role.

Note the asymmetry in the module above. The **build** role uses `StringLike` with `repo:OWNER/REPO:*`, because pull requests from branches need to build. The **deploy** role uses `StringEquals` on one exact ref. A `StringLike` there would let a pull request deploy to production, which is the same class of mistake wearing a subtler disguise.

Verify what you actually created:

```powershell
aws iam get-role --role-name auditor-dev-github-deploy --query "Role.AssumeRolePolicyDocument"
```

Read the `sub` line. If it contains a bare `*` before your repository name, fix it now.

---

# 3. Two roles, not one

The reference uses `AWS_DEPLOY_ROLE_ARN` for both building and deploying. Split them.

```text
auditor-dev-github-build     ecr:GetAuthorizationToken
                             ecr:PutImage, UploadLayerPart, etc.
                             → any branch, including PRs

auditor-dev-github-deploy    ecs:DescribeTaskDefinition
                             ecs:RegisterTaskDefinition
                             ecs:UpdateService, DescribeServices
                             iam:PassRole (the two task roles only)
                             → main branch only
```

`iam:PassRole` is the one to get right. Unscoped, on `"Resource": "*"`, it lets the pipeline register a task definition using **any** role in the account — an admin role included — and then run a container as it. That turns deploy access into account takeover.

The module scopes it to exactly two ARNs and adds `iam:PassedToService = ecs-tasks.amazonaws.com`, so even those two can only be handed to ECS.

Note also what `RegisterTaskDefinition` is not scoped by: it takes no resource, and ECS grants it account-wide. The `PassRole` statement is the *only* thing standing between that permission and an arbitrary privileged container. Read those two statements together or neither makes sense.

---

# 4. Concurrency

The reference workflow has no concurrency control. Push twice in quick succession and two deploys race on `update-service`, each registering task definitions and each waiting for a rollout the other is disturbing.

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false
```

`cancel-in-progress: false` for deploys. Cancelling a deploy halfway leaves ECS mid-rollout with no one watching. Queue instead.

---

# 5. Gating on secrets you may not have

Here is a problem the reference never hits, because it assumes an AWS account is always there. Five of these jobs need one. In a repository with no account configured — a fresh clone, a fork, this repository today — those five fail on every push, and a permanently red pipeline teaches people to stop reading it.

The obvious fix does not work:

```yaml
# Does not work. `secrets` is not available in a job-level `if`.
if: secrets.AWS_DEPLOY_ROLE_ARN != ''
```

The `secrets` context is unavailable there. What is available is `needs`, so a job reads the secret and hands the answer down as an output:

```yaml
  preflight:
    runs-on: ubuntu-latest
    outputs:
      aws: ${{ steps.check.outputs.aws }}
      openai: ${{ steps.check.outputs.openai }}
    steps:
      - id: check
        env:
          DEPLOY_ROLE: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}
        run: |
          if [ -n "$DEPLOY_ROLE" ]; then
            echo "aws=true" >> "$GITHUB_OUTPUT"
          else
            echo "aws=false" >> "$GITHUB_OUTPUT"
            echo "::notice::AWS_DEPLOY_ROLE_ARN is unset - build, deploy and smoke will be skipped."
          fi
```

The `::notice::` matters as much as the output. A silently skipped job looks identical to a job that was never written.

The split this buys you is worth stating plainly:

```text
always            lint, test-python, test-frontend, terraform
needs a key       eval
needs an account  tf-plan, build, deploy, smoke
```

The four unconditional jobs cover everything a laptop currently checks by hand. Everything else is a bonus that arrives when the account does.

---

# 6. Test jobs with real service containers

Your integration tests need DynamoDB Local, ElasticMQ, and Redis. GitHub Actions service containers give you two of the three:

```yaml
    services:
      dynamodb:
        image: amazon/dynamodb-local
        ports: ["8000:8000"]
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-retries 5
```

ElasticMQ runs via `docker run` instead, because it needs `worker/elasticmq.conf` mounted and service containers start **before** the checkout exists. That also means it gets no health check, so the readiness loop is load-bearing rather than decorative — without it the first test races the queue's startup.

Every Python step carries `working-directory: worker`. All the Python in this repository lives there, and `pyproject.toml` sets `pythonpath = ["."]` relative to it.

This job is where the 34 `integration` tests finally run on their own. They had never been run automatically before this phase: locally they collide with the compose stack, because `conftest.py`'s `jwks_server` fixture starts a real uvicorn on `127.0.0.1:8080` and compose publishes the API on that port. A fresh runner has no such conflict, which is a good argument for CI having a clean machine rather than a replica of yours.

Contrast with the reference, which points its test env at real AWS ARNs:

```yaml
SQS_SCAN_JOBS_URL: https://sqs.us-east-1.amazonaws.com/000000000000/test.fifo
DYNAMODB_SCAN_JOBS_TABLE: test-scan-jobs
```

None of those exist. Any test touching AWS fails, which means every test must be mocked — and we saw in Phase 5 what those mocks are worth. Real service containers let you test the actual client code.

---

# 7. The eval gate

This is the job the reference doesn't have, and the reason Phase 5 exists.

```yaml
      - name: Run the eval gate
        run: uv run pytest -m eval -v
        working-directory: worker
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          CVE_MODEL: gpt-4o
          MAX_VULNERABILITIES_TO_MODEL: "25"
```

Three deliberate choices.

**Only on push to main**, not on every PR. It costs real money and calls a third-party API. Running it on every commit to every branch turns a cheap check into a monthly bill.

**The scanner cache is keyed on the fixture files.** Trivy output only changes when a Dockerfile changes, so the key is `hashFiles('worker/eval/fixtures/**')`. Change a fixture, get a fresh scan; change a prompt, reuse the cache and pay only for model calls.

**`MAX_VULNERABILITIES_TO_MODEL: "25"`.** CI doesn't need the full 150 to catch a regression. Recall on a smaller sample is noisier but the gate is a ratchet, not a measurement.

That last one required a code change, because the constant was hardcoded:

```python
MAX_VULNERABILITIES_TO_MODEL = int(
    os.environ.get("MAX_VULNERABILITIES_TO_MODEL", "150")
)

CVE_MODEL = os.environ.get("CVE_MODEL", "gpt-4o")
```

Worth checking rather than assuming. An environment variable set in a workflow beside a constant that ignores it is a configuration that looks right in review, runs green, and does nothing — the same failure shape as the declared-but-unwritten DynamoDB TTL in Phase 12.

Note the variable names. There is no `LLM_API_KEY` or `LLM_MODEL` in this codebase; `app/agents/runner.py` builds `ChatOpenAI` and the SDK reads `OPENAI_API_KEY` from the environment.

Run once at the CI sample size, the gate passes in about 50 seconds: recall above `MIN_RECALL` on the bad fixture, no false positives on the clean one. That is the thing that closes the loop. A prompt edit that drops recall now fails the build, whether or not anyone remembers to check.

---

# 8. Terraform gets a job too

The reference has no Terraform job at all, so infrastructure drifts from what's committed with nothing noticing.

Split it in two, because most of it is free:

```yaml
  terraform:
    steps:
      - run: terraform fmt -recursive -check
        working-directory: terraform
      - run: terraform init -backend=false
        working-directory: terraform
      - run: terraform validate
        working-directory: terraform
```

`fmt` and `validate` need no credentials, no state and no account. They catch unresolvable references, type errors and bad module wiring, which is most of what goes wrong. So they run on every pull request, unconditionally.

The `plan` is a separate job gated on the account existing, and it plans but never applies. Applying infrastructure automatically on merge is a decision with real blast radius — a bad plan can delete a database. Surface the plan on the PR, apply from a laptop or a manually-triggered workflow.

---

# 9. Build with a matrix

The reference has three near-identical build blocks, about 60 lines. One matrix replaces them:

```yaml
    strategy:
      matrix:
        include:
          - service: worker
            context: ./worker
            target: worker-aws
          - service: api
            context: ./worker
            target: api
          - service: frontend
            context: ./frontend
            target: runner
```

Two of those three lines differ from what you would write from the doc alone.

**The contexts are `./worker` and `./frontend`, not `.`.** There is no Dockerfile at the repository root, and a root context would ship `.git` to the builder on every push — the Phase 11 argument, arriving in a new place.

**The worker target is `worker-aws`, not `worker`.** The local target carries the docker CLI and expects a socket to mount. Fargate has neither. The deployed image is the one with the Trivy binary and `SCANNER_MODE=registry`, and building the wrong one produces a task that starts cleanly and fails on its first scan.

Three more details.

**`scope=${{ matrix.service }}` on the cache.** The reference uses `mode=max` on all three builds without scoping, so they share one cache namespace and evict each other. GitHub's Actions cache is 10 GB per repository, and three unscoped max-mode Docker caches will thrash constantly.

**Tagged with the commit SHA and `latest`.** The SHA tag is what deploys; `latest` is for humans. Deploying `latest` means you cannot tell which commit is running, and rollback becomes guesswork.

**`vars` not `secrets` for the public URLs.** `NEXT_PUBLIC_*` values end up in the browser bundle. Storing them as secrets implies a confidentiality they don't have and makes them harder to read when debugging.

Matrix jobs run in parallel, so three images build concurrently rather than sequentially.

---

# 10. Deploy, with rollback

The reference repeats the same twenty lines three times for deploy and another twenty three times for waiting — about 120 lines that should be twenty. Worse, if the wait fails, the broken deployment stays up. There is no rollback anywhere in the pipeline.

Four things this pipeline does that the reference doesn't.

**Captures the previous task definition ARN before changing anything.** You cannot roll back to a revision you didn't record.

**`if: failure()` rollback.** A task that crashes on boot gets reverted automatically instead of sitting broken until someone notices.

**`aws ecs wait services-stable`** replaces sixty lines of hand-rolled polling. The reference's loop is competent — it checks `rolloutState` and exits on `FAILED` — but it's sixty lines of shell repeated three times, and the AWS CLI already does this.

**`fail-fast: false`.** One service failing shouldn't cancel the other two mid-rollout. Same reasoning as `return_exceptions=True` in Phase 3, in a different tool.

`--force-new-deployment` is absent. Registering a new task definition and pointing the service at it already triggers a rollout. The reference passes both, which is harmless but suggests uncertainty about which one does the work.

One subtlety in the `needs`. `deploy` depends on `eval`, and `eval` is skipped when no model key is configured — and a skipped dependency skips the dependent job too. So the condition is written on results rather than on completion:

```yaml
    if: >-
      always()
      && needs.build.result == 'success'
      && needs.eval.result != 'failure'
      && needs.eval.result != 'cancelled'
```

Deploy when the build succeeded and the eval did not fail. Skipped is not failure.

---

# 11. The step that makes green mean something

A successful `update-service` means the API accepted your request. It says nothing about whether the container starts.

```text
without a wait step:
  update-service returns 200
  job goes green
  task crashes on boot
  ECS retries, fails, retries
  you find out from a user
```

`aws ecs wait services-stable` blocks until the rollout completes and the desired count is running, or fails. That's the difference between a green check meaning "deployed" and meaning "requested".

Then the smoke job verifies it actually works — and asserts that one thing is *absent*:

```yaml
      - name: Dev endpoints must be absent
        run: |
          CODE=$(curl -s -o /dev/null -w "%{http_code}" "${{ vars.API_URL }}/dev/token" || true)
          if [ "$CODE" != "404" ]; then
            echo "::error::/dev/token returned $CODE - DEV_AUTH is enabled on the deployed API"
            exit 1
          fi
```

Phase 8 built an endpoint that mints tokens for anyone, gated on `DEV_AUTH`. A single misconfigured environment variable turns your deployed API into an open credential dispenser. Assert its absence on every deploy rather than trusting that nobody set the variable.

**A limitation to name rather than hide.** `vars.API_URL` has to be set by hand on the learning tier, because Fargate tasks get a fresh public IP on every deployment and there is no load balancer to put a stable name in front of them. The same applies to `NEXT_PUBLIC_API_URL`, which is baked into the browser bundle at build time. The smoke job therefore skips when the variable is unset rather than failing. Both wants the same thing: the production tier's ALB, or a small script that reads the task's IP after each deploy and updates the variable. Until then this is a pipeline that deploys correctly and cannot fully verify itself.

---

# 12. Workflow-level permissions

```yaml
permissions:
  contents: read
```

At the top, this sets the floor for every job. Jobs that need more declare it themselves — `id-token: write` for OIDC.

Without it, jobs inherit whatever the repository default is, which on older repositories is read/write on everything. A compromised dependency in a test job could then push commits.

```text
default at the workflow level    contents: read
elevate per job                  only where needed
never at the workflow level      id-token: write
```

One consistency note, since Phases 11 and 12 both argued for pinning by digest. The actions here are referenced by major tag — `actions/checkout@v4`, not a commit SHA. A tag is mutable, so this is the same exposure those phases warned about, accepted deliberately: these are first-party and widely-audited publishers, and forty SHA-pinned lines are considerably harder to read. It is a real trade, and the honest version of it is written down rather than left for you to notice.

---

# 13. The whole file

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# The floor for every job. Without it, jobs inherit the repository default,
# which on older repositories is read/write on everything - a compromised
# dependency in a test job could then push commits. Jobs that need more ask
# for it themselves.
permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  # Never cancel a deploy halfway: that leaves ECS mid-rollout with nobody
  # watching. Queue instead. PR-only jobs opt into cancellation below.
  cancel-in-progress: false

env:
  AWS_REGION: us-east-1
  TF_VERSION: "1.14.5"

jobs:
  # The secrets context is not available in a job-level `if`, so a job has to
  # read it and hand the answer down as an output. Without this the AWS jobs
  # would fail on every push in a repository that has no AWS account behind
  # it, and a permanently red pipeline teaches people to ignore the pipeline.
  preflight:
    runs-on: ubuntu-latest
    outputs:
      aws: ${{ steps.check.outputs.aws }}
      openai: ${{ steps.check.outputs.openai }}
    steps:
      - id: check
        env:
          DEPLOY_ROLE: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}
          OPENAI_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          if [ -n "$DEPLOY_ROLE" ]; then
            echo "aws=true" >> "$GITHUB_OUTPUT"
          else
            echo "aws=false" >> "$GITHUB_OUTPUT"
            echo "::notice::AWS_DEPLOY_ROLE_ARN is unset - build, deploy and smoke will be skipped."
          fi

          if [ -n "$OPENAI_KEY" ]; then
            echo "openai=true" >> "$GITHUB_OUTPUT"
          else
            echo "openai=false" >> "$GITHUB_OUTPUT"
            echo "::notice::OPENAI_API_KEY is unset - the eval gate will be skipped."
          fi

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true

      - run: uv sync --frozen
        working-directory: worker

      - run: uv run ruff check .
        working-directory: worker

      - run: uv run ruff format --check .
        working-directory: worker

      - run: uv run mypy app eval
        working-directory: worker

      # The docs carry the working code inline. This is what stops them
      # drifting back into teaching a bug that has already been fixed.
      - name: Docs match the code they describe
        run: python docs/learning/check_code_blocks.py

  test-python:
    runs-on: ubuntu-latest
    services:
      dynamodb:
        image: amazon/dynamodb-local
        ports: ["8000:8000"]
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true

      - run: uv sync --frozen
        working-directory: worker

      # Not a service container: it needs worker/elasticmq.conf mounted, and
      # service containers start before the checkout exists. That also means
      # it gets no health check, so the readiness loop below is load-bearing.
      - name: Start ElasticMQ
        run: |
          docker run -d --name elasticmq -p 9324:9324 \
            -v "${{ github.workspace }}/worker/elasticmq.conf:/opt/elasticmq.conf" \
            softwaremill/elasticmq-native

          for i in $(seq 1 30); do
            if curl -sf -o /dev/null "http://localhost:9324/?Action=ListQueues"; then
              echo "elasticmq up after ${i}s"
              exit 0
            fi
            sleep 1
          done

          echo "::error::ElasticMQ never became ready"
          docker logs elasticmq
          exit 1

      - name: Unit tests
        run: uv run pytest -m "not eval and not integration" -q
        working-directory: worker

      # These have never run outside a laptop. They exercise the real boto3
      # and redis clients against real servers rather than mocks - Phase 5
      # showed what the mocked versions were worth.
      - name: Integration tests
        run: uv run pytest -m integration -q
        working-directory: worker
        env:
          DEV_AUTH: "1"
          DYNAMODB_ENDPOINT_URL: http://localhost:8000
          SQS_ENDPOINT_URL: http://localhost:9324
          SCAN_QUEUE_URL: http://localhost:9324/000000000000/scan-jobs.fifo
          REDIS_URL: redis://localhost:6379/0

  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: npm
          cache-dependency-path: frontend/package-lock.json

      # ci, not install: it installs exactly what the lockfile says and fails
      # if the lockfile is stale.
      - run: npm ci
        working-directory: frontend

      - run: npx tsc --noEmit
        working-directory: frontend

      - run: npm run lint
        working-directory: frontend

      - run: npm test
        working-directory: frontend

      - run: npm run build
        working-directory: frontend
        env:
          NEXT_PUBLIC_API_URL: ${{ vars.NEXT_PUBLIC_API_URL || 'http://localhost:8080' }}
          NEXT_PUBLIC_WS_URL: ${{ vars.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080' }}

  # fmt and validate need no credentials and no state, so they run on every
  # PR. Without a job like this, infrastructure drifts from what is committed
  # and nothing notices until an apply surprises somebody.
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}

      - run: terraform fmt -recursive -check
        working-directory: terraform

      - run: terraform init -backend=false
        working-directory: terraform

      - run: terraform validate
        working-directory: terraform

  # A plan needs the real state and real credentials, so it only runs where
  # those exist. Plan, never apply: an automatic apply on merge can delete a
  # database, and that decision belongs to a human at a terminal.
  tf-plan:
    runs-on: ubuntu-latest
    needs: [preflight, terraform]
    if: needs.preflight.outputs.aws == 'true'
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TERRAFORM_ROLE_ARN || secrets.AWS_DEPLOY_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Init
        working-directory: terraform
        run: |
          terraform init \
            -backend-config="bucket=${{ secrets.TF_STATE_BUCKET }}" \
            -backend-config="key=dev/terraform.tfstate" \
            -backend-config="region=${{ env.AWS_REGION }}" \
            -backend-config="dynamodb_table=auditor-tflocks" \
            -backend-config="encrypt=true"

      - name: Plan
        working-directory: terraform
        run: terraform plan -no-color -input=false -out=tfplan
        env:
          TF_VAR_llm_api_key: ${{ secrets.OPENAI_API_KEY }}
          TF_VAR_github_repository: ${{ github.repository }}

  # The job that closes the Phase 5 loop: a prompt edit that drops recall
  # below MIN_RECALL fails the build whether or not anyone remembers to look.
  #
  # Only on push to main. It calls a paid third-party API, so running it on
  # every commit to every branch turns a cheap check into a monthly bill.
  eval:
    runs-on: ubuntu-latest
    needs: [preflight, test-python]
    if: >-
      needs.preflight.outputs.openai == 'true'
      && github.event_name == 'push'
      && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true

      - run: uv sync --frozen
        working-directory: worker

      - name: Build fixture images
        working-directory: worker
        run: |
          docker build -t auditor-eval:bad eval/fixtures/bad
          docker build -t auditor-eval:clean eval/fixtures/clean

      # Trivy and docker history output only change when a fixture changes, so
      # the key is the fixtures. Edit a prompt and you reuse the cache and pay
      # for model calls alone.
      - name: Cache scanner output
        uses: actions/cache@v4
        with:
          path: worker/eval/.cache
          key: scanners-${{ hashFiles('worker/eval/fixtures/**') }}

      - name: Run the eval gate
        run: uv run pytest -m eval -v
        working-directory: worker
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          CVE_MODEL: gpt-4o
          # CI does not need the full 150 to catch a regression. Recall on a
          # smaller sample is noisier, but the gate is a ratchet, not a
          # measurement.
          MAX_VULNERABILITIES_TO_MODEL: "25"

  build:
    runs-on: ubuntu-latest
    needs: [preflight, lint, test-python, test-frontend, terraform]
    if: >-
      needs.preflight.outputs.aws == 'true'
      && github.event_name == 'push'
      && github.ref == 'refs/heads/main'
    permissions:
      id-token: write
      contents: read
    outputs:
      tag: ${{ steps.meta.outputs.tag }}
    strategy:
      matrix:
        include:
          # worker-aws, not worker. The local target carries the docker CLI
          # and expects a socket; Fargate has none, so the deployed image is
          # the one with the Trivy binary and SCANNER_MODE=registry.
          - service: worker
            context: ./worker
            target: worker-aws
          - service: api
            context: ./worker
            target: api
          - service: frontend
            context: ./frontend
            target: runner
    steps:
      - uses: actions/checkout@v4

      - id: meta
        run: echo "tag=${GITHUB_SHA::8}" >> "$GITHUB_OUTPUT"

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_BUILD_ROLE_ARN || secrets.AWS_DEPLOY_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - id: ecr
        uses: aws-actions/amazon-ecr-login@v2

      - uses: docker/setup-buildx-action@v3

      - uses: docker/build-push-action@v6
        with:
          context: ${{ matrix.context }}
          target: ${{ matrix.target }}
          push: true
          # The SHA tag is what deploys; latest is for humans. Deploy latest
          # and you cannot say which commit is running, which makes rollback
          # guesswork.
          tags: |
            ${{ steps.ecr.outputs.registry }}/auditor-dev-${{ matrix.service }}:${{ steps.meta.outputs.tag }}
            ${{ steps.ecr.outputs.registry }}/auditor-dev-${{ matrix.service }}:latest
          # vars, not secrets. These end up in the browser bundle, so calling
          # them secret implies a confidentiality they do not have.
          build-args: |
            NEXT_PUBLIC_API_URL=${{ vars.NEXT_PUBLIC_API_URL }}
            NEXT_PUBLIC_WS_URL=${{ vars.NEXT_PUBLIC_WS_URL }}
          # Scoped per service. Unscoped, three mode=max caches share one
          # namespace inside a 10 GB budget and evict each other constantly.
          cache-from: type=gha,scope=${{ matrix.service }}
          cache-to: type=gha,mode=max,scope=${{ matrix.service }}

  deploy:
    runs-on: ubuntu-latest
    needs: [preflight, build, eval]
    # eval may legitimately be skipped when no model key is configured, and a
    # skipped dependency would otherwise skip this job too. Deploy when build
    # succeeded and eval did not fail.
    if: >-
      always()
      && needs.build.result == 'success'
      && needs.eval.result != 'failure'
      && needs.eval.result != 'cancelled'
    environment: dev
    permissions:
      id-token: write
      contents: read
    strategy:
      # One service failing must not cancel the other two mid-rollout. Same
      # reasoning as return_exceptions=True in Phase 3, different tool.
      fail-fast: false
      matrix:
        service: [worker, api, frontend]
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - id: ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Register new task definition
        id: register
        env:
          REGISTRY: ${{ steps.ecr.outputs.registry }}
          TAG: ${{ needs.build.outputs.tag }}
        run: |
          SERVICE="auditor-dev-${{ matrix.service }}"
          IMAGE="${REGISTRY}/${SERVICE}:${TAG}"

          # Captured BEFORE anything changes. You cannot roll back to a
          # revision you never recorded.
          PREVIOUS=$(aws ecs describe-services \
            --cluster auditor-dev --services "$SERVICE" \
            --query 'services[0].taskDefinition' --output text)
          echo "previous=$PREVIOUS" >> "$GITHUB_OUTPUT"

          aws ecs describe-task-definition --task-definition "$SERVICE" \
            --query taskDefinition --output json \
          | jq --arg IMAGE "$IMAGE" '
              .containerDefinitions[0].image = $IMAGE
              | del(.taskDefinitionArn, .revision, .status,
                    .requiresAttributes, .compatibilities,
                    .registeredAt, .registeredBy)' > taskdef.json

          NEW=$(aws ecs register-task-definition \
            --cli-input-json file://taskdef.json \
            --query 'taskDefinition.taskDefinitionArn' --output text)
          echo "new=$NEW" >> "$GITHUB_OUTPUT"

      # No --force-new-deployment. Pointing the service at a new task
      # definition already triggers a rollout; passing both suggests
      # uncertainty about which one does the work.
      - name: Update service
        run: |
          aws ecs update-service \
            --cluster auditor-dev \
            --service "auditor-dev-${{ matrix.service }}" \
            --task-definition "${{ steps.register.outputs.new }}"

      # The step that makes green mean something. update-service returning 200
      # says the API accepted the request, not that the container starts.
      - name: Wait for stability
        timeout-minutes: 15
        run: |
          aws ecs wait services-stable \
            --cluster auditor-dev \
            --services "auditor-dev-${{ matrix.service }}"

      - name: Roll back
        if: failure() && steps.register.outputs.previous != ''
        run: |
          echo "::error::Deploy of ${{ matrix.service }} failed, rolling back to ${{ steps.register.outputs.previous }}"
          aws ecs update-service \
            --cluster auditor-dev \
            --service "auditor-dev-${{ matrix.service }}" \
            --task-definition "${{ steps.register.outputs.previous }}"
          aws ecs wait services-stable \
            --cluster auditor-dev \
            --services "auditor-dev-${{ matrix.service }}"

  smoke:
    runs-on: ubuntu-latest
    needs: [deploy]
    # API_URL has to be set by hand on the learning tier: Fargate tasks get a
    # fresh public IP on every deployment and there is no load balancer, so
    # there is no stable hostname to bake in. Skip rather than fail when it is
    # absent.
    if: vars.API_URL != ''
    steps:
      - name: API health
        run: |
          for i in $(seq 1 20); do
            CODE=$(curl -s -o /dev/null -w "%{http_code}" "${{ vars.API_URL }}/health" || true)
            echo "attempt $i: $CODE"
            if [ "$CODE" = "200" ]; then exit 0; fi
            sleep 10
          done

          echo "::error::API health check never returned 200"
          exit 1

      # Phase 8 built an endpoint that mints a token for any tenant, gated on
      # DEV_AUTH. One misconfigured environment variable turns the deployed API
      # into an open credential dispenser, so assert its absence every time
      # rather than trusting that nobody set it.
      - name: Dev endpoints must be absent
        run: |
          CODE=$(curl -s -o /dev/null -w "%{http_code}" "${{ vars.API_URL }}/dev/token" || true)
          if [ "$CODE" != "404" ]; then
            echo "::error::/dev/token returned $CODE - DEV_AUTH is enabled on the deployed API"
            exit 1
          fi
```

---

# 14. What the reference gets right, and what it doesn't

Worth an honest tally, because it is not a bad pipeline.

```text
RIGHT
  OIDC, no long-lived AWS keys
  tests fan out in parallel, build waits for all three
  GHA layer caching on Docker builds
  rollout-state polling that distinguishes COMPLETED from FAILED
  images tagged with the commit SHA
  deploy gated on branch

WRONG
  no terraform job at all — infra drifts silently
  no eval — prompt regressions ship freely
  ~120 lines of triplicated deploy and wait logic
  no rollback on a failed rollout
  no concurrency group — two pushes race
  npm install where npm ci belongs
  unscoped GHA cache across three max-mode builds
  no smoke test after deploy
  everything assumes the AWS account exists
```

The duplication is the one that compounds. Three copies of the same deploy logic means a fix applied to one and forgotten in the other two, which is how services drift apart in ways nobody intended.

---

# 15. Quality gate

Most of this pipeline can be checked before it ever runs, which is the point of the phase.

```powershell
docker run --rm -v "${PWD}:/repo" --workdir /repo rhysd/actionlint:latest -color
```

`actionlint` catches undefined `needs` references, invalid `if` expressions, unknown contexts and bad `matrix` keys — most of what goes wrong in a file you cannot execute locally. Run it before pushing, not after.

Then run the pipeline's own commands, in its order and its working directories:

```powershell
cd worker;   uv sync --frozen; uv run ruff check .; uv run ruff format --check .; uv run mypy app eval
cd ..;       python docs/learning/check_code_blocks.py
cd worker;   uv run pytest -m "not eval and not integration" -q
cd frontend; npm ci; npx tsc --noEmit; npm run lint; npm test; npm run build
cd terraform; terraform fmt -recursive -check; terraform init -backend=false; terraform validate
```

The integration tests need the compose API and worker stopped first, for the port-8080 reason in section 6:

```powershell
docker compose stop api worker
cd worker; uv run pytest -m integration -q
```

Doing this catches the boring failures — a line one character over the formatter's limit, a path that only exists on your machine — at a desk rather than in a pipeline you are watching a progress bar for.

Then push a branch and open a PR. You should see `preflight`, `lint`, `test-python`, `test-frontend` and `terraform` run, and everything else skip with a notice explaining why.

Merge to main with the secrets configured, and verify the security properties by hand:

```powershell
aws iam get-role --role-name auditor-dev-github-deploy --query "Role.AssumeRolePolicyDocument.Statement[0].Condition"
aws iam get-role-policy --role-name auditor-dev-github-deploy --policy-name deploy --query "PolicyDocument.Statement[?Action=='iam:PassRole']"
```

The `sub` must name your repository and one ref. `Resource` on `PassRole` must be a list of specific role ARNs, never `*`.

Then break something on purpose. Push a commit that makes the worker crash on boot — a syntax error in the worker entrypoint will do. The deploy job should fail at the wait step, roll back automatically, and leave the previous revision running:

```powershell
aws ecs describe-services --cluster auditor-dev --services auditor-dev-worker --query "services[0].taskDefinition"
```

It should point at the previous revision, not the broken one. Then revert.

You should have:

```text
✓ actionlint clean before the first push
✓ OIDC with a sub condition naming your repo, in Terraform not a README
✓ Separate build and deploy roles, PassRole scoped and PassedToService set
✓ workflow-level permissions: contents: read
✓ concurrency group, cancel-in-progress false for deploys
✓ Jobs gated on secrets via a preflight output, with a notice when skipped
✓ 34 integration tests running against real service containers
✓ Terraform validated on every PR, planned only where state exists, never applied
✓ Eval gate on main, sample size overridable, recall floor enforced
✓ Build and deploy as matrices, worker-aws for Fargate
✓ Previous task definition captured, rollback on failure
✓ wait services-stable before green
✓ Smoke test asserts /dev/token returns 404
```

---

# 16. What you built

Thirteen phases. Worth naming what's actually different from where you started.

```text
Phase 1-2    a scanner and one agent with a hard contract
Phase 3-4    six agents, parallel where the data allows,
             degrading visibly where it doesn't
Phase 5      a number that goes down when you make it worse
Phase 6-7    state that survives a restart, jobs that survive
             a worker dying mid-scan
Phase 8-9    an HTTP front door that authorizes every object,
             live progress that works across processes
Phase 10     a UI that cannot render a partial result as a
             complete one
Phase 11-13  three images, infrastructure you can turn off,
             a pipeline where green means running
```

The seven ideas that transfer to anything else you build:

**Reduce deterministically before you reason.** Phase 1's twenty-line extraction function is why the agents are affordable. Never hand a model a raw API response when Python can cut it by 50x first.

**A parse failure and an empty result are different facts.** Phase 2 exists entirely to keep those apart. The reference implementation collapses them into `return []`, which makes a vulnerable image look clean.

**Bound every call, isolate every failure, and check the types.** `wait_for` inside `gather` with `return_exceptions=True` and the `isinstance` checks that must accompany it. The flag without the checks is worse than neither.

**Degradation must be visible in the data.** Phase 4's `degraded` flag and computed confidence, Phase 10's dashed ring and two different empty states. Confidence is a property of the pipeline, never an opinion of the model.

**Authentication is not authorization.** Phase 8's ownership dependency and Phase 9's per-subscription check. The reference authenticates the request and then never uses the result, which is the most common serious bug in web APIs.

**In append-only systems, removal is fiction.** Docker layers, git history, event logs. The only way to not ship something is to never add it — which is why Phase 11's `deps` stage exists and why an `rm` would not have done.

**Infrastructure decides which bugs are fixable in code.** A GSI keyed on `repo_id` makes tenant-scoped queries impossible to express in Python. Some fixes live in one layer, some in the other, and a few need both to agree.

And the habit underneath all of it: the reference implementation is a real project by someone who shipped more than most people do. Its README promises seven agents, Ragas evaluation, and a chat endpoint, and the code has six agents, no evaluation, and no chat. That gap is not unusual — you will inherit it in every codebase you join.

```text
run grep against the README
before you trust it
```

Including this one. Nine of the thirteen phase documents in `docs/learning/` were corrected against their own working code, several of them because following the instructions exactly produced something that did not run. `docs/learning/check_code_blocks.py` exists so that stops happening silently, and the `lint` job above is what makes it happen without anyone remembering to.

---

## Where to go next

Four directions, roughly by value.

**Give the pipeline a stable hostname.** The smoke test and the frontend build both want one and the learning tier has none. An ALB is the textbook answer and costs ~$16/mo; a small deploy step that reads the task's public IP and updates a repository variable is free and teaches you more about the ECS API.

**Build the chat agent.** The README has promised it since the beginning. You have scan records in DynamoDB, a working auth layer, and panel space in the UI. An endpoint that loads a scan by `job_id` and answers questions against it is the highest-value missing feature, and your Phase 5 harness can measure whether the answers are grounded.

**Give an agent a real LangGraph cycle.** All six are still single-node graphs. The CVE analyst with a validation node and a conditional edge back on parse failure is about fifteen lines, and it's the difference between importing LangGraph and using it.

**Add LLM-as-judge to the eval, carefully.** Keyword matching is brittle. A judge handles paraphrase — but you must validate the judge against human labels first, or you have moved the uncertainty rather than removed it.
