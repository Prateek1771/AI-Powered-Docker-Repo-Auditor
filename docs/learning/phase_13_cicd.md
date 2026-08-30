# Phase 13 — CI/CD: OIDC, Matrices, Rollback & the Gate That Matters

The last phase, and the shortest. Most of it is deleting duplication.

```text
   lint ─────────┐
   test-python ──┼──→ eval gate ──→ build ──→ deploy ──→ smoke
   test-frontend ┘     (matrix)    (matrix)   (matrix)     │
   terraform ────┘                                ▲        │
                                                  │        ▼
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

Register the provider once per account:

```powershell
aws iam create-open-id-connect-provider `
  --url https://token.actions.githubusercontent.com `
  --client-id-list sts.amazonaws.com `
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

---

# 2. The trust policy condition that matters

This is where OIDC setups go badly wrong, and the failure is silent.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:YOU/YOUR-REPO:*"
      }
    }
  }]
}
```

The `sub` condition is the entire security boundary. Get it wrong and any GitHub Actions workflow, in anyone's repository, can assume your role.

```text
"sub": "repo:*"                          catastrophic — the whole of GitHub
missing sub condition entirely           catastrophic — same
"sub": "repo:YOU/YOUR-REPO:*"            good — your repo, any branch
"sub": "repo:YOU/YOUR-REPO:ref:refs/heads/main"   better — main only
"sub": "repo:YOU/YOUR-REPO:environment:production" best — gated environment
```

The reason this bites people is that a too-broad condition works perfectly. Your pipeline goes green. Nothing tells you that a stranger's fork can also assume the role.

Tighten it for the deploy role specifically:

```text
StringLike  repo:YOU/YOUR-REPO:*                    → for read-only jobs
StringEquals repo:YOU/YOUR-REPO:ref:refs/heads/main → for the deploy role
```

Verify what you actually created:

```powershell
aws iam get-role --role-name auditor-github-deploy --query "Role.AssumeRolePolicyDocument"
```

Read the `sub` line. If it contains a bare `*` before your repo name, fix it now.

---

# 3. Two roles, not one

The reference uses `AWS_DEPLOY_ROLE_ARN` for both building and deploying. Split them.

```text
auditor-github-build     ecr:GetAuthorizationToken
                         ecr:BatchCheckLayerAvailability
                         ecr:PutImage, UploadLayerPart, etc.
                         → any branch, including PRs

auditor-github-deploy    ecs:DescribeTaskDefinition
                         ecs:RegisterTaskDefinition
                         ecs:UpdateService, DescribeServices
                         iam:PassRole (task roles only)
                         → main branch only
```

`iam:PassRole` needs scoping or it becomes a privilege-escalation path:

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": [
    "arn:aws:iam::ACCOUNT:role/auditor-dev-task",
    "arn:aws:iam::ACCOUNT:role/auditor-dev-execution"
  ]
}
```

Unscoped `iam:PassRole` on `"Resource": "*"` lets the pipeline register a task definition using **any** role in the account, including an admin role, and then run a container as it. That turns deploy access into account takeover.

---

# 4. Concurrency

The reference workflow has no concurrency control. Push twice in quick succession and two deploys race on `update-service`, each registering task definitions and each waiting for a rollout the other is disturbing.

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false
```

`cancel-in-progress: false` for deploys. Cancelling a deploy halfway leaves ECS mid-rollout with no one watching. Queue instead.

For PR checks, cancelling is right — nobody needs results from a commit that's already superseded. Set that per-job.

---

# 5. Test jobs with real service containers

Your integration tests need DynamoDB Local, ElasticMQ, and Redis. GitHub Actions service containers give you all three.

```yaml
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

      - run: uv sync --all-extras --dev

      - name: Start ElasticMQ
        run: |
          docker run -d --name elasticmq -p 9324:9324 \
            -v ${{ github.workspace }}/elasticmq.conf:/opt/elasticmq.conf \
            softwaremill/elasticmq-native
          for i in $(seq 1 30); do
            curl -sf http://localhost:9324 >/dev/null && break
            sleep 1
          done

      - run: uv run ruff check .
      - run: uv run ruff format --check .
      - run: uv run mypy app eval

      - name: Unit tests
        run: uv run pytest -m "not eval and not integration" -v

      - name: Integration tests
        run: uv run pytest -m integration -v
        env:
          DEV_AUTH: "1"
          DYNAMODB_ENDPOINT_URL: http://localhost:8000
          SQS_ENDPOINT_URL: http://localhost:9324
          SCAN_QUEUE_URL: http://localhost:9324/000000000000/scan-jobs.fifo
          REDIS_URL: redis://localhost:6379/0
```

ElasticMQ runs via `docker run` rather than `services:` because it needs a config file mount, and service containers can't mount workspace files — the workspace isn't checked out when they start.

The readiness loop matters. Service containers get health checks; a manually started container doesn't, and your first test will race the queue's startup.

Contrast with the reference, which points its test env at real AWS ARNs:

```yaml
SQS_SCAN_JOBS_URL: https://sqs.us-east-1.amazonaws.com/000000000000/test.fifo
DYNAMODB_SCAN_JOBS_TABLE: test-scan-jobs
```

None of those exist. Any test touching AWS fails, which means every test must be mocked — and we saw in Phase 5 what those mocks are worth. Real service containers let you test the actual client code.

---

# 6. The eval gate

This is the job the reference doesn't have, and the reason Phase 5 exists.

```yaml
  eval:
    runs-on: ubuntu-latest
    needs: [test-python]
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true

      - run: uv sync --all-extras --dev

      - name: Build fixture images
        run: |
          docker build -t auditor-eval:bad eval/fixtures/bad
          docker build -t auditor-eval:clean eval/fixtures/clean

      - name: Cache scanner output
        uses: actions/cache@v4
        with:
          path: eval/.cache
          key: trivy-${{ hashFiles('eval/fixtures/**') }}

      - name: Run the eval gate
        run: uv run pytest -m eval -v
        env:
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
          LLM_MODEL: gpt-4o
          MAX_VULNERABILITIES_TO_MODEL: "25"
```

Three deliberate choices.

**Only on push to main**, not on every PR. It costs real money and calls a third-party API. Running it on every commit to every branch turns a $0.30 check into a monthly bill.

**The scanner cache is keyed on the fixture files.** Trivy output only changes when a Dockerfile changes, so the key is `hashFiles('eval/fixtures/**')`. Change a fixture, get a fresh scan; change a prompt, reuse the cache and pay only for model calls.

**`MAX_VULNERABILITIES_TO_MODEL: 25`.** CI doesn't need the full 150 to catch a regression. Recall on a smaller sample is noisier but the gate is a ratchet, not a measurement.

This is the thing that closes the loop. A prompt edit that drops recall below `MIN_RECALL` now fails the build, whether or not anyone remembers to check. The reference project's README claims an evaluation layer; this is what having one actually looks like.

---

# 7. Terraform gets a job too

The reference has no Terraform job at all, so infrastructure drifts from what's committed with nothing noticing.

```yaml
  terraform:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.9.0

      - run: terraform fmt -recursive -check
        working-directory: terraform

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_TERRAFORM_ROLE_ARN }}
          aws-region: us-east-1

      - name: Init
        working-directory: terraform
        run: |
          terraform init \
            -backend-config="bucket=${{ secrets.TF_STATE_BUCKET }}" \
            -backend-config="key=dev/terraform.tfstate" \
            -backend-config="region=us-east-1" \
            -backend-config="dynamodb_table=auditor-tflocks"

      - run: terraform validate
        working-directory: terraform

      - name: Plan
        working-directory: terraform
        run: terraform plan -no-color -input=false -out=tfplan
        env:
          TF_VAR_llm_api_key: ${{ secrets.LLM_API_KEY }}
```

Plan, never apply, from CI. Applying infrastructure automatically on merge is a decision with real blast radius — a bad plan can delete a database. Surface the plan on the PR, apply from a laptop or a manually-triggered workflow.

`terraform fmt -check` before the AWS credentials step. Formatting failures shouldn't consume a role assumption.

---

# 8. Build with a matrix

The reference has three near-identical build blocks, about 60 lines. One matrix replaces them:

```yaml
  build:
    runs-on: ubuntu-latest
    needs: [test-python, test-frontend, terraform]
    if: github.ref == 'refs/heads/main'
    permissions:
      id-token: write
      contents: read
    outputs:
      tag: ${{ steps.meta.outputs.tag }}
    strategy:
      matrix:
        include:
          - service: worker
            context: .
            target: worker
          - service: api
            context: .
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
          role-to-assume: ${{ secrets.AWS_BUILD_ROLE_ARN }}
          aws-region: us-east-1

      - id: ecr
        uses: aws-actions/amazon-ecr-login@v2

      - uses: docker/setup-buildx-action@v3

      - uses: docker/build-push-action@v5
        with:
          context: ${{ matrix.context }}
          target: ${{ matrix.target }}
          push: true
          tags: |
            ${{ steps.ecr.outputs.registry }}/auditor-dev-${{ matrix.service }}:${{ steps.meta.outputs.tag }}
            ${{ steps.ecr.outputs.registry }}/auditor-dev-${{ matrix.service }}:latest
          build-args: |
            NEXT_PUBLIC_API_URL=${{ vars.NEXT_PUBLIC_API_URL }}
            NEXT_PUBLIC_WS_URL=${{ vars.NEXT_PUBLIC_WS_URL }}
          cache-from: type=gha,scope=${{ matrix.service }}
          cache-to: type=gha,mode=max,scope=${{ matrix.service }}
```

Three details.

**`scope=${{ matrix.service }}` on the cache.** The reference uses `mode=max` on all three builds without scoping, so they share one cache namespace and evict each other. GitHub's Actions cache is 10 GB per repository, and three unscoped max-mode Docker caches will thrash constantly.

**Tagged with the commit SHA and `latest`.** The SHA tag is what deploys; `latest` is for humans. Deploying `latest` means you cannot tell which commit is running, and rollback becomes guesswork.

**`vars` not `secrets` for the public URLs.** `NEXT_PUBLIC_*` values end up in the browser bundle. Storing them as secrets implies a confidentiality they don't have and makes them harder to read when debugging. GitHub Actions variables are the right home.

Matrix jobs run in parallel, so three images build concurrently rather than sequentially.

---

# 9. Deploy, with rollback

The reference repeats the same twenty lines three times for deploy and another twenty three times for waiting — about 120 lines that should be twenty. Worse, if the wait fails, the broken deployment stays up. There is no rollback anywhere in the pipeline.

```yaml
  deploy:
    runs-on: ubuntu-latest
    needs: [build, eval]
    if: github.ref == 'refs/heads/main'
    environment: dev
    permissions:
      id-token: write
      contents: read
    strategy:
      fail-fast: false
      matrix:
        service: [worker, api, frontend]
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}
          aws-region: us-east-1

      - id: ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Register new task definition
        id: register
        run: |
          SERVICE="auditor-dev-${{ matrix.service }}"
          IMAGE="${{ steps.ecr.outputs.registry }}/${SERVICE}:${{ needs.build.outputs.tag }}"

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

      - name: Update service
        run: |
          aws ecs update-service \
            --cluster auditor-dev \
            --service "auditor-dev-${{ matrix.service }}" \
            --task-definition "${{ steps.register.outputs.new }}"

      - name: Wait for stability
        id: wait
        timeout-minutes: 15
        run: |
          aws ecs wait services-stable \
            --cluster auditor-dev \
            --services "auditor-dev-${{ matrix.service }}"

      - name: Roll back
        if: failure() && steps.register.outputs.previous != ''
        run: |
          echo "::error::Deploy of ${{ matrix.service }} failed, rolling back"
          aws ecs update-service \
            --cluster auditor-dev \
            --service "auditor-dev-${{ matrix.service }}" \
            --task-definition "${{ steps.register.outputs.previous }}"
          aws ecs wait services-stable \
            --cluster auditor-dev \
            --services "auditor-dev-${{ matrix.service }}"
```

Four things this does that the reference doesn't.

**Captures the previous task definition ARN before changing anything.** You cannot roll back to a revision you didn't record.

**`if: failure()` rollback.** A task that crashes on boot gets reverted automatically instead of sitting broken until someone notices.

**`aws ecs wait services-stable`** replaces sixty lines of hand-rolled polling. The reference's loop is competent — it checks `rolloutState` and exits on `FAILED` — but it's sixty lines of shell repeated three times, and the AWS CLI already does this.

**`fail-fast: false`.** One service failing shouldn't cancel the other two mid-rollout. Same reasoning as `return_exceptions=True` in Phase 3, in a different tool.

Note that `--force-new-deployment` is absent. Registering a new task definition and pointing the service at it already triggers a rollout. The reference passes both, which is harmless but suggests uncertainty about which one does the work.

---

# 10. The step that makes green mean something

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

Then verify it actually works:

```yaml
  smoke:
    runs-on: ubuntu-latest
    needs: [deploy]
    if: github.ref == 'refs/heads/main'
    steps:
      - name: API health
        run: |
          for i in $(seq 1 20); do
            CODE=$(curl -s -o /dev/null -w "%{http_code}" ${{ vars.API_URL }}/health || true)
            echo "attempt $i: $CODE"
            [ "$CODE" = "200" ] && exit 0
            sleep 10
          done
          echo "::error::API health check never returned 200"
          exit 1

      - name: Dev endpoints must be absent
        run: |
          CODE=$(curl -s -o /dev/null -w "%{http_code}" ${{ vars.API_URL }}/dev/token || true)
          if [ "$CODE" != "404" ]; then
            echo "::error::/dev/token returned $CODE — DEV_AUTH is enabled in production"
            exit 1
          fi
```

That second check is worth having. Phase 8 built an endpoint that mints tokens for anyone, gated on `DEV_AUTH`. A single misconfigured environment variable turns your production API into an open credential dispenser. Assert its absence on every deploy rather than trusting that nobody set the variable.

---

# 11. Workflow-level permissions

```yaml
name: CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false
```

`permissions: contents: read` at the top sets the floor for every job. Jobs that need more declare it themselves — `id-token: write` for OIDC, `pull-requests: write` for plan comments.

Without this, jobs inherit whatever the repository default is, which on older repositories is read/write on everything. A compromised dependency in a test job could then push commits.

```text
default at the workflow level    contents: read
elevate per job                  only where needed
never at the workflow level      id-token: write
```

---

# 12. What the reference gets right, and what it doesn't

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
  ENV=dev hardcoded, so main deploys to dev and prod has no path
  no smoke test after deploy
```

The duplication is the one that compounds. Three copies of the same deploy logic means a fix applied to one and forgotten in the other two, which is how services drift apart in ways nobody intended.

---

# 13. Quality gate

Push a branch and open a PR. You should see `lint`, `test-python`, `test-frontend`, and `terraform` run, and `eval`, `build`, `deploy`, `smoke` skip.

Merge to main. All eight run in order.

Then verify the security properties by hand:

```powershell
aws iam get-role --role-name auditor-github-deploy --query "Role.AssumeRolePolicyDocument.Statement[0].Condition"
```

Read the `sub` value. It must name your repository.

```powershell
aws iam get-role-policy --role-name auditor-github-deploy --policy-name deploy --query "PolicyDocument.Statement[?Action=='iam:PassRole']"
```

`Resource` must be a list of specific role ARNs, never `*`.

Then break something on purpose. Push a commit that makes the worker crash on boot — a syntax error in `app/main.py` will do. The deploy job should fail at the wait step, roll back automatically, and leave the previous revision running. Confirm with:

```powershell
aws ecs describe-services --cluster auditor-dev --services auditor-dev-worker --query "services[0].taskDefinition"
```

It should point at the previous revision, not the broken one. Then revert.

You should have:

```text
✓ OIDC with a sub condition naming your repo
✓ Separate build and deploy roles, PassRole scoped to task roles
✓ workflow-level permissions: contents: read
✓ concurrency group, cancel-in-progress false for deploys
✓ Integration tests against real service containers
✓ Terraform validated and planned, never auto-applied
✓ Eval gate on main, scanner output cached, recall floor enforced
✓ Build and deploy as matrices, no triplicated logic
✓ Previous task definition captured, rollback on failure
✓ wait services-stable before green
✓ Smoke test asserts /dev/token returns 404
```

---

# 14. What you built

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

**Degradation must be visible in the data.** Phase 4's `degraded` flag and computed confidence, Phase 10's dashed borders and two different empty states. Confidence is a property of the pipeline, never an opinion of the model.

**Authentication is not authorization.** Phase 8's ownership dependency and Phase 9's per-subscription check. The reference authenticates the request and then never uses the result, which is the most common serious bug in web APIs.

**In append-only systems, removal is fiction.** Docker layers, git history, event logs. The only way to not ship something is to never add it.

**Infrastructure decides which bugs are fixable in code.** A GSI keyed on `repo_id` makes tenant-scoped queries impossible to express in Python. Some fixes live in one layer, some in the other, and a few need both to agree.

And the habit underneath all of it: the reference implementation is a real project by someone who shipped more than most people do. Its README promises seven agents, Ragas evaluation, and a chat endpoint, and the code has six agents, no evaluation, and no chat. That gap is not unusual — you will inherit it in every codebase you join.

```text
run grep against the README
before you trust it
```

---

## Where to go next

Four directions, roughly by value.

**Build the chat agent.** The README has promised it since the beginning. You have scan records in DynamoDB, a working auth layer, and panel space in the UI. An endpoint that loads a scan by `job_id` and answers questions against it is the highest-value missing feature, and your Phase 5 harness can measure whether the answers are grounded.

**Give an agent a real LangGraph cycle.** All six are still single-node graphs. The CVE analyst with a validation node and a conditional edge back on parse failure is about fifteen lines, and it's the difference between importing LangGraph and using it.

**Add LLM-as-judge to the eval, carefully.** Keyword matching is brittle. A judge handles paraphrase — but you must validate the judge against human labels first, or you have moved the uncertainty rather than removed it.

**Run the model bake-off.** You have a recall harness and a config that takes any OpenAI-compatible endpoint. Benchmark five models on your actual task. The ranking will probably not match the leaderboards, because structured extraction against a fixed schema rewards instruction-following over reasoning — and knowing that about your own workload is worth more than any benchmark.