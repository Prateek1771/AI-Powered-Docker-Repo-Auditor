# Phase 12 — Infrastructure: Build Order, Encoded Fixes & What It Costs

Everything so far ran free on your laptop. This phase does not.

```text
   iam          roles, OIDC              no dependencies
   networking   VPC, subnets, SGs
   ecr          image repositories
   auth         Cognito pool
   secrets      Secrets Manager
   database     DynamoDB tables
   storage      S3 + lifecycle
   queue        SQS FIFO + DLQ
   cache        ElastiCache Redis
   api          API Gateway WebSocket
   monitoring   dashboards, alarms
   ecs          clusters, tasks, services   depends on everything
        │
        └──→ build inside-out, never outside-in
```

The rule for this phase:

```text
the fixes you made in application code
must also exist in the infrastructure
or they are not fixes
```

---

# 1. Read this before you run apply

A realistic always-on deployment of this architecture runs roughly:

```text
NAT gateway          ~$32/mo   + data processing
Application LB       ~$16/mo   + LCU charges
ElastiCache t4g.micro ~$12/mo
Fargate, 2 tasks     ~$25/mo   at 0.25 vCPU / 0.5 GB
DynamoDB, S3, SQS      ~$1/mo   on-demand, low volume
                     ────────
                     ~$86/mo   before a single scan runs
```

Those are approximations — check the AWS pricing calculator for your region, since rates change and I can't see your account.

Most of that is fixed cost for capacity sitting idle. For a learning project that is a bad trade, so this phase gives you two tiers:

```text
LEARNING TIER          ~$5-15/mo
  no NAT gateway       Fargate tasks in public subnets
  no ElastiCache       Redis as a container in the task
  no ALB               public IP on the API task
  scale to zero        desired_count 0 when not in use

PRODUCTION TIER        ~$86/mo
  private subnets + NAT
  managed Redis
  ALB with TLS
  always-on
```

Build the learning tier. Section 14 shows the swap to production, and section 15 gives you a teardown you can trust. **Set a billing alarm before you run `apply`, not after.**

```powershell
aws budgets create-budget --account-id (aws sts get-caller-identity --query Account --output text) --budget file://budget.json
```

Or set one in the Billing console. Either way, do it first.

---

# 2. Bootstrap the state backend

Terraform stores state somewhere, and that somewhere cannot itself be managed by the Terraform run that needs it. Chicken and egg, so bootstrap it by hand once.

```powershell
$ACCOUNT = (aws sts get-caller-identity --query Account --output text)
$BUCKET = "auditor-tfstate-$ACCOUNT"
```

```powershell
aws s3api create-bucket --bucket $BUCKET --region us-east-1
aws s3api put-bucket-versioning --bucket $BUCKET --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket $BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

```powershell
aws dynamodb create-table --table-name auditor-tflocks --attribute-definitions AttributeName=LockID,AttributeType=S --key-schema AttributeName=LockID,KeyType=HASH --billing-mode PAY_PER_REQUEST
```

Versioning is the one that saves you. State corruption happens, and a versioned bucket means you can restore yesterday's state instead of reconciling by hand.

The lock table prevents two `apply` runs racing. With one person that feels unnecessary; the first time CI applies while you're mid-`plan`, it isn't.

---

# 3. Partial backend configuration

The reference implementation hardcodes the bucket:

```hcl
backend "s3" {
  bucket         = "docker-auditor-terraform-state"
  key            = "terraform.tfstate"
  region         = "us-east-1"
  dynamodb_table = "docker-auditor-terraform-locks"
}
```

Then its README tells you to init with a *different* bucket:

```text
terraform init -backend-config="bucket=docker-auditor-terraform-state-789438508565" ...
```

The committed value is wrong and silently overridden. Anyone cloning the repo and running plain `terraform init` points at a bucket that doesn't exist, or worse, one that belongs to somebody else.

Leave it empty instead:

```hcl
terraform {
  backend "s3" {}

  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}
```

```powershell
terraform init `
  -backend-config="bucket=$BUCKET" `
  -backend-config="key=dev/terraform.tfstate" `
  -backend-config="region=us-east-1" `
  -backend-config="dynamodb_table=auditor-tflocks" `
  -backend-config="encrypt=true"
```

An empty block is honest about the fact that the value is environment-specific. A wrong hardcoded value pretends otherwise.

---

# 4. Nothing real goes in git

The reference README contains, in plain text on a public repository:

```text
account ID       789438508565
Cognito pool     us-east-1_A86f32tcr
Sentry DSN       https://ab2fc5f13383b...@o4511369794158592.ingest.us.sentry.io/...
ALB hostnames    docker-auditor-dev-backend-904913202.us-east-1.elb.amazonaws.com
```

None of those is a credential on its own. Together they are a reconnaissance package: the account ID enables cross-account role-assumption attempts, the pool ID enables targeted enumeration against a known Cognito endpoint, and the DSN accepts events from anyone who has it.

There's also a hardcoded ALB URL inside `orchestrator.py` — the scan-complete email link — which breaks whenever the load balancer is replaced.

```text
account IDs, pool IDs, endpoints, DSNs
  →  Terraform variables and outputs
  →  never a literal in code or a README
```

Create `terraform/variables.tf`:

```hcl
variable "project" {
  type    = string
  default = "auditor"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "tier" {
  type        = string
  default     = "learning"
  description = "learning (cheap, public subnets) or production (private + NAT)"

  validation {
    condition     = contains(["learning", "production"], var.tier)
    error_message = "tier must be learning or production."
  }
}

variable "llm_api_key" {
  type      = string
  sensitive = true
}

locals {
  name = "${var.project}-${var.environment}"

  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
```

Create `terraform.tfvars` and add it to `.gitignore`:

```hcl
llm_api_key = "sk-..."
```

`sensitive = true` keeps the value out of plan and apply output. It does **not** keep it out of the state file — state contains every value in plaintext, which is why the bucket has encryption and blocked public access.

---

# 5. Build inside-out

The dependency order at the top of this phase is not a suggestion. Modules with no dependencies come first; the module that wires everything together comes last.

The reference `ecs` module is 671 lines because it references the VPC, the ECR image URIs, the secret ARNs, the queue URL, the table names, and the Redis endpoint simultaneously. Build it early and every `plan` fails on an unresolvable reference.

```text
if module A reads an output of module B
    B is built first
    always
```

Create `terraform/main.tf` and wire modules in that order:

```hcl
module "networking" {
  source = "./modules/networking"

  name = local.name
  tier = var.tier
  tags = local.tags
}

module "ecr" {
  source = "./modules/ecr"

  name = local.name
  tags = local.tags
}

module "database" {
  source = "./modules/database"

  name = local.name
  tags = local.tags
}

module "queue" {
  source = "./modules/queue"

  name = local.name
  tags = local.tags
}

module "storage" {
  source = "./modules/storage"

  name = local.name
  tags = local.tags
}

module "ecs" {
  source = "./modules/ecs"

  name               = local.name
  tier               = var.tier
  vpc_id             = module.networking.vpc_id
  subnet_ids         = module.networking.task_subnet_ids
  security_group_ids = [module.networking.task_security_group_id]
  worker_image       = "${module.ecr.worker_repository_url}:latest"
  api_image          = "${module.ecr.api_repository_url}:latest"
  jobs_table         = module.database.jobs_table_name
  results_table      = module.database.results_table_name
  queue_url          = module.queue.scan_queue_url
  queue_arn          = module.queue.scan_queue_arn
  reports_bucket     = module.storage.reports_bucket
  llm_api_key        = var.llm_api_key
  tags               = local.tags
}
```

Read it top to bottom and the dependency graph is visible without a diagram.

---

# 6. Networking, and the NAT decision

Create `terraform/modules/networking/main.tf`:

```hcl
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  private = var.tier == "production"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = var.name })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = var.tags
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, { Name = "${var.name}-public-${count.index}" })
}

resource "aws_subnet" "private" {
  count = local.private ? 2 : 0

  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.tags, { Name = "${var.name}-private-${count.index}" })
}

resource "aws_eip" "nat" {
  count = local.private ? 1 : 0

  domain = "vpc"
  tags   = var.tags
}

resource "aws_nat_gateway" "main" {
  count = local.private ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = var.tags

  depends_on = [aws_internet_gateway.main]
}
```

Two subnets minimum, in two availability zones. That isn't for resilience here — ALBs and several other services simply refuse to create with only one AZ.

The NAT gateway is your single biggest line item, roughly $32/month plus per-GB processing, and it exists so tasks in private subnets can reach the internet outbound while nothing reaches them inbound.

```text
learning tier    tasks in public subnets, public IP
                 security group blocks all inbound
                 saves ~$32/mo

production tier  tasks in private subnets
                 NAT for outbound
                 nothing routable from the internet
```

A public subnet with a locked-down security group is not the same as a private subnet, and the difference matters: a security group misconfiguration in a public subnet exposes the task, whereas the same mistake in a private subnet exposes nothing. That's a real trade, and it's the right one to make while learning and the wrong one to keep.

Note the reference implementation provisions a **single** NAT gateway rather than one per AZ. That halves cost and creates a single point of failure — a defensible choice, but one worth making knowingly.

---

# 7. Database: encoding the Phase 6 fixes

Phase 6 fixed a tenancy bug and a broken TTL in application code. Neither fix survives unless the table definition agrees.

Create `terraform/modules/database/main.tf`:

```hcl
resource "aws_dynamodb_table" "jobs" {
  name         = "${var.name}-scan-jobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "started_at"
    type = "S"
  }

  global_secondary_index {
    name            = "TenantIndex"
    hash_key        = "tenant_id"
    range_key       = "started_at"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}

resource "aws_dynamodb_table" "results" {
  name         = "${var.name}-scan-results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "tenant_repo"
    type = "S"
  }

  attribute {
    name = "scan_date"
    type = "S"
  }

  global_secondary_index {
    name            = "TenantRepoIndex"
    hash_key        = "tenant_repo"
    range_key       = "scan_date"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}
```

The GSI hash key is `tenant_repo`, not `repo_id`. That single choice is the tenancy fix — it makes "the latest scan of repo R for tenant T" answerable by key condition alone, with no `FilterExpression` and no `Limit` semantics to get wrong.

The reference keys its GSI on `repo_id` alone, forcing the filter-after-limit query that lets two tenants hide each other's results. **You cannot fix that in application code.** The index shape decides which queries are possible.

`ttl` on `expires_at` is declared here exactly as the reference does. The difference is that Phase 6's `create_job` actually writes the attribute, as an integer epoch. Declaring the TTL without writing the attribute — which is what the reference does — gives you a feature that exists in the console and does nothing.

`PAY_PER_REQUEST` avoids capacity planning, which is right for spiky scan traffic. `point_in_time_recovery` costs a little and buys you 35 days of restore.

---

# 8. Queue: encoding the Phase 7 fixes

Create `terraform/modules/queue/main.tf`:

```hcl
resource "aws_sqs_queue" "dlq" {
  name                        = "${var.name}-scan-jobs-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = false
  message_retention_seconds   = 1209600

  tags = var.tags
}

resource "aws_sqs_queue" "scan" {
  name                        = "${var.name}-scan-jobs.fifo"
  fifo_queue                  = true
  content_based_deduplication = false
  deduplication_scope         = "messageGroup"
  fifo_throughput_limit       = "perMessageGroupId"

  visibility_timeout_seconds = 300
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })

  tags = var.tags
}
```

`visibility_timeout_seconds = 300`, not 900. Phase 7 replaced the guess with a heartbeat that extends visibility every sixty seconds while work is in progress. A short timeout plus a heartbeat recovers from a dead worker in five minutes and never duplicates a slow one; a long fixed timeout does the opposite on both counts.

`content_based_deduplication = false` because Phase 7's producer supplies an explicit dedup ID derived from the request. The reference sets this to `true` *and* passes a fresh UUID, so the explicit ID overrides the content hash and deduplication never fires.

`deduplication_scope = "messageGroup"` with `fifo_throughput_limit = "perMessageGroupId"` gives high-throughput FIFO, so ordering is enforced per repo rather than across the whole queue.

The redrive policy is identical to the reference. The difference is entirely in Phase 7's consumer, which re-raises on failure so `delete_message` is skipped and `ApproximateReceiveCount` can actually reach 3. Correct infrastructure plus a swallowing handler equals a DLQ that stays empty forever.

---

# 9. Secrets and IAM

Create `terraform/modules/secrets/main.tf`:

```hcl
resource "aws_secretsmanager_secret" "llm" {
  name                    = "${var.name}/llm-api-key"
  recovery_window_in_days = 7

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "llm" {
  secret_id     = aws_secretsmanager_secret.llm.id
  secret_string = var.llm_api_key
}
```

The task role gets read access to exactly that secret, and nothing else:

```hcl
data "aws_iam_policy_document" "task" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.llm_secret_arn]
  }

  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
    ]
    resources = [
      var.jobs_table_arn,
      "${var.jobs_table_arn}/index/*",
      var.results_table_arn,
      "${var.results_table_arn}/index/*",
    ]
  }

  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]
    resources = [var.queue_arn]
  }

  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.reports_bucket_arn}/*"]
  }
}
```

Three details worth copying.

**No `dynamodb:Scan` and no `dynamodb:DeleteItem`.** The application never needs either. If a future change adds a scan, the permission failure is the review conversation you want to have.

**`/index/*` is listed explicitly.** Querying a GSI needs permission on the index ARN as well as the table. Omit it and every GSI query fails with an access-denied error that names the table, not the index, and you lose an hour.

**`sqs:ChangeMessageVisibility` is included.** Phase 7's heartbeat calls it every sixty seconds. Miss it and the heartbeat fails silently — logged as a warning, and your long scans start duplicating.

---

# 10. The endpoints disappear

Every local override you've been setting was a placeholder for real infrastructure.

```text
LOCAL                                  AWS
DYNAMODB_ENDPOINT_URL=localhost:8000   unset — boto3 finds DynamoDB
SQS_ENDPOINT_URL=localhost:9324        unset — boto3 finds SQS
REDIS_URL=redis://localhost:6379       the ElastiCache endpoint
JWKS_URL=localhost:8080/dev/...        the Cognito JWKS URL
DEV_AUTH=1                             unset
BLOB_DIR=./.blobs                      S3 bucket
```

That's the payoff for putting them behind environment variables in Phase 6 rather than hardcoding. In the task definition:

```hcl
environment = [
  { name = "AWS_REGION",          value = var.region },
  { name = "SCAN_JOBS_TABLE",     value = var.jobs_table },
  { name = "SCAN_RESULTS_TABLE",  value = var.results_table },
  { name = "SCAN_QUEUE_URL",      value = var.queue_url },
  { name = "REPORTS_BUCKET",      value = var.reports_bucket },
  { name = "REDIS_URL",           value = "redis://${var.redis_endpoint}:6379/0" },
]

secrets = [
  { name = "LLM_API_KEY", valueFrom = var.llm_secret_arn },
]
```

`environment` values are visible in the console and in `describe-task-definition`. `secrets` are fetched by the ECS agent at start and never appear in the task definition. Put an API key in `environment` and it's readable by anyone with console access.

One code change is still needed. `app/storage/blobs.py` was a local directory; it becomes S3:

```python
import json
import os

import boto3

_BUCKET = os.environ.get("REPORTS_BUCKET")


def put_blob(key: str, payload: dict) -> str:
    if not _BUCKET:
        return _put_local(key, payload)

    boto3.client("s3").put_object(
        Bucket=_BUCKET,
        Key=f"{key}.json",
        Body=json.dumps(payload, default=str).encode(),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    return key


def get_blob(key: str) -> dict | None:
    if not _BUCKET:
        return _get_local(key)

    try:
        resp = boto3.client("s3").get_object(
            Bucket=_BUCKET, Key=f"{key}.json"
        )
    except boto3.client("s3").exceptions.NoSuchKey:
        return None

    return json.loads(resp["Body"].read())
```

Two function bodies. Nothing above `app/storage/` changes, which is what the interface in Phase 6 was for.

---

# 11. ECS task definitions

Create `terraform/modules/ecs/main.tf`:

```hcl
resource "aws_ecs_cluster" "main" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = var.tier == "production" ? "enabled" : "disabled"
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${var.name}-worker"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = var.worker_image
      essential = true

      environment = local.worker_environment
      secrets     = local.worker_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "worker"
        }
      }

      stopTimeout = 120
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "worker" {
  name            = "${var.name}-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = var.tier == "learning"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}
```

Three things here matter more than they look.

**`cpu = 1024, memory = 2048`.** The worker runs Trivy, which is memory-hungry on large images. Start too small and you get task exits with code 137 — OOM-killed — which reads like a crash rather than a resource limit.

**`stopTimeout = 120`.** ECS sends SIGTERM, waits, then SIGKILL. Phase 7's loop only checks the shutdown flag between messages, so a scan in flight needs time to finish. The default 30 seconds hard-kills mid-scan. That's survivable because of Phase 7's idempotent claim, but 120 makes it rare rather than routine.

**`ignore_changes = [desired_count]`.** Without it, an autoscaler or a manual scale-to-zero gets reverted on the next `apply`. Terraform owns the shape of the service; runtime scaling owns the count.

---

# 12. Apply in stages

Do not run `terraform apply` against thirteen modules on the first attempt. Apply in dependency order and read each plan.

```powershell
terraform plan -out=tfplan
```

Read it. Then:

```powershell
terraform apply -target=module.networking -target=module.ecr
```

```powershell
terraform apply -target=module.database -target=module.queue -target=module.storage
```

```powershell
terraform apply
```

`-target` is a debugging tool, not a workflow — Terraform warns about it for good reason. Use it for the first build to keep blast radius small and errors readable, then never again.

Push images before the ECS apply, or tasks will fail pulling a tag that doesn't exist:

```powershell
$ACCOUNT = (aws sts get-caller-identity --query Account --output text)
$REGISTRY = "$ACCOUNT.dkr.ecr.us-east-1.amazonaws.com"

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $REGISTRY

docker build --target worker -t "$REGISTRY/auditor-dev-worker:latest" .
docker push "$REGISTRY/auditor-dev-worker:latest"

docker build --target api -t "$REGISTRY/auditor-dev-api:latest" .
docker push "$REGISTRY/auditor-dev-api:latest"
```

Then verify the worker came up:

```powershell
aws logs tail /ecs/auditor-dev-worker --follow
```

You want "Worker started, polling for scan jobs". If you see boto3 credential errors, the task role is missing a permission — the error names the action, which tells you which statement to add.

---

# 13. Trivy without a Docker socket

One thing genuinely changes in AWS. Locally, the worker mounted `/var/run/docker.sock` to shell out to Trivy and `docker history`. Fargate has no Docker socket, and mounting one would be a serious privilege problem anyway.

Trivy can scan a registry image directly, with no daemon:

```python
def build_command(target: str) -> list[str]:
    return [
        "trivy",
        "image",
        "--format", "json",
        "--quiet",
        "--scanners", TRIVY_SCANNERS,
        "--timeout", "10m",
        target,
    ]
```

No `docker run`, no socket — Trivy is installed in the image from Phase 11, and it pulls from ECR using the task role.

`docker history` has no such escape, so `app/scanners/docker_history.py` needs a registry-based replacement. Trivy's own output carries the layer history under `Metadata.ImageConfig.history`, which gives you the commands, though not the per-layer sizes. Either derive layers from that and accept size estimates, or call the ECR API for the manifest. The first is simpler; take it and note the limitation in the bloat prompt.

This is the kind of thing that only surfaces at deploy time, which is the argument for deploying early rather than after you've built everything.

---

# 14. Moving to the production tier

One variable:

```powershell
terraform apply -var="tier=production"
```

That switches tasks into private subnets, creates the NAT gateway, enables Container Insights, and stops assigning public IPs. Add the ALB and ElastiCache modules at the same time.

Do this when you want the architecture to be real. Don't do it and then forget it's running.

---

# 15. Teardown you can trust

```powershell
terraform destroy
```

Then verify, because `destroy` does not catch everything:

```powershell
aws ec2 describe-nat-gateways --filter "Name=state,Values=available" --query "NatGateways[].NatGatewayId"
aws elbv2 describe-load-balancers --query "LoadBalancers[].LoadBalancerName"
aws ecs list-clusters
aws logs describe-log-groups --query "logGroups[?starts_with(logGroupName,'/ecs/auditor')].logGroupName"
aws ecr describe-repositories --query "repositories[].repositoryName"
```

Four things commonly survive a destroy and keep billing:

```text
NAT gateway + EIP   the EIP charges when unattached
CloudWatch logs     retention 14 days, but storage bills meanwhile
ECR images          storage per GB, easy to forget
S3 objects          a non-empty bucket blocks destroy, then gets skipped
```

Empty the buckets first:

```powershell
aws s3 rm s3://auditor-dev-reports --recursive
```

If you only want to stop paying without tearing down:

```powershell
aws ecs update-service --cluster auditor-dev --service auditor-dev-worker --desired-count 0
aws ecs update-service --cluster auditor-dev --service auditor-dev-api --desired-count 0
```

That's why `ignore_changes = [desired_count]` is in the service. Scale to zero, keep the infrastructure, pay for almost nothing. The NAT gateway still bills, so on the learning tier there isn't one.

Check your bill 24 hours after teardown rather than trusting the destroy output.

---

# 16. Quality gate

```powershell
terraform fmt -recursive -check
terraform validate
terraform plan
```

```powershell
aws logs tail /ecs/auditor-dev-worker --since 10m
```

Run a real scan against the deployed stack. Then verify the Phase 6 and 7 fixes survived the trip:

```powershell
aws dynamodb describe-time-to-live --table-name auditor-dev-scan-jobs
```

Expect `ENABLED` on `expires_at`. Then confirm an actual row carries it:

```powershell
aws dynamodb scan --table-name auditor-dev-scan-jobs --max-items 1 --query "Items[0].expires_at"
```

Expect a number. A declared TTL with no attribute is the reference implementation's bug, and this is the two-command check that catches it.

```powershell
aws sqs get-queue-attributes --queue-url $QUEUE_URL --attribute-names VisibilityTimeout RedrivePolicy
```

You should have:

```text
✓ State in a versioned, encrypted, locked S3 backend
✓ Backend configured at init, not hardcoded
✓ No account IDs, pool IDs, or DSNs in the repository
✓ Modules applied inside-out
✓ GSI keyed on tenant_repo, tenancy fixed in the index
✓ TTL declared AND written, verified against a real row
✓ Visibility 300s with heartbeat, dedup by request
✓ IAM without Scan or DeleteItem, index ARNs included
✓ Secrets via secrets, not environment
✓ Learning tier costs under $15/mo
✓ Teardown verified against the console, not the plan output
```

---

# 17. Where this sits

```text
 Phase 10       Phase 11         Phase 12  ◄── here
┌───────────┐ ┌────────────┐ ┌──────────────────┐
│ honest UI │→│ three      │→│ it runs in AWS   │
│           │ │ images     │ │ and you can turn │
│           │ │            │ │ it off           │
└───────────┘ └────────────┘ └──────────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │    Phase 13      │
                              │     CI/CD        │
                              └──────────────────┘
```

The thing worth carrying forward: **infrastructure decides which bugs are fixable in code.** The tenancy bug in Phase 6 could not be fixed in Python, because a GSI keyed on `repo_id` makes the correct query impossible to express. The TTL could not be fixed in Terraform, because a declared TTL with no attribute written does nothing. Some fixes live in one layer, some in the other, and a few need both to agree.

---

## Next: Phase 13 — CI/CD

The last phase, and the shortest.

```text
  test-python ─┐
  test-frontend ┼→ build & push ─→ deploy ─→ wait for stability
  test-terraform ┘                              │
                                                ▼
                                         green means running
```

```text
1. OIDC instead of long-lived AWS keys — GitHub
   presents a short-lived token, AWS trusts the
   provider, and you never store a secret

2. why `aws ecs wait services-stable` is the step
   that makes a green check mean something, rather
   than "the API accepted my request"

3. running the Phase 5 eval as a gated job, so a
   prompt change that drops recall fails the build
```

That last one closes the loop. The evaluation harness stops being something you remember to run and becomes something that runs whether you remember or not.