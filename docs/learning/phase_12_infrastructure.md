# Phase 12 — Infrastructure: Build Order, Encoded Fixes & What It Costs

Everything so far ran free on your laptop. This phase does not.

```text
   networking   VPC, subnets, SGs, Cloud Map    no dependencies
   ecr          image repositories
   database     DynamoDB tables
   queue        SQS FIFO + DLQ
   storage      S3 + lifecycle
   secrets      Secrets Manager
   auth         Cognito pool
   cache        ElastiCache (production only)
   iam          roles, reading every ARN above
   ecs          cluster, tasks, services        depends on everything
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
  no ElastiCache       Redis as its own small Fargate service
  no ALB               public IP on the API task
  scale to zero        worker_count 0 when not in use

PRODUCTION TIER        ~$86/mo
  private subnets + NAT
  managed Redis
  always-on
```

Build the learning tier. Section 14 shows the swap. **Set a billing alarm before you run `apply`, not after.**

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

The reference implementation hardcodes the bucket, then its README tells you to init with a *different* one. The committed value is wrong and silently overridden — anyone cloning the repo and running plain `terraform init` points at a bucket that doesn't exist, or worse, one that belongs to somebody else.

Leave it empty instead. Create `terraform/versions.tf`:

```hcl
terraform {
  required_version = ">= 1.7.0"

  # Deliberately empty. The bucket is per-account, so a committed value is
  # either wrong for whoever clones this or points at someone else's bucket.
  # Supply it with -backend-config at init time.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}
```

```powershell
cd terraform
terraform init `
  -backend-config="bucket=$BUCKET" `
  -backend-config="key=dev/terraform.tfstate" `
  -backend-config="region=us-east-1" `
  -backend-config="dynamodb_table=auditor-tflocks" `
  -backend-config="encrypt=true"
```

An empty block is honest about the fact that the value is environment-specific. A wrong hardcoded value pretends otherwise.

Commit `.terraform.lock.hcl` when it appears. It pins each provider to a set of hashes, which is the same argument as the digest pinning in Phase 11 applied to your supply chain rather than your base image.

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
  description = "learning (cheap, public subnets, Redis in the cluster) or production (private subnets, NAT, ElastiCache)"

  validation {
    condition     = contains(["learning", "production"], var.tier)
    error_message = "tier must be learning or production."
  }
}

variable "llm_api_key" {
  type        = string
  sensitive   = true
  description = "OpenAI key. sensitive keeps it out of plan output, NOT out of state - which is why the state bucket is encrypted and private."
}

variable "worker_count" {
  type        = number
  default     = 1
  description = "Set to 0 to stop paying for compute without destroying anything."
}

variable "api_count" {
  type    = number
  default = 1
}

variable "github_repository" {
  type        = string
  description = "owner/repo, for the OIDC trust policy. The CI/CD roles are the only thing that reads it."
}

variable "cors_origins" {
  type        = string
  default     = "http://localhost:3000"
  description = "Comma-separated, matching what app/config/api.py splits on."
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

Create `terraform.tfvars`, which the repository's gitignore already covers:

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

Create `terraform/main.tf`:

```hcl
# Inside-out. Every module below reads only from modules above it, so the file
# is the dependency graph - and the ECS module is last because it references
# nearly everything else at once.

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

module "secrets" {
  source = "./modules/secrets"

  name        = local.name
  llm_api_key = var.llm_api_key
  tags        = local.tags
}

module "auth" {
  source = "./modules/auth"

  name   = local.name
  region = var.region
  tags   = local.tags
}

module "cache" {
  source = "./modules/cache"

  name              = local.name
  tier              = var.tier
  subnet_ids        = module.networking.task_subnet_ids
  security_group_id = module.networking.task_security_group_id
  tags              = local.tags
}

module "iam" {
  source = "./modules/iam"

  name               = local.name
  llm_secret_arn     = module.secrets.llm_secret_arn
  jobs_table_arn     = module.database.jobs_table_arn
  results_table_arn  = module.database.results_table_arn
  queue_arns         = [module.queue.scan_queue_arn, module.queue.dlq_arn]
  reports_bucket_arn = module.storage.reports_bucket_arn
  ecr_repository_arns = [
    module.ecr.worker_repository_arn,
    module.ecr.api_repository_arn,
    module.ecr.frontend_repository_arn,
  ]
  tags = local.tags
}

module "ecs" {
  source = "./modules/ecs"

  name   = local.name
  tier   = var.tier
  region = var.region

  subnet_ids         = module.networking.task_subnet_ids
  security_group_ids = [module.networking.task_security_group_id]
  namespace_id       = module.networking.service_namespace_id
  namespace_name     = module.networking.service_namespace_name

  execution_role_arn = module.iam.execution_role_arn
  task_role_arn      = module.iam.task_role_arn

  worker_image   = "${module.ecr.worker_repository_url}:latest"
  api_image      = "${module.ecr.api_repository_url}:latest"
  frontend_image = "${module.ecr.frontend_repository_url}:latest"

  jobs_table     = module.database.jobs_table_name
  results_table  = module.database.results_table_name
  queue_url      = module.queue.scan_queue_url
  reports_bucket = module.storage.reports_bucket
  llm_secret_arn = module.secrets.llm_secret_arn
  jwks_url       = module.auth.jwks_url
  token_audience = module.auth.client_id

  redis_host   = module.cache.redis_host
  worker_count = var.worker_count
  api_count    = var.api_count
  cors_origins = var.cors_origins

  tags = local.tags
}

# Last, because the deploy role is scoped to the cluster it updates and the
# exact roles it may pass.
module "cicd" {
  source = "./modules/cicd"

  name              = local.name
  github_repository = var.github_repository

  ecr_repository_arns = [
    module.ecr.worker_repository_arn,
    module.ecr.api_repository_arn,
    module.ecr.frontend_repository_arn,
  ]

  task_role_arns = [
    module.iam.task_role_arn,
    module.iam.execution_role_arn,
  ]

  cluster_arn = module.ecs.cluster_arn

  tags = local.tags
}
```

Read it top to bottom and the dependency graph is visible without a diagram. The `cicd` module at the bottom belongs to Phase 13 — it creates the GitHub OIDC roles, and it is last because the deploy role is scoped to the cluster it updates and the exact roles it may pass. Ignore it for now; `github_repository` is the only variable it needs and it has no default, so `validate` will tell you if you forget it.

Note what `ecs` is handed for the model key: `module.secrets.llm_secret_arn`, not `var.llm_api_key`. Passing the key itself would put it in the task definition as an environment value, readable by anyone with console access — see section 10. The module needs the **name of where the key lives**, never the key.

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

# Two AZs minimum. Not for resilience at this size - several services simply
# refuse to create with one subnet.
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

# The single biggest line item, ~$32/mo plus per-GB. It exists only so private
# tasks can reach the internet outbound, so the learning tier does without it
# and puts tasks in public subnets behind a closed security group instead.
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

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(var.tags, { Name = "${var.name}-public" })
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count = local.private ? 1 : 0

  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[0].id
  }

  tags = merge(var.tags, { Name = "${var.name}-private" })
}

resource "aws_route_table_association" "private" {
  count = local.private ? 2 : 0

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_security_group" "task" {
  name        = "${var.name}-task"
  description = "ECS tasks. Egress open, ingress only from inside the group."
  vpc_id      = aws_vpc.main.id

  tags = merge(var.tags, { Name = "${var.name}-task" })
}

# Tasks reach SQS, DynamoDB, ECR, Secrets Manager and the OpenAI API outbound.
resource "aws_vpc_security_group_egress_rule" "task_all" {
  security_group_id = aws_security_group.task.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "All outbound"
}

# Self-referencing, so the API can reach Redis and nothing outside the group
# can reach either. On the learning tier the tasks hold public IPs, so this
# rule is the only thing standing between Redis and the internet - which is
# exactly the trade section 6 of the doc describes.
resource "aws_vpc_security_group_ingress_rule" "task_self" {
  security_group_id            = aws_security_group.task.id
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "-1"
  description                  = "Between tasks in this group only"
}

# Private DNS inside the VPC, so the API can resolve redis.<name>.local without
# an ElastiCache bill. Roughly $0.50/mo for the hosted zone.
resource "aws_service_discovery_private_dns_namespace" "main" {
  name = "${var.name}.local"
  vpc  = aws_vpc.main.id

  tags = var.tags
}
```

Two subnets minimum, in two availability zones. That isn't for resilience here — several services simply refuse to create with only one AZ.

The NAT gateway is your single biggest line item, roughly $32/month plus per-GB processing, and it exists so tasks in private subnets can reach the internet outbound while nothing reaches them inbound.

```text
learning tier    tasks in public subnets, public IP
                 security group allows ingress only from itself
                 saves ~$32/mo

production tier  tasks in private subnets
                 NAT for outbound
                 nothing routable from the internet
```

A public subnet with a locked-down security group is not the same as a private subnet, and the difference matters: a security group misconfiguration in a public subnet exposes the task, whereas the same mistake in a private subnet exposes nothing. That's a real trade, and it's the right one to make while learning and the wrong one to keep.

The Cloud Map private DNS namespace at the bottom is what lets the API find Redis by name without an ElastiCache bill. Section 11 explains why that has to be a name rather than a sidecar.

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

  # Declaring this is half the fix. app/storage/jobs.py has to write expires_at
  # as an integer epoch, and it does - a TTL with no attribute is a feature
  # that shows as enabled in the console and deletes nothing.
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

  # The tenancy fix, and it lives here rather than in Python. Keyed on
  # tenant_repo, "the latest scan of repo R for tenant T" is answerable by key
  # condition alone. Keyed on repo_id it needs a filter after the limit, which
  # is what lets one tenant's rows hide another's. The index shape decides
  # which queries are expressible.
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

`ttl` on `expires_at` is declared here exactly as the reference does. The difference is that Phase 6's `create_job` actually writes the attribute, as an integer epoch. Declaring the TTL without writing the attribute gives you a feature that exists in the console and does nothing.

---

# 8. Queue: encoding the Phase 7 fixes

Create `terraform/modules/queue/main.tf`:

```hcl
resource "aws_sqs_queue" "dlq" {
  name                        = "${var.name}-scan-jobs-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = false
  message_retention_seconds   = 1209600

  sqs_managed_sse_enabled = true

  tags = var.tags
}

resource "aws_sqs_queue" "scan" {
  name       = "${var.name}-scan-jobs.fifo"
  fifo_queue = true

  # false, because app/queue/producer.py supplies an explicit dedup id derived
  # from the request. Setting this true as well means the explicit id wins and
  # the content hash never applies - dedup silently stops working.
  content_based_deduplication = false

  deduplication_scope   = "messageGroup"
  fifo_throughput_limit = "perMessageGroupId"

  # 300, not 900. Phase 7 replaced the guess with a heartbeat that extends
  # visibility every 60s while work is in flight, so a short timeout recovers
  # from a dead worker in five minutes and still never cuts off a slow one.
  visibility_timeout_seconds = 300
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 20

  sqs_managed_sse_enabled = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })

  tags = var.tags
}

resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.scan.arn]
  })
}
```

`visibility_timeout_seconds = 300`, not 900. Phase 7 replaced the guess with a heartbeat that extends visibility every sixty seconds while work is in progress. A short timeout plus a heartbeat recovers from a dead worker in five minutes and never duplicates a slow one; a long fixed timeout does the opposite on both counts.

`content_based_deduplication = false` because Phase 7's producer supplies an explicit dedup ID derived from the request. The reference sets this to `true` *and* passes a fresh UUID, so the explicit ID overrides the content hash and deduplication never fires.

The redrive policy is identical to the reference. The difference is entirely in Phase 7's consumer, which re-raises on failure so `delete_message` is skipped and `ApproximateReceiveCount` can actually reach 3. Correct infrastructure plus a swallowing handler equals a DLQ that stays empty forever.

---

# 9. Storage, secrets, and the auth hole

Create `terraform/modules/storage/main.tf`:

```hcl
resource "aws_s3_bucket" "reports" {
  bucket = "${var.name}-reports"

  # A non-empty bucket blocks destroy, and then gets skipped - which is how a
  # "successful" teardown leaves you paying for storage.
  force_destroy = true

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Matches JOB_TTL_DAYS in app/config/storage.py. The summary row in DynamoDB
# expires after 30 days, so a report that outlives it is unreachable storage
# nobody can find and nobody stops paying for.
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-reports"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }
}
```

The lifecycle rule matters more than it looks. `JOB_TTL_DAYS = 30` expires the DynamoDB summary, and the summary is the only thing that carries `report_key`. Without a matching S3 rule, every report outlives the row that points at it — unreachable objects nobody can find and nobody stops paying for.

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

Then the part the reference architecture never addresses. On the learning tier the API task has a **public IP**, and `DEV_AUTH=1` mounts `/dev/token`, which mints a valid token for any tenant you name. That is fine on `localhost` and is a full authentication bypass on the open internet.

So `DEV_AUTH` stays unset in AWS, and something has to issue the tokens instead. Create `terraform/modules/auth/main.tf`:

```hcl
# DEV_AUTH is not an option in AWS. On the learning tier the API task carries a
# public IP, and /dev/token hands a valid token for any tenant to any caller -
# so the dev signer stays off and this pool is what JWKS_URL points at.
resource "aws_cognito_user_pool" "main" {
  name = var.name

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 3
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = var.tags
}

resource "aws_cognito_user_pool_client" "web" {
  name         = "${var.name}-web"
  user_pool_id = aws_cognito_user_pool.main.id

  # Public browser client, so no secret to leak into a bundle.
  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  id_token_validity      = 60
  access_token_validity  = 60
  refresh_token_validity = 30

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }
}
```

`JWKS_URL` then points at Cognito rather than at the app's own dev signer, and `app/api/auth.py` needs no change at all — it already fetches a JWKS URL and caches it for `JWKS_CACHE_SECONDS`. That is the payoff for verifying tokens against a URL in Phase 8 instead of a hardcoded key.

---

# 10. IAM: least privilege, and the role people conflate

Create `terraform/modules/iam/main.tf`:

```hcl
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# The execution role is the ECS agent's: pull the image, fetch the secret, open
# the log stream. It is not the application's role and must not be reused as
# one - the task role below is what the running code gets.
resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_extra" {
  # The managed policy covers ECR and logs but not Secrets Manager, and the
  # agent is what resolves `secrets` entries in the task definition.
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.llm_secret_arn]
  }
}

resource "aws_iam_role_policy" "execution_extra" {
  name   = "${var.name}-execution-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_extra.json
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "task" {
  # No dynamodb:Scan and no dynamodb:DeleteItem. The application needs neither,
  # and a future change that adds one fails loudly rather than quietly reading
  # every tenant's rows.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
    ]

    # /index/* is listed on purpose. Querying a GSI needs permission on the
    # index as well as the table, and without it the denial names the table,
    # not the index - an hour of looking in the wrong place.
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
      "sqs:GetQueueAttributes",
      # The Phase 7 heartbeat calls this every 60 seconds. Omit it and the
      # heartbeat fails as a logged warning while long scans start duplicating.
      "sqs:ChangeMessageVisibility",
    ]
    resources = var.queue_arns
  }

  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.reports_bucket_arn}/*"]
  }

  # The worker scans images out of ECR with the Trivy binary, which needs to
  # read them the same way a pull does.
  statement {
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages",
    ]
    resources = var.ecr_repository_arns
  }

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${var.name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}
```

**There are two roles and they are not interchangeable.** The *execution* role belongs to the ECS agent: it pulls the image, resolves `secrets`, and opens the log stream, all before your code exists. The *task* role is what the running process gets. Put `secretsmanager:GetSecretValue` only on the task role — which is what the obvious reading of "the task needs the secret" gives you — and the task never starts at all. It fails with `ResourceInitializationError` at pull time, which does not mention IAM in a way that points you at the right role.

Three more details worth copying.

**No `dynamodb:Scan` and no `dynamodb:DeleteItem`.** The application never needs either. If a future change adds a scan, the permission failure is the review conversation you want to have.

**`/index/*` is listed explicitly.** Querying a GSI needs permission on the index ARN as well as the table. Omit it and every GSI query fails with an access-denied error that names the table, not the index, and you lose an hour.

**`sqs:ChangeMessageVisibility` is included.** Phase 7's heartbeat calls it every sixty seconds. Miss it and the heartbeat fails silently — logged as a warning, and your long scans start duplicating.

---

# 11. Redis cannot be a sidecar

Create `terraform/modules/cache/main.tf`:

```hcl
# ElastiCache is ~$12/mo for a t4g.micro that sits idle most of the time, so the
# learning tier runs Redis as a container in the cluster instead (see the ecs
# module) and this creates nothing at all.
locals {
  managed = var.tier == "production"
}

resource "aws_elasticache_subnet_group" "main" {
  count = local.managed ? 1 : 0

  name       = var.name
  subnet_ids = var.subnet_ids

  tags = var.tags
}

resource "aws_elasticache_replication_group" "main" {
  count = local.managed ? 1 : 0

  replication_group_id = var.name
  description          = "Progress pub/sub for ${var.name}"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = "cache.t4g.micro"

  num_cache_clusters = 1
  port               = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main[0].name
  security_group_ids = [var.security_group_id]

  at_rest_encryption_enabled = true

  # Progress events are transient and the bus tolerates a cold start, so an
  # unavailable Redis costs live updates rather than results.
  snapshot_retention_limit = 0

  tags = var.tags
}
```

On the learning tier that module creates nothing, and Redis runs as its own Fargate service instead. It is tempting to save even that by adding a Redis container to the worker's task definition — containers in a task share a network namespace, so `localhost:6379` would just work.

It would work for the worker and be invisible to the API. Phase 9 made Redis the *bus*: the worker publishes progress and the API's WebSocket subscribes, in a different task. A sidecar gives each task its own private Redis, both perfectly healthy, and the browser never receives an event. The failure looks like a WebSocket bug and is a topology bug.

So it gets a service and a DNS name both tasks resolve, which is the whole reason the Cloud Map namespace exists in section 6.

---

# 12. The endpoints disappear

Every local override you've been setting was a placeholder for real infrastructure.

```text
LOCAL                                  AWS
DYNAMODB_ENDPOINT_URL=localhost:8000   unset — boto3 finds DynamoDB
SQS_ENDPOINT_URL=localhost:9324        unset — boto3 finds SQS
REDIS_URL=redis://localhost:6379       redis.auditor-dev.local
JWKS_URL=localhost:8080/dev/...        the Cognito JWKS URL
DEV_AUTH=1                             unset
BLOB_DIR=./.blobs                      REPORTS_BUCKET, an S3 bucket
SCANNER_MODE=socket                    registry
```

That's the payoff for putting them behind environment variables in Phase 6 rather than hardcoding. Create `terraform/modules/ecs/main.tf`:

```hcl
locals {
  public = var.tier == "learning"

  # On the learning tier Redis is a task in this cluster, reachable by private
  # DNS. On production it is the ElastiCache endpoint the cache module made.
  redis_host = var.redis_host != "" ? var.redis_host : "redis.${var.namespace_name}"

  # Every one of these was a local override in earlier phases. The endpoint
  # variables simply go away here: with DYNAMODB_ENDPOINT_URL and
  # SQS_ENDPOINT_URL unset, boto3 finds the real services. That is what putting
  # them behind environment variables in Phase 6 bought.
  common_environment = [
    { name = "AWS_REGION", value = var.region },
    { name = "SCAN_JOBS_TABLE", value = var.jobs_table },
    { name = "SCAN_RESULTS_TABLE", value = var.results_table },
    { name = "SCAN_QUEUE_URL", value = var.queue_url },
    { name = "REPORTS_BUCKET", value = var.reports_bucket },
    { name = "REDIS_URL", value = "redis://${local.redis_host}:6379/0" },
  ]

  # environment values are readable by anyone with console access. secrets are
  # fetched by the ECS agent at start and never appear in the task definition.
  llm_secrets = [
    { name = "OPENAI_API_KEY", valueFrom = var.llm_secret_arn },
  ]
}

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

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.name}-api"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "redis" {
  count = local.public ? 1 : 0

  name              = "/ecs/${var.name}-redis"
  retention_in_days = 3

  tags = var.tags
}

# ------------------------------------------------------------------- worker

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"

  # Trivy is memory-hungry on large images. Start smaller and the task exits
  # 137 - OOM-killed - which reads like a crash rather than a limit.
  cpu    = 1024
  memory = 2048

  execution_role_arn = var.execution_role_arn
  task_role_arn      = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = var.worker_image
      essential = true

      environment = concat(local.common_environment, [
        # No Docker socket on Fargate, so app/scanners/ reads layer history out
        # of Trivy's own report instead of `docker history`.
        { name = "SCANNER_MODE", value = "registry" },
      ])

      secrets = local.llm_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "worker"
        }
      }

      # ECS sends SIGTERM then SIGKILL. app/main.py only checks the shutdown
      # flag between messages, so a scan in flight needs room to finish. The
      # 30s default hard-kills mid-scan - survivable thanks to the idempotent
      # claim, but routine rather than rare.
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
    assign_public_ip = local.public
  }

  # Terraform owns the shape of the service; runtime owns the count. Without
  # this, a scale-to-zero gets reverted by the next apply - and scale-to-zero
  # is how you stop paying without tearing anything down.
  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}

# ---------------------------------------------------------------------- api

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024

  execution_role_arn = var.execution_role_arn
  task_role_arn      = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = var.api_image
      essential = true

      portMappings = [{ containerPort = 8080, protocol = "tcp" }]

      environment = concat(local.common_environment, [
        # DEV_AUTH stays unset. /dev/token mints a valid token for any tenant,
        # and on this tier the task has a public IP.
        { name = "JWKS_URL", value = var.jwks_url },
        { name = "TOKEN_AUDIENCE", value = var.token_audience },
        { name = "CORS_ORIGINS", value = var.cors_origins },
      ])

      secrets = local.llm_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "api"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_service_discovery_service" "api" {
  name = "api"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_ecs_service" "api" {
  name            = "${var.name}-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = local.public
  }

  service_registries {
    registry_arn = aws_service_discovery_service.api.arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}

# ----------------------------------------------------------------- frontend

resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/ecs/${var.name}-frontend"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "${var.name}-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  execution_role_arn = var.execution_role_arn

  # No task role. The standalone Next server talks to nothing in AWS - the
  # browser calls the API directly, which is why NEXT_PUBLIC_API_URL has to be
  # host-reachable rather than a service name.
  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = var.frontend_image
      essential = true

      portMappings = [{ containerPort = 3000, protocol = "tcp" }]

      environment = [
        { name = "NODE_ENV", value = "production" },
        { name = "HOSTNAME", value = "0.0.0.0" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.frontend.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "frontend"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_service_discovery_service" "frontend" {
  name = "frontend"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_ecs_service" "frontend" {
  name            = "${var.name}-frontend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = var.frontend_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = local.public
  }

  service_registries {
    registry_arn = aws_service_discovery_service.frontend.arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}

# -------------------------------------------------------------------- redis

# Phase 9 made Redis load-bearing: progress routing goes through pub/sub, so
# the API and the worker must reach the SAME instance. A sidecar in one task
# would be invisible to the other, which is why this is its own service with a
# DNS name both can resolve.
resource "aws_service_discovery_service" "redis" {
  count = local.public ? 1 : 0

  name = "redis"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "redis" {
  count = local.public ? 1 : 0

  family                   = "${var.name}-redis"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name      = "redis"
      image     = "public.ecr.aws/docker/library/redis:7-alpine"
      essential = true

      portMappings = [{ containerPort = 6379, protocol = "tcp" }]

      # No persistence and a hard cap. Progress events are transient, and an
      # unbounded Redis in a 512 MB task is an OOM waiting for a busy day.
      command = [
        "redis-server",
        "--save", "",
        "--appendonly", "no",
        "--maxmemory", "256mb",
        "--maxmemory-policy", "allkeys-lru",
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.redis[0].name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "redis"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "redis" {
  count = local.public ? 1 : 0

  name            = "${var.name}-redis"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.redis[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = true
  }

  service_registries {
    registry_arn = aws_service_discovery_service.redis[0].arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}
```

`environment` values are visible in the console and in `describe-task-definition`. `secrets` are fetched by the ECS agent at start and never appear in the task definition. Put an API key in `environment` and it's readable by anyone with console access.

Note the secret's `name` is `OPENAI_API_KEY`. There is no `LLM_API_KEY` in this codebase — `app/agents/runner.py` builds `ChatOpenAI` and the SDK reads that exact variable from the environment. An invented name here produces a task that starts cleanly and fails on its first model call.

The frontend service arrives with Phase 13's deploy matrix and is shaped like the API's, minus a task role — the standalone Next server talks to nothing in AWS, because the browser calls the API directly. That is the same reason `NEXT_PUBLIC_API_URL` has to be host-reachable rather than a service name.

Three things in the task definitions matter more than they look.

**`cpu = 1024, memory = 2048`** on the worker. Trivy is memory-hungry on large images. Start too small and you get task exits with code 137 — OOM-killed — which reads like a crash rather than a resource limit.

**`stopTimeout = 120`.** ECS sends SIGTERM, waits, then SIGKILL. Phase 7's loop only checks the shutdown flag between messages, so a scan in flight needs time to finish. The default 30 seconds hard-kills mid-scan. That's survivable because of Phase 7's idempotent claim, but 120 makes it rare rather than routine.

**`ignore_changes = [desired_count]`.** Without it, a manual scale-to-zero gets reverted on the next `apply`. Terraform owns the shape of the service; runtime scaling owns the count.

Finally, `terraform/outputs.tf` — the values the reference pasted into its README:

```hcl
output "worker_repository_url" {
  value = module.ecr.worker_repository_url
}

output "api_repository_url" {
  value = module.ecr.api_repository_url
}

output "cluster_name" {
  value = module.ecs.cluster_name
}

output "jobs_table_name" {
  value = module.database.jobs_table_name
}

output "results_table_name" {
  value = module.database.results_table_name
}

output "scan_queue_url" {
  value = module.queue.scan_queue_url
}

output "reports_bucket" {
  value = module.storage.reports_bucket
}

# The values the reference implementation pasted into its README. They are
# outputs so the frontend build can read them from state, and so nothing has to
# be hardcoded in a file anyone can clone.
output "user_pool_id" {
  value = module.auth.user_pool_id
}

output "user_pool_client_id" {
  value = module.auth.client_id
}

output "jwks_url" {
  value = module.auth.jwks_url
}

output "frontend_repository_url" {
  value = module.ecr.frontend_repository_url
}

# The two values GitHub needs as Actions secrets.
output "github_build_role_arn" {
  value = module.cicd.build_role_arn
}

output "github_deploy_role_arn" {
  value = module.cicd.deploy_role_arn
}
```

---

# 13. Reports move to S3

The local directory becomes S3, and the presence of `REPORTS_BUCKET` is the only switch. Replace `worker/app/storage/blobs.py`:

```python
import json
from pathlib import Path
from typing import Any

import boto3

from app.config.storage import AWS_REGION, BLOB_DIR, REPORTS_BUCKET


def _client() -> Any:
    return boto3.client("s3", region_name=AWS_REGION)


def _path(key: str) -> Path:
    path = Path(BLOB_DIR) / f"{key}.json"

    path.parent.mkdir(parents=True, exist_ok=True)

    return path


def put_blob(key: str, payload: dict) -> str:
    if not REPORTS_BUCKET:
        _path(key).write_text(json.dumps(payload, default=str))

        return key

    _client().put_object(
        Bucket=REPORTS_BUCKET,
        Key=f"{key}.json",
        Body=json.dumps(payload, default=str).encode(),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    return key


def get_blob(key: str) -> dict | None:
    if not REPORTS_BUCKET:
        path = _path(key)

        if not path.exists():
            return None

        return json.loads(path.read_text())

    client = _client()

    try:
        resp = client.get_object(Bucket=REPORTS_BUCKET, Key=f"{key}.json")
    # NoSuchKey is only raised for get_object; a missing report is a normal
    # answer here, not an error worth propagating to the API layer.
    except client.exceptions.NoSuchKey:
        return None

    return json.loads(resp["Body"].read())
```

Two function bodies. Nothing above `app/storage/` changes, which is what the interface in Phase 6 was for — `store_result` and `get_full_report` never learn that the report crossed a network.

One detail the obvious version gets wrong: `except boto3.client("s3").exceptions.NoSuchKey` constructs a **new S3 client inside the except clause**, on the error path, every time a report is missing. Bind the client once and catch off that.

This also retires the shared Docker volume from Phase 11. Locally, the worker wrote a file the API read back off a bind mount; in AWS both talk to the same bucket, and the two-containers-one-path problem disappears rather than being solved.

---

# 14. Trivy without a Docker socket

One thing genuinely changes in AWS. Locally, the worker mounted `/var/run/docker.sock` to run Trivy as a sibling container and to shell out to `docker history`. Fargate has no Docker socket, and mounting one would be a serious privilege problem anyway.

Trivy scans a registry image directly with no daemon, so `build_command` branches on one variable:

```python
def build_command(target: str) -> list[str]:
    if SCANNER_MODE == "registry":
        return ["trivy", "image", "--format", "json", "--quiet", ...]

    return ["docker", "run", "--rm", "-v", "/var/run/docker.sock:...", ...]
```

`SCANNER_MODE` is read from the environment and defaults to `socket`. It is explicit rather than inferred from whether `/var/run/docker.sock` exists, because that path is absent on Windows even when the CLI works perfectly — a probe would guess wrong on every local machine in the project.

`docker history` has no such escape. But it turns out it does not need one: **Trivy's report already carries everything required to reconstruct it exactly.**

```text
Metadata.ImageConfig.history      every build step, oldest first,
                                  including the ones that made no layer
Metadata.ImageConfig.rootfs
        .diff_ids                 ordered ids of the steps that DID
Metadata.Layers[].{DiffID,Size}   the size of each of those
```

Walk the history; each non-empty step consumes the next `diff_id`; look its size up in `Layers`. That is `history_from_report` in `app/scanners/docker_history.py`, and checked against `docker history` on the worker's own image it reproduces all 19 steps, in order, with the same commands and the same empty/non-empty split.

The sizes land about 8% lower, consistently. Not an error: `docker history` reports the unpacked size on the local storage driver, including block overhead, while Trivy reports the size of the tar diff — which is what a `docker pull` actually transfers. On a `WORKDIR` layer the gap is 1.5 KB against 8 KB, which is filesystem block accounting rather than compression.

The same report supplies the image config, so the inspect scanner needs no daemon either. Replace `worker/app/scanners/image_inspect.py`:

```python
import json

from app.config.scanning import SCANNER_MODE
from app.scanners.docker_history import (
    DockerHistoryError,
    _run,
    ensure_image_present,
)
from app.scanners.trivy import image_report


def inspect_from_report(report: dict) -> dict:
    """Shape a Trivy report's image config like `docker image inspect` output.

    Trivy's `Metadata.ImageConfig.config` is the OCI config block and already
    uses the capitalised keys the CLI emits (User, Env, ExposedPorts, Cmd,
    Entrypoint, Healthcheck), so processors/profile.py needs no branch of its
    own - it keeps reading `.Config`.
    """
    metadata = report.get("Metadata") or {}
    config = metadata.get("ImageConfig") or {}

    if not config:
        raise DockerHistoryError("Trivy report carries no image config")

    return {
        "Config": config.get("config") or {},
        "Architecture": config.get("architecture", ""),
        "Os": config.get("os", ""),
        "Id": metadata.get("ImageID", ""),
        "RepoTags": metadata.get("RepoTags") or [],
        "RepoDigests": metadata.get("RepoDigests") or [],
        "Size": metadata.get("Size", 0),
    }


async def run_image_inspect(target: str) -> dict:
    if SCANNER_MODE == "registry":
        return inspect_from_report(await image_report(target))

    await ensure_image_present(target)

    code, stdout, stderr = await _run(["docker", "image", "inspect", target])

    if code != 0:
        raise DockerHistoryError(
            f"docker image inspect exited {code}: {stderr.decode()[:300]}"
        )

    payload = json.loads(stdout)

    if not payload:
        raise DockerHistoryError(f"Empty inspect output for {target}")

    return payload[0]
```

`Metadata.ImageConfig.config` is the OCI config block and already uses the capitalised keys the CLI emits, so `processors/profile.py` keeps reading `.Config` and gains no branch of its own.

One consequence to design around. In registry mode all three scanners want that one report, and the orchestrator gathers them concurrently — so Trivy would run three times over the same image, tripling the slowest step in the scan. `app/scanners/trivy.py` shares the run between callers that are already waiting and keeps nothing afterwards:

```python
_inflight: dict[str, asyncio.Task[dict]] = {}


async def image_report(target: str) -> dict:
    task = _inflight.get(target)

    if task is None:
        task = asyncio.create_task(_execute(target))
        _inflight[target] = task
        task.add_done_callback(lambda _: _inflight.pop(target, None))

    return await asyncio.shield(task)
```

A result cache would be shorter and wrong. Tags are mutable; someone rebuilds `auditor-api:latest` and rescans, and a cache hands back the pre-rebuild report — the one answer a vulnerability scanner must never give. Sharing only in-flight work gets the same saving with no staleness at all.

Finally, the image needs the Trivy binary, which the Phase 11 worker deliberately does not have. That is a separate build target rather than a flag, because the binary is 168 MB and local runs would carry it for nothing:

```dockerfile
FROM base AS worker-aws

COPY --from=aquasec/trivy:0.74.0@sha256:62b1e65e... /usr/local/bin/trivy /usr/local/bin/trivy

ENV SCANNER_MODE=registry \
    TRIVY_CACHE_DIR=/tmp/trivy-cache
```

`TRIVY_CACHE_DIR` points at `/tmp` because the task runs as uid 1001 and Trivy writes its database at scan time — the same "anything the process writes to needs to be writable" rule from Phase 11 section 6, arriving in a new place.

```text
auditor-worker       430 MB   docker CLI, socket mode
auditor-worker-aws   587 MB   trivy binary, registry mode
```

This is the kind of thing that only surfaces at deploy time, which is the argument for deploying early rather than after you've built everything.

---

# 15. Apply in stages

Before any of it, check the configuration without touching an account:

```powershell
cd terraform
terraform init -backend=false
terraform fmt -recursive -check
terraform validate
```

`validate` catches unresolvable references, type errors and bad module wiring without credentials and without cost. Run it every time; it is the only gate in this phase that is free.

Then, with the backend configured, do not run `terraform apply` against ten modules on the first attempt. Apply in dependency order and read each plan.

```powershell
terraform apply -target=module.networking -target=module.ecr
terraform apply -target=module.database -target=module.queue -target=module.storage
terraform apply -target=module.secrets -target=module.auth -target=module.iam
terraform apply
```

`-target` is a debugging tool, not a workflow — Terraform warns about it for good reason. Use it for the first build to keep blast radius small and errors readable, then never again.

Push images before the ECS apply, or tasks will fail pulling a tag that doesn't exist. Note the worker uses the `worker-aws` target:

```powershell
$REGISTRY = (terraform output -raw worker_repository_url).Split('/')[0]
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $REGISTRY

docker build --target worker-aws -t "$(terraform output -raw worker_repository_url):latest" ../worker
docker push "$(terraform output -raw worker_repository_url):latest"

docker build --target api -t "$(terraform output -raw api_repository_url):latest" ../worker
docker push "$(terraform output -raw api_repository_url):latest"
```

Then verify the worker came up:

```powershell
aws logs tail /ecs/auditor-dev-worker --follow
```

You want "Worker started, polling for scan jobs". If you see boto3 credential errors, the task role is missing a permission — the error names the action, which tells you which statement to add.

---

# 16. Moving to the production tier

One variable:

```powershell
terraform apply -var="tier=production"
```

That switches tasks into private subnets, creates the NAT gateway, enables Container Insights, stops assigning public IPs, and replaces the in-cluster Redis with ElastiCache. Add an ALB at the same time.

Do this when you want the architecture to be real. Don't do it and then forget it's running.

---

# 17. Teardown you can trust

```powershell
terraform destroy
```

Then verify, because `destroy` does not catch everything:

```powershell
aws ec2 describe-nat-gateways --filter "Name=state,Values=available" --query "NatGateways[].NatGatewayId"
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

The storage module sets `force_destroy = true` and the ECR repositories expire untagged images after 7 days, which handles two of those four. The other two are yours to check.

If you only want to stop paying without tearing down:

```powershell
aws ecs update-service --cluster auditor-dev --service auditor-dev-worker --desired-count 0
aws ecs update-service --cluster auditor-dev --service auditor-dev-api --desired-count 0
```

That's why `ignore_changes = [desired_count]` is in the service. Scale to zero, keep the infrastructure, pay for almost nothing. The NAT gateway still bills, so on the learning tier there isn't one.

Check your bill 24 hours after teardown rather than trusting the destroy output.

---

# 18. Quality gate

Free, and run before anything else:

```powershell
cd terraform; terraform fmt -recursive -check; terraform validate
cd ../worker; uv run pytest -m "not eval and not integration" -q
```

The registry-mode scanners have their own tests in `worker/tests/test_registry_mode.py` and need neither AWS nor Docker: the layer reconstruction, the config mapping, and the single-flight are all exercised against a fixture report.

Then, deployed:

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

You should have:

```text
✓ State in a versioned, encrypted, locked S3 backend
✓ Backend configured at init, not hardcoded; provider lock committed
✓ No account IDs, pool IDs, or DSNs in the repository
✓ terraform validate green before any apply
✓ Modules applied inside-out
✓ GSI keyed on tenant_repo, tenancy fixed in the index
✓ TTL declared AND written, verified against a real row
✓ S3 lifecycle matching JOB_TTL_DAYS, so no orphaned reports
✓ Visibility 300s with heartbeat, dedup by request
✓ Secret readable by the EXECUTION role, not just the task role
✓ IAM without Scan or DeleteItem, index ARNs included
✓ DEV_AUTH off, Cognito issuing tokens
✓ Redis a service both tasks resolve, never a sidecar
✓ Registry-mode scanners, verified against docker history
✓ Learning tier costs under $15/mo
✓ Teardown verified against the console, not the plan output
```

---

# 19. Where this sits

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

The Redis sidecar is the same lesson wearing different clothes. Nothing in the application code is wrong when progress events stop arriving; the topology is.

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
