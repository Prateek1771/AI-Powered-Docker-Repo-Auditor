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
    { name = "REDIS_URL", value = "${local.redis_scheme}://${local.redis_host}:6379/0" },
  ]

  # rediss:// only where there is a certificate to verify. ElastiCache has one
  # once transit encryption is on; the in-cluster Redis task does not, and
  # inventing a self-signed cert to check against ourselves would be theatre.
  # That path is protected by the security group plus the password below.
  redis_scheme = var.redis_host != "" ? "rediss" : "redis"

  # environment values are readable by anyone with console access. secrets are
  # fetched by the ECS agent at start and never appear in the task definition.
  #
  # REDIS_PASSWORD travels here rather than inside REDIS_URL for exactly that
  # reason: a credential in the URL would make the whole URL an environment
  # value, and console-readable. See docs/audits/audit-01-backend.md P4-3.
  task_secrets = [
    { name = "OPENAI_API_KEY", valueFrom = var.llm_secret_arn },
    { name = "REDIS_PASSWORD", valueFrom = var.redis_secret_arn },
  ]

  # Applied to every container. See docs/audits/audit-01-backend.md P4-4.
  #
  # The images already drop to a non-root uid at build time - "everything runs
  # as uid 0" was not true - but nothing ASSERTED it here, so an image
  # regression that lost its USER line would have promoted the task to root
  # silently. That is exactly what nearly happened to redis in P4-3.
  #
  # cap_drop ALL is safe throughout: registry mode needs no Docker socket
  # (Fargate has none), nothing binds a port below 1024, and privilege is
  # dropped at build time so nothing needs CAP_SETUID at runtime. The repo
  # already runs Trivy itself under --cap-drop=ALL in socket mode.
  hardening = {
    readonlyRootFilesystem = true

    linuxParameters = {
      capabilities = { drop = ["ALL"] }
      # Reaps zombies. Trivy shells out, and a read-only root makes an
      # orphaned child harder to notice.
      initProcessEnabled = true
    }

    dockerSecurityOptions = ["no-new-privileges:true"]

    # Trivy opens many layer files at once and uvicorn holds a socket per
    # WebSocket. The default soft limit of 1024 is the one that bites first.
    ulimits = [
      { name = "nofile", softLimit = 8192, hardLimit = 8192 },
    ]
  }

  # readonlyRootFilesystem needs somewhere to write, and linuxParameters.tmpfs
  # is EC2-only - on Fargate the only mechanism is a task-level volume backed
  # by ephemeral task storage. These are the first volumes in this stack.
  tmp_mount = [
    { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
  ]

  # Redis itself needs the password and nothing else. No reason for the cache
  # to hold the model key.
  #
  # The same secret twice, under two names, so the health check can use
  # redis-cli with NO arguments: redis-cli reads REDISCLI_AUTH by itself, which
  # keeps the token out of the probe's argv every 30 seconds.
  redis_secrets = [
    { name = "REDIS_PASSWORD", valueFrom = var.redis_secret_arn },
    { name = "REDISCLI_AUTH", valueFrom = var.redis_secret_arn },
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

  execution_role_arn = var.execution_app_role_arn
  task_role_arn      = var.task_worker_role_arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = var.worker_image
      essential = true

      # Already the image's uid; asserted here so an image regression
      # cannot silently promote this task to root.
      user = "1001"

      readonlyRootFilesystem = local.hardening.readonlyRootFilesystem
      linuxParameters        = local.hardening.linuxParameters
      dockerSecurityOptions  = local.hardening.dockerSecurityOptions
      ulimits                = local.hardening.ulimits

      mountPoints = local.tmp_mount

      environment = concat(local.common_environment, [
        # No Docker socket on Fargate, so app/scanners/ reads layer history out
        # of Trivy's own report instead of `docker history`.
        { name = "SCANNER_MODE", value = "registry" },
        # Defaults to .enrichment-cache relative to CWD, which is /app - and
        # /app is root-owned while the process is uid 1001, so the write has
        # always failed. kev.py swallows it in `except OSError`, so the CISA
        # catalog was silently re-downloaded on every scan instead of cached.
        { name = "ENRICHMENT_CACHE_DIR", value = "/tmp/enrichment-cache" },
        # Trivy respects TMPDIR for layer extraction scratch space. Explicit,
        # because the read-only root makes anywhere else fail.
        { name = "TMPDIR", value = "/tmp" },
      ])

      secrets = local.task_secrets

      # Same probe as worker/Dockerfile's own HEALTHCHECK - a real SQS call,
      # not just "the process is alive". langchain's import cost ruled out
      # anything that imports app.main.
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"from app.config.queue import SCAN_QUEUE_URL; from app.queue.producer import get_client; get_client().get_queue_attributes(QueueUrl=SCAN_QUEUE_URL, AttributeNames=['QueueArn'])\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 15
      }

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


  # Backs the /tmp mount. An empty volume block is ephemeral task storage,
  # which is the only writable-directory mechanism Fargate offers under
  # readonlyRootFilesystem - linuxParameters.tmpfs is EC2-only.
  volume {
    name = "tmp"
  }

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
    # task_definition too: CI registers a new revision per deploy and points
    # the service at it, so an apply that reset this would roll production
    # back to whatever var.image_tag happened to say.
    ignore_changes = [desired_count, task_definition]
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

  execution_role_arn = var.execution_app_role_arn
  task_role_arn      = var.task_api_role_arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = var.api_image
      essential = true

      # Already the image's uid; asserted here so an image regression
      # cannot silently promote this task to root.
      user = "1001"

      readonlyRootFilesystem = local.hardening.readonlyRootFilesystem
      linuxParameters        = local.hardening.linuxParameters
      dockerSecurityOptions  = local.hardening.dockerSecurityOptions
      ulimits                = local.hardening.ulimits

      mountPoints = local.tmp_mount

      portMappings = [{ containerPort = 8080, protocol = "tcp" }]

      environment = concat(local.common_environment, [
        # DEV_AUTH stays unset. /dev/token mints a valid token for any tenant,
        # and on this tier the task has a public IP.
        # The api image does not bake SCANNER_MODE and the default is "socket",
        # so the deployed API believed it had a Docker daemon: _socket_mode_only
        # did NOT 404 the upload and image routes as its comment claims, and
        # POST /images/upload 500'd on a permission error instead. See P4-4.
        { name = "SCANNER_MODE", value = "registry" },
        { name = "JWKS_URL", value = var.jwks_url },
        { name = "TOKEN_AUDIENCE", value = var.token_audience },
        # Without this, TOKEN_ISSUER falls back to the local dev issuer and
        # assert_production_auth() refuses to start the API. See AUDIT_02 F15.
        { name = "TOKEN_ISSUER", value = var.token_issuer },
        { name = "CORS_ORIGINS", value = var.cors_origins },
      ])

      secrets = local.task_secrets

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health').read()\" || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 5
      }

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


  # Backs the /tmp mount. An empty volume block is ephemeral task storage,
  # which is the only writable-directory mechanism Fargate offers under
  # readonlyRootFilesystem - linuxParameters.tmpfs is EC2-only.
  volume {
    name = "tmp"
  }

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
    # task_definition too: CI registers a new revision per deploy and points
    # the service at it, so an apply that reset this would roll production
    # back to whatever var.image_tag happened to say.
    ignore_changes = [desired_count, task_definition]
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

  execution_role_arn = var.execution_web_role_arn

  # No task role. The standalone Next server talks to nothing in AWS - the
  # browser calls the API directly, which is why NEXT_PUBLIC_API_URL has to be
  # host-reachable rather than a service name.
  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = var.frontend_image
      essential = true

      # Already the image's uid; asserted here so an image regression
      # cannot silently promote this task to root.
      user = "1001"

      readonlyRootFilesystem = local.hardening.readonlyRootFilesystem
      linuxParameters        = local.hardening.linuxParameters
      dockerSecurityOptions  = local.hardening.dockerSecurityOptions
      ulimits                = local.hardening.ulimits

      portMappings = [{ containerPort = 3000, protocol = "tcp" }]

      environment = [
        { name = "NODE_ENV", value = "production" },
        { name = "HOSTNAME", value = "0.0.0.0" },
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "node -e \"require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<400?0:1)).on('error',()=>process.exit(1))\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }

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
    # task_definition too: CI registers a new revision per deploy and points
    # the service at it, so an apply that reset this would roll production
    # back to whatever var.image_tag happened to say.
    ignore_changes = [desired_count, task_definition]
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
  execution_role_arn       = var.execution_redis_role_arn

  container_definitions = jsonencode([
    {
      name      = "redis"
      image     = "public.ecr.aws/docker/library/redis:7-alpine"
      essential = true

      readonlyRootFilesystem = local.hardening.readonlyRootFilesystem
      linuxParameters        = local.hardening.linuxParameters
      dockerSecurityOptions  = local.hardening.dockerSecurityOptions
      ulimits                = local.hardening.ulimits

      portMappings = [{ containerPort = 6379, protocol = "tcp" }]

      secrets = local.redis_secrets

      # 999 is the image's own `redis` user, and it is load-bearing rather than
      # hardening-for-its-own-sake: the image's docker-entrypoint.sh drops from
      # root to that user via setpriv, and the `sh -c` shim below REPLACES that
      # entrypoint - so without this, adding a password would have quietly
      # promoted Redis from uid 999 to root. Verified both ways in a container.
      #
      # Numeric, not "redis": a name has to resolve inside the image, and that
      # is a failure at task-start rather than at plan.
      user = "999"

      # The shim exists because `command` is stored in the task definition in
      # cleartext, so "--requirepass <token>" cannot be written literally
      # without undoing the point of Secrets Manager. The shell expands
      # $REDIS_PASSWORD from the injected secret at start. Bare $, not ${...} -
      # Terraform would interpolate the latter.
      #
      # No persistence and a hard cap. Progress events are transient, and an
      # unbounded Redis in a 512 MB task is an OOM waiting for a busy day.
      entryPoint = ["sh", "-c"]

      command = [
        join(" ", [
          "exec redis-server",
          "--requirepass \"$REDIS_PASSWORD\"",
          "--save ''",
          "--appendonly no",
          "--maxmemory 256mb",
          "--maxmemory-policy allkeys-lru",
        ])
      ]

      healthCheck = {
        # No -a flag: redis-cli picks the token up from REDISCLI_AUTH, so it
        # never reaches argv. grep rather than the exit code, because an
        # unauthenticated ping prints NOAUTH and relying on redis-cli's status
        # across error replies is not something a liveness probe should do.
        command     = ["CMD-SHELL", "redis-cli ping | grep -q PONG"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 5
      }

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
    subnets         = var.subnet_ids
    security_groups = var.security_group_ids

    # Was hardcoded true while the other three services read local.public.
    # Cosmetic today - this whole resource is count = local.public ? 1 : 0, so
    # it only exists when that is already true - but a hardcoded exception is
    # how the next person learns the wrong rule. See docs/audits/audit-01-backend.md P4-3.
    assign_public_ip = local.public
  }

  service_registries {
    registry_arn = aws_service_discovery_service.redis[0].arn
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = var.tags
}
