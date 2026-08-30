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
