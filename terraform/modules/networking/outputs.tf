output "vpc_id" {
  value = aws_vpc.main.id
}

# The learning tier runs tasks in public subnets with a closed security group.
# That is not the same as a private subnet: a security group mistake here
# exposes the task, whereas the same mistake in a private subnet exposes
# nothing. Right while learning, wrong to keep.
output "task_subnet_ids" {
  value = var.tier == "production" ? aws_subnet.private[*].id : aws_subnet.public[*].id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "task_security_group_id" {
  value = aws_security_group.task.id
}

output "service_namespace_id" {
  value = aws_service_discovery_private_dns_namespace.main.id
}

output "service_namespace_name" {
  value = aws_service_discovery_private_dns_namespace.main.name
}
