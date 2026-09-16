# Three execution roles and two task roles where there were one of each. Every
# one of these ARNs also has to reach module.cicd's iam:PassRole list, or
# RegisterTaskDefinition fails in the deploy pipeline with an opaque denial.

output "execution_app_role_arn" {
  value = aws_iam_role.execution_app.arn
}

output "execution_redis_role_arn" {
  value = aws_iam_role.execution_redis.arn
}

output "execution_web_role_arn" {
  value = aws_iam_role.execution_web.arn
}

output "task_worker_role_arn" {
  value = aws_iam_role.task_worker.arn
}

output "task_api_role_arn" {
  value = aws_iam_role.task_api.arn
}

# Every role this module makes, for the deploy role's PassRole scope. Derived
# rather than hand-listed, so adding a role cannot silently break the deploy.
output "all_role_arns" {
  value = [
    aws_iam_role.execution_app.arn,
    aws_iam_role.execution_redis.arn,
    aws_iam_role.execution_web.arn,
    aws_iam_role.task_worker.arn,
    aws_iam_role.task_api.arn,
  ]
}
