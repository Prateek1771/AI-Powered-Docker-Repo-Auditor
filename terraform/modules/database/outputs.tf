output "jobs_table_name" {
  value = aws_dynamodb_table.jobs.name
}

output "results_table_name" {
  value = aws_dynamodb_table.results.name
}

output "jobs_table_arn" {
  value = aws_dynamodb_table.jobs.arn
}

output "results_table_arn" {
  value = aws_dynamodb_table.results.arn
}
