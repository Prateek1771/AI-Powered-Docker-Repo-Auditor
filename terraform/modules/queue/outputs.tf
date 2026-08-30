output "scan_queue_url" {
  value = aws_sqs_queue.scan.url
}

output "scan_queue_arn" {
  value = aws_sqs_queue.scan.arn
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}
