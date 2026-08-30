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
