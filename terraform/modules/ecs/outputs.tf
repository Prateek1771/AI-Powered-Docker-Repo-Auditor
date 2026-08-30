output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "worker_service_name" {
  value = aws_ecs_service.worker.name
}

output "api_service_name" {
  value = aws_ecs_service.api.name
}

output "frontend_service_name" {
  value = aws_ecs_service.frontend.name
}

output "cluster_arn" {
  value = aws_ecs_cluster.main.arn
}
