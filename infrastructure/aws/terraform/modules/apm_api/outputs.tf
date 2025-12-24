output "otlp_metrics_route_id" {
  description = "Route ID for OTLP metrics endpoint"
  value       = aws_apigatewayv2_route.otlp_metrics.id
}

output "otlp_traces_route_id" {
  description = "Route ID for OTLP traces endpoint"
  value       = aws_apigatewayv2_route.otlp_traces.id
}

output "service_map_route_id" {
  description = "Route ID for service map endpoint"
  value       = aws_apigatewayv2_route.service_map.id
}

output "services_list_route_id" {
  description = "Route ID for services list endpoint"
  value       = aws_apigatewayv2_route.services_list.id
}

output "otlp_endpoint" {
  description = "Base endpoint for OTLP ingestion"
  value       = "/v1"
}

output "apm_api_endpoint" {
  description = "Base endpoint for APM API"
  value       = "/api/apm"
}
