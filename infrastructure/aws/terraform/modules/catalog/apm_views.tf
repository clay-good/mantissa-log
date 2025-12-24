# APM (Application Performance Monitoring) Athena Views
# Pre-computed views for service maps, stats, and common APM queries

# ==============================================================================
# Service Map View
# ==============================================================================
# Shows service-to-service communication patterns derived from trace parent-child
# relationships. Used for dependency visualization and bottleneck identification.

resource "aws_athena_named_query" "apm_service_map_view" {
  name        = "create_apm_service_map_view"
  description = "Create view for service dependency map showing inter-service communication"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.name
  query       = <<-SQL
    CREATE OR REPLACE VIEW apm_service_map AS
    SELECT
      client.service_name AS source_service,
      server.service_name AS target_service,
      COUNT(*) AS call_count,
      SUM(CASE WHEN client.status = 'error' THEN 1 ELSE 0 END) AS error_count,
      CAST(SUM(CASE WHEN client.status = 'error' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) AS error_rate,
      AVG(client.duration_ms) AS avg_latency_ms,
      APPROX_PERCENTILE(client.duration_ms, 0.5) AS p50_latency_ms,
      APPROX_PERCENTILE(client.duration_ms, 0.95) AS p95_latency_ms,
      APPROX_PERCENTILE(client.duration_ms, 0.99) AS p99_latency_ms
    FROM apm_traces client
    INNER JOIN apm_traces server
      ON client.trace_id = server.trace_id
      AND client.span_id = server.parent_span_id
    WHERE client.kind = 'client'
      AND server.kind = 'server'
    GROUP BY client.service_name, server.service_name
  SQL
}

# ==============================================================================
# Service Statistics View
# ==============================================================================
# Aggregated service statistics showing request counts, error rates, and latencies
# for each service and operation combination.

resource "aws_athena_named_query" "apm_service_stats_view" {
  name        = "create_apm_service_stats_view"
  description = "Create view for service-level statistics including latency percentiles"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.name
  query       = <<-SQL
    CREATE OR REPLACE VIEW apm_service_stats AS
    SELECT
      service_name,
      operation_name,
      COUNT(*) AS request_count,
      SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_count,
      CAST(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) AS error_rate,
      AVG(duration_ms) AS avg_latency_ms,
      APPROX_PERCENTILE(duration_ms, 0.5) AS p50_latency_ms,
      APPROX_PERCENTILE(duration_ms, 0.95) AS p95_latency_ms,
      APPROX_PERCENTILE(duration_ms, 0.99) AS p99_latency_ms,
      MIN(start_time) AS first_seen,
      MAX(start_time) AS last_seen
    FROM apm_traces
    WHERE kind IN ('server', 'consumer')
    GROUP BY service_name, operation_name
  SQL
}

# ==============================================================================
# Slow Spans View
# ==============================================================================
# Identifies slow operations based on p95 latency threshold
# Useful for performance troubleshooting queries like "Why is X slow?"

resource "aws_athena_named_query" "apm_slow_spans_view" {
  name        = "create_apm_slow_spans_view"
  description = "Create view for identifying slow operations"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.name
  query       = <<-SQL
    CREATE OR REPLACE VIEW apm_slow_spans AS
    WITH service_baselines AS (
      SELECT
        service_name,
        operation_name,
        APPROX_PERCENTILE(duration_ms, 0.95) AS p95_baseline
      FROM apm_traces
      WHERE kind IN ('server', 'consumer')
        AND start_time >= date_add('day', -7, current_date)
      GROUP BY service_name, operation_name
    )
    SELECT
      t.trace_id,
      t.span_id,
      t.service_name,
      t.operation_name,
      t.duration_ms,
      t.start_time,
      t.status,
      t.attributes,
      b.p95_baseline,
      CAST(t.duration_ms AS DOUBLE) / NULLIF(b.p95_baseline, 0) AS slowness_ratio
    FROM apm_traces t
    JOIN service_baselines b
      ON t.service_name = b.service_name
      AND t.operation_name = b.operation_name
    WHERE t.duration_ms > b.p95_baseline
      AND t.kind IN ('server', 'consumer')
  SQL
}

# ==============================================================================
# Error Traces View
# ==============================================================================
# Pre-filters traces with errors for faster error analysis queries

resource "aws_athena_named_query" "apm_error_traces_view" {
  name        = "create_apm_error_traces_view"
  description = "Create view for error trace analysis"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.name
  query       = <<-SQL
    CREATE OR REPLACE VIEW apm_error_traces AS
    SELECT
      trace_id,
      span_id,
      parent_span_id,
      service_name,
      operation_name,
      status_message AS error_message,
      duration_ms,
      start_time,
      attributes,
      resource_deployment_environment AS environment
    FROM apm_traces
    WHERE status = 'error'
  SQL
}

# ==============================================================================
# Trace Summary View
# ==============================================================================
# Aggregates spans into trace-level summaries for high-level analysis

resource "aws_athena_named_query" "apm_trace_summary_view" {
  name        = "create_apm_trace_summary_view"
  description = "Create view for trace-level summaries"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.name
  query       = <<-SQL
    CREATE OR REPLACE VIEW apm_trace_summary AS
    SELECT
      trace_id,
      MIN(start_time) AS trace_start,
      MAX(end_time) AS trace_end,
      COUNT(*) AS span_count,
      COUNT(DISTINCT service_name) AS service_count,
      SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_span_count,
      ARRAY_AGG(DISTINCT service_name) AS services,
      MAX(duration_ms) AS total_duration_ms,
      -- Get root span info
      MAX(CASE WHEN parent_span_id IS NULL THEN service_name END) AS root_service,
      MAX(CASE WHEN parent_span_id IS NULL THEN operation_name END) AS root_operation
    FROM apm_traces
    GROUP BY trace_id
  SQL
}

# ==============================================================================
# Hourly Metrics Aggregation View
# ==============================================================================
# Pre-aggregates metrics by hour for dashboard queries

resource "aws_athena_named_query" "apm_metrics_hourly_view" {
  name        = "create_apm_metrics_hourly_view"
  description = "Create view for hourly metric aggregations"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.name
  query       = <<-SQL
    CREATE OR REPLACE VIEW apm_metrics_hourly AS
    SELECT
      service_name,
      name AS metric_name,
      metric_type,
      date_trunc('hour', from_iso8601_timestamp(timestamp)) AS hour,
      COUNT(*) AS sample_count,
      AVG(value) AS avg_value,
      MIN(value) AS min_value,
      MAX(value) AS max_value,
      APPROX_PERCENTILE(value, 0.5) AS p50_value,
      APPROX_PERCENTILE(value, 0.95) AS p95_value,
      APPROX_PERCENTILE(value, 0.99) AS p99_value
    FROM apm_metrics
    GROUP BY
      service_name,
      name,
      metric_type,
      date_trunc('hour', from_iso8601_timestamp(timestamp))
  SQL
}
