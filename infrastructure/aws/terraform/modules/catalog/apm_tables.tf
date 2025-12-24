# APM (Application Performance Monitoring) Glue Tables
# Stores OpenTelemetry metrics and traces for observability queries

# ==============================================================================
# APM Metrics Table
# ==============================================================================
# Stores metric data from OpenTelemetry instrumentation
# Supports gauges, counters, histograms, and summaries

resource "aws_glue_catalog_table" "apm_metrics" {
  name          = "apm_metrics"
  database_name = aws_glue_catalog_database.main.name
  description   = "Application metrics from OpenTelemetry instrumentation. Includes gauges, counters, histograms, and summaries."

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"         = "json"
    "compressionType"        = "gzip"
    "typeOfData"             = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/apm/metrics/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "apm-metrics-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "true"
      }
    }

    # Core metric fields
    columns {
      name    = "event_id"
      type    = "string"
      comment = "Unique identifier for this metric event"
    }

    columns {
      name    = "name"
      type    = "string"
      comment = "Metric name (e.g., http.server.duration, process.cpu.utilization)"
    }

    columns {
      name    = "value"
      type    = "double"
      comment = "Metric value"
    }

    columns {
      name    = "metric_type"
      type    = "string"
      comment = "Type of metric: gauge, counter, histogram, summary"
    }

    columns {
      name    = "unit"
      type    = "string"
      comment = "Unit of measurement (ms, bytes, 1 for counts)"
    }

    columns {
      name    = "labels"
      type    = "map<string,string>"
      comment = "Dimension labels for filtering and grouping"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "When the metric was recorded (ISO 8601)"
    }

    # Resource attributes
    columns {
      name    = "service_name"
      type    = "string"
      comment = "Name of the service emitting this metric"
    }

    columns {
      name    = "service_version"
      type    = "string"
      comment = "Version of the service"
    }

    columns {
      name    = "host_name"
      type    = "string"
      comment = "Hostname where the service is running"
    }

    columns {
      name    = "deployment_environment"
      type    = "string"
      comment = "Environment: production, staging, development"
    }

    # Histogram-specific fields
    columns {
      name    = "bucket_counts"
      type    = "array<bigint>"
      comment = "Histogram bucket counts"
    }

    columns {
      name    = "bucket_boundaries"
      type    = "array<double>"
      comment = "Histogram bucket boundaries"
    }

    # Summary-specific fields
    columns {
      name    = "quantile_values"
      type    = "map<double,double>"
      comment = "Pre-calculated quantile values (e.g., 0.5: 100, 0.99: 500)"
    }

    columns {
      name    = "description"
      type    = "string"
      comment = "Human-readable description of the metric"
    }
  }

  partition_keys {
    name = "year"
    type = "string"
  }

  partition_keys {
    name = "month"
    type = "string"
  }

  partition_keys {
    name = "day"
    type = "string"
  }

  partition_keys {
    name = "hour"
    type = "string"
  }
}

# ==============================================================================
# APM Traces Table
# ==============================================================================
# Stores span data from distributed traces
# Each row is a single span; use trace_id to correlate spans

resource "aws_glue_catalog_table" "apm_traces" {
  name          = "apm_traces"
  database_name = aws_glue_catalog_database.main.name
  description   = "Distributed trace spans from OpenTelemetry. Each row is a span; use trace_id to correlate and parent_span_id to build trace trees."

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"         = "json"
    "compressionType"        = "gzip"
    "typeOfData"             = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/apm/traces/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "apm-traces-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "true"
      }
    }

    # Core span identification
    columns {
      name    = "event_id"
      type    = "string"
      comment = "Unique identifier for this span event"
    }

    columns {
      name    = "trace_id"
      type    = "string"
      comment = "Unique identifier for the entire trace (32 hex chars)"
    }

    columns {
      name    = "span_id"
      type    = "string"
      comment = "Unique identifier for this span (16 hex chars)"
    }

    columns {
      name    = "parent_span_id"
      type    = "string"
      comment = "Parent span ID if this is a child span (null for root spans)"
    }

    # Span metadata
    columns {
      name    = "operation_name"
      type    = "string"
      comment = "Name of the operation (e.g., GET /api/users, process_order)"
    }

    columns {
      name    = "service_name"
      type    = "string"
      comment = "Name of the service that emitted this span"
    }

    columns {
      name    = "kind"
      type    = "string"
      comment = "Span kind: client, server, internal, producer, consumer"
    }

    columns {
      name    = "status"
      type    = "string"
      comment = "Span status: ok, error, unset"
    }

    columns {
      name    = "status_message"
      type    = "string"
      comment = "Error message if status is error"
    }

    # Timing
    columns {
      name    = "start_time"
      type    = "string"
      comment = "When the span started (ISO 8601)"
    }

    columns {
      name    = "end_time"
      type    = "string"
      comment = "When the span ended (ISO 8601)"
    }

    columns {
      name    = "duration_ms"
      type    = "bigint"
      comment = "Span duration in milliseconds"
    }

    # Span data
    columns {
      name    = "attributes"
      type    = "map<string,string>"
      comment = "Span attributes (tags) for filtering"
    }

    columns {
      name    = "events"
      type    = "array<struct<name:string,timestamp:string,attributes:map<string,string>>>"
      comment = "Span events (logs within the span)"
    }

    columns {
      name    = "links"
      type    = "array<struct<trace_id:string,span_id:string>>"
      comment = "Links to other traces/spans"
    }

    # Resource attributes
    columns {
      name    = "resource_service_version"
      type    = "string"
      comment = "Version of the service"
    }

    columns {
      name    = "resource_host_name"
      type    = "string"
      comment = "Hostname where the service is running"
    }

    columns {
      name    = "resource_deployment_environment"
      type    = "string"
      comment = "Environment: production, staging, development"
    }
  }

  partition_keys {
    name = "year"
    type = "string"
  }

  partition_keys {
    name = "month"
    type = "string"
  }

  partition_keys {
    name = "day"
    type = "string"
  }

  partition_keys {
    name = "hour"
    type = "string"
  }
}
