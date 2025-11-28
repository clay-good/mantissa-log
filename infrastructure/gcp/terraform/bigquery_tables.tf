/**
 * BigQuery Table Definitions for GCP Logs
 */

# Cloud Audit Logs table
resource "google_bigquery_table" "audit_logs" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "audit_logs"

  schema = jsonencode([
    {
      name = "timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name = "severity"
      type = "STRING"
      mode = "NULLABLE"
      description = "Log severity level"
    },
    {
      name = "protoPayload"
      type = "RECORD"
      mode = "NULLABLE"
      description = "Audit log payload"
      fields = [
        {
          name = "serviceName"
          type = "STRING"
          mode = "NULLABLE"
        },
        {
          name = "methodName"
          type = "STRING"
          mode = "NULLABLE"
        },
        {
          name = "resourceName"
          type = "STRING"
          mode = "NULLABLE"
        },
        {
          name = "authenticationInfo"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "principalEmail"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "serviceAccountKeyName"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        },
        {
          name = "authorizationInfo"
          type = "RECORD"
          mode = "REPEATED"
          fields = [
            {
              name = "permission"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "granted"
              type = "BOOLEAN"
              mode = "NULLABLE"
            },
            {
              name = "resource"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        },
        {
          name = "requestMetadata"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "callerIp"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "callerSuppliedUserAgent"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        },
        {
          name = "status"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "code"
              type = "INTEGER"
              mode = "NULLABLE"
            },
            {
              name = "message"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        }
      ]
    },
    {
      name = "resource"
      type = "RECORD"
      mode = "NULLABLE"
      description = "Resource information"
      fields = [
        {
          name = "type"
          type = "STRING"
          mode = "NULLABLE"
        },
        {
          name = "labels"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "project_id"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        }
      ]
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["severity", "protoPayload.serviceName"]

  labels = local.common_labels
}

# VPC Flow Logs table
resource "google_bigquery_table" "vpc_flow_logs" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "vpc_flow_logs"

  schema = jsonencode([
    {
      name = "timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
      description = "Flow record timestamp"
    },
    {
      name = "jsonPayload"
      type = "RECORD"
      mode = "NULLABLE"
      description = "Flow log payload"
      fields = [
        {
          name = "connection"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "src_ip"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "dest_ip"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "src_port"
              type = "INTEGER"
              mode = "NULLABLE"
            },
            {
              name = "dest_port"
              type = "INTEGER"
              mode = "NULLABLE"
            },
            {
              name = "protocol"
              type = "INTEGER"
              mode = "NULLABLE"
            }
          ]
        },
        {
          name = "packets_sent"
          type = "INTEGER"
          mode = "NULLABLE"
        },
        {
          name = "bytes_sent"
          type = "INTEGER"
          mode = "NULLABLE"
        },
        {
          name = "rtt_msec"
          type = "INTEGER"
          mode = "NULLABLE"
        },
        {
          name = "reporter"
          type = "STRING"
          mode = "NULLABLE"
        }
      ]
    },
    {
      name = "resource"
      type = "RECORD"
      mode = "NULLABLE"
      description = "Resource information"
      fields = [
        {
          name = "type"
          type = "STRING"
          mode = "NULLABLE"
        },
        {
          name = "labels"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "project_id"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "subnetwork_name"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        }
      ]
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["jsonPayload.connection.src_ip", "jsonPayload.connection.dest_ip"]

  labels = local.common_labels
}

# External table for Cloud Storage logs (for SaaS sources like Okta, Google Workspace)
resource "google_bigquery_table" "external_logs" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "external_logs"

  external_data_configuration {
    autodetect    = true
    source_format = "NEWLINE_DELIMITED_JSON"

    source_uris = [
      "gs://${google_storage_bucket.logs.name}/*/normalized/*/*.json"
    ]

    hive_partitioning_options {
      mode              = "AUTO"
      source_uri_prefix = "gs://${google_storage_bucket.logs.name}/"
    }
  }

  labels = local.common_labels
}
