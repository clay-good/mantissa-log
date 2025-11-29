/**
 * BigQuery Table Definitions for GCP Cloud Logging
 *
 * Comprehensive table schemas for GCP Cloud Logging data including
 * Audit Logs, VPC Flow Logs, Firewall Logs, GKE Audit Logs, and Data Access Logs
 */

# Normalized GCP Audit Logs table (ECS format)
resource "google_bigquery_table" "gcp_audit_normalized" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_audit_normalized"

  description = "Normalized GCP Audit Logs in ECS format"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp (ECS @timestamp)"
    },
    {
      name        = "event_action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Event action (ECS event.action)"
    },
    {
      name        = "event_category"
      type        = "STRING"
      mode        = "REPEATED"
      description = "Event category array (ECS event.category)"
    },
    {
      name        = "event_outcome"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Event outcome: success, failure (ECS event.outcome)"
    },
    {
      name        = "event_type"
      type        = "STRING"
      mode        = "REPEATED"
      description = "Event type array (ECS event.type)"
    },
    {
      name        = "user_email"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "User email (ECS user.email)"
    },
    {
      name        = "user_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "User name (ECS user.name)"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address (ECS source.ip)"
    },
    {
      name        = "user_agent"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "User agent string (ECS user_agent.original)"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Cloud provider: gcp (ECS cloud.provider)"
    },
    {
      name        = "cloud_project"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GCP project ID (ECS cloud.project.id)"
    },
    {
      name        = "cloud_region"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GCP region (ECS cloud.region)"
    },
    {
      name        = "resource_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource name"
    },
    {
      name        = "resource_type"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource type"
    },
    {
      name        = "gcp"
      type        = "RECORD"
      mode        = "NULLABLE"
      description = "GCP-specific audit log fields"
      fields = [
        {
          name = "audit"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "service_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "method_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "resource_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "num_response_items"
              type = "INTEGER"
              mode = "NULLABLE"
            },
            {
              name = "service_account_key_name"
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
        },
        {
          name = "request"
          type = "STRING"
          mode = "NULLABLE"
          description = "Request payload as JSON string"
        },
        {
          name = "response"
          type = "STRING"
          mode = "NULLABLE"
          description = "Response payload as JSON string"
        }
      ]
    },
    {
      name        = "raw"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Original raw log event"
    },
    {
      name        = "log_type"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Log type classification"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["event_action", "user_email", "log_type"]

  labels = local.common_labels
}

# Raw GCP Audit Logs table
resource "google_bigquery_table" "gcp_audit_raw" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_audit_raw"

  description = "Raw GCP Audit Logs from Cloud Logging API"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "severity"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Log severity level"
    },
    {
      name        = "logName"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Full log name"
    },
    {
      name        = "protoPayload"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Audit log payload as JSON string"
    },
    {
      name        = "resource"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource information as JSON string"
    },
    {
      name        = "insertId"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Unique entry identifier"
    },
    {
      name        = "labels"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Labels as JSON string"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["severity", "logName"]

  labels = local.common_labels
}

# Normalized GCP VPC Flow Logs table
resource "google_bigquery_table" "gcp_vpc_flow_normalized" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_vpc_flow_normalized"

  description = "Normalized GCP VPC Flow Logs in ECS format"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Flow record timestamp"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address (ECS source.ip)"
    },
    {
      name        = "source_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Source port (ECS source.port)"
    },
    {
      name        = "destination_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Destination IP address (ECS destination.ip)"
    },
    {
      name        = "destination_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Destination port (ECS destination.port)"
    },
    {
      name        = "network_transport"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Protocol: tcp, udp, icmp (ECS network.transport)"
    },
    {
      name        = "network_bytes"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Total bytes transferred (ECS network.bytes)"
    },
    {
      name        = "network_packets"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Total packets transferred (ECS network.packets)"
    },
    {
      name        = "event_action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Flow action: accept, deny"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Cloud provider: gcp"
    },
    {
      name        = "cloud_project"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GCP project ID"
    },
    {
      name        = "gcp"
      type        = "RECORD"
      mode        = "NULLABLE"
      description = "GCP-specific VPC flow fields"
      fields = [
        {
          name = "vpc_flow"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "reporter"
              type = "STRING"
              mode = "NULLABLE"
              description = "SRC or DEST"
            },
            {
              name = "rtt_msec"
              type = "INTEGER"
              mode = "NULLABLE"
              description = "Round-trip time in milliseconds"
            },
            {
              name = "vpc_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "subnetwork_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "src_instance"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "dest_instance"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        }
      ]
    },
    {
      name        = "raw"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Original raw log event"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["source_ip", "destination_ip", "event_action"]

  labels = local.common_labels
}

# Raw GCP VPC Flow Logs table
resource "google_bigquery_table" "gcp_vpc_flow_raw" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_vpc_flow_raw"

  description = "Raw GCP VPC Flow Logs"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Flow record timestamp"
    },
    {
      name        = "jsonPayload"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Flow log payload as JSON string"
    },
    {
      name        = "resource"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource information as JSON string"
    },
    {
      name        = "insertId"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Unique entry identifier"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  labels = local.common_labels
}

# Normalized GCP Firewall Logs table
resource "google_bigquery_table" "gcp_firewall_normalized" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_firewall_normalized"

  description = "Normalized GCP Firewall Logs in ECS format"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "event_action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Firewall action: allowed, denied"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address"
    },
    {
      name        = "source_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Source port"
    },
    {
      name        = "destination_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Destination IP address"
    },
    {
      name        = "destination_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Destination port"
    },
    {
      name        = "network_transport"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Protocol: tcp, udp, icmp"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Cloud provider: gcp"
    },
    {
      name        = "cloud_project"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GCP project ID"
    },
    {
      name        = "gcp"
      type        = "RECORD"
      mode        = "NULLABLE"
      description = "GCP-specific firewall fields"
      fields = [
        {
          name = "firewall"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "disposition"
              type = "STRING"
              mode = "NULLABLE"
              description = "ALLOWED or DENIED"
            },
            {
              name = "rule_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "rule_direction"
              type = "STRING"
              mode = "NULLABLE"
              description = "INGRESS or EGRESS"
            },
            {
              name = "rule_priority"
              type = "INTEGER"
              mode = "NULLABLE"
            },
            {
              name = "instance_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "vpc_name"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        }
      ]
    },
    {
      name        = "raw"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Original raw log event"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["event_action", "destination_port"]

  labels = local.common_labels
}

# Raw GCP Firewall Logs table
resource "google_bigquery_table" "gcp_firewall_raw" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_firewall_raw"

  description = "Raw GCP Firewall Logs"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "jsonPayload"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Firewall log payload as JSON string"
    },
    {
      name        = "resource"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource information as JSON string"
    },
    {
      name        = "insertId"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Unique entry identifier"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  labels = local.common_labels
}

# Normalized GKE Audit Logs table
resource "google_bigquery_table" "gcp_gke_audit_normalized" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_gke_audit_normalized"

  description = "Normalized GKE Audit Logs in ECS format"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "event_action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Kubernetes API action"
    },
    {
      name        = "event_outcome"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Event outcome: success, failure"
    },
    {
      name        = "user_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Kubernetes user or service account"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address"
    },
    {
      name        = "user_agent"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "User agent (kubectl, etc.)"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Cloud provider: gcp"
    },
    {
      name        = "cloud_project"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GCP project ID"
    },
    {
      name        = "gcp"
      type        = "RECORD"
      mode        = "NULLABLE"
      description = "GCP-specific GKE fields"
      fields = [
        {
          name = "gke"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "cluster_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "namespace"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "resource_type"
              type = "STRING"
              mode = "NULLABLE"
              description = "pods, deployments, secrets, etc."
            },
            {
              name = "resource_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "verb"
              type = "STRING"
              mode = "NULLABLE"
              description = "get, create, update, delete, patch"
            },
            {
              name = "method_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "authorization_decision"
              type = "STRING"
              mode = "NULLABLE"
            }
          ]
        }
      ]
    },
    {
      name        = "raw"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Original raw log event"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["event_action", "user_name"]

  labels = local.common_labels
}

# Raw GKE Audit Logs table
resource "google_bigquery_table" "gcp_gke_audit_raw" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_gke_audit_raw"

  description = "Raw GKE Audit Logs"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "protoPayload"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GKE audit log payload as JSON string"
    },
    {
      name        = "resource"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource information as JSON string"
    },
    {
      name        = "insertId"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Unique entry identifier"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  labels = local.common_labels
}

# Normalized GCP Data Access Logs table
resource "google_bigquery_table" "gcp_data_access_normalized" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_data_access_normalized"

  description = "Normalized GCP Data Access Logs in ECS format"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "event_action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Data access action"
    },
    {
      name        = "event_outcome"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Event outcome: success, failure"
    },
    {
      name        = "user_email"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "User email"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Cloud provider: gcp"
    },
    {
      name        = "cloud_project"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "GCP project ID"
    },
    {
      name        = "gcp"
      type        = "RECORD"
      mode        = "NULLABLE"
      description = "GCP-specific data access fields"
      fields = [
        {
          name = "data_access"
          type = "RECORD"
          mode = "NULLABLE"
          fields = [
            {
              name = "service_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "method_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "resource_name"
              type = "STRING"
              mode = "NULLABLE"
            },
            {
              name = "num_response_items"
              type = "INTEGER"
              mode = "NULLABLE"
            },
            {
              name = "is_sensitive"
              type = "BOOLEAN"
              mode = "NULLABLE"
              description = "Whether data access involved sensitive resources"
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
      name        = "raw"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Original raw log event"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["event_action", "user_email"]

  labels = local.common_labels
}

# Raw GCP Data Access Logs table
resource "google_bigquery_table" "gcp_data_access_raw" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "gcp_data_access_raw"

  description = "Raw GCP Data Access Logs"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "protoPayload"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Data access log payload as JSON string"
    },
    {
      name        = "resource"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Resource information as JSON string"
    },
    {
      name        = "insertId"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Unique entry identifier"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  labels = local.common_labels
}
