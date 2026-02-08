/**
 * BigQuery Table Definitions for Network Security Events
 *
 * Tables for normalized network flow records, DNS query logs,
 * and firewall/IDS events across all cloud providers.
 */

# Network flow records (VPC flow logs, Zeek conn, Suricata flow)
resource "google_bigquery_table" "network_flows" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "network_flows"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address"
    },
    {
      name        = "destination_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Destination IP address"
    },
    {
      name        = "source_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Source port number"
    },
    {
      name        = "destination_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Destination port number"
    },
    {
      name        = "protocol"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Network protocol (tcp, udp, icmp)"
    },
    {
      name        = "bytes_sent"
      type        = "INT64"
      mode        = "NULLABLE"
      description = "Total bytes sent"
    },
    {
      name        = "bytes_received"
      type        = "INT64"
      mode        = "NULLABLE"
      description = "Total bytes received"
    },
    {
      name        = "packets_sent"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Total packets sent"
    },
    {
      name        = "packets_received"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Total packets received"
    },
    {
      name        = "duration_seconds"
      type        = "FLOAT64"
      mode        = "NULLABLE"
      description = "Flow duration in seconds"
    },
    {
      name        = "action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Flow action (accept, reject, allow, deny, drop)"
    },
    {
      name        = "direction"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Traffic direction (inbound, outbound)"
    },
    {
      name        = "tcp_flags"
      type        = "STRING"
      mode        = "REPEATED"
      description = "Array of TCP flag names"
    },
    {
      name        = "conn_state"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Zeek connection state codes"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Originating cloud provider (aws, gcp, azure, on_prem)"
    },
    {
      name        = "source_type"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Log source type (vpc_flow, nsg_flow, zeek_conn, suricata_flow)"
    },
    {
      name        = "vpc_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "VPC or virtual network identifier"
    },
    {
      name        = "subnet_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Subnet identifier"
    },
    {
      name        = "instance_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Compute instance identifier"
    },
    {
      name        = "is_internal"
      type        = "BOOLEAN"
      mode        = "NULLABLE"
      description = "Whether the flow is internal to the network"
    },
    {
      name        = "aws_service"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "AWS service name if traffic involves an AWS service"
    },
    {
      name        = "flow_direction"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Flow direction indicator"
    },
    {
      name        = "metadata"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Additional metadata as JSON blob"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["source_ip", "destination_ip", "source_type", "cloud_provider"]

  labels = local.common_labels
}

# DNS query logs (Route 53, Cloud DNS, Azure DNS, Zeek DNS, Suricata DNS)
resource "google_bigquery_table" "dns_queries" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "dns_queries"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "IP address of the DNS client"
    },
    {
      name        = "query_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "DNS query domain name"
    },
    {
      name        = "query_type"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "DNS query type (A, AAAA, CNAME, TXT, MX, SRV, etc.)"
    },
    {
      name        = "response_code"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "DNS response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)"
    },
    {
      name        = "resolved_ips"
      type        = "STRING"
      mode        = "REPEATED"
      description = "Array of resolved IP addresses"
    },
    {
      name        = "is_nxdomain"
      type        = "BOOLEAN"
      mode        = "NULLABLE"
      description = "Whether the response was NXDOMAIN"
    },
    {
      name        = "subdomain_entropy"
      type        = "FLOAT64"
      mode        = "NULLABLE"
      description = "Shannon entropy of subdomain labels for DGA detection"
    },
    {
      name        = "subdomain_label_count"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Number of subdomain labels"
    },
    {
      name        = "transport"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "DNS transport protocol (udp, tcp)"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Originating cloud provider"
    },
    {
      name        = "source_type"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Log source type (route53, gcp_cloud_dns, azure_dns, zeek_dns, suricata_dns)"
    },
    {
      name        = "vpc_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "VPC or virtual network identifier"
    },
    {
      name        = "ttl_values"
      type        = "INTEGER"
      mode        = "REPEATED"
      description = "Array of TTL values from DNS responses"
    },
    {
      name        = "answers_count"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Number of answers in the DNS response"
    },
    {
      name        = "metadata"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Additional metadata as JSON blob"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["query_name", "source_ip", "source_type"]

  labels = local.common_labels
}

# Firewall and IDS/IPS events (AWS Network Firewall, GCP Firewall, Azure Firewall, Suricata alerts)
resource "google_bigquery_table" "firewall_events" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "firewall_events"

  schema = jsonencode([
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp"
    },
    {
      name        = "source_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Source IP address"
    },
    {
      name        = "destination_ip"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Destination IP address"
    },
    {
      name        = "source_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Source port number"
    },
    {
      name        = "destination_port"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Destination port number"
    },
    {
      name        = "protocol"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Network protocol"
    },
    {
      name        = "action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Firewall action (allow, deny, drop, alert)"
    },
    {
      name        = "firewall_rule_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Name of the firewall rule that matched"
    },
    {
      name        = "direction"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Traffic direction"
    },
    {
      name        = "threat_category"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Threat or attack category from IDS/IPS"
    },
    {
      name        = "signature_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "IDS/IPS signature identifier"
    },
    {
      name        = "signature_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "IDS/IPS signature name or description"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Originating cloud provider"
    },
    {
      name        = "source_type"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Log source type (aws_network_firewall, gcp_firewall, azure_firewall, suricata_alert)"
    },
    {
      name        = "metadata"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Additional metadata as JSON blob"
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["source_ip", "destination_ip", "action", "source_type"]

  labels = local.common_labels
}
