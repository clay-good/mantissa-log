# Network Security Glue Tables
# Stores normalized network flow, DNS query, and firewall event data
# across multi-cloud (AWS, GCP, Azure) and on-prem sources

# ==============================================================================
# Network Flows Table
# ==============================================================================
# Normalized network flow records from VPC Flow Logs, NSG Flow Logs,
# Zeek connection logs, and Suricata flow records

resource "aws_glue_catalog_table" "network_flows" {
  name          = "network_flows"
  database_name = aws_glue_catalog_database.main.name
  description   = "Normalized network flow records from multi-cloud and on-prem sources. Includes VPC Flow Logs, NSG Flow Logs, Zeek connection logs, and Suricata flow records."

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/network_flows/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "ISO 8601 event timestamp"
    }

    columns {
      name    = "source_ip"
      type    = "string"
      comment = "Source IP address"
    }

    columns {
      name    = "destination_ip"
      type    = "string"
      comment = "Destination IP address"
    }

    columns {
      name    = "source_port"
      type    = "int"
      comment = "Source port number"
    }

    columns {
      name    = "destination_port"
      type    = "int"
      comment = "Destination port number"
    }

    columns {
      name    = "protocol"
      type    = "string"
      comment = "Network protocol: tcp, udp, icmp"
    }

    columns {
      name    = "bytes_sent"
      type    = "bigint"
      comment = "Total bytes sent from source to destination"
    }

    columns {
      name    = "bytes_received"
      type    = "bigint"
      comment = "Total bytes received from destination"
    }

    columns {
      name    = "packets_sent"
      type    = "int"
      comment = "Total packets sent from source to destination"
    }

    columns {
      name    = "packets_received"
      type    = "int"
      comment = "Total packets received from destination"
    }

    columns {
      name    = "duration_seconds"
      type    = "double"
      comment = "Duration of the flow in seconds"
    }

    columns {
      name    = "action"
      type    = "string"
      comment = "Flow action: accept, reject, allow, deny, drop"
    }

    columns {
      name    = "direction"
      type    = "string"
      comment = "Traffic direction: inbound, outbound"
    }

    columns {
      name    = "tcp_flags"
      type    = "array<string>"
      comment = "TCP flags observed during the flow"
    }

    columns {
      name    = "conn_state"
      type    = "string"
      comment = "Zeek-style connection state (e.g., SF, S0, REJ)"
    }

    columns {
      name    = "cloud_provider"
      type    = "string"
      comment = "Originating cloud: aws, gcp, azure, on_prem"
    }

    columns {
      name    = "source_type"
      type    = "string"
      comment = "Log source type: vpc_flow, nsg_flow, zeek_conn, suricata_flow"
    }

    columns {
      name    = "vpc_id"
      type    = "string"
      comment = "VPC or VNet identifier"
    }

    columns {
      name    = "subnet_id"
      type    = "string"
      comment = "Subnet identifier"
    }

    columns {
      name    = "instance_id"
      type    = "string"
      comment = "Compute instance identifier"
    }

    columns {
      name    = "is_internal"
      type    = "boolean"
      comment = "Whether the flow is internal (RFC 1918 on both ends)"
    }

    columns {
      name    = "aws_service"
      type    = "string"
      comment = "AWS service name if applicable (nullable)"
    }

    columns {
      name    = "flow_direction"
      type    = "string"
      comment = "Flow direction classification"
    }

    columns {
      name    = "metadata"
      type    = "string"
      comment = "Additional metadata as JSON blob"
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
# DNS Queries Table
# ==============================================================================
# Normalized DNS query and response records from Route 53 resolver logs,
# GCP Cloud DNS, Azure DNS, Zeek DNS, and Suricata DNS logs

resource "aws_glue_catalog_table" "dns_queries" {
  name          = "dns_queries"
  database_name = aws_glue_catalog_database.main.name
  description   = "Normalized DNS query and response records from multi-cloud and network sensor sources. Includes entropy and label count fields for DNS tunneling detection."

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/dns_queries/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "ISO 8601 event timestamp"
    }

    columns {
      name    = "source_ip"
      type    = "string"
      comment = "IP address of the DNS client"
    }

    columns {
      name    = "query_name"
      type    = "string"
      comment = "Queried domain name (FQDN)"
    }

    columns {
      name    = "query_type"
      type    = "string"
      comment = "DNS query type: A, AAAA, CNAME, TXT, MX, SRV, etc."
    }

    columns {
      name    = "response_code"
      type    = "string"
      comment = "DNS response code: NOERROR, NXDOMAIN, SERVFAIL, etc."
    }

    columns {
      name    = "resolved_ips"
      type    = "array<string>"
      comment = "IP addresses returned in the DNS response"
    }

    columns {
      name    = "is_nxdomain"
      type    = "boolean"
      comment = "Whether the response was NXDOMAIN (non-existent domain)"
    }

    columns {
      name    = "subdomain_entropy"
      type    = "double"
      comment = "Shannon entropy of the subdomain portion for tunneling detection"
    }

    columns {
      name    = "subdomain_label_count"
      type    = "int"
      comment = "Number of labels in the subdomain portion"
    }

    columns {
      name    = "transport"
      type    = "string"
      comment = "DNS transport protocol: udp, tcp"
    }

    columns {
      name    = "cloud_provider"
      type    = "string"
      comment = "Originating cloud: aws, gcp, azure, on_prem"
    }

    columns {
      name    = "source_type"
      type    = "string"
      comment = "Log source type: route53, gcp_cloud_dns, azure_dns, zeek_dns, suricata_dns"
    }

    columns {
      name    = "vpc_id"
      type    = "string"
      comment = "VPC or VNet identifier"
    }

    columns {
      name    = "ttl_values"
      type    = "array<int>"
      comment = "TTL values from the DNS response records"
    }

    columns {
      name    = "answers_count"
      type    = "int"
      comment = "Number of answers in the DNS response"
    }

    columns {
      name    = "metadata"
      type    = "string"
      comment = "Additional metadata as JSON blob"
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
# Firewall Events Table
# ==============================================================================
# Normalized firewall rule match and threat detection events from
# AWS Network Firewall, GCP Firewall, Azure Firewall, and Suricata alerts

resource "aws_glue_catalog_table" "firewall_events" {
  name          = "firewall_events"
  database_name = aws_glue_catalog_database.main.name
  description   = "Normalized firewall rule match and threat detection events from multi-cloud firewalls and Suricata IDS/IPS alerts."

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/firewall_events/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "ISO 8601 event timestamp"
    }

    columns {
      name    = "source_ip"
      type    = "string"
      comment = "Source IP address"
    }

    columns {
      name    = "destination_ip"
      type    = "string"
      comment = "Destination IP address"
    }

    columns {
      name    = "source_port"
      type    = "int"
      comment = "Source port number"
    }

    columns {
      name    = "destination_port"
      type    = "int"
      comment = "Destination port number"
    }

    columns {
      name    = "protocol"
      type    = "string"
      comment = "Network protocol: tcp, udp, icmp"
    }

    columns {
      name    = "action"
      type    = "string"
      comment = "Firewall action: allow, deny, drop, alert"
    }

    columns {
      name    = "firewall_rule_name"
      type    = "string"
      comment = "Name or ID of the matched firewall rule"
    }

    columns {
      name    = "direction"
      type    = "string"
      comment = "Traffic direction: inbound, outbound"
    }

    columns {
      name    = "threat_category"
      type    = "string"
      comment = "Threat category from IDS/IPS detection (nullable)"
    }

    columns {
      name    = "signature_id"
      type    = "string"
      comment = "IDS/IPS signature ID that triggered the event (nullable)"
    }

    columns {
      name    = "signature_name"
      type    = "string"
      comment = "IDS/IPS signature name or description (nullable)"
    }

    columns {
      name    = "cloud_provider"
      type    = "string"
      comment = "Originating cloud: aws, gcp, azure, on_prem"
    }

    columns {
      name    = "source_type"
      type    = "string"
      comment = "Log source type: aws_network_firewall, gcp_firewall, azure_firewall, suricata_alert"
    }

    columns {
      name    = "metadata"
      type    = "string"
      comment = "Additional metadata as JSON blob"
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
