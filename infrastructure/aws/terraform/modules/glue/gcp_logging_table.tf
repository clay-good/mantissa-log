/**
 * AWS Glue Table Definitions for GCP Cloud Logging
 *
 * Creates tables for both raw and normalized GCP Cloud Logging entries including
 * Audit Logs, VPC Flow Logs, Firewall Logs, and GKE Audit Logs.
 */

# Raw GCP Cloud Logging Table
resource "aws_glue_catalog_table" "gcp_logging_raw" {
  name          = "gcp_logging_raw"
  database_name = var.glue_database_name
  description   = "Raw GCP Cloud Logging entries including Audit, VPC Flow, and Firewall logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/gcp_logging/raw/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "ignore.malformed.json" = "FALSE"
        "dots.in.keys"          = "TRUE"
        "case.insensitive"      = "TRUE"
      }
    }

    # Common Log Entry Fields
    columns {
      name    = "logname"
      type    = "string"
      comment = "Full resource name of the log"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "Timestamp when the event occurred (RFC3339)"
    }

    columns {
      name    = "receivetimestamp"
      type    = "string"
      comment = "Timestamp when the log was received"
    }

    columns {
      name    = "severity"
      type    = "string"
      comment = "Log severity (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY)"
    }

    columns {
      name    = "insertid"
      type    = "string"
      comment = "Unique identifier for the log entry"
    }

    columns {
      name    = "trace"
      type    = "string"
      comment = "Resource name of the trace"
    }

    columns {
      name    = "spanid"
      type    = "string"
      comment = "Span ID within the trace"
    }

    # Resource Fields
    columns {
      name    = "resource_type"
      type    = "string"
      comment = "Monitored resource type"
    }

    columns {
      name    = "resource_labels"
      type    = "string"
      comment = "Resource labels (JSON)"
    }

    columns {
      name    = "project_id"
      type    = "string"
      comment = "GCP project ID"
    }

    columns {
      name    = "location"
      type    = "string"
      comment = "Resource location (zone/region)"
    }

    # Audit Log Fields (protoPayload)
    columns {
      name    = "servicename"
      type    = "string"
      comment = "API service name"
    }

    columns {
      name    = "methodname"
      type    = "string"
      comment = "API method name"
    }

    columns {
      name    = "resourcename"
      type    = "string"
      comment = "Resource being accessed"
    }

    columns {
      name    = "principalemail"
      type    = "string"
      comment = "Email of the authenticated principal"
    }

    columns {
      name    = "callerip"
      type    = "string"
      comment = "IP address of the caller"
    }

    columns {
      name    = "calleruseragent"
      type    = "string"
      comment = "User agent of the caller"
    }

    columns {
      name    = "status_code"
      type    = "int"
      comment = "Status code of the operation"
    }

    columns {
      name    = "status_message"
      type    = "string"
      comment = "Status message"
    }

    # VPC Flow Log Fields (jsonPayload)
    columns {
      name    = "src_ip"
      type    = "string"
      comment = "Source IP address"
    }

    columns {
      name    = "dest_ip"
      type    = "string"
      comment = "Destination IP address"
    }

    columns {
      name    = "src_port"
      type    = "int"
      comment = "Source port"
    }

    columns {
      name    = "dest_port"
      type    = "int"
      comment = "Destination port"
    }

    columns {
      name    = "protocol"
      type    = "int"
      comment = "IP protocol number"
    }

    columns {
      name    = "bytes_sent"
      type    = "bigint"
      comment = "Bytes transferred"
    }

    columns {
      name    = "packets_sent"
      type    = "bigint"
      comment = "Packets transferred"
    }

    columns {
      name    = "reporter"
      type    = "string"
      comment = "Reporter (SRC or DEST)"
    }

    # Firewall Log Fields
    columns {
      name    = "disposition"
      type    = "string"
      comment = "Firewall action (ALLOWED, DENIED)"
    }

    columns {
      name    = "rule_reference"
      type    = "string"
      comment = "Firewall rule reference"
    }

    columns {
      name    = "rule_direction"
      type    = "string"
      comment = "Rule direction (INGRESS, EGRESS)"
    }

    columns {
      name    = "rule_priority"
      type    = "int"
      comment = "Rule priority"
    }

    # Instance Fields
    columns {
      name    = "instance_name"
      type    = "string"
      comment = "Compute instance name"
    }

    columns {
      name    = "instance_zone"
      type    = "string"
      comment = "Instance zone"
    }

    # GKE Fields
    columns {
      name    = "cluster_name"
      type    = "string"
      comment = "GKE cluster name"
    }

    columns {
      name    = "k8s_namespace"
      type    = "string"
      comment = "Kubernetes namespace"
    }

    columns {
      name    = "k8s_resource_type"
      type    = "string"
      comment = "Kubernetes resource type"
    }

    columns {
      name    = "k8s_resource_name"
      type    = "string"
      comment = "Kubernetes resource name"
    }

    # Payload Fields
    columns {
      name    = "textpayload"
      type    = "string"
      comment = "Text payload"
    }

    columns {
      name    = "jsonpayload"
      type    = "string"
      comment = "JSON payload"
    }

    columns {
      name    = "protopayload"
      type    = "string"
      comment = "Proto payload (JSON)"
    }

    columns {
      name    = "labels"
      type    = "string"
      comment = "Log entry labels (JSON)"
    }
  }

  partition_keys {
    name = "log_type"
    type = "string"
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
}

# Normalized GCP Cloud Logging Table (ECS format)
resource "aws_glue_catalog_table" "gcp_logging" {
  name          = "gcp_logging"
  database_name = var.glue_database_name
  description   = "GCP Cloud Logging entries normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/gcp_logging/normalized/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "ignore.malformed.json" = "FALSE"
        "dots.in.keys"          = "TRUE"
        "case.insensitive"      = "TRUE"
        "mapping"               = "true"
      }
    }

    # ECS Standard Fields
    columns {
      name    = "@timestamp"
      type    = "string"
      comment = "Date/time when the event originated (ISO 8601)"
    }

    columns {
      name    = "ecs"
      type    = "struct<version:string>"
      comment = "ECS version"
    }

    columns {
      name    = "event"
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string,id:string,severity:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "message"
      type    = "string"
      comment = "Human-readable event description"
    }

    # User Fields
    columns {
      name    = "user"
      type    = "struct<email:string,name:string,id:string,domain:string>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,port:int,bytes:bigint,packets:bigint,geo:struct<country_iso_code:string,region_name:string,city_name:string>,nat:struct<ip:string>>"
      comment = "ECS source fields"
    }

    # Destination Fields
    columns {
      name    = "destination"
      type    = "struct<ip:string,port:int,bytes:bigint,packets:bigint,geo:struct<country_iso_code:string,region_name:string,city_name:string>>"
      comment = "ECS destination fields"
    }

    # Network Fields
    columns {
      name    = "network"
      type    = "struct<transport:string,bytes:bigint,packets:bigint,type:string>"
      comment = "ECS network fields"
    }

    # User Agent Fields
    columns {
      name    = "user_agent"
      type    = "struct<original:string>"
      comment = "ECS user agent fields"
    }

    # Cloud Fields
    columns {
      name    = "cloud"
      type    = "struct<provider:string,project:struct<id:string>,region:string,service:struct<name:string>>"
      comment = "ECS cloud fields"
    }

    # Rule Fields (for firewall logs)
    columns {
      name    = "rule"
      type    = "struct<name:string,id:string>"
      comment = "ECS rule fields"
    }

    # Orchestrator Fields (for GKE)
    columns {
      name    = "orchestrator"
      type    = "struct<type:string,cluster:struct<name:string>,namespace:string,resource:struct<type:string,name:string>>"
      comment = "ECS orchestrator fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # GCP-Specific Fields
    columns {
      name    = "gcp"
      type    = "struct<audit:struct<method_name:string,service_name:string,resource_name:string,resource_type:string,log_name:string,insert_id:string,trace:string,span_id:string,is_critical:boolean>,authentication:struct<principal_email:string,principal_subject:string,service_account_delegation:array<struct<principal_email:string,first_party_principal:string>>>,authorization:struct<permissions:array<string>,resources:array<string>,granted:boolean>,request_metadata:struct<caller_ip:string,caller_user_agent:string,caller_network:string,destination_ip:string,destination_port:int>,status:struct<code:int,message:string>,request:string,response:string,labels:string,project_id:string,location:string,vpc_flow:struct<reporter:string,src_instance:struct<project_id:string,zone:string,vm_name:string,region:string>,dest_instance:struct<project_id:string,zone:string,vm_name:string,region:string>,src_vpc:struct<project_id:string,vpc_name:string,subnetwork_name:string>,dest_vpc:struct<project_id:string,vpc_name:string,subnetwork_name:string>,rtt_msec:int,start_time:string,end_time:string>,subnetwork_id:string,subnetwork_name:string,firewall:struct<disposition:string,rule_reference:string,rule_direction:string,rule_priority:int,rule_action:string,rule_network:string,rule_ip_ports:array<string>,rule_target_tags:array<string>,rule_source_ranges:array<string>,instance:struct<project_id:string,zone:string,vm_name:string,network_interface:string,region:string>,remote_location:struct<continent:string,country:string,region:string,city:string>>,gke:struct<cluster_name:string,cluster_location:string,method_name:string,service_name:string,resource_name:string,principal_email:string,caller_ip:string,k8s_namespace:string,k8s_resource_type:string,k8s_resource_name:string>,data_access:struct<method_name:string,service_name:string,resource_name:string,principal_email:string,caller_ip:string,is_sensitive:boolean,num_response_items:int,resource_location:string>,log_entry:struct<log_name:string,resource_type:string,severity:string,trace:string,span_id:string,labels:string>>"
      comment = "GCP-specific event fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "log_type"
    type = "string"
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
}
