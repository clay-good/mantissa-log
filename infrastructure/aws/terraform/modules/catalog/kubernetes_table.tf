/**
 * AWS Glue Table Definitions for Kubernetes Audit Logs
 *
 * Creates tables for both raw and normalized Kubernetes API server audit logs.
 * Supports audit events from Kubernetes API server configured with webhook backend.
 */

# Raw Kubernetes Audit Logs Table
resource "aws_glue_catalog_table" "kubernetes_logs_raw" {
  name          = "kubernetes_logs_raw"
  database_name = aws_glue_catalog_database.main.name
  description   = "Raw Kubernetes API server audit logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/kubernetes/raw/"
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

    columns {
      name    = "kind"
      type    = "string"
      comment = "Event kind"
    }

    columns {
      name    = "apiVersion"
      type    = "string"
      comment = "Audit API version"
    }

    columns {
      name    = "level"
      type    = "string"
      comment = "Audit level (None, Metadata, Request, RequestResponse)"
    }

    columns {
      name    = "auditID"
      type    = "string"
      comment = "Unique audit ID"
    }

    columns {
      name    = "stage"
      type    = "string"
      comment = "Request stage (RequestReceived, ResponseStarted, ResponseComplete, Panic)"
    }

    columns {
      name    = "requestURI"
      type    = "string"
      comment = "Request URI"
    }

    columns {
      name    = "verb"
      type    = "string"
      comment = "Kubernetes verb (get, list, create, update, patch, delete, etc.)"
    }

    columns {
      name    = "user"
      type    = "struct<username:string,uid:string,groups:array<string>,extra:map<string,array<string>>>"
      comment = "User who made the request"
    }

    columns {
      name    = "impersonatedUser"
      type    = "struct<username:string,uid:string,groups:array<string>,extra:map<string,array<string>>>"
      comment = "Impersonated user if applicable"
    }

    columns {
      name    = "sourceIPs"
      type    = "array<string>"
      comment = "Source IP addresses"
    }

    columns {
      name    = "userAgent"
      type    = "string"
      comment = "User agent string"
    }

    columns {
      name    = "objectRef"
      type    = "struct<resource:string,namespace:string,name:string,uid:string,apiGroup:string,apiVersion:string,resourceVersion:string,subresource:string>"
      comment = "Object reference"
    }

    columns {
      name    = "responseStatus"
      type    = "struct<metadata:map<string,string>,status:string,message:string,reason:string,details:struct<name:string,group:string,kind:string,uid:string,causes:array<struct<reason:string,message:string,field:string>>,retryAfterSeconds:int>,code:int>"
      comment = "Response status"
    }

    columns {
      name    = "requestObject"
      type    = "string"
      comment = "Request object body (if captured)"
    }

    columns {
      name    = "responseObject"
      type    = "string"
      comment = "Response object body (if captured)"
    }

    columns {
      name    = "requestReceivedTimestamp"
      type    = "string"
      comment = "Time request was received (RFC 3339)"
    }

    columns {
      name    = "stageTimestamp"
      type    = "string"
      comment = "Time current stage was reached (RFC 3339)"
    }

    columns {
      name    = "annotations"
      type    = "map<string,string>"
      comment = "Audit annotations from admission webhooks"
    }
  }

  partition_keys {
    name = "cluster"
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

# Normalized Kubernetes Audit Logs Table (ECS format)
resource "aws_glue_catalog_table" "kubernetes_logs" {
  name          = "kubernetes_logs"
  database_name = aws_glue_catalog_database.main.name
  description   = "Kubernetes audit logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/kubernetes/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,created:string,id:string,provider:string,module:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "message"
      type    = "string"
      comment = "Log message"
    }

    # User Fields
    columns {
      name    = "user"
      type    = "struct<name:string,id:string,roles:array<string>>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<city_name:string,country_name:string>>"
      comment = "ECS source fields"
    }

    # User Agent
    columns {
      name    = "user_agent"
      type    = "struct<original:string>"
      comment = "ECS user agent fields"
    }

    # HTTP Fields
    columns {
      name    = "http"
      type    = "struct<request:struct<method:string>,response:struct<status_code:int>>"
      comment = "ECS HTTP fields"
    }

    # URL Fields
    columns {
      name    = "url"
      type    = "struct<path:string,original:string>"
      comment = "ECS URL fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Kubernetes-Specific Fields
    columns {
      name    = "kubernetes"
      type    = "struct<audit_id:string,stage:string,level:string,verb:string,request_uri:string,user:struct<username:string,uid:string,groups:array<string>,extra:map<string,array<string>>>,source_ips:array<string>,user_agent:string,object_ref:struct<resource:string,namespace:string,name:string,api_version:string,api_group:string,subresource:string,resource_version:string>,response_status:struct<metadata:map<string,string>,status:string,message:string,reason:string,code:int>,request_object:string,response_object:string,request_received_timestamp:string,stage_timestamp:string,annotations:map<string,string>>"
      comment = "Kubernetes-specific audit fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "cluster"
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
