/**
 * AWS Glue Table Definitions for Slack Audit Logs
 *
 * Creates tables for both raw and normalized Slack Enterprise Grid audit logs.
 */

# Raw Slack Audit Logs Table
resource "aws_glue_catalog_table" "slack_logs_raw" {
  name          = "slack_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Slack Enterprise Grid audit logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/slack/raw/"
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
      name    = "id"
      type    = "string"
      comment = "Unique event identifier"
    }

    columns {
      name    = "date_create"
      type    = "bigint"
      comment = "Unix timestamp when event was created"
    }

    columns {
      name    = "action"
      type    = "string"
      comment = "Action performed"
    }

    columns {
      name    = "actor"
      type    = "struct<type:string,user:struct<id:string,name:string,email:string,team:string>>"
      comment = "User who performed the action"
    }

    columns {
      name    = "entity"
      type    = "struct<type:string,id:string,name:string,domain:string,privacy:string,app:struct<id:string,name:string,distributed:boolean,directory_approved:boolean>>"
      comment = "Entity affected by the action"
    }

    columns {
      name    = "context"
      type    = "struct<location:struct<type:string,id:string,name:string,domain:string>,ua:string,ip_address:string,session_id:string,device_id:string,app:struct<id:string,name:string>>"
      comment = "Context information for the event"
    }

    columns {
      name    = "details"
      type    = "string"
      comment = "Additional event details (JSON)"
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

# Normalized Slack Audit Logs Table (ECS format)
resource "aws_glue_catalog_table" "slack_logs" {
  name          = "slack_logs"
  database_name = var.glue_database_name
  description   = "Slack audit logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/slack/normalized/"
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
      type    = "struct<id:string,email:string,name:string>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<country_name:string,region_name:string,city_name:string>>"
      comment = "ECS source fields"
    }

    # User Agent
    columns {
      name    = "user_agent"
      type    = "struct<original:string>"
      comment = "ECS user agent fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Slack-Specific Fields
    columns {
      name    = "slack"
      type    = "struct<id:string,action:string,date_create:bigint,actor:struct<type:string,user:struct<id:string,email:string,name:string,team:string>>,context:struct<ua:string,ip_address:string,location:struct<country:string,region:string,city:string>,session_id:string,app:struct<id:string,name:string>,device_id:string>,entity:struct<type:string,id:string,name:string,domain:string,privacy:string,app:struct<id:string,name:string>>,details:string>"
      comment = "Slack-specific audit log fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
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
}
