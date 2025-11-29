/**
 * AWS Glue Table Definitions for CrowdStrike Falcon Logs
 *
 * Creates tables for both raw and normalized CrowdStrike Event Streams data.
 * Supports: DetectionSummaryEvent, IncidentSummaryEvent, AuditEvent, UserActivityAuditEvent
 */

# Raw CrowdStrike Logs Table
resource "aws_glue_catalog_table" "crowdstrike_logs_raw" {
  name          = "crowdstrike_logs_raw"
  database_name = aws_glue_catalog_database.main.name
  description   = "Raw CrowdStrike Falcon Event Streams data"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/crowdstrike/raw/"
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
      name    = "metadata"
      type    = "struct<customerIDString:string,offset:bigint,eventType:string,eventCreationTime:bigint,version:string>"
      comment = "Event metadata"
    }

    columns {
      name    = "event"
      type    = "string"
      comment = "Event payload (varies by event type)"
    }
  }

  partition_keys {
    name = "stream"
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

  partition_keys {
    name = "hour"
    type = "string"
  }
}

# Normalized CrowdStrike Logs Table (ECS format)
resource "aws_glue_catalog_table" "crowdstrike_logs" {
  name          = "crowdstrike_logs"
  database_name = aws_glue_catalog_database.main.name
  description   = "CrowdStrike Falcon events normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/crowdstrike/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,severity:int,created:string,id:string,provider:string,module:string,reason:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "message"
      type    = "string"
      comment = "Log message"
    }

    # Host Fields
    columns {
      name    = "host"
      type    = "struct<name:string,hostname:string,mac:array<string>,ip:array<string>>"
      comment = "ECS host fields"
    }

    # User Fields
    columns {
      name    = "user"
      type    = "struct<name:string,id:string>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<city_name:string,country_name:string>>"
      comment = "ECS source fields"
    }

    # File Fields
    columns {
      name    = "file"
      type    = "struct<name:string,path:string,hash:struct<md5:string,sha256:string>>"
      comment = "ECS file fields"
    }

    # Process Fields
    columns {
      name    = "process"
      type    = "struct<command_line:string,name:string,pid:int>"
      comment = "ECS process fields"
    }

    # Threat Fields
    columns {
      name    = "threat"
      type    = "struct<tactic:struct<name:array<string>>,technique:struct<name:array<string>>>"
      comment = "ECS threat fields for MITRE ATT&CK mapping"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>,hash:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # CrowdStrike-Specific Fields
    columns {
      name    = "crowdstrike"
      type    = "struct<metadata:struct<customerIDString:string,offset:bigint,eventType:string,eventCreationTime:bigint,version:string>,detection:struct<id:string,severity:string,tactic:string,technique:string,pattern_disposition:string,confidence:int,objective:string,scenario:string>,incident:struct<id:string,state:string,status:string,fine_score:int,start_time:string,end_time:string,hosts:array<string>,users:array<string>>,audit:struct<operation_name:string,service_name:string,success:boolean,audit_key_values:map<string,string>>,user_activity:struct<operation_name:string,success:boolean,user_ip:string>,event:string>"
      comment = "CrowdStrike-specific fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "stream"
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
