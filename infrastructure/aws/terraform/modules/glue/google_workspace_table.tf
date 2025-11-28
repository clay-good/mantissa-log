/**
 * AWS Glue Table Definitions for Google Workspace Logs
 *
 * Creates tables for both raw and normalized Google Workspace audit logs.
 * Supports multiple applications: admin, login, drive, token, groups, mobile
 */

# Raw Google Workspace Logs Table
resource "aws_glue_catalog_table" "google_workspace_logs_raw" {
  name          = "google_workspace_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Google Workspace audit logs from Reports API"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/google_workspace/raw/"
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

    columns {
      name    = "kind"
      type    = "string"
      comment = "Kind of resource"
    }

    columns {
      name    = "id"
      type    = "struct<time:string,uniqueQualifier:string,applicationName:string,customerId:string>"
      comment = "Unique identifier for each activity record"
    }

    columns {
      name    = "etag"
      type    = "string"
      comment = "ETag of the entry"
    }

    columns {
      name    = "actor"
      type    = "struct<callerType:string,email:string,profileId:string,key:string>"
      comment = "User performing the action"
    }

    columns {
      name    = "ownershipDomain"
      type    = "string"
      comment = "Domain that owns the event"
    }

    columns {
      name    = "ipAddress"
      type    = "string"
      comment = "IP address of the user performing the action"
    }

    columns {
      name    = "events"
      type    = "array<struct<type:string,name:string,parameters:array<struct<name:string,value:string,intValue:bigint,boolValue:boolean,multiValue:array<string>,multiIntValue:array<bigint>,messageValue:struct<parameter:array<struct<name:string,value:string>>>>>>>"
      comment = "Activity events"
    }

    columns {
      name    = "orgUnitPath"
      type    = "string"
      comment = "Organization unit path"
    }
  }

  partition_keys {
    name = "application"
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

# Normalized Google Workspace Logs Table (ECS format)
resource "aws_glue_catalog_table" "google_workspace_logs" {
  name          = "google_workspace_logs"
  database_name = var.glue_database_name
  description   = "Google Workspace audit logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/google_workspace/normalized/"
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
      comment = "Log message optimized for viewing in a log viewer"
    }

    # User Fields
    columns {
      name    = "user"
      type    = "struct<email:string,id:string,name:string,full_name:string>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<city_name:string,country_name:string,region_name:string,location:struct<lat:double,lon:double>>>"
      comment = "ECS source fields"
    }

    # Organization Fields
    columns {
      name    = "organization"
      type    = "struct<id:string,name:string>"
      comment = "ECS organization fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Google Workspace-Specific Fields
    columns {
      name    = "google_workspace"
      type    = "struct<kind:string,id:struct<time:string,unique_qualifier:string,application_name:string,customer_id:string>,actor:struct<email:string,profile_id:string,caller_type:string>,ownership_domain:string,events:array<struct<name:string,type:string,parameters:map<string,string>>>,org_unit_path:string,etag:string>"
      comment = "Google Workspace-specific fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "application"
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
