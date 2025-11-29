/**
 * AWS Glue Table Definitions for 1Password Events
 *
 * Creates tables for both raw and normalized 1Password events including
 * sign-in attempts, item usages, and audit events.
 */

# Raw 1Password Events Table
resource "aws_glue_catalog_table" "onepassword_logs_raw" {
  name          = "onepassword_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw 1Password Events API data including sign-ins, item usage, and audit events"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/onepassword/raw/"
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

    # Common Event Fields
    columns {
      name    = "uuid"
      type    = "string"
      comment = "Unique event identifier"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "Event timestamp (ISO 8601)"
    }

    columns {
      name    = "action"
      type    = "string"
      comment = "Action performed"
    }

    columns {
      name    = "object_type"
      type    = "string"
      comment = "Type of object affected"
    }

    # Actor Fields (user performing action)
    columns {
      name    = "actor_uuid"
      type    = "string"
      comment = "Actor UUID"
    }

    columns {
      name    = "actor_email"
      type    = "string"
      comment = "Actor email address"
    }

    columns {
      name    = "actor_name"
      type    = "string"
      comment = "Actor display name"
    }

    columns {
      name    = "actor_type"
      type    = "string"
      comment = "Type of actor (user, service_account)"
    }

    # Target/Object Fields
    columns {
      name    = "target_uuid"
      type    = "string"
      comment = "Target object UUID"
    }

    columns {
      name    = "target_name"
      type    = "string"
      comment = "Target object name"
    }

    columns {
      name    = "target_type"
      type    = "string"
      comment = "Target object type"
    }

    # Vault Fields
    columns {
      name    = "vault_uuid"
      type    = "string"
      comment = "Vault UUID"
    }

    columns {
      name    = "vault_name"
      type    = "string"
      comment = "Vault name"
    }

    # Item Fields
    columns {
      name    = "item_uuid"
      type    = "string"
      comment = "Item UUID"
    }

    columns {
      name    = "item_title"
      type    = "string"
      comment = "Item title"
    }

    columns {
      name    = "item_category"
      type    = "string"
      comment = "Item category (Login, Credit Card, etc.)"
    }

    # Session/Client Fields
    columns {
      name    = "session_uuid"
      type    = "string"
      comment = "Session UUID"
    }

    columns {
      name    = "device_uuid"
      type    = "string"
      comment = "Device UUID"
    }

    columns {
      name    = "client_app_name"
      type    = "string"
      comment = "Client application name"
    }

    columns {
      name    = "client_app_version"
      type    = "string"
      comment = "Client application version"
    }

    columns {
      name    = "client_platform"
      type    = "string"
      comment = "Client platform/OS"
    }

    columns {
      name    = "client_os_version"
      type    = "string"
      comment = "Client OS version"
    }

    # Location Fields
    columns {
      name    = "ip"
      type    = "string"
      comment = "Source IP address"
    }

    columns {
      name    = "country"
      type    = "string"
      comment = "Country code"
    }

    columns {
      name    = "region"
      type    = "string"
      comment = "Region/state"
    }

    columns {
      name    = "city"
      type    = "string"
      comment = "City name"
    }

    # Sign-in Specific Fields
    columns {
      name    = "signin_type"
      type    = "string"
      comment = "Sign-in type (sso, password, etc.)"
    }

    columns {
      name    = "signin_result"
      type    = "string"
      comment = "Sign-in result"
    }

    columns {
      name    = "mfa_type"
      type    = "string"
      comment = "MFA type used"
    }

    # Item Usage Specific Fields
    columns {
      name    = "used_version"
      type    = "int"
      comment = "Item version used"
    }

    columns {
      name    = "usage_type"
      type    = "string"
      comment = "Type of item usage"
    }

    # Audit Event Specific Fields
    columns {
      name    = "aux_info"
      type    = "string"
      comment = "Additional audit information (JSON)"
    }
  }

  partition_keys {
    name = "event_type"
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

# Normalized 1Password Logs Table (ECS format)
resource "aws_glue_catalog_table" "onepassword_logs" {
  name          = "onepassword_logs"
  database_name = var.glue_database_name
  description   = "1Password events normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/onepassword/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string,id:string>"
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
      type    = "struct<id:string,name:string,email:string,target:struct<id:string,name:string>>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<country_iso_code:string,region_name:string,city_name:string>>"
      comment = "ECS source fields"
    }

    # User Agent Fields
    columns {
      name    = "user_agent"
      type    = "struct<name:string,version:string,os:struct<name:string>>"
      comment = "ECS user agent fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # 1Password-Specific Fields
    columns {
      name    = "onepassword"
      type    = "struct<action:string,uuid:string,actor:struct<uuid:string,email:string,name:string,type:string>,vault:struct<uuid:string,name:string>,item:struct<uuid:string,title:string,category:string>,target:struct<type:string,uuid:string,name:string>,session:struct<uuid:string,login_time:string,device_uuid:string>,client:struct<app_name:string,app_version:string,platform:string,os_version:string>,location:struct<country:string,region:string,city:string,ip:string>,aux_info:string,is_sensitive:boolean,is_sharing:boolean>"
      comment = "1Password-specific event fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "event_type"
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
