/**
 * AWS Glue Table Definitions for Jamf Pro Logs
 *
 * Creates tables for both raw and normalized Jamf Pro events including
 * audit logs, computer events, mobile device events, and security state.
 */

# Raw Jamf Pro Events Table
resource "aws_glue_catalog_table" "jamf_logs_raw" {
  name          = "jamf_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Jamf Pro audit logs, device events, and webhook notifications"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/jamf/raw/"
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
      name    = "id"
      type    = "string"
      comment = "Event or record identifier"
    }

    columns {
      name    = "eventType"
      type    = "string"
      comment = "Type of event (ComputerCheckIn, AuditLogEntry, etc.)"
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "Event timestamp"
    }

    columns {
      name    = "dateTime"
      type    = "string"
      comment = "Alternative timestamp field"
    }

    # Webhook Fields
    columns {
      name    = "webhookEvent"
      type    = "string"
      comment = "Webhook event type"
    }

    columns {
      name    = "webhookId"
      type    = "bigint"
      comment = "Webhook configuration ID"
    }

    columns {
      name    = "webhookName"
      type    = "string"
      comment = "Webhook name"
    }

    # Computer Fields
    columns {
      name    = "computer_id"
      type    = "bigint"
      comment = "Computer record ID"
    }

    columns {
      name    = "computer_name"
      type    = "string"
      comment = "Computer name"
    }

    columns {
      name    = "serial_number"
      type    = "string"
      comment = "Device serial number"
    }

    columns {
      name    = "udid"
      type    = "string"
      comment = "Device UDID"
    }

    columns {
      name    = "mac_address"
      type    = "string"
      comment = "MAC address"
    }

    columns {
      name    = "ip_address"
      type    = "string"
      comment = "IP address"
    }

    columns {
      name    = "os_version"
      type    = "string"
      comment = "Operating system version"
    }

    columns {
      name    = "os_build"
      type    = "string"
      comment = "OS build number"
    }

    columns {
      name    = "model"
      type    = "string"
      comment = "Hardware model"
    }

    columns {
      name    = "model_identifier"
      type    = "string"
      comment = "Hardware model identifier"
    }

    columns {
      name    = "processor_type"
      type    = "string"
      comment = "Processor type"
    }

    columns {
      name    = "total_ram_mb"
      type    = "bigint"
      comment = "Total RAM in MB"
    }

    # Mobile Device Fields
    columns {
      name    = "mobile_device_id"
      type    = "bigint"
      comment = "Mobile device record ID"
    }

    columns {
      name    = "device_name"
      type    = "string"
      comment = "Mobile device name"
    }

    columns {
      name    = "phone_number"
      type    = "string"
      comment = "Phone number"
    }

    columns {
      name    = "wifi_mac_address"
      type    = "string"
      comment = "WiFi MAC address"
    }

    columns {
      name    = "bluetooth_mac_address"
      type    = "string"
      comment = "Bluetooth MAC address"
    }

    # Management Status
    columns {
      name    = "managed"
      type    = "boolean"
      comment = "Device is managed"
    }

    columns {
      name    = "supervised"
      type    = "boolean"
      comment = "Device is supervised"
    }

    columns {
      name    = "enrolled_via_dep"
      type    = "boolean"
      comment = "Enrolled via DEP/ABM"
    }

    columns {
      name    = "mdm_capable"
      type    = "boolean"
      comment = "MDM capable"
    }

    columns {
      name    = "last_contact_time"
      type    = "string"
      comment = "Last contact timestamp"
    }

    columns {
      name    = "last_inventory_update"
      type    = "string"
      comment = "Last inventory update timestamp"
    }

    # Security Fields
    columns {
      name    = "filevault_enabled"
      type    = "boolean"
      comment = "FileVault enabled status"
    }

    columns {
      name    = "filevault_status"
      type    = "string"
      comment = "FileVault status details"
    }

    columns {
      name    = "gatekeeper_status"
      type    = "string"
      comment = "Gatekeeper status"
    }

    columns {
      name    = "xprotect_version"
      type    = "string"
      comment = "XProtect version"
    }

    columns {
      name    = "firewall_enabled"
      type    = "boolean"
      comment = "Firewall enabled status"
    }

    columns {
      name    = "sip_status"
      type    = "string"
      comment = "System Integrity Protection status"
    }

    columns {
      name    = "secure_boot_level"
      type    = "string"
      comment = "Secure boot level"
    }

    columns {
      name    = "activation_lock_enabled"
      type    = "boolean"
      comment = "Activation lock enabled"
    }

    columns {
      name    = "passcode_present"
      type    = "boolean"
      comment = "Passcode is set"
    }

    columns {
      name    = "passcode_compliant"
      type    = "boolean"
      comment = "Passcode is compliant"
    }

    columns {
      name    = "jailbreak_detected"
      type    = "string"
      comment = "Jailbreak detection status"
    }

    # User Fields
    columns {
      name    = "username"
      type    = "string"
      comment = "Username"
    }

    columns {
      name    = "user_id"
      type    = "string"
      comment = "User ID"
    }

    columns {
      name    = "email_address"
      type    = "string"
      comment = "User email address"
    }

    # Audit Log Fields
    columns {
      name    = "action"
      type    = "string"
      comment = "Audit action performed"
    }

    columns {
      name    = "object_type"
      type    = "string"
      comment = "Object type affected"
    }

    columns {
      name    = "object_id"
      type    = "string"
      comment = "Object ID affected"
    }

    columns {
      name    = "object_name"
      type    = "string"
      comment = "Object name"
    }

    columns {
      name    = "details"
      type    = "string"
      comment = "Audit details"
    }

    # Policy Fields
    columns {
      name    = "policy_id"
      type    = "bigint"
      comment = "Policy ID"
    }

    columns {
      name    = "policy_name"
      type    = "string"
      comment = "Policy name"
    }

    columns {
      name    = "policy_trigger"
      type    = "string"
      comment = "Policy trigger type"
    }

    columns {
      name    = "policy_status"
      type    = "string"
      comment = "Policy execution status"
    }

    # Site and Location
    columns {
      name    = "site_id"
      type    = "bigint"
      comment = "Site ID"
    }

    columns {
      name    = "site_name"
      type    = "string"
      comment = "Site name"
    }

    columns {
      name    = "building"
      type    = "string"
      comment = "Building name"
    }

    columns {
      name    = "department"
      type    = "string"
      comment = "Department name"
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

# Normalized Jamf Pro Logs Table (ECS format)
resource "aws_glue_catalog_table" "jamf_logs" {
  name          = "jamf_logs"
  database_name = var.glue_database_name
  description   = "Jamf Pro logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/jamf/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,reason:string,provider:string,module:string,id:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "message"
      type    = "string"
      comment = "Human-readable event description"
    }

    # Host Fields (for device events)
    columns {
      name    = "host"
      type    = "struct<id:string,name:string,hostname:string,mac:array<string>,ip:array<string>,os:struct<name:string,version:string,full:string>,architecture:string,serial_number:string,udid:string>"
      comment = "ECS host fields for managed devices"
    }

    # User Fields
    columns {
      name    = "user"
      type    = "struct<id:string,name:string,email:string>"
      comment = "ECS user fields"
    }

    # Source Fields (for network events)
    columns {
      name    = "source"
      type    = "struct<ip:string>"
      comment = "ECS source fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>,hosts:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Jamf-Specific Fields
    columns {
      name    = "jamf"
      type    = "struct<event_type:string,webhook:struct<id:bigint,name:string,enabled:boolean>,computer:struct<id:bigint,udid:string,serial_number:string,management_status:boolean,supervised:boolean,mdm_capable:boolean,enrolled_via_dep:boolean,site:string,building:string,department:string>,mobile_device:struct<id:bigint,udid:string,serial_number:string,phone_number:string,managed:boolean,supervised:boolean,device_ownership_level:string,enrolled_via_automated_device_enrollment:boolean,site:string,model:string,model_identifier:string,model_display:string>,hardware:struct<model:string,model_identifier:string,processor_type:string,processor_speed:bigint,total_ram_mb:bigint,sip_status:string>,security:struct<filevault_enabled:boolean,filevault_status:string,gatekeeper_status:string,xprotect_version:string,firewall_enabled:boolean,external_boot_level:string,secure_boot_level:string,activation_lock_enabled:boolean,data_protection:boolean,passcode_present:boolean,passcode_compliant:boolean,hardware_encryption:int,jailbreak_detected:string,lost_mode_enabled:boolean,lost_mode_enforced:boolean>,audit:struct<id:string,action:string,object_type:string,object_id:string,object_name:string,details:string,note:string>,policy:struct<id:bigint,name:string,enabled:boolean,trigger:string,frequency:string,category:string,site:string,self_service:boolean>,execution:struct<status:string,duration_ms:bigint,exit_code:int>,event_data:string>"
      comment = "Jamf Pro-specific event fields"
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
