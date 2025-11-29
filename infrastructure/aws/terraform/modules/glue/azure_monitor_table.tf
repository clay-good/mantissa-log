/**
 * AWS Glue Table Definitions for Azure Monitor Logs
 *
 * Creates tables for both raw and normalized Azure Monitor logs including
 * Activity Logs, Sign-in Logs, Audit Logs, Security Alerts, and NSG Flow Logs.
 */

# Raw Azure Monitor Logs Table
resource "aws_glue_catalog_table" "azure_monitor_logs_raw" {
  name          = "azure_monitor_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Azure Monitor logs including Activity, Sign-in, Audit, and Security logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/azure_monitor/raw/"
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
      name    = "time"
      type    = "string"
      comment = "Event timestamp (ISO 8601)"
    }

    columns {
      name    = "resourceid"
      type    = "string"
      comment = "Azure resource ID"
    }

    columns {
      name    = "operationname"
      type    = "string"
      comment = "Name of the operation"
    }

    columns {
      name    = "operationversion"
      type    = "string"
      comment = "API version of the operation"
    }

    columns {
      name    = "category"
      type    = "string"
      comment = "Log category"
    }

    columns {
      name    = "resulttype"
      type    = "string"
      comment = "Result of the operation"
    }

    columns {
      name    = "resultsignature"
      type    = "string"
      comment = "Sub-status of the operation"
    }

    columns {
      name    = "resultdescription"
      type    = "string"
      comment = "Description of the result"
    }

    columns {
      name    = "durationms"
      type    = "bigint"
      comment = "Duration of operation in milliseconds"
    }

    columns {
      name    = "calleripaddress"
      type    = "string"
      comment = "IP address of the caller"
    }

    columns {
      name    = "correlationid"
      type    = "string"
      comment = "Correlation ID for tracing"
    }

    columns {
      name    = "level"
      type    = "string"
      comment = "Log level (Information, Warning, Error)"
    }

    columns {
      name    = "location"
      type    = "string"
      comment = "Azure region"
    }

    # Activity Log Specific Fields
    columns {
      name    = "caller"
      type    = "string"
      comment = "Identity of the caller"
    }

    columns {
      name    = "eventtimestamp"
      type    = "string"
      comment = "Timestamp when the event was generated"
    }

    columns {
      name    = "submissiontimestamp"
      type    = "string"
      comment = "Timestamp when the event was submitted"
    }

    columns {
      name    = "subscriptionid"
      type    = "string"
      comment = "Azure subscription ID"
    }

    columns {
      name    = "tenantid"
      type    = "string"
      comment = "Azure AD tenant ID"
    }

    columns {
      name    = "operationid"
      type    = "string"
      comment = "Operation ID"
    }

    columns {
      name    = "httpmethod"
      type    = "string"
      comment = "HTTP method used"
    }

    columns {
      name    = "clientrequestid"
      type    = "string"
      comment = "Client request ID"
    }

    # Sign-in Log Specific Fields
    columns {
      name    = "userprincipalname"
      type    = "string"
      comment = "User principal name (email)"
    }

    columns {
      name    = "userdisplayname"
      type    = "string"
      comment = "User display name"
    }

    columns {
      name    = "userid"
      type    = "string"
      comment = "User object ID"
    }

    columns {
      name    = "appid"
      type    = "string"
      comment = "Application (client) ID"
    }

    columns {
      name    = "appdisplayname"
      type    = "string"
      comment = "Application display name"
    }

    columns {
      name    = "ipaddress"
      type    = "string"
      comment = "Client IP address"
    }

    columns {
      name    = "clientappused"
      type    = "string"
      comment = "Client application used"
    }

    columns {
      name    = "conditionalaccessstatus"
      type    = "string"
      comment = "Conditional access policy status"
    }

    columns {
      name    = "isinteractive"
      type    = "boolean"
      comment = "Whether the sign-in was interactive"
    }

    columns {
      name    = "risklevel"
      type    = "string"
      comment = "Risk level of the sign-in"
    }

    columns {
      name    = "riskstate"
      type    = "string"
      comment = "Risk state"
    }

    columns {
      name    = "riskdetail"
      type    = "string"
      comment = "Risk detail"
    }

    # Audit Log Specific Fields
    columns {
      name    = "activitydisplayname"
      type    = "string"
      comment = "Display name of the activity"
    }

    columns {
      name    = "activitydatetime"
      type    = "string"
      comment = "Activity timestamp"
    }

    columns {
      name    = "loggedbyservice"
      type    = "string"
      comment = "Service that logged the activity"
    }

    columns {
      name    = "operationtype"
      type    = "string"
      comment = "Type of operation performed"
    }

    columns {
      name    = "result"
      type    = "string"
      comment = "Result of the operation"
    }

    columns {
      name    = "resultreason"
      type    = "string"
      comment = "Reason for the result"
    }

    # Security Alert Specific Fields
    columns {
      name    = "alertname"
      type    = "string"
      comment = "Security alert name"
    }

    columns {
      name    = "alerttype"
      type    = "string"
      comment = "Type of security alert"
    }

    columns {
      name    = "severity"
      type    = "string"
      comment = "Alert severity"
    }

    columns {
      name    = "description"
      type    = "string"
      comment = "Alert description"
    }

    columns {
      name    = "status"
      type    = "string"
      comment = "Alert status"
    }

    columns {
      name    = "compromisedentity"
      type    = "string"
      comment = "Compromised entity"
    }

    columns {
      name    = "intent"
      type    = "string"
      comment = "Attack intent/kill chain stage"
    }

    # NSG Flow Log Specific Fields
    columns {
      name    = "rule"
      type    = "string"
      comment = "NSG rule name"
    }

    columns {
      name    = "flows"
      type    = "string"
      comment = "Flow tuples (JSON array)"
    }

    columns {
      name    = "version"
      type    = "int"
      comment = "NSG flow log version"
    }

    # Nested/Complex Fields
    columns {
      name    = "properties"
      type    = "string"
      comment = "Additional properties (JSON)"
    }

    columns {
      name    = "claims"
      type    = "string"
      comment = "Authentication claims (JSON)"
    }

    columns {
      name    = "targetresources"
      type    = "string"
      comment = "Target resources (JSON array)"
    }

    columns {
      name    = "initiatedby"
      type    = "string"
      comment = "Initiated by (JSON)"
    }

    columns {
      name    = "devicedetail"
      type    = "string"
      comment = "Device details (JSON)"
    }

    columns {
      name    = "locationinfo"
      type    = "string"
      comment = "Location information (JSON)"
    }

    columns {
      name    = "mfadetail"
      type    = "string"
      comment = "MFA details (JSON)"
    }

    columns {
      name    = "appliedconditionalaccesspolicies"
      type    = "string"
      comment = "Applied conditional access policies (JSON array)"
    }

    columns {
      name    = "authenticationdetails"
      type    = "string"
      comment = "Authentication details (JSON array)"
    }

    columns {
      name    = "entities"
      type    = "string"
      comment = "Security alert entities (JSON array)"
    }

    columns {
      name    = "extendedproperties"
      type    = "string"
      comment = "Extended properties (JSON)"
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

# Normalized Azure Monitor Logs Table (ECS format)
resource "aws_glue_catalog_table" "azure_monitor_logs" {
  name          = "azure_monitor_logs"
  database_name = var.glue_database_name
  description   = "Azure Monitor logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/azure_monitor/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string,id:string,severity:string,reason:string>"
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
      type    = "struct<id:string,name:string,email:string,domain:string,target:struct<id:string,name:string,email:string>,risk:struct<static_level:string,calculated_level:string>>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<country_iso_code:string,region_name:string,city_name:string,location:struct<lat:double,lon:double>>>"
      comment = "ECS source fields"
    }

    # Destination Fields (for NSG flows)
    columns {
      name    = "destination"
      type    = "struct<ip:string,port:int>"
      comment = "ECS destination fields"
    }

    # Network Fields (for NSG flows)
    columns {
      name    = "network"
      type    = "struct<transport:string,direction:string,type:string>"
      comment = "ECS network fields"
    }

    # User Agent Fields
    columns {
      name    = "user_agent"
      type    = "struct<name:string,os:struct<name:string>>"
      comment = "ECS user agent fields"
    }

    # Host Fields
    columns {
      name    = "host"
      type    = "struct<id:string,os:struct<name:string>>"
      comment = "ECS host fields"
    }

    # Cloud Fields
    columns {
      name    = "cloud"
      type    = "struct<provider:string,account:struct<id:string>,region:string,service:struct<name:string>>"
      comment = "ECS cloud fields"
    }

    # Rule Fields (for security alerts)
    columns {
      name    = "rule"
      type    = "struct<name:string,description:string,category:string>"
      comment = "ECS rule fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Azure-Specific Activity Log Fields
    columns {
      name    = "azure"
      type    = "struct<subscription_id:string,resource_group:string,resource_id:string,resource_type:string,resource_name:string,operation_name:string,category:string,correlation_id:string,operation_id:string,level:string,status:string,sub_status:string,is_critical:boolean,caller:string,claims:struct<object_id:string,upn:string,app_id:string,aud:string,iss:string>,properties:string,http_request:string,signin:struct<user_principal_name:string,user_display_name:string,user_id:string,correlation_id:string,app_display_name:string,app_id:string,resource_display_name:string,resource_id:string,client_app_used:string,is_interactive:boolean,token_issuer_type:string,processing_time_ms:int>,status:struct<error_code:string,failure_reason:string,additional_details:string>,location:struct<country:string,state:string,city:string,latitude:double,longitude:double>,device:struct<device_id:string,browser:string,operating_system:string,is_managed:boolean,is_compliant:boolean,trust_type:string>,risk:struct<level:string,state:string,detail:string,event_types:array<string>>,conditional_access:struct<status:string,policies:array<struct<id:string,display_name:string,result:string,enforcement:array<string>>>>,mfa:struct<auth_method:string,auth_detail:string,auth_methods:array<struct<method:string,method_detail:string,succeeded:boolean>>>,audit:struct<activity_display_name:string,category:string,result:string,result_reason:string,correlation_id:string,logged_by_service:string,operation_type:string,tenant_id:string>,initiator:struct<type:string,id:string,display_name:string,user_principal_name:string,ip_address:string>,target:struct<type:string,id:string,display_name:string,user_principal_name:string,group_type:string>,modified_properties:array<struct<name:string,old_value:string,new_value:string>>,additional_targets:array<struct<type:string,id:string,display_name:string>>,security_alert:struct<alert_name:string,alert_type:string,description:string,severity:string,status:string,resource_id:string,subscription_id:string,vendor_name:string,product_name:string,compromised_entity:string,intent:string,confidence_level:string,extended_properties:string,entities:string>,nsg_flow:struct<rule_name:string,flow_count:int,flows:array<struct<timestamp:string,source_ip:string,dest_ip:string,source_port:string,dest_port:string,protocol:string,direction:string,action:string,mac:string,packets_s2d:string,bytes_s2d:string,packets_d2s:string,bytes_d2s:string>>,resource_id:string,mac_address:string,version:int>,resource_log:struct<resource_id:string,resource_type:string,resource_name:string,resource_group:string,category:string,operation_name:string,result_type:string,result_signature:string,result_description:string,duration_ms:int,caller_ip:string,correlation_id:string,level:string,properties:string>>"
      comment = "Azure-specific event fields"
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
