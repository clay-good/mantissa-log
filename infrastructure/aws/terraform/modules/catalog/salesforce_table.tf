/**
 * AWS Glue Table Definitions for Salesforce Event Logs
 *
 * Creates tables for both raw and normalized Salesforce events including
 * Event Log Files, Login History, and Setup Audit Trail.
 */

# Raw Salesforce Events Table
resource "aws_glue_catalog_table" "salesforce_logs_raw" {
  name          = "salesforce_logs_raw"
  database_name = aws_glue_catalog_database.main.name
  description   = "Raw Salesforce Event Log Files, Login History, and Setup Audit Trail"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/salesforce/raw/"
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

    # Event Log File Common Fields
    columns {
      name    = "EventType"
      type    = "string"
      comment = "Type of event (Login, Logout, API, Report, etc.)"
    }

    columns {
      name    = "LogDate"
      type    = "string"
      comment = "Date when the event was logged"
    }

    columns {
      name    = "Timestamp"
      type    = "string"
      comment = "Timestamp with time zone"
    }

    columns {
      name    = "TIMESTAMP_DERIVED"
      type    = "string"
      comment = "Derived timestamp in ISO format"
    }

    columns {
      name    = "USER_ID"
      type    = "string"
      comment = "User ID (18-character)"
    }

    columns {
      name    = "USER_NAME"
      type    = "string"
      comment = "Username (email format)"
    }

    columns {
      name    = "USER_TYPE"
      type    = "string"
      comment = "Type of user (Standard, Admin, etc.)"
    }

    columns {
      name    = "REQUEST_ID"
      type    = "string"
      comment = "Unique request identifier"
    }

    columns {
      name    = "SESSION_KEY"
      type    = "string"
      comment = "Session key for correlation"
    }

    columns {
      name    = "ORGANIZATION_ID"
      type    = "string"
      comment = "Salesforce organization ID"
    }

    # Login Event Fields
    columns {
      name    = "LOGIN_KEY"
      type    = "string"
      comment = "Login key for session tracking"
    }

    columns {
      name    = "LOGIN_STATUS"
      type    = "string"
      comment = "Login status code"
    }

    columns {
      name    = "LOGIN_TYPE"
      type    = "string"
      comment = "Login type (Application, SAML, etc.)"
    }

    columns {
      name    = "LOGIN_SUB_TYPE"
      type    = "string"
      comment = "Login sub-type"
    }

    columns {
      name    = "SOURCE_IP"
      type    = "string"
      comment = "Source IP address"
    }

    columns {
      name    = "CLIENT_IP"
      type    = "string"
      comment = "Client IP address"
    }

    columns {
      name    = "BROWSER_TYPE"
      type    = "string"
      comment = "Browser user agent"
    }

    columns {
      name    = "PLATFORM_TYPE"
      type    = "string"
      comment = "Operating system platform"
    }

    columns {
      name    = "TLS_PROTOCOL"
      type    = "string"
      comment = "TLS protocol version"
    }

    columns {
      name    = "CIPHER_SUITE"
      type    = "string"
      comment = "TLS cipher suite used"
    }

    columns {
      name    = "API_TYPE"
      type    = "string"
      comment = "API type used"
    }

    columns {
      name    = "API_VERSION"
      type    = "string"
      comment = "API version"
    }

    # API Event Fields
    columns {
      name    = "METHOD_NAME"
      type    = "string"
      comment = "API method name"
    }

    columns {
      name    = "ENTITY_NAME"
      type    = "string"
      comment = "Salesforce object name"
    }

    columns {
      name    = "ROWS_PROCESSED"
      type    = "string"
      comment = "Number of rows processed"
    }

    columns {
      name    = "STATUS_CODE"
      type    = "string"
      comment = "HTTP status code"
    }

    columns {
      name    = "URI"
      type    = "string"
      comment = "Request URI"
    }

    columns {
      name    = "URI_ID_DERIVED"
      type    = "string"
      comment = "Extracted ID from URI"
    }

    columns {
      name    = "QUERY"
      type    = "string"
      comment = "SOQL query if applicable"
    }

    # Report Event Fields
    columns {
      name    = "REPORT_ID"
      type    = "string"
      comment = "Report ID"
    }

    columns {
      name    = "DASHBOARD_ID"
      type    = "string"
      comment = "Dashboard ID"
    }

    columns {
      name    = "REPORT_NAME"
      type    = "string"
      comment = "Report name"
    }

    columns {
      name    = "DASHBOARD_NAME"
      type    = "string"
      comment = "Dashboard name"
    }

    columns {
      name    = "DISPLAY_TYPE"
      type    = "string"
      comment = "Display type for reports"
    }

    # Data Export Fields
    columns {
      name    = "NUMBER_FIELDS"
      type    = "string"
      comment = "Number of fields exported"
    }

    columns {
      name    = "NUMBER_SOQL_QUERIES"
      type    = "string"
      comment = "Number of SOQL queries"
    }

    columns {
      name    = "DB_TOTAL_TIME"
      type    = "string"
      comment = "Total database time"
    }

    # Setup Audit Trail Fields
    columns {
      name    = "Action"
      type    = "string"
      comment = "Setup action performed"
    }

    columns {
      name    = "Section"
      type    = "string"
      comment = "Setup section"
    }

    columns {
      name    = "CreatedDate"
      type    = "string"
      comment = "Record creation timestamp"
    }

    columns {
      name    = "CreatedById"
      type    = "string"
      comment = "User who made the change"
    }

    columns {
      name    = "Display"
      type    = "string"
      comment = "Display name of changed item"
    }

    columns {
      name    = "DelegateUser"
      type    = "string"
      comment = "Delegate user if applicable"
    }

    columns {
      name    = "ResponsibleNamespacePrefix"
      type    = "string"
      comment = "Namespace prefix if managed package"
    }

    # Login History Specific Fields
    columns {
      name    = "Id"
      type    = "string"
      comment = "Login history record ID"
    }

    columns {
      name    = "UserId"
      type    = "string"
      comment = "User ID"
    }

    columns {
      name    = "LoginTime"
      type    = "string"
      comment = "Login timestamp"
    }

    columns {
      name    = "LoginUrl"
      type    = "string"
      comment = "Login URL used"
    }

    columns {
      name    = "Status"
      type    = "string"
      comment = "Login status"
    }

    columns {
      name    = "Application"
      type    = "string"
      comment = "Application name"
    }

    columns {
      name    = "CountryIso"
      type    = "string"
      comment = "Country ISO code from GeoIP"
    }

    columns {
      name    = "AuthenticationServiceId"
      type    = "string"
      comment = "SSO authentication service ID"
    }

    # Performance Fields
    columns {
      name    = "CPU_TIME"
      type    = "string"
      comment = "CPU time in milliseconds"
    }

    columns {
      name    = "RUN_TIME"
      type    = "string"
      comment = "Total runtime in milliseconds"
    }

    columns {
      name    = "EXEC_TIME"
      type    = "string"
      comment = "Execution time"
    }

    columns {
      name    = "RESPONSE_SIZE"
      type    = "string"
      comment = "Response size in bytes"
    }

    columns {
      name    = "REQUEST_SIZE"
      type    = "string"
      comment = "Request size in bytes"
    }
  }

  partition_keys {
    name = "org_id"
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

# Normalized Salesforce Logs Table (ECS format)
resource "aws_glue_catalog_table" "salesforce_logs" {
  name          = "salesforce_logs"
  database_name = aws_glue_catalog_database.main.name
  description   = "Salesforce event logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/salesforce/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string,reason:string,duration:bigint>"
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
      type    = "struct<id:string,name:string,email:string,roles:array<string>,target:struct<id:string,name:string>>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<country_iso_code:string,city_name:string>>"
      comment = "ECS source fields"
    }

    # Client Fields
    columns {
      name    = "client"
      type    = "struct<ip:string>"
      comment = "ECS client fields"
    }

    # User Agent Fields
    columns {
      name    = "user_agent"
      type    = "struct<original:string,os:struct<name:string>>"
      comment = "ECS user agent fields"
    }

    # URL Fields
    columns {
      name    = "url"
      type    = "struct<original:string,path:string,domain:string>"
      comment = "ECS URL fields"
    }

    # HTTP Fields
    columns {
      name    = "http"
      type    = "struct<request:struct<method:string,bytes:bigint>,response:struct<status_code:int,bytes:bigint>>"
      comment = "ECS HTTP fields"
    }

    # TLS Fields
    columns {
      name    = "tls"
      type    = "struct<version:string,cipher:string>"
      comment = "ECS TLS fields"
    }

    # Organization Fields
    columns {
      name    = "organization"
      type    = "struct<id:string,name:string>"
      comment = "ECS organization fields"
    }

    # Cloud Fields
    columns {
      name    = "cloud"
      type    = "struct<provider:string,service:struct<name:string>>"
      comment = "ECS cloud fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Salesforce-Specific Fields
    columns {
      name    = "salesforce"
      type    = "struct<event_type:string,log_date:string,request_id:string,session_key:string,login_key:string,login_status:string,login_type:string,api:struct<type:string,version:string,method:string>,entity:struct<name:string,id:string>,query:string,report:struct<id:string,name:string>,dashboard:struct<id:string,name:string>,rows_processed:int,performance:struct<cpu_time:double,run_time:double,db_time:double>,setup:struct<action:string,section:string,display:string,delegate_user:string>>"
      comment = "Salesforce-specific event fields"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "org_id"
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
