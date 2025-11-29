/**
 * AWS Glue Table Definitions for Snowflake Audit Logs
 *
 * Creates tables for both raw and normalized Snowflake events including
 * LOGIN_HISTORY, QUERY_HISTORY, ACCESS_HISTORY, GRANTS, and more.
 */

# Raw Snowflake Events Table
resource "aws_glue_catalog_table" "snowflake_logs_raw" {
  name          = "snowflake_logs_raw"
  database_name = aws_glue_catalog_database.main.name
  description   = "Raw Snowflake audit logs from ACCOUNT_USAGE schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/snowflake/raw/"
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

    # Login History Fields
    columns {
      name    = "EVENT_ID"
      type    = "string"
      comment = "Unique event identifier"
    }

    columns {
      name    = "EVENT_TIMESTAMP"
      type    = "string"
      comment = "Event timestamp"
    }

    columns {
      name    = "EVENT_TYPE"
      type    = "string"
      comment = "Type of login event"
    }

    columns {
      name    = "USER_NAME"
      type    = "string"
      comment = "Username"
    }

    columns {
      name    = "CLIENT_IP"
      type    = "string"
      comment = "Client IP address"
    }

    columns {
      name    = "REPORTED_CLIENT_TYPE"
      type    = "string"
      comment = "Client application type"
    }

    columns {
      name    = "REPORTED_CLIENT_VERSION"
      type    = "string"
      comment = "Client application version"
    }

    columns {
      name    = "FIRST_AUTHENTICATION_FACTOR"
      type    = "string"
      comment = "Primary authentication method"
    }

    columns {
      name    = "SECOND_AUTHENTICATION_FACTOR"
      type    = "string"
      comment = "Secondary authentication method (MFA)"
    }

    columns {
      name    = "IS_SUCCESS"
      type    = "string"
      comment = "Login success status (YES/NO)"
    }

    columns {
      name    = "ERROR_CODE"
      type    = "string"
      comment = "Error code for failed logins"
    }

    columns {
      name    = "ERROR_MESSAGE"
      type    = "string"
      comment = "Error message for failed logins"
    }

    # Query History Fields
    columns {
      name    = "QUERY_ID"
      type    = "string"
      comment = "Unique query identifier"
    }

    columns {
      name    = "QUERY_TEXT"
      type    = "string"
      comment = "SQL query text"
    }

    columns {
      name    = "QUERY_TYPE"
      type    = "string"
      comment = "Query type (SELECT, INSERT, etc.)"
    }

    columns {
      name    = "DATABASE_NAME"
      type    = "string"
      comment = "Database name"
    }

    columns {
      name    = "SCHEMA_NAME"
      type    = "string"
      comment = "Schema name"
    }

    columns {
      name    = "ROLE_NAME"
      type    = "string"
      comment = "Role used for query"
    }

    columns {
      name    = "WAREHOUSE_NAME"
      type    = "string"
      comment = "Warehouse used for query"
    }

    columns {
      name    = "WAREHOUSE_SIZE"
      type    = "string"
      comment = "Warehouse size"
    }

    columns {
      name    = "EXECUTION_STATUS"
      type    = "string"
      comment = "Query execution status"
    }

    columns {
      name    = "START_TIME"
      type    = "string"
      comment = "Query start timestamp"
    }

    columns {
      name    = "END_TIME"
      type    = "string"
      comment = "Query end timestamp"
    }

    columns {
      name    = "TOTAL_ELAPSED_TIME"
      type    = "bigint"
      comment = "Total query time in milliseconds"
    }

    columns {
      name    = "BYTES_SCANNED"
      type    = "bigint"
      comment = "Bytes scanned by query"
    }

    columns {
      name    = "ROWS_PRODUCED"
      type    = "bigint"
      comment = "Rows returned by query"
    }

    columns {
      name    = "CREDITS_USED_CLOUD_SERVICES"
      type    = "double"
      comment = "Cloud services credits consumed"
    }

    # Grant Fields
    columns {
      name    = "GRANTEE_NAME"
      type    = "string"
      comment = "Name of user or role receiving grant"
    }

    columns {
      name    = "PRIVILEGE"
      type    = "string"
      comment = "Privilege granted"
    }

    columns {
      name    = "GRANTED_ON"
      type    = "string"
      comment = "Object type for grant"
    }

    columns {
      name    = "GRANTED_BY"
      type    = "string"
      comment = "User who granted privilege"
    }

    columns {
      name    = "GRANT_OPTION"
      type    = "string"
      comment = "Whether grant can be passed on"
    }

    # Session Fields
    columns {
      name    = "SESSION_ID"
      type    = "bigint"
      comment = "Session identifier"
    }

    columns {
      name    = "CREATED_ON"
      type    = "string"
      comment = "Session creation timestamp"
    }

    columns {
      name    = "AUTHENTICATION_METHOD"
      type    = "string"
      comment = "Authentication method used"
    }

    # Data Transfer Fields
    columns {
      name    = "SOURCE_CLOUD"
      type    = "string"
      comment = "Source cloud provider"
    }

    columns {
      name    = "SOURCE_REGION"
      type    = "string"
      comment = "Source region"
    }

    columns {
      name    = "TARGET_CLOUD"
      type    = "string"
      comment = "Target cloud provider"
    }

    columns {
      name    = "TARGET_REGION"
      type    = "string"
      comment = "Target region"
    }

    columns {
      name    = "BYTES_TRANSFERRED"
      type    = "bigint"
      comment = "Bytes transferred"
    }

    columns {
      name    = "TRANSFER_TYPE"
      type    = "string"
      comment = "Type of data transfer"
    }

    # Copy History Fields
    columns {
      name    = "FILE_NAME"
      type    = "string"
      comment = "Name of file loaded"
    }

    columns {
      name    = "STAGE_LOCATION"
      type    = "string"
      comment = "Stage location for file"
    }

    columns {
      name    = "TABLE_NAME"
      type    = "string"
      comment = "Target table name"
    }

    columns {
      name    = "ROW_COUNT"
      type    = "bigint"
      comment = "Number of rows loaded"
    }

    columns {
      name    = "FILE_SIZE"
      type    = "bigint"
      comment = "Size of file in bytes"
    }

    columns {
      name    = "STATUS"
      type    = "string"
      comment = "Load status"
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

# Normalized Snowflake Logs Table (ECS format)
resource "aws_glue_catalog_table" "snowflake_logs" {
  name          = "snowflake_logs"
  database_name = aws_glue_catalog_database.main.name
  description   = "Snowflake audit logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/snowflake/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,reason:string,duration:bigint,id:string,provider:string,module:string>"
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
      type    = "struct<name:string,id:string,roles:array<string>,target:struct<name:string>>"
      comment = "ECS user fields"
    }

    # Source Fields
    columns {
      name    = "source"
      type    = "struct<ip:string,cloud:struct<provider:string,region:string>>"
      comment = "ECS source fields"
    }

    # Destination Fields
    columns {
      name    = "destination"
      type    = "struct<cloud:struct<provider:string,region:string>>"
      comment = "ECS destination fields"
    }

    # User Agent Fields
    columns {
      name    = "user_agent"
      type    = "struct<name:string,version:string>"
      comment = "ECS user agent fields"
    }

    # File Fields
    columns {
      name    = "file"
      type    = "struct<name:string,size:bigint,path:string>"
      comment = "ECS file fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Snowflake-Specific Fields
    columns {
      name    = "snowflake"
      type    = "struct<event_id:string,event_type:string,login:struct<is_success:string,error_code:string,error_message:string,first_auth_factor:string,second_auth_factor:string,client_type:string,client_version:string,connection_id:string,session_id:string>,query:struct<id:string,text:string,type:string,tag:string,hash:string,parameterized_hash:string>,execution:struct<status:string,error_code:string,error_message:string>,database:struct<name:string,schema:string>,warehouse:struct<name:string,size:string,type:string>,role:string,session_id:string,performance:struct<elapsed_time_ms:bigint,bytes_scanned:bigint,bytes_written:bigint,bytes_spilled_local:bigint,bytes_spilled_remote:bigint,rows_produced:bigint,rows_inserted:bigint,rows_updated:bigint,rows_deleted:bigint,compilation_time_ms:bigint,execution_time_ms:bigint,queued_provisioning_time_ms:bigint,queued_overload_time_ms:bigint,credits_used:double,partitions_scanned:bigint,partitions_total:bigint>,cluster_number:int,is_client_generated:boolean,grant:struct<privilege:string,granted_on:string,object_name:string,grantee_name:string,granted_by:string,grant_option:boolean,is_high_risk:boolean,table_catalog:string,table_schema:string>,session:struct<id:bigint,authentication_method:string,login_event_id:string,client_application_id:string,client_environment:map<string,string>,client_build_id:string,client_version:string>,access:struct<direct_objects:string,base_objects:string,objects_modified:string,object_count:int,policy_name:string,parent_query_id:string,root_query_id:string>,copy:struct<table_name:string,table_catalog:string,table_schema:string,stage_location:string,file_name:string,status:string,row_count:bigint,row_parsed:bigint,file_size:bigint,first_error_message:string,first_error_line_number:int,error_count:int,error_limit:int,pipe_name:string,pipe_received_time:string>,transfer:struct<type:string,source_cloud:string,source_region:string,target_cloud:string,target_region:string,bytes_transferred:bigint>>"
      comment = "Snowflake-specific event fields"
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
