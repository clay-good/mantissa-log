# Glue table for Duo Security logs (normalized to ECS format)

resource "aws_glue_catalog_table" "duo_authentication_logs" {
  name          = "duo_authentication_logs"
  database_name = var.glue_database_name
  description   = "Duo Security authentication logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"         = "json"
    "compressionType"        = "none"
    "typeOfData"             = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/duo/authentication/normalized/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "duo-auth-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "false"
      }
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "Event timestamp in ISO 8601 format"
    }

    columns {
      name    = "ecs_version"
      type    = "string"
      comment = "ECS schema version"
    }

    columns {
      name    = "event"
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,reason:string,id:string,provider:string,module:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "user"
      type    = "struct<name:string,id:string,email:string>"
      comment = "User information"
    }

    columns {
      name    = "source"
      type    = "struct<ip:string,geo:struct<city_name:string,region_name:string,country_iso_code:string>>"
      comment = "Source IP and geolocation"
    }

    columns {
      name    = "user_agent"
      type    = "struct<name:string,os:struct<name:string,version:string>,original:string>"
      comment = "User agent information"
    }

    columns {
      name    = "related"
      type    = "struct<ip:array<string>,user:array<string>>"
      comment = "Related entities for correlation"
    }

    columns {
      name    = "duo"
      type    = "struct<txid:string,event_type:string,result:string,reason:string,factor:string,integration:string,integration_key:string,user:struct<name:string,key:string,groups:array<string>>,access_device:struct<ip:string,hostname:string,browser:string,browser_version:string,os:string,os_version:string,flash_version:string,java_version:string,is_encryption_enabled:boolean,is_firewall_enabled:boolean,is_password_set:boolean,location:struct<city:string,state:string,country:string>>,auth_device:struct<name:string,ip:string,type:string,location:struct<city:string,state:string,country:string>>,application:struct<name:string,key:string>,alias:string,email:string,isotimestamp:string,new_enrollment:boolean,trusted_endpoint_status:string>"
      comment = "Duo-specific authentication fields"
    }

    columns {
      name    = "_raw"
      type    = "string"
      comment = "Original raw event JSON"
    }

    # Partition columns
    columns {
      name    = "year"
      type    = "string"
      comment = "Partition: Year"
    }

    columns {
      name    = "month"
      type    = "string"
      comment = "Partition: Month"
    }

    columns {
      name    = "day"
      type    = "string"
      comment = "Partition: Day"
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

# Glue table for Duo administrator activity logs
resource "aws_glue_catalog_table" "duo_admin_logs" {
  name          = "duo_admin_logs"
  database_name = var.glue_database_name
  description   = "Duo Security administrator activity logs normalized to ECS"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"         = "json"
    "compressionType"        = "none"
    "typeOfData"             = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/duo/admin/normalized/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "duo-admin-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "false"
      }
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "Event timestamp in ISO 8601 format"
    }

    columns {
      name    = "ecs_version"
      type    = "string"
      comment = "ECS schema version"
    }

    columns {
      name    = "event"
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "user"
      type    = "struct<name:string>"
      comment = "Admin user information"
    }

    columns {
      name    = "duo"
      type    = "struct<action:string,object:string,description:map<string,string>,admin_name:string,isotimestamp:string>"
      comment = "Duo-specific admin activity fields"
    }

    columns {
      name    = "_raw"
      type    = "string"
      comment = "Original raw event JSON"
    }

    # Partition columns
    columns {
      name    = "year"
      type    = "string"
      comment = "Partition: Year"
    }

    columns {
      name    = "month"
      type    = "string"
      comment = "Partition: Month"
    }

    columns {
      name    = "day"
      type    = "string"
      comment = "Partition: Day"
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

# Glue table for Duo telephony logs
resource "aws_glue_catalog_table" "duo_telephony_logs" {
  name          = "duo_telephony_logs"
  database_name = var.glue_database_name
  description   = "Duo Security telephony logs (SMS and phone calls) normalized to ECS"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"         = "json"
    "compressionType"        = "none"
    "typeOfData"             = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/duo/telephony/normalized/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "duo-telephony-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "false"
      }
    }

    columns {
      name    = "timestamp"
      type    = "string"
      comment = "Event timestamp in ISO 8601 format"
    }

    columns {
      name    = "ecs_version"
      type    = "string"
      comment = "ECS schema version"
    }

    columns {
      name    = "event"
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "duo"
      type    = "struct<phone:string,telephony_type:string,context:string,credits:int,isotimestamp:string>"
      comment = "Duo-specific telephony fields"
    }

    columns {
      name    = "_raw"
      type    = "string"
      comment = "Original raw event JSON"
    }

    # Partition columns
    columns {
      name    = "year"
      type    = "string"
      comment = "Partition: Year"
    }

    columns {
      name    = "month"
      type    = "string"
      comment = "Partition: Month"
    }

    columns {
      name    = "day"
      type    = "string"
      comment = "Partition: Day"
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

# Raw logs tables (before normalization)

resource "aws_glue_catalog_table" "duo_authentication_logs_raw" {
  name          = "duo_authentication_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Duo authentication logs from API"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "none"
    "typeOfData"      = "file"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/duo/authentication/raw/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "duo-auth-raw-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name    = "txid"
      type    = "string"
      comment = "Transaction ID"
    }

    columns {
      name    = "timestamp"
      type    = "bigint"
      comment = "Unix timestamp"
    }

    columns {
      name    = "user"
      type    = "struct<name:string,key:string,email:string,groups:array<string>>"
      comment = "User information"
    }

    columns {
      name    = "factor"
      type    = "string"
      comment = "Authentication factor used"
    }

    columns {
      name    = "result"
      type    = "string"
      comment = "Authentication result"
    }

    columns {
      name    = "reason"
      type    = "string"
      comment = "Result reason"
    }

    columns {
      name    = "event_type"
      type    = "string"
      comment = "Event type"
    }

    columns {
      name    = "access_device"
      type    = "struct<ip:string,hostname:string,browser:string,browser_version:string,os:string,os_version:string,location:struct<city:string,state:string,country:string>>"
      comment = "Access device information"
    }

    columns {
      name    = "auth_device"
      type    = "struct<name:string,ip:string,type:string,location:struct<city:string,state:string,country:string>>"
      comment = "Authentication device information"
    }

    columns {
      name    = "application"
      type    = "struct<name:string,key:string>"
      comment = "Application information"
    }

    columns {
      name    = "isotimestamp"
      type    = "string"
      comment = "ISO timestamp"
    }

    # Partition columns
    columns {
      name = "year"
      type = "string"
    }

    columns {
      name = "month"
      type = "string"
    }

    columns {
      name = "day"
      type = "string"
    }

    columns {
      name = "hour"
      type = "string"
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

resource "aws_glue_catalog_table" "duo_admin_logs_raw" {
  name          = "duo_admin_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Duo administrator activity logs from API"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "none"
    "typeOfData"      = "file"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/duo/admin/raw/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "duo-admin-raw-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name    = "timestamp"
      type    = "bigint"
      comment = "Unix timestamp"
    }

    columns {
      name    = "username"
      type    = "string"
      comment = "Admin username"
    }

    columns {
      name    = "action"
      type    = "string"
      comment = "Admin action performed"
    }

    columns {
      name    = "object"
      type    = "string"
      comment = "Object affected"
    }

    columns {
      name    = "description"
      type    = "map<string,string>"
      comment = "Action description"
    }

    columns {
      name    = "isotimestamp"
      type    = "string"
      comment = "ISO timestamp"
    }

    # Partition columns
    columns {
      name = "year"
      type = "string"
    }

    columns {
      name = "month"
      type = "string"
    }

    columns {
      name = "day"
      type = "string"
    }

    columns {
      name = "hour"
      type = "string"
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

resource "aws_glue_catalog_table" "duo_telephony_logs_raw" {
  name          = "duo_telephony_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Duo telephony logs from API"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "none"
    "typeOfData"      = "file"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/duo/telephony/raw/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "duo-telephony-raw-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format"  = "1"
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name    = "timestamp"
      type    = "bigint"
      comment = "Unix timestamp"
    }

    columns {
      name    = "phone"
      type    = "string"
      comment = "Phone number"
    }

    columns {
      name    = "type"
      type    = "string"
      comment = "Telephony type (sms, call)"
    }

    columns {
      name    = "context"
      type    = "string"
      comment = "Context"
    }

    columns {
      name    = "credits"
      type    = "int"
      comment = "Credits used"
    }

    columns {
      name    = "isotimestamp"
      type    = "string"
      comment = "ISO timestamp"
    }

    # Partition columns
    columns {
      name = "year"
      type = "string"
    }

    columns {
      name = "month"
      type = "string"
    }

    columns {
      name = "day"
      type = "string"
    }

    columns {
      name = "hour"
      type = "string"
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
