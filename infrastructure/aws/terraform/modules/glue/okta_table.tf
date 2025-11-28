# Glue table for Okta logs (normalized to ECS format)

resource "aws_glue_catalog_table" "okta_logs" {
  name          = "okta_logs"
  database_name = var.glue_database_name
  description   = "Okta System Log events normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/okta/normalized/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "okta-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format" = "1"
        "ignore.malformed.json" = "false"
      }
    }

    columns {
      name = "timestamp"
      type = "string"
      comment = "Event timestamp in ISO 8601 format"
    }

    columns {
      name = "ecs_version"
      type = "string"
      comment = "ECS schema version"
    }

    columns {
      name = "event"
      type = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,severity:int,created:string,id:string,provider:string,reason:string>"
      comment = "ECS event fields"
    }

    columns {
      name = "message"
      type = "string"
      comment = "Human-readable event message"
    }

    columns {
      name = "user"
      type = "struct<name:string,id:string,full_name:string,email:string>"
      comment = "User information"
    }

    columns {
      name = "source"
      type = "struct<ip:string,geo:struct<city_name:string,country_name:string,region_name:string,postal_code:string,location:struct<lat:double,lon:double>>>"
      comment = "Source IP and geolocation"
    }

    columns {
      name = "user_agent"
      type = "struct<original:string>"
      comment = "User agent string"
    }

    columns {
      name = "related"
      type = "struct<ip:array<string>,user:array<string>>"
      comment = "Related entities for correlation"
    }

    columns {
      name = "okta"
      type = "struct<event_type:string,display_message:string,severity:string,transaction:struct<id:string,type:string>,authentication_context:struct<authentication_provider:string,authentication_step:int,credential_provider:string,credential_type:string,external_session_id:string>,security_context:struct<as_number:int,as_org:string,isp:string,domain:string>,client:struct<device:string,id:string,zone:string>,target:array<struct<id:string,type:string,alternate_id:string,display_name:string>>,outcome:struct<result:string,reason:string>>"
      comment = "Okta-specific fields"
    }

    columns {
      name = "_raw"
      type = "string"
      comment = "Original raw event JSON"
    }

    # Partition columns
    columns {
      name = "year"
      type = "string"
      comment = "Partition: Year"
    }

    columns {
      name = "month"
      type = "string"
      comment = "Partition: Month"
    }

    columns {
      name = "day"
      type = "string"
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

# Glue table for raw Okta logs (before normalization)
resource "aws_glue_catalog_table" "okta_logs_raw" {
  name          = "okta_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Okta System Log events from API"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/okta/raw/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "okta-raw-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format" = "1"
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "uuid"
      type = "string"
      comment = "Unique event identifier"
    }

    columns {
      name = "published"
      type = "string"
      comment = "Event timestamp"
    }

    columns {
      name = "eventtype"
      type = "string"
      comment = "Event type"
    }

    columns {
      name = "version"
      type = "string"
      comment = "API version"
    }

    columns {
      name = "severity"
      type = "string"
      comment = "Event severity"
    }

    columns {
      name = "displaymessage"
      type = "string"
      comment = "Display message"
    }

    columns {
      name = "actor"
      type = "struct<id:string,type:string,alternateid:string,displayname:string,detailentry:map<string,string>>"
      comment = "Actor (user) information"
    }

    columns {
      name = "client"
      type = "struct<useragent:struct<rawuseragent:string,os:string,browser:string>,geographicalcontext:struct<geolocation:struct<lat:double,lon:double>,city:string,state:string,country:string,postalcode:string>,zone:string,ipaddress:string,device:string,id:string>"
      comment = "Client information"
    }

    columns {
      name = "outcome"
      type = "struct<result:string,reason:string>"
      comment = "Outcome information"
    }

    columns {
      name = "target"
      type = "array<struct<id:string,type:string,alternateid:string,displayname:string,detailentry:map<string,string>>>"
      comment = "Target resources"
    }

    columns {
      name = "transaction"
      type = "struct<id:string,type:string,detail:map<string,string>>"
      comment = "Transaction information"
    }

    columns {
      name = "debugcontext"
      type = "struct<debugdata:map<string,string>>"
      comment = "Debug context"
    }

    columns {
      name = "authenticationcontext"
      type = "struct<authenticationprovider:string,authenticationstep:int,credentialprovider:string,credentialtype:string,externalsessionid:string,interface:string,issuer:struct<id:string,type:string>>"
      comment = "Authentication context"
    }

    columns {
      name = "securitycontext"
      type = "struct<asnumber:int,asorg:string,isp:string,domain:string,isproxy:boolean>"
      comment = "Security context"
    }

    columns {
      name = "request"
      type = "struct<ipchain:array<struct<ip:string,geographicalcontext:struct<city:string,state:string,country:string,postalcode:string,geolocation:struct<lat:double,lon:double>>,version:string,source:string>>>"
      comment = "Request information including IP chain"
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
