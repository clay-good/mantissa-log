resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.main.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "gzip"
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

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/cloudtrail/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }

    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }

    columns {
      name = "eventtime"
      type = "string"
    }

    columns {
      name = "eventsource"
      type = "string"
    }

    columns {
      name = "eventname"
      type = "string"
    }

    columns {
      name = "awsregion"
      type = "string"
    }

    columns {
      name = "sourceipaddress"
      type = "string"
    }

    columns {
      name = "useragent"
      type = "string"
    }

    columns {
      name = "errorcode"
      type = "string"
    }

    columns {
      name = "errormessage"
      type = "string"
    }

    columns {
      name = "requestparameters"
      type = "string"
    }

    columns {
      name = "responseelements"
      type = "string"
    }

    columns {
      name = "additionaleventdata"
      type = "string"
    }

    columns {
      name = "requestid"
      type = "string"
    }

    columns {
      name = "eventid"
      type = "string"
    }

    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }

    columns {
      name = "eventtype"
      type = "string"
    }

    columns {
      name = "recipientaccountid"
      type = "string"
    }
  }
}

resource "aws_glue_catalog_table" "vpc_flow_logs" {
  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.main.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "skip.header.line.count" = "1"
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

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/flowlogs/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      parameters = {
        "field.delim" = " "
      }
    }

    columns {
      name = "version"
      type = "int"
    }

    columns {
      name = "account_id"
      type = "string"
    }

    columns {
      name = "interface_id"
      type = "string"
    }

    columns {
      name = "srcaddr"
      type = "string"
    }

    columns {
      name = "dstaddr"
      type = "string"
    }

    columns {
      name = "srcport"
      type = "int"
    }

    columns {
      name = "dstport"
      type = "int"
    }

    columns {
      name = "protocol"
      type = "int"
    }

    columns {
      name = "packets"
      type = "bigint"
    }

    columns {
      name = "bytes"
      type = "bigint"
    }

    columns {
      name = "start"
      type = "bigint"
    }

    columns {
      name = "end"
      type = "bigint"
    }

    columns {
      name = "action"
      type = "string"
    }

    columns {
      name = "log_status"
      type = "string"
    }
  }
}

resource "aws_glue_catalog_table" "guardduty" {
  name          = "guardduty_findings"
  database_name = aws_glue_catalog_database.main.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "gzip"
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

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/guardduty/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "schemaversion"
      type = "string"
    }

    columns {
      name = "accountid"
      type = "string"
    }

    columns {
      name = "region"
      type = "string"
    }

    columns {
      name = "partition"
      type = "string"
    }

    columns {
      name = "id"
      type = "string"
    }

    columns {
      name = "arn"
      type = "string"
    }

    columns {
      name = "type"
      type = "string"
    }

    columns {
      name = "resource"
      type = "string"
    }

    columns {
      name = "severity"
      type = "double"
    }

    columns {
      name = "createdat"
      type = "string"
    }

    columns {
      name = "updatedat"
      type = "string"
    }

    columns {
      name = "title"
      type = "string"
    }

    columns {
      name = "description"
      type = "string"
    }
  }
}
