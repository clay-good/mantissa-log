/**
 * AWS Glue Table Definitions for Docker Container Runtime Logs
 *
 * Creates tables for both raw and normalized Docker daemon events
 * and container logs. Supports events from Docker API and logging drivers.
 */

# Raw Docker Events Table
resource "aws_glue_catalog_table" "docker_logs_raw" {
  name          = "docker_logs_raw"
  database_name = var.glue_database_name
  description   = "Raw Docker daemon events and container logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/docker/raw/"
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

    # Docker Events API Fields
    columns {
      name    = "Type"
      type    = "string"
      comment = "Event type (container, image, volume, network, daemon, plugin)"
    }

    columns {
      name    = "Action"
      type    = "string"
      comment = "Event action (create, start, stop, kill, die, destroy, etc.)"
    }

    columns {
      name    = "Actor"
      type    = "struct<ID:string,Attributes:map<string,string>>"
      comment = "Event actor (container, image, volume, network that triggered event)"
    }

    columns {
      name    = "scope"
      type    = "string"
      comment = "Event scope (local or swarm)"
    }

    columns {
      name    = "time"
      type    = "bigint"
      comment = "Unix timestamp in seconds"
    }

    columns {
      name    = "timeNano"
      type    = "bigint"
      comment = "Unix timestamp in nanoseconds"
    }

    columns {
      name    = "status"
      type    = "string"
      comment = "Event status"
    }

    columns {
      name    = "id"
      type    = "string"
      comment = "Container or resource ID"
    }

    columns {
      name    = "from"
      type    = "string"
      comment = "Image name for container events"
    }

    # Container Log Fields (from logging drivers)
    columns {
      name    = "log"
      type    = "string"
      comment = "Container log message"
    }

    columns {
      name    = "stream"
      type    = "string"
      comment = "Log stream (stdout or stderr)"
    }

    columns {
      name    = "container_id"
      type    = "string"
      comment = "Container ID"
    }

    columns {
      name    = "container_name"
      type    = "string"
      comment = "Container name"
    }

    columns {
      name    = "source"
      type    = "string"
      comment = "Log source"
    }

    columns {
      name    = "host"
      type    = "string"
      comment = "Docker host name"
    }

    # Kubernetes Context (if running in K8s)
    columns {
      name    = "kubernetes"
      type    = "struct<namespace_name:string,pod_name:string,container_name:string,pod_id:string,labels:map<string,string>>"
      comment = "Kubernetes context if container is running in K8s"
    }
  }

  partition_keys {
    name = "host_name"
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

# Normalized Docker Logs Table (ECS format)
resource "aws_glue_catalog_table" "docker_logs" {
  name          = "docker_logs"
  database_name = var.glue_database_name
  description   = "Docker container runtime logs normalized to Elastic Common Schema"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"              = "TRUE"
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"            = "file"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${var.logs_bucket}/docker/normalized/"
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
      type    = "struct<kind:string,category:array<string>,type:array<string>,action:string,outcome:string,provider:string,module:string>"
      comment = "ECS event fields"
    }

    columns {
      name    = "message"
      type    = "string"
      comment = "Log message (for container logs)"
    }

    # Container Fields (ECS standard)
    columns {
      name    = "container"
      type    = "struct<id:string,name:string,image:struct<name:string,tag:string>,runtime:string>"
      comment = "ECS container fields"
    }

    # Host Fields
    columns {
      name    = "host"
      type    = "struct<hostname:string,name:string>"
      comment = "ECS host fields"
    }

    # Process Fields
    columns {
      name    = "process"
      type    = "struct<exit_code:int>"
      comment = "ECS process fields"
    }

    # Log Fields
    columns {
      name    = "log"
      type    = "struct<level:string,logger:string>"
      comment = "ECS log fields"
    }

    # Related Fields
    columns {
      name    = "related"
      type    = "struct<hosts:array<string>>"
      comment = "ECS related fields for correlation"
    }

    # Docker-Specific Fields
    columns {
      name    = "docker"
      type    = "struct<type:string,action:string,actor:struct<id:string,attributes:map<string,string>>,scope:string,status:string,container:struct<id:string,name:string,image:string,stream:string,labels:map<string,string>>,image:struct<id:string,name:string>,volume:struct<name:string,driver:string>,network:struct<name:string,type:string,container:string>,log:struct<stream:string,source:string>>"
      comment = "Docker-specific event fields"
    }

    # Kubernetes Context (if present)
    columns {
      name    = "kubernetes"
      type    = "struct<namespace:string,pod:struct<name:string>,container:struct<name:string>>"
      comment = "Kubernetes context if container is running in K8s"
    }

    # Raw Event Preservation
    columns {
      name    = "_raw"
      type    = "string"
      comment = "Raw event data preserved for forensics"
    }
  }

  partition_keys {
    name = "host_name"
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
