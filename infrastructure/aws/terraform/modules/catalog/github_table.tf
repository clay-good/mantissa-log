/**
 * AWS Glue Table Definitions for GitHub Enterprise Audit Logs
 *
 * Defines schemas for raw and normalized GitHub Enterprise audit logs.
 * Supports both enterprise-level and organization-level audit logs.
 */

resource "aws_glue_catalog_table" "github_raw" {
  name          = "github_raw"
  database_name = aws_glue_catalog_database.main.name

  description = "Raw GitHub Enterprise audit logs (NDJSON)"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"           = "file"
    "skip.header.line.count" = "0"
  }

  partition_keys {
    name = "source_type"
    type = "string"
    comment = "Source type (enterprise or org)"
  }

  partition_keys {
    name = "source_name"
    type = "string"
    comment = "Enterprise slug or organization name"
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

  storage_descriptor {
    location      = "s3://${var.logs_bucket_name}/github/raw/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "ignore.malformed.json" = "true"
        "case.insensitive"      = "false"
      }
    }

    # Core audit log fields
    columns {
      name = "@timestamp"
      type = "bigint"
      comment = "Unix timestamp in milliseconds when event occurred"
    }

    columns {
      name = "action"
      type = "string"
      comment = "Name of the action that was performed"
    }

    columns {
      name = "actor"
      type = "string"
      comment = "User who performed the action"
    }

    columns {
      name = "actor_id"
      type = "bigint"
      comment = "ID of the user who performed the action"
    }

    columns {
      name = "actor_location"
      type = "struct<country_code:string>"
      comment = "Physical location where action was performed"
    }

    columns {
      name = "created_at"
      type = "bigint"
      comment = "Unix timestamp in milliseconds when log was created"
    }

    columns {
      name = "_document_id"
      type = "string"
      comment = "Unique identifier for the audit log event"
    }

    # Organization/Enterprise fields
    columns {
      name = "org"
      type = "string"
      comment = "Organization name"
    }

    columns {
      name = "org_id"
      type = "bigint"
      comment = "Organization ID"
    }

    columns {
      name = "business"
      type = "string"
      comment = "Enterprise account name"
    }

    columns {
      name = "business_id"
      type = "bigint"
      comment = "Enterprise account ID"
    }

    # User fields
    columns {
      name = "user"
      type = "string"
      comment = "User affected by the action"
    }

    columns {
      name = "user_id"
      type = "bigint"
      comment = "ID of user affected by the action"
    }

    # Repository fields
    columns {
      name = "repo"
      type = "string"
      comment = "Repository name (org/repo format)"
    }

    columns {
      name = "repo_id"
      type = "bigint"
      comment = "Repository ID"
    }

    columns {
      name = "repository"
      type = "string"
      comment = "Repository name"
    }

    columns {
      name = "repository_public"
      type = "boolean"
      comment = "Whether repository is public"
    }

    columns {
      name = "visibility"
      type = "string"
      comment = "Visibility level (public, private, internal)"
    }

    columns {
      name = "public"
      type = "boolean"
      comment = "Whether resource is public"
    }

    # Team fields
    columns {
      name = "team"
      type = "string"
      comment = "Team name"
    }

    columns {
      name = "team_id"
      type = "bigint"
      comment = "Team ID"
    }

    # Permission fields
    columns {
      name = "permission"
      type = "string"
      comment = "Permission level granted or changed"
    }

    # User agent
    columns {
      name = "user_agent"
      type = "string"
      comment = "User agent string from client"
    }

    # OAuth/Application fields
    columns {
      name = "oauth_application_id"
      type = "bigint"
      comment = "OAuth application ID"
    }

    columns {
      name = "application"
      type = "string"
      comment = "Application name"
    }

    columns {
      name = "oauth_scopes"
      type = "array<string>"
      comment = "OAuth scopes granted"
    }

    columns {
      name = "token_scopes"
      type = "string"
      comment = "Token scopes"
    }

    columns {
      name = "programmatic_access_type"
      type = "string"
      comment = "Type of programmatic access (OAuth, PAT, etc.)"
    }

    # Transport protocol
    columns {
      name = "transport_protocol"
      type = "int"
      comment = "Transport protocol ID"
    }

    columns {
      name = "transport_protocol_name"
      type = "string"
      comment = "Transport protocol name (http, ssh)"
    }

    # Issue/PR fields
    columns {
      name = "issue"
      type = "string"
      comment = "Issue reference"
    }

    columns {
      name = "pull_request"
      type = "string"
      comment = "Pull request reference"
    }

    # Branch/Protection fields
    columns {
      name = "branch"
      type = "string"
      comment = "Branch name"
    }

    columns {
      name = "protected_branch"
      type = "string"
      comment = "Protected branch name"
    }

    # Workflow fields
    columns {
      name = "workflow"
      type = "string"
      comment = "Workflow name"
    }

    columns {
      name = "workflow_id"
      type = "bigint"
      comment = "Workflow ID"
    }

    columns {
      name = "workflow_run_id"
      type = "bigint"
      comment = "Workflow run ID"
    }

    # External identity fields
    columns {
      name = "external_identity_nameid"
      type = "string"
      comment = "External SAML identity NameID"
    }

    columns {
      name = "external_identity_username"
      type = "string"
      comment = "External SAML identity username"
    }

    # Hook fields
    columns {
      name = "hook_id"
      type = "bigint"
      comment = "Webhook ID"
    }

    columns {
      name = "events"
      type = "array<string>"
      comment = "Webhook events subscribed to"
    }

    columns {
      name = "active"
      type = "boolean"
      comment = "Whether webhook is active"
    }

    # Deployment fields
    columns {
      name = "deployment_id"
      type = "bigint"
      comment = "Deployment ID"
    }

    columns {
      name = "environment"
      type = "string"
      comment = "Deployment environment"
    }

    # Billing fields
    columns {
      name = "previous_plan_name"
      type = "string"
      comment = "Previous billing plan name"
    }

    columns {
      name = "plan_name"
      type = "string"
      comment = "Current billing plan name"
    }

    # Additional data
    columns {
      name = "data"
      type = "map<string,string>"
      comment = "Additional event-specific data"
    }

    # Invite fields
    columns {
      name = "email"
      type = "string"
      comment = "Email address for invitations"
    }

    # Secret scanning fields
    columns {
      name = "secret_type"
      type = "string"
      comment = "Type of secret detected"
    }

    columns {
      name = "secret_scanning_push_protection_bypassed"
      type = "boolean"
      comment = "Whether secret push protection was bypassed"
    }

    # IP allow list fields
    columns {
      name = "ip_allow_list_entry"
      type = "string"
      comment = "IP allow list entry"
    }

    columns {
      name = "ip_allow_list_enabled"
      type = "boolean"
      comment = "Whether IP allow list is enabled"
    }

    # Dependabot fields
    columns {
      name = "alert_id"
      type = "bigint"
      comment = "Dependabot alert ID"
    }

    columns {
      name = "package_name"
      type = "string"
      comment = "Package name for dependency"
    }

    columns {
      name = "package_ecosystem"
      type = "string"
      comment = "Package ecosystem (npm, pip, etc.)"
    }
  }
}

resource "aws_glue_catalog_table" "github_normalized" {
  name          = "github_normalized"
  database_name = aws_glue_catalog_database.main.name

  description = "ECS-normalized GitHub Enterprise audit logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "parquet"
    "compressionType" = "snappy"
  }

  partition_keys {
    name = "source_name"
    type = "string"
    comment = "Enterprise slug or organization name"
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
    location      = "s3://${var.logs_bucket_name}/github/normalized/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      name                  = "parquet"
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    # ECS Core Fields
    columns {
      name = "timestamp"
      type = "timestamp"
      comment = "ECS @timestamp"
    }

    columns {
      name = "ecs_version"
      type = "string"
      comment = "ECS version"
    }

    # Event fields
    columns {
      name = "event_kind"
      type = "string"
      comment = "ECS event.kind"
    }

    columns {
      name = "event_category"
      type = "array<string>"
      comment = "ECS event.category"
    }

    columns {
      name = "event_type"
      type = "array<string>"
      comment = "ECS event.type"
    }

    columns {
      name = "event_action"
      type = "string"
      comment = "ECS event.action"
    }

    columns {
      name = "event_outcome"
      type = "string"
      comment = "ECS event.outcome"
    }

    columns {
      name = "event_created"
      type = "timestamp"
      comment = "ECS event.created"
    }

    columns {
      name = "event_id"
      type = "string"
      comment = "ECS event.id"
    }

    columns {
      name = "event_provider"
      type = "string"
      comment = "ECS event.provider"
    }

    columns {
      name = "event_module"
      type = "string"
      comment = "ECS event.module"
    }

    # User fields
    columns {
      name = "user_name"
      type = "string"
      comment = "ECS user.name"
    }

    columns {
      name = "user_id"
      type = "string"
      comment = "ECS user.id"
    }

    # Source fields
    columns {
      name = "source_geo_country_iso_code"
      type = "string"
      comment = "ECS source.geo.country_iso_code"
    }

    # User agent fields
    columns {
      name = "user_agent_original"
      type = "string"
      comment = "ECS user_agent.original"
    }

    # Organization fields
    columns {
      name = "organization_name"
      type = "string"
      comment = "ECS organization.name"
    }

    # Related fields
    columns {
      name = "related_user"
      type = "array<string>"
      comment = "ECS related.user"
    }

    # GitHub-specific fields
    columns {
      name = "github_action"
      type = "string"
      comment = "GitHub action"
    }

    columns {
      name = "github_actor"
      type = "string"
      comment = "GitHub actor"
    }

    columns {
      name = "github_actor_id"
      type = "bigint"
      comment = "GitHub actor ID"
    }

    columns {
      name = "github_actor_location"
      type = "struct<country_code:string>"
      comment = "GitHub actor location"
    }

    columns {
      name = "github_org"
      type = "string"
      comment = "GitHub organization"
    }

    columns {
      name = "github_business"
      type = "string"
      comment = "GitHub enterprise"
    }

    columns {
      name = "github_repo"
      type = "string"
      comment = "GitHub repository"
    }

    columns {
      name = "github_created_at"
      type = "bigint"
      comment = "GitHub created_at timestamp"
    }

    columns {
      name = "github_document_id"
      type = "string"
      comment = "GitHub document ID"
    }

    columns {
      name = "github_user"
      type = "string"
      comment = "GitHub user"
    }

    columns {
      name = "github_user_agent"
      type = "string"
      comment = "GitHub user agent"
    }

    columns {
      name = "github_team"
      type = "string"
      comment = "GitHub team"
    }

    columns {
      name = "github_permission"
      type = "string"
      comment = "GitHub permission"
    }

    columns {
      name = "github_visibility"
      type = "string"
      comment = "GitHub visibility"
    }

    columns {
      name = "github_public"
      type = "boolean"
      comment = "GitHub public flag"
    }

    columns {
      name = "github_oauth_application_id"
      type = "bigint"
      comment = "GitHub OAuth application ID"
    }

    columns {
      name = "github_application"
      type = "string"
      comment = "GitHub application"
    }

    columns {
      name = "github_transport_protocol"
      type = "int"
      comment = "GitHub transport protocol"
    }

    columns {
      name = "github_transport_protocol_name"
      type = "string"
      comment = "GitHub transport protocol name"
    }

    columns {
      name = "github_data"
      type = "map<string,string>"
      comment = "GitHub additional data"
    }

    columns {
      name = "github_programmatic_access_type"
      type = "string"
      comment = "GitHub programmatic access type"
    }

    columns {
      name = "github_token_scopes"
      type = "string"
      comment = "GitHub token scopes"
    }

    columns {
      name = "github_repo_id"
      type = "bigint"
      comment = "GitHub repository ID"
    }

    columns {
      name = "github_repository"
      type = "string"
      comment = "GitHub repository name"
    }

    columns {
      name = "github_repository_public"
      type = "boolean"
      comment = "GitHub repository public flag"
    }

    columns {
      name = "github_issue"
      type = "string"
      comment = "GitHub issue"
    }

    columns {
      name = "github_pull_request"
      type = "string"
      comment = "GitHub pull request"
    }

    columns {
      name = "github_branch"
      type = "string"
      comment = "GitHub branch"
    }

    columns {
      name = "github_protected_branch"
      type = "string"
      comment = "GitHub protected branch"
    }

    columns {
      name = "github_workflow"
      type = "string"
      comment = "GitHub workflow"
    }

    columns {
      name = "github_workflow_id"
      type = "bigint"
      comment = "GitHub workflow ID"
    }

    columns {
      name = "github_workflow_run_id"
      type = "bigint"
      comment = "GitHub workflow run ID"
    }

    columns {
      name = "github_external_identity_nameid"
      type = "string"
      comment = "GitHub external identity NameID"
    }

    columns {
      name = "github_external_identity_username"
      type = "string"
      comment = "GitHub external identity username"
    }

    columns {
      name = "github_hook_id"
      type = "bigint"
      comment = "GitHub hook ID"
    }

    columns {
      name = "github_events"
      type = "array<string>"
      comment = "GitHub webhook events"
    }

    columns {
      name = "github_active"
      type = "boolean"
      comment = "GitHub active flag"
    }

    columns {
      name = "github_deployment_id"
      type = "bigint"
      comment = "GitHub deployment ID"
    }

    columns {
      name = "github_environment"
      type = "string"
      comment = "GitHub environment"
    }

    columns {
      name = "github_previous_plan_name"
      type = "string"
      comment = "GitHub previous plan name"
    }

    columns {
      name = "github_plan_name"
      type = "string"
      comment = "GitHub plan name"
    }
  }
}
