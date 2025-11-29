/**
 * AWS Glue Table Definitions for Microsoft 365 Logs
 *
 * Defines schemas for raw and normalized Microsoft 365 Management Activity API logs.
 * Supports multiple content types: Azure AD, Exchange, SharePoint, Teams, DLP.
 */

resource "aws_glue_catalog_table" "microsoft365_raw" {
  name          = "microsoft365_raw"
  database_name = aws_glue_catalog_database.main.name

  description = "Raw Microsoft 365 Management Activity API logs (NDJSON)"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"        = "json"
    "compressionType"       = "none"
    "typeOfData"           = "file"
    "skip.header.line.count" = "0"
  }

  partition_keys {
    name = "content_type"
    type = "string"
    comment = "Microsoft 365 content type (audit_azureactivedirectory, audit_exchange, etc.)"
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
    location      = "s3://${var.logs_bucket_name}/microsoft365/raw/"
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

    columns {
      name = "Id"
      type = "string"
      comment = "Unique identifier for audit record"
    }

    columns {
      name = "RecordType"
      type = "int"
      comment = "Type of operation indicated by record"
    }

    columns {
      name = "CreationTime"
      type = "string"
      comment = "Date and time in UTC when event occurred"
    }

    columns {
      name = "Operation"
      type = "string"
      comment = "Name of user or admin activity"
    }

    columns {
      name = "OrganizationId"
      type = "string"
      comment = "GUID for organization's Office 365 tenant"
    }

    columns {
      name = "UserType"
      type = "int"
      comment = "Type of user that performed operation"
    }

    columns {
      name = "UserKey"
      type = "string"
      comment = "Alternative ID for user in UserId property"
    }

    columns {
      name = "Workload"
      type = "string"
      comment = "Office 365 service where activity occurred"
    }

    columns {
      name = "ResultStatus"
      type = "string"
      comment = "Indicates whether action was successful"
    }

    columns {
      name = "ObjectId"
      type = "string"
      comment = "Full path name of object accessed"
    }

    columns {
      name = "UserId"
      type = "string"
      comment = "UPN of user who performed action"
    }

    columns {
      name = "ClientIP"
      type = "string"
      comment = "IP address of device used"
    }

    columns {
      name = "Scope"
      type = "string"
      comment = "Event created by hosted O365 service or on-premises"
    }

    # Azure AD specific fields
    columns {
      name = "AzureActiveDirectoryEventType"
      type = "int"
      comment = "Type of Azure AD event"
    }

    columns {
      name = "ExtendedProperties"
      type = "array<struct<Name:string,Value:string>>"
      comment = "Extended properties of Azure AD event"
    }

    columns {
      name = "ModifiedProperties"
      type = "array<struct<Name:string,NewValue:string,OldValue:string>>"
      comment = "Properties modified in Azure AD"
    }

    columns {
      name = "Actor"
      type = "array<struct<ID:string,Type:int>>"
      comment = "User or app that performed action"
    }

    columns {
      name = "ActorContextId"
      type = "string"
      comment = "GUID of organization actor belongs to"
    }

    columns {
      name = "ActorIpAddress"
      type = "string"
      comment = "Actor's IP address in IPv4 or IPv6 format"
    }

    columns {
      name = "InterSystemsId"
      type = "string"
      comment = "GUID tracking actions across components"
    }

    columns {
      name = "IntraSystemId"
      type = "string"
      comment = "GUID tracking actions within component"
    }

    columns {
      name = "SupportTicketId"
      type = "string"
      comment = "Customer support ticket ID for act-on-behalf-of situations"
    }

    columns {
      name = "Target"
      type = "array<struct<ID:string,Type:int>>"
      comment = "User action was performed on"
    }

    columns {
      name = "TargetContextId"
      type = "string"
      comment = "GUID of organization targeted user belongs to"
    }

    columns {
      name = "ApplicationId"
      type = "string"
      comment = "GUID representing application requesting login"
    }

    # Exchange specific fields
    columns {
      name = "Item"
      type = "struct<Id:string,Subject:string,ParentFolder:struct<Id:string,Name:string,Path:string>>"
      comment = "Details about mailbox item"
    }

    columns {
      name = "ItemType"
      type = "string"
      comment = "Type of object accessed or modified"
    }

    columns {
      name = "Folder"
      type = "struct<Id:string,Path:string>"
      comment = "Folder information"
    }

    columns {
      name = "AffectedItems"
      type = "array<struct<Id:string,Subject:string,ParentFolder:struct<Id:string>>>"
      comment = "Items affected by operation"
    }

    columns {
      name = "ExternalAccess"
      type = "boolean"
      comment = "Indicates if user is outside organization"
    }

    columns {
      name = "MailboxGuid"
      type = "string"
      comment = "Exchange GUID of accessed mailbox"
    }

    columns {
      name = "MailboxOwnerUPN"
      type = "string"
      comment = "Email address of mailbox owner"
    }

    columns {
      name = "LogonType"
      type = "string"
      comment = "Type of mailbox access (Owner, Delegate, Admin)"
    }

    # SharePoint specific fields
    columns {
      name = "SiteUrl"
      type = "string"
      comment = "URL of site where file or folder is located"
    }

    columns {
      name = "SourceRelativeUrl"
      type = "string"
      comment = "URL of folder containing accessed file"
    }

    columns {
      name = "SourceFileName"
      type = "string"
      comment = "Name of file or folder accessed"
    }

    columns {
      name = "SourceFileExtension"
      type = "string"
      comment = "File extension of accessed file"
    }

    columns {
      name = "DestinationRelativeUrl"
      type = "string"
      comment = "Destination folder URL for copied/moved file"
    }

    columns {
      name = "DestinationFileName"
      type = "string"
      comment = "Name of file that is copied or moved"
    }

    columns {
      name = "UserAgent"
      type = "string"
      comment = "User agent information from user's browser"
    }

    columns {
      name = "EventSource"
      type = "string"
      comment = "Event occurred in SharePoint (SharePoint or ObjectModel)"
    }

    # Teams specific fields
    columns {
      name = "TeamName"
      type = "string"
      comment = "Name of team"
    }

    columns {
      name = "TeamGuid"
      type = "string"
      comment = "GUID of team"
    }

    columns {
      name = "ChannelType"
      type = "string"
      comment = "Type of channel (Standard, Private)"
    }

    columns {
      name = "ChannelName"
      type = "string"
      comment = "Name of channel"
    }

    columns {
      name = "ChannelGuid"
      type = "string"
      comment = "GUID of channel"
    }

    columns {
      name = "Members"
      type = "array<struct<UPN:string,Role:string>>"
      comment = "Team or channel members"
    }

    columns {
      name = "CommunicationType"
      type = "string"
      comment = "Type of communication (OneOnOne, GroupCall)"
    }

    # DLP specific fields
    columns {
      name = "PolicyId"
      type = "string"
      comment = "GUID of DLP policy"
    }

    columns {
      name = "PolicyName"
      type = "string"
      comment = "Friendly name of DLP policy"
    }

    columns {
      name = "RuleId"
      type = "string"
      comment = "GUID of DLP rule"
    }

    columns {
      name = "RuleName"
      type = "string"
      comment = "Friendly name of DLP rule"
    }

    columns {
      name = "SensitiveInfoTypeData"
      type = "array<struct<SensitiveInformationType:string,Count:int,Confidence:int>>"
      comment = "Sensitive information types detected"
    }

    columns {
      name = "Severity"
      type = "string"
      comment = "Severity of DLP rule match"
    }

    columns {
      name = "SharePointMetaData"
      type = "struct<From:string,itemCreationTime:string,SiteAdmin:string,FileOwner:string,FilePathUrl:string,DocumentLastModifier:string,UniqueId:string,LastModifiedTime:string>"
      comment = "SharePoint metadata for DLP event"
    }

    # Common additional fields
    columns {
      name = "AppId"
      type = "string"
      comment = "GUID for application performing operation"
    }

    columns {
      name = "Parameters"
      type = "array<struct<Name:string,Value:string>>"
      comment = "Parameters for operation"
    }

    columns {
      name = "ClientInfoString"
      type = "string"
      comment = "Information about email client used"
    }

    columns {
      name = "CustomUniqueId"
      type = "boolean"
      comment = "Indicates custom unique ID"
    }
  }
}

resource "aws_glue_catalog_table" "microsoft365_normalized" {
  name          = "microsoft365_normalized"
  database_name = aws_glue_catalog_database.main.name

  description = "ECS-normalized Microsoft 365 logs"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "parquet"
    "compressionType" = "snappy"
  }

  partition_keys {
    name = "workload"
    type = "string"
    comment = "Microsoft 365 workload (azureactivedirectory, exchange, sharepoint, teams, dlp)"
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
    location      = "s3://${var.logs_bucket_name}/microsoft365/normalized/"
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
      name = "user_id"
      type = "string"
      comment = "ECS user.id"
    }

    columns {
      name = "user_email"
      type = "string"
      comment = "ECS user.email"
    }

    columns {
      name = "user_name"
      type = "string"
      comment = "ECS user.name"
    }

    # Source fields
    columns {
      name = "source_ip"
      type = "string"
      comment = "ECS source.ip"
    }

    # Organization fields
    columns {
      name = "organization_id"
      type = "string"
      comment = "ECS organization.id"
    }

    # Related fields
    columns {
      name = "related_ip"
      type = "array<string>"
      comment = "ECS related.ip"
    }

    columns {
      name = "related_user"
      type = "array<string>"
      comment = "ECS related.user"
    }

    # Microsoft 365 specific fields
    columns {
      name = "microsoft365_record_type"
      type = "int"
      comment = "Microsoft 365 record type number"
    }

    columns {
      name = "microsoft365_record_type_name"
      type = "string"
      comment = "Microsoft 365 record type name"
    }

    columns {
      name = "microsoft365_operation"
      type = "string"
      comment = "Microsoft 365 operation"
    }

    columns {
      name = "microsoft365_workload"
      type = "string"
      comment = "Microsoft 365 workload"
    }

    columns {
      name = "microsoft365_creation_time"
      type = "string"
      comment = "Microsoft 365 creation time"
    }

    columns {
      name = "microsoft365_user_id"
      type = "string"
      comment = "Microsoft 365 user ID"
    }

    columns {
      name = "microsoft365_user_type"
      type = "int"
      comment = "Microsoft 365 user type"
    }

    columns {
      name = "microsoft365_user_key"
      type = "string"
      comment = "Microsoft 365 user key"
    }

    columns {
      name = "microsoft365_organization_id"
      type = "string"
      comment = "Microsoft 365 organization ID"
    }

    columns {
      name = "microsoft365_result_status"
      type = "string"
      comment = "Microsoft 365 result status"
    }

    columns {
      name = "microsoft365_object_id"
      type = "string"
      comment = "Microsoft 365 object ID"
    }

    columns {
      name = "microsoft365_item_type"
      type = "string"
      comment = "Microsoft 365 item type"
    }

    columns {
      name = "microsoft365_site_url"
      type = "string"
      comment = "Microsoft 365 site URL"
    }

    columns {
      name = "microsoft365_source_file_name"
      type = "string"
      comment = "Microsoft 365 source file name"
    }

    columns {
      name = "microsoft365_source_relative_url"
      type = "string"
      comment = "Microsoft 365 source relative URL"
    }

    columns {
      name = "microsoft365_extended_properties"
      type = "array<struct<Name:string,Value:string>>"
      comment = "Microsoft 365 extended properties"
    }

    columns {
      name = "microsoft365_parameters"
      type = "array<struct<Name:string,Value:string>>"
      comment = "Microsoft 365 parameters"
    }

    columns {
      name = "microsoft365_app_id"
      type = "string"
      comment = "Microsoft 365 app ID"
    }

    columns {
      name = "microsoft365_application_id"
      type = "string"
      comment = "Microsoft 365 application ID"
    }

    columns {
      name = "microsoft365_azure_ad_app_id"
      type = "int"
      comment = "Microsoft 365 Azure AD event type"
    }
  }
}
