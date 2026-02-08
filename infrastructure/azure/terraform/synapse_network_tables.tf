# ----------------------------------------------------------------------
# Synapse Analytics External Tables — Network Telemetry
#
# Defines external table infrastructure for 3 network telemetry tables
# in Azure Synapse Serverless SQL pool:
#
#   1. network_flows    — VPC/VNet flow records, connection metadata
#   2. dns_queries      — DNS resolution logs with entropy scoring
#   3. firewall_events  — Firewall allow/deny/threat events
#
# Data is stored as NDJSON in Azure Data Lake Gen2 (logs storage account)
# and queried via Synapse Serverless SQL external tables. Directory paths
# are provisioned as Data Lake Gen2 paths, and DDL is executed via
# null_resource provisioner using the Azure CLI.
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Data Lake Gen2 directory paths for each table
# ----------------------------------------------------------------------

resource "azurerm_storage_data_lake_gen2_path" "network_flows" {
  path               = "network_flows"
  filesystem_name    = azurerm_storage_data_lake_gen2_filesystem.synapse.name
  storage_account_id = azurerm_storage_account.synapse.id
  resource           = "directory"
}

resource "azurerm_storage_data_lake_gen2_path" "dns_queries" {
  path               = "dns_queries"
  filesystem_name    = azurerm_storage_data_lake_gen2_filesystem.synapse.name
  storage_account_id = azurerm_storage_account.synapse.id
  resource           = "directory"
}

resource "azurerm_storage_data_lake_gen2_path" "firewall_events" {
  path               = "firewall_events"
  filesystem_name    = azurerm_storage_data_lake_gen2_filesystem.synapse.name
  storage_account_id = azurerm_storage_account.synapse.id
  resource           = "directory"
}

# ----------------------------------------------------------------------
# SQL DDL for external data source, file format, and external tables
# ----------------------------------------------------------------------

locals {
  synapse_network_tables_ddl = <<-SQL
    -- External data source pointing to the Synapse Data Lake Gen2 filesystem
    IF NOT EXISTS (SELECT * FROM sys.external_data_sources WHERE name = 'MantissaLogs')
    CREATE EXTERNAL DATA SOURCE MantissaLogs
    WITH (
        LOCATION = 'abfss://${azurerm_storage_data_lake_gen2_filesystem.synapse.name}@${azurerm_storage_account.synapse.name}.dfs.core.windows.net'
    );

    -- NDJSON file format (single-field-per-line with non-printable delimiters)
    IF NOT EXISTS (SELECT * FROM sys.external_file_formats WHERE name = 'NdjsonFormat')
    CREATE EXTERNAL FILE FORMAT NdjsonFormat
    WITH (
        FORMAT_TYPE = DELIMITEDTEXT,
        FORMAT_OPTIONS (
            FIELD_TERMINATOR = '0x0b',
            STRING_DELIMITER = '0x0b',
            FIRST_ROW = 1
        )
    );

    -- ----------------------------------------------------------------
    -- Table 1: network_flows
    -- VPC/VNet flow records with connection metadata, byte/packet
    -- counters, and cloud-provider-specific fields.
    -- ----------------------------------------------------------------
    IF NOT EXISTS (SELECT * FROM sys.external_tables WHERE name = 'network_flows')
    CREATE EXTERNAL TABLE [dbo].[network_flows] (
        [timestamp]        VARCHAR(100),
        [source_ip]        VARCHAR(45),
        [destination_ip]   VARCHAR(45),
        [source_port]      INT,
        [destination_port] INT,
        [protocol]         VARCHAR(20),
        [bytes_sent]       BIGINT,
        [bytes_received]   BIGINT,
        [packets_sent]     INT,
        [packets_received] INT,
        [duration_seconds] FLOAT,
        [action]           VARCHAR(20),
        [direction]        VARCHAR(20),
        [tcp_flags]        VARCHAR(200),
        [conn_state]       VARCHAR(20),
        [cloud_provider]   VARCHAR(20),
        [source_type]      VARCHAR(50),
        [vpc_id]           VARCHAR(100),
        [subnet_id]        VARCHAR(100),
        [instance_id]      VARCHAR(100),
        [is_internal]      BIT,
        [aws_service]      VARCHAR(100),
        [flow_direction]   VARCHAR(20),
        [metadata]         VARCHAR(MAX)
    )
    WITH (
        LOCATION = 'network_flows/',
        DATA_SOURCE = MantissaLogs,
        FILE_FORMAT = NdjsonFormat
    );

    -- ----------------------------------------------------------------
    -- Table 2: dns_queries
    -- DNS resolution logs with entropy scoring for subdomain analysis
    -- and response metadata.
    -- ----------------------------------------------------------------
    IF NOT EXISTS (SELECT * FROM sys.external_tables WHERE name = 'dns_queries')
    CREATE EXTERNAL TABLE [dbo].[dns_queries] (
        [timestamp]            VARCHAR(100),
        [source_ip]            VARCHAR(45),
        [query_name]           VARCHAR(500),
        [query_type]           VARCHAR(20),
        [response_code]        VARCHAR(20),
        [resolved_ips]         VARCHAR(1000),
        [is_nxdomain]          BIT,
        [subdomain_entropy]    FLOAT,
        [subdomain_label_count] INT,
        [transport]            VARCHAR(10),
        [cloud_provider]       VARCHAR(20),
        [source_type]          VARCHAR(50),
        [vpc_id]               VARCHAR(100),
        [ttl_values]           VARCHAR(200),
        [answers_count]        INT,
        [metadata]             VARCHAR(MAX)
    )
    WITH (
        LOCATION = 'dns_queries/',
        DATA_SOURCE = MantissaLogs,
        FILE_FORMAT = NdjsonFormat
    );

    -- ----------------------------------------------------------------
    -- Table 3: firewall_events
    -- Firewall allow/deny events with threat intelligence fields
    -- and rule matching metadata.
    -- ----------------------------------------------------------------
    IF NOT EXISTS (SELECT * FROM sys.external_tables WHERE name = 'firewall_events')
    CREATE EXTERNAL TABLE [dbo].[firewall_events] (
        [timestamp]          VARCHAR(100),
        [source_ip]          VARCHAR(45),
        [destination_ip]     VARCHAR(45),
        [source_port]        INT,
        [destination_port]   INT,
        [protocol]           VARCHAR(20),
        [action]             VARCHAR(20),
        [firewall_rule_name] VARCHAR(200),
        [direction]          VARCHAR(20),
        [threat_category]    VARCHAR(200),
        [signature_id]       VARCHAR(50),
        [signature_name]     VARCHAR(500),
        [cloud_provider]     VARCHAR(20),
        [source_type]        VARCHAR(50),
        [metadata]           VARCHAR(MAX)
    )
    WITH (
        LOCATION = 'firewall_events/',
        DATA_SOURCE = MantissaLogs,
        FILE_FORMAT = NdjsonFormat
    );
  SQL
}

# ----------------------------------------------------------------------
# Provisioner to execute DDL against Synapse Serverless SQL pool
#
# Uses `az synapse sql query` via local-exec to create the external
# data source, file format, and all 3 external tables. The provisioner
# runs only on resource creation; subsequent changes to the DDL will
# trigger a recreate via the triggers hash.
# ----------------------------------------------------------------------

resource "null_resource" "synapse_network_tables" {
  depends_on = [
    azurerm_synapse_workspace.main,
    azurerm_storage_data_lake_gen2_path.network_flows,
    azurerm_storage_data_lake_gen2_path.dns_queries,
    azurerm_storage_data_lake_gen2_path.firewall_events,
  ]

  triggers = {
    ddl_hash       = sha256(local.synapse_network_tables_ddl)
    workspace_name = azurerm_synapse_workspace.main.name
  }

  provisioner "local-exec" {
    command = <<-EOT
      az synapse sql query \
        --workspace-name "${azurerm_synapse_workspace.main.name}" \
        --database-name "mantissa_logs" \
        --query-text "${replace(local.synapse_network_tables_ddl, "\"", "\\\"")}"
    EOT

    environment = {
      AZURE_STORAGE_ACCOUNT = azurerm_storage_account.synapse.name
    }
  }
}

# ----------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------

output "synapse_network_tables_ddl_hash" {
  description = "SHA256 hash of the network tables DDL for change tracking"
  value       = sha256(local.synapse_network_tables_ddl)
}

output "synapse_network_flows_path" {
  description = "Data Lake Gen2 path for network_flows table data"
  value       = azurerm_storage_data_lake_gen2_path.network_flows.path
}

output "synapse_dns_queries_path" {
  description = "Data Lake Gen2 path for dns_queries table data"
  value       = azurerm_storage_data_lake_gen2_path.dns_queries.path
}

output "synapse_firewall_events_path" {
  description = "Data Lake Gen2 path for firewall_events table data"
  value       = azurerm_storage_data_lake_gen2_path.firewall_events.path
}
