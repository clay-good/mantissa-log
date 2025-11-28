# Mantissa Log - Microsoft Azure Implementation

This document outlines the planned implementation of Mantissa Log on Microsoft Azure.

## Azure Architecture Overview

### Core Components

- **Azure Blob Storage**: Log storage and archival
- **Azure Synapse Analytics**: SQL query engine for log analysis
- **Azure Functions**: Serverless compute for detection engine and LLM integration
- **Azure Logic Apps**: Workflow orchestration for scheduled detection
- **Azure Key Vault**: Secure storage for API keys and credentials
- **Azure AD B2C**: User authentication and authorization
- **Azure Cosmos DB**: State management for detection engine and query sessions
- **Azure Event Grid**: Event routing for alerts
- **Azure Monitor**: Centralized logging and diagnostics

## Component Mapping: AWS to Azure

| AWS Service | Azure Equivalent | Purpose |
|------------|------------------|---------|
| S3 | Blob Storage | Log storage |
| Athena | Synapse Analytics | SQL query engine |
| Glue Data Catalog | Synapse metadata | Table schemas and partitions |
| Lambda | Azure Functions | Serverless compute |
| EventBridge | Logic Apps / Event Grid | Scheduled rule execution |
| Secrets Manager | Key Vault | Credential storage |
| Cognito | Azure AD B2C | User authentication |
| DynamoDB | Cosmos DB | State storage |
| API Gateway | API Management | REST API |
| CloudFront | Azure CDN | Web interface delivery |
| SNS/SQS | Event Grid / Service Bus | Alert routing |

## Azure Log Sources

### Native Azure Logs

1. **Azure Activity Logs**
   - Administrative operations
   - Resource health events
   - Service health notifications
   - Autoscale events

2. **Network Security Group (NSG) Flow Logs**
   - Network traffic metadata
   - Similar structure to AWS VPC Flow Logs
   - Integration with Network Watcher

3. **Azure Sentinel**
   - Security alerts and incidents
   - Threat intelligence
   - Comparable to AWS GuardDuty and Security Hub

4. **Azure Monitor Diagnostic Logs**
   - Application logs
   - Resource-specific logs
   - Custom log exports
   - Container logs from AKS

5. **Azure AD Sign-in Logs**
   - User authentication events
   - Conditional access decisions
   - Risky sign-in detection

## Implementation Plan

### Phase 1: Storage and Query Layer (8 weeks)

Objectives:
- Set up Blob Storage containers with lifecycle policies
- Create Synapse Analytics workspace and SQL pools
- Implement log export from Azure Monitor
- Develop query execution layer

Deliverables:
- Terraform modules for Azure infrastructure
- Synapse table schemas
- Data ingestion pipelines
- Query execution API

### Phase 2: Detection Engine (6 weeks)

Objectives:
- Port detection engine to Azure Functions
- Implement Logic Apps for scheduling
- Set up Cosmos DB for state management
- Adapt detection rules for T-SQL (Synapse)

Deliverables:
- Azure Functions for detection engine
- Logic Apps workflows
- Detection rule format adapters
- State management layer

### Phase 3: Web Interface Adaptation (4 weeks)

Objectives:
- Adapt web interface for Azure endpoints
- Configure Azure AD B2C
- Set up Azure CDN
- Implement Azure-specific features

Deliverables:
- Updated web application
- Authentication flow with Azure AD B2C
- Deployment scripts
- Azure-specific UI components

### Phase 4: Full Feature Parity (6 weeks)

Objectives:
- Complete all AWS features
- Implement alert routing
- Add LLM integration
- Performance optimization

Deliverables:
- Alert routing to Slack, PagerDuty, etc.
- LLM query generation for Synapse
- Performance benchmarks
- Cost optimization

## Shared Code Utilization

### 100% Reusable

- Parsers: Cloud-agnostic
- Detection logic: No changes needed
- Alert routing: Works with any cloud provider
- LLM layer: 90% reusable (different schema context)

### New Implementation Required

- Infrastructure: New Terraform modules (Azure provider)
- Query execution: Synapse Analytics API vs Athena API
- Authentication: Azure AD B2C vs Cognito
- State management: Cosmos DB vs DynamoDB

## T-SQL Considerations

Synapse Analytics uses T-SQL, which differs from Athena's Presto SQL and BigQuery's Standard SQL.

### Query Translation Examples

**Athena (Presto SQL):**
```sql
SELECT 
  useridentity.username,
  COUNT(*) as failed_logins
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode = 'Failed authentication'
  AND year = '2024' AND month = '11'
GROUP BY useridentity.username
HAVING COUNT(*) > 5
```

**Synapse (T-SQL):**
```sql
SELECT 
  JSON_VALUE(useridentity, '$.username') as username,
  COUNT(*) as failed_logins
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode = 'Failed authentication'
  AND year = '2024' AND month = '11'
GROUP BY JSON_VALUE(useridentity, '$.username')
HAVING COUNT(*) > 5
```

### Key Differences

1. **JSON Handling**: Synapse uses `JSON_VALUE()` instead of dot notation
2. **Date Functions**: Different syntax for date operations
3. **String Functions**: Some function names differ
4. **Window Functions**: Similar but with syntax variations

## Azure-Specific Features

### 1. Azure Sentinel Integration

```yaml
# Example detection rule with Sentinel integration
name: suspicious_azure_ad_signin
data_source: azure_ad_signin_logs
query: |
  SELECT 
    userPrincipalName,
    location,
    ipAddress,
    COUNT(*) as failed_attempts
  FROM signin_logs
  WHERE resultType != '0'  -- Non-successful sign-ins
    AND DATEDIFF(hour, createdDateTime, GETUTCDATE()) <= 1
  GROUP BY userPrincipalName, location, ipAddress
  HAVING COUNT(*) > 5
severity: high
alert:
  - type: sentinel
    workspace_id: ${SENTINEL_WORKSPACE_ID}
```

### 2. Network Watcher Flow Logs

```yaml
# NSG Flow Log detection
name: port_scan_detection_nsg
data_source: nsg_flow_logs
query: |
  SELECT 
    sourceAddress,
    COUNT(DISTINCT destinationPort) as unique_ports
  FROM nsg_flow_logs
  WHERE flowDirection = 'I'
    AND DATEDIFF(minute, flowStartTime, GETUTCDATE()) <= 10
  GROUP BY sourceAddress
  HAVING COUNT(DISTINCT destinationPort) > 20
severity: medium
```

## Synapse Table Schemas

### Activity Logs Table

```sql
CREATE EXTERNAL TABLE activity_logs (
    time DATETIME2,
    resourceId NVARCHAR(500),
    operationName NVARCHAR(200),
    category NVARCHAR(100),
    resultType NVARCHAR(50),
    resultSignature NVARCHAR(100),
    callerIpAddress NVARCHAR(50),
    identity NVARCHAR(MAX),
    properties NVARCHAR(MAX),
    year NVARCHAR(4),
    month NVARCHAR(2),
    day NVARCHAR(2)
)
WITH (
    LOCATION = '/logs/activity/',
    DATA_SOURCE = blob_storage,
    FILE_FORMAT = json_format
)
```

### NSG Flow Logs Table

```sql
CREATE EXTERNAL TABLE nsg_flow_logs (
    time DATETIME2,
    resourceId NVARCHAR(500),
    flowTuples NVARCHAR(MAX),
    sourceAddress NVARCHAR(50),
    destinationAddress NVARCHAR(50),
    sourcePort INT,
    destinationPort INT,
    protocol NVARCHAR(10),
    flowDirection NVARCHAR(1),
    flowState NVARCHAR(1),
    year NVARCHAR(4),
    month NVARCHAR(2),
    day NVARCHAR(2)
)
WITH (
    LOCATION = '/logs/nsg-flow/',
    DATA_SOURCE = blob_storage,
    FILE_FORMAT = json_format
)
```

## Cost Optimization

### Storage Tiers

Azure Blob Storage offers multiple tiers:
- **Hot**: Frequently accessed logs (last 30 days)
- **Cool**: Infrequently accessed (31-90 days)
- **Archive**: Long-term retention (90+ days)

### Synapse Cost Management

1. **Pause SQL Pools**: Stop compute when not querying
2. **Serverless Pools**: Pay per query for ad-hoc analysis
3. **Result Set Caching**: Cache query results to reduce compute
4. **Materialized Views**: Pre-compute common queries

### Example Lifecycle Policy

```json
{
  "rules": [
    {
      "name": "move-to-cool",
      "enabled": true,
      "type": "Lifecycle",
      "definition": {
        "filters": {
          "blobTypes": ["blockBlob"],
          "prefixMatch": ["logs/"]
        },
        "actions": {
          "baseBlob": {
            "tierToCool": {
              "daysAfterModificationGreaterThan": 30
            },
            "tierToArchive": {
              "daysAfterModificationGreaterThan": 90
            },
            "delete": {
              "daysAfterModificationGreaterThan": 365
            }
          }
        }
      }
    }
  ]
}
```

## Security and Compliance

### 1. Data Encryption

- **At Rest**: Azure Storage Service Encryption (SSE) with customer-managed keys
- **In Transit**: TLS 1.2+ for all data transfer
- **Key Management**: Azure Key Vault for encryption key rotation

### 2. Access Control

- **RBAC**: Azure Role-Based Access Control for resource access
- **Azure AD**: Centralized identity management
- **Managed Identities**: Service-to-service authentication without credentials
- **Private Endpoints**: Network isolation for sensitive resources

### 3. Compliance Features

- **Azure Policy**: Enforce organizational standards
- **Azure Blueprints**: Repeatable compliance patterns
- **Compliance Manager**: Track compliance with regulations
- **Audit Logs**: Complete audit trail of all operations

## Migration from AWS

### Step 1: Export Data

```bash
# Export CloudTrail logs from S3
aws s3 sync s3://logs-bucket/cloudtrail/ ./cloudtrail-export/

# Upload to Azure Blob Storage
az storage blob upload-batch \
  --account-name mantissalogs \
  --destination logs \
  --source ./cloudtrail-export/ \
  --pattern "*.json"
```

### Step 2: Schema Translation

Convert Athena table definitions to Synapse:

```python
# Example schema converter
def athena_to_synapse(athena_schema):
    type_mapping = {
        'string': 'NVARCHAR(MAX)',
        'bigint': 'BIGINT',
        'double': 'FLOAT',
        'timestamp': 'DATETIME2',
        'boolean': 'BIT'
    }
    
    synapse_columns = []
    for col in athena_schema['columns']:
        synapse_type = type_mapping.get(col['type'], 'NVARCHAR(MAX)')
        synapse_columns.append(f"{col['name']} {synapse_type}")
    
    return synapse_columns
```

### Step 3: Query Translation

Detection rules need SQL dialect translation:

```python
# Query translator for detection rules
class QueryTranslator:
    def translate_to_synapse(self, athena_query):
        # Replace Presto-specific functions
        query = athena_query
        query = query.replace('date_diff', 'DATEDIFF')
        query = query.replace('current_timestamp', 'GETUTCDATE()')
        
        # Handle JSON path notation
        query = self._convert_json_paths(query)
        
        return query
    
    def _convert_json_paths(self, query):
        # Convert useridentity.username to JSON_VALUE(useridentity, '$.username')
        import re
        pattern = r'(\w+)\.(\w+)'
        
        def replacer(match):
            return f"JSON_VALUE({match.group(1)}, '$.{match.group(2)}')"
        
        return re.sub(pattern, replacer, query)
```

## Performance Optimization

### 1. Partitioning Strategy

```sql
-- Partition by date for efficient queries
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventname NVARCHAR(100),
    eventtime DATETIME2,
    useridentity NVARCHAR(MAX),
    sourceipaddress NVARCHAR(50)
)
WITH (
    LOCATION = '/logs/cloudtrail/',
    DATA_SOURCE = blob_storage,
    FILE_FORMAT = json_format,
    DISTRIBUTION = HASH(eventname),
    PARTITION (
        year NVARCHAR(4),
        month NVARCHAR(2),
        day NVARCHAR(2)
    )
)
```

### 2. Indexing

```sql
-- Create columnstore index for analytical queries
CREATE CLUSTERED COLUMNSTORE INDEX cci_cloudtrail
ON cloudtrail_logs
```

### 3. Query Optimization

```sql
-- Use result set caching
SET RESULT_SET_CACHING ON;

-- Use query hints for performance
SELECT /*+ LABEL('detection_rule_001') */
    useridentity,
    COUNT(*) as event_count
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
GROUP BY useridentity
OPTION (HASH GROUP);
```

## Development Roadmap

### Immediate (0-3 months)
- Terraform infrastructure modules
- Basic log ingestion pipeline
- Synapse table schemas
- Query execution layer

### Short-term (3-6 months)
- Detection engine migration
- Azure Functions implementation
- Azure AD B2C integration
- Alert routing to Azure Event Grid

### Medium-term (6-12 months)
- Full feature parity with AWS version
- Azure Sentinel integration
- Advanced analytics with Synapse ML
- Multi-region deployment

### Long-term (12+ months)
- Azure-specific optimizations
- Cost reduction initiatives
- Hybrid cloud scenarios
- Azure Stack support for on-premises

## Comparison: Azure vs AWS vs GCP

| Feature | AWS | GCP | Azure |
|---------|-----|-----|-------|
| SQL Engine | Athena (Presto) | BigQuery (Standard SQL) | Synapse (T-SQL) |
| Query Performance | Good | Excellent | Very Good |
| Cost per TB scanned | $5 | $5 | $5-7 (depends on pool) |
| Serverless | Yes | Yes | Yes (Serverless SQL) |
| Max Query Size | 30min timeout | No limit | 30min timeout |
| Native Logs | CloudTrail, VPC | Audit Logs, VPC | Activity, NSG |
| Security Service | GuardDuty | Security Command Center | Sentinel |

## Conclusion

Azure implementation of Mantissa Log leverages:
- **Synapse Analytics** for powerful SQL querying with T-SQL
- **Azure Functions** for serverless detection engine
- **Cosmos DB** for global state management
- **Azure AD B2C** for enterprise authentication
- **Event Grid** for flexible alert routing

The core detection logic and parsers remain 100% portable, with only infrastructure and query syntax requiring adaptation for Azure's ecosystem.
