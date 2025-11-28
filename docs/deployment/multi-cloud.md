# Multi-Cloud Deployment Guide

Mantissa Log supports deployment across AWS, GCP, and Azure through a unified architecture. Detection rules written in Sigma format automatically convert to the appropriate SQL dialect for each cloud provider.

## Architecture Overview

```
Sigma Detection Rule (Cloud-Agnostic)
            ↓
    pySigma Converter
            ↓
    ┌───────┼───────┐
    ↓       ↓       ↓
 Athena  BigQuery  Synapse
  (AWS)    (GCP)   (Azure)
```

## Supported Cloud Providers

### AWS (Production Ready)

**Query Engine:** Amazon Athena (Presto SQL)

**Components:**
- S3 for log storage
- Athena for query execution
- Glue Data Catalog for schema
- Lambda for detection engine
- DynamoDB for state management
- EventBridge for scheduling

**Deployment Status:** Fully implemented and tested

**Estimated Monthly Cost:** $30-50 for small deployments

### GCP (Beta)

**Query Engine:** BigQuery (Standard SQL)

**Components:**
- Cloud Storage for log storage
- BigQuery for query execution
- Cloud Functions for detection engine
- Firestore for state management
- Cloud Scheduler for scheduling

**Deployment Status:** Query executor implemented, infrastructure in development

**Estimated Monthly Cost:** $40-60 for small deployments

### Azure (Beta)

**Query Engine:** Azure Synapse Analytics (T-SQL)

**Components:**
- Azure Blob Storage for log storage
- Synapse Analytics for query execution
- Azure Functions for detection engine
- Cosmos DB for state management
- Azure Logic Apps for scheduling

**Deployment Status:** Query executor implemented, infrastructure in development

**Estimated Monthly Cost:** $50-70 for small deployments

## Query Executor Configuration

### AWS Athena

```python
from src.shared.detection.executors.config import (
    CloudProviderConfig,
    CloudProvider,
    AWSConfig,
    create_executor_from_config
)

config = CloudProviderConfig(
    provider=CloudProvider.AWS,
    aws=AWSConfig(
        database='security_logs',
        output_location='s3://my-bucket/query-results/',
        region='us-east-1',
        workgroup='primary'
    )
)

executor = create_executor_from_config(config)
```

### GCP BigQuery

```python
from src.shared.detection.executors.config import (
    CloudProviderConfig,
    CloudProvider,
    GCPConfig,
    create_executor_from_config
)

config = CloudProviderConfig(
    provider=CloudProvider.GCP,
    gcp=GCPConfig(
        project_id='my-project',
        dataset='security_logs',
        location='US'
    )
)

executor = create_executor_from_config(config)
```

### Azure Synapse

```python
from src.shared.detection.executors.config import (
    CloudProviderConfig,
    CloudProvider,
    AzureConfig,
    create_executor_from_config
)

config = CloudProviderConfig(
    provider=CloudProvider.AZURE,
    azure=AzureConfig(
        server='my-synapse.sql.azuresynapse.net',
        database='security_logs',
        use_managed_identity=True
    )
)

executor = create_executor_from_config(config)
```

## SQL Dialect Differences

The same Sigma rule generates different SQL for each provider:

### Time Functions

**Athena (Presto):**
```sql
WHERE eventtime > CURRENT_TIMESTAMP - INTERVAL '1' HOUR
```

**BigQuery:**
```sql
WHERE eventtime > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
```

**Synapse (T-SQL):**
```sql
WHERE eventtime > DATEADD(HOUR, -1, GETUTCDATE())
```

### String Operations

**Athena:**
```sql
WHERE eventname LIKE '%Login%'
```

**BigQuery:**
```sql
WHERE REGEXP_CONTAINS(eventname, r'Login')
```

**Synapse:**
```sql
WHERE eventname LIKE '%Login%'
```

### Aggregations

**Athena:**
```sql
SELECT sourceipaddress, COUNT(*) as count
FROM cloudtrail
GROUP BY sourceipaddress
HAVING COUNT(*) >= 10
```

**BigQuery:**
```sql
SELECT sourceipaddress, COUNT(*) as count
FROM cloudtrail
GROUP BY sourceipaddress
HAVING COUNT(*) >= 10
```

**Synapse:**
```sql
SELECT sourceipaddress, COUNT(*) as count
FROM cloudtrail
GROUP BY sourceipaddress
HAVING COUNT(*) >= 10
```

## Detection Engine Integration

### Using Detection Engine with Multiple Clouds

```python
from src.shared.detection.engine import DetectionEngine
from src.shared.detection.rule import RuleLoader
from src.shared.detection.executors.config import create_executor_from_config

# Load Sigma rules
loader = RuleLoader(
    rules_path="rules/sigma",
    backend_type="athena"  # or "bigquery", "synapse"
)

# Create executor for your cloud
config = CloudProviderConfig(
    provider=CloudProvider.AWS,
    aws=AWSConfig(
        database='security_logs',
        output_location='s3://bucket/results/'
    )
)
executor = create_executor_from_config(config)

# Initialize detection engine
engine = DetectionEngine(
    rule_loader=loader,
    query_executor=executor
)

# Execute all enabled rules
results = engine.execute_all_rules()
```

## Multi-Cloud Rule Testing

Test the same Sigma rule across all cloud providers:

```python
from src.shared.detection.sigma_converter import SigmaRuleConverter

rule_path = "rules/sigma/aws/cloudtrail/brute_force_login.yml"

# Test on AWS
athena_converter = SigmaRuleConverter(backend_type="athena")
athena_sql = athena_converter.convert_rule_to_sql(rule_path)
print("Athena SQL:", athena_sql)

# Test on GCP
bigquery_converter = SigmaRuleConverter(backend_type="bigquery")
bigquery_sql = bigquery_converter.convert_rule_to_sql(rule_path)
print("BigQuery SQL:", bigquery_sql)

# Test on Azure
synapse_converter = SigmaRuleConverter(backend_type="synapse")
synapse_sql = synapse_converter.convert_rule_to_sql(rule_path)
print("Synapse SQL:", synapse_sql)
```

## Cost Estimation Across Clouds

### AWS Athena

```python
from src.shared.detection.executors.athena import AthenaQueryExecutor

executor = AthenaQueryExecutor(
    database='security_logs',
    output_location='s3://bucket/results/'
)

# Athena: $5 per TB scanned
cost = executor.get_query_cost_estimate(query)
print(f"Estimated cost: ${cost:.4f}")
```

### GCP BigQuery

```python
from src.shared.detection.executors.bigquery import BigQueryExecutor

executor = BigQueryExecutor(
    project_id='my-project',
    dataset='security_logs'
)

# BigQuery: $5 per TB scanned (on-demand)
cost = executor.get_query_cost_estimate(query)
print(f"Estimated cost: ${cost:.4f}")
```

### Azure Synapse

```python
from src.shared.detection.executors.synapse import SynapseExecutor

executor = SynapseExecutor(
    server='my-synapse.sql.azuresynapse.net',
    database='security_logs'
)

# Synapse: DWU-based pricing
cost = executor.get_query_cost_estimate(query)
print(f"Estimated cost: ${cost:.4f}")
```

## Deployment Strategies

### Single Cloud

Deploy to one cloud provider for simplicity:

```bash
# AWS only
export CLOUD_PROVIDER=aws
./scripts/deploy.sh
```

### Multi-Cloud Active-Active

Run detection in multiple clouds simultaneously for redundancy:

**Benefits:**
- High availability
- Geographic distribution
- Vendor redundancy

**Challenges:**
- Increased complexity
- Higher cost
- State synchronization

### Multi-Cloud Backup

Primary cloud with backup failover:

**Primary:** AWS (main detection)
**Backup:** GCP (failover only)

## Log Source Mapping

Map log sources to appropriate tables for each cloud:

### CloudTrail → Cloud Audit Logs

| AWS CloudTrail | GCP Cloud Audit | Azure Activity Logs |
|----------------|-----------------|---------------------|
| eventName      | protoPayload.methodName | operationName |
| sourceIPAddress | protoPayload.requestMetadata.callerIp | callerIpAddress |
| userIdentity.principalId | authenticationInfo.principalEmail | caller |

### VPC Flow Logs

| AWS VPC Flow | GCP VPC Flow | Azure NSG Flow |
|--------------|--------------|----------------|
| srcaddr      | connection.src_ip | sourceIPAddress |
| dstport      | connection.dest_port | destinationPort |
| action       | disposition | flowState |

## Schema Normalization

Normalize schemas across clouds using Sigma field mappings:

```python
# src/shared/detection/sigma_pipeline.py

FIELD_MAPPINGS = {
    "aws": {
        "cloudtrail": {
            "eventName": "eventname",
            "sourceIPAddress": "sourceipaddress",
            "userIdentity.principalId": "useridentity_principalid"
        }
    },
    "gcp": {
        "audit": {
            "protoPayload.methodName": "method_name",
            "protoPayload.requestMetadata.callerIp": "caller_ip"
        }
    },
    "azure": {
        "activity": {
            "operationName": "operation_name",
            "callerIpAddress": "caller_ip"
        }
    }
}
```

## Authentication

### AWS

Uses IAM roles and temporary credentials:

```python
import boto3

# Automatic credential chain
client = boto3.client('athena')
```

### GCP

Uses service accounts:

```python
from google.cloud import bigquery

# Uses GOOGLE_APPLICATION_CREDENTIALS environment variable
client = bigquery.Client(project='my-project')
```

### Azure

Uses managed identity or service principal:

```python
import pyodbc

# Managed identity
conn_str = (
    "Driver={ODBC Driver 17 for SQL Server};"
    "Server=tcp:my-synapse.sql.azuresynapse.net,1433;"
    "Database=security_logs;"
    "Authentication=ActiveDirectoryMsi;"
)
```

## Performance Optimization

### Partition Strategy

**AWS Athena:**
```sql
CREATE EXTERNAL TABLE cloudtrail (
    eventname string,
    eventtime timestamp
)
PARTITIONED BY (
    year string,
    month string,
    day string
)
```

**GCP BigQuery:**
```sql
CREATE TABLE cloudtrail (
    eventname STRING,
    eventtime TIMESTAMP
)
PARTITION BY DATE(eventtime)
```

**Azure Synapse:**
```sql
CREATE TABLE cloudtrail (
    eventname NVARCHAR(256),
    eventtime DATETIME2
)
WITH (
    DISTRIBUTION = HASH(eventtime),
    CLUSTERED COLUMNSTORE INDEX
)
```

### Query Optimization

Use the same Sigma rule, but optimize table structure per cloud:

- **Athena:** Partition by date hierarchy (year/month/day)
- **BigQuery:** Use date partitioning and clustering
- **Synapse:** Use distribution and clustered columnstore indexes

## Limitations

### AWS Athena
- Maximum query execution time: 30 minutes
- Maximum result size: 1 GB (can increase with pagination)
- Query queuing during high concurrency

### GCP BigQuery
- Maximum query execution time: 6 hours
- Maximum result size: unlimited (paginated)
- Slot limits for concurrent queries

### Azure Synapse
- Query timeout based on DWU configuration
- Maximum table size: 240 TB
- Concurrent query limits based on resource class

## Migration Between Clouds

### Exporting Rules

Rules are cloud-agnostic if using Sigma format:

```bash
# Copy Sigma rules to new deployment
cp -r rules/sigma/ /new-cloud-deployment/rules/sigma/
```

### Exporting Data

**From AWS to GCP:**
```bash
# Export from S3
aws s3 sync s3://aws-logs/ ./local-logs/

# Import to GCS
gsutil -m cp -r ./local-logs/ gs://gcp-logs/
```

**From GCP to Azure:**
```bash
# Export from GCS
gsutil -m cp -r gs://gcp-logs/ ./local-logs/

# Import to Azure Blob
az storage blob upload-batch \
    --destination azure-logs \
    --source ./local-logs/
```

## Troubleshooting

### Connection Issues

**AWS:**
```bash
# Test Athena access
aws athena start-query-execution \
    --query-string "SELECT 1" \
    --query-execution-context Database=security_logs \
    --result-configuration OutputLocation=s3://bucket/results/
```

**GCP:**
```bash
# Test BigQuery access
bq query --use_legacy_sql=false "SELECT 1"
```

**Azure:**
```bash
# Test Synapse access
sqlcmd -S my-synapse.sql.azuresynapse.net \
    -d security_logs \
    -G \
    -Q "SELECT 1"
```

### Query Conversion Errors

If a Sigma rule fails to convert:

1. Check the Sigma rule syntax is valid
2. Verify the logsource is supported
3. Check field mappings exist for your backend
4. Review pySigma backend documentation

### Performance Issues

**Slow queries on Athena:**
- Add partitions
- Use columnar formats (Parquet, ORC)
- Limit time ranges

**Slow queries on BigQuery:**
- Use table partitioning
- Add clustering keys
- Enable caching

**Slow queries on Synapse:**
- Increase DWUs
- Optimize distribution
- Use result set caching

## Best Practices

1. **Use Sigma rules** for cloud portability
2. **Normalize schemas** across clouds using field mappings
3. **Test queries** on all target clouds before deploying
4. **Monitor costs** - each cloud has different pricing
5. **Implement caching** to reduce query costs
6. **Use partitioning** for better performance
7. **Version control** infrastructure as code
8. **Document** cloud-specific customizations

## Resources

- [AWS Athena Documentation](https://docs.aws.amazon.com/athena/)
- [GCP BigQuery Documentation](https://cloud.google.com/bigquery/docs)
- [Azure Synapse Documentation](https://docs.microsoft.com/azure/synapse-analytics/)
- [pySigma Backends](https://github.com/SigmaHQ/pySigma)
- [Mantissa Log GitHub](https://github.com/clay-good/mantissa-log)
