# Scaling Guide

This guide covers scaling Mantissa Log for high-volume environments and optimizing costs.

## Overview

Mantissa Log scales automatically with serverless components, but optimization is needed for:
- High event volumes (> 10M events/month)
- Cost optimization
- Query performance
- Multi-account deployments

## Scaling Dimensions

### Event Volume

| Volume | Events/Month | Recommended Configuration |
|--------|--------------|---------------------------|
| Small | < 1M | Default configuration |
| Medium | 1M - 10M | Optimized partitioning, Parquet conversion |
| Large | 10M - 100M | Reserved capacity, query optimization |
| Enterprise | > 100M | Multi-region, dedicated resources |

### Query Volume

| Queries/Day | Configuration |
|-------------|---------------|
| < 100 | Default |
| 100 - 1000 | Query caching, result reuse |
| > 1000 | Reserved Athena capacity |

## Cost Optimization

### Athena Query Optimization

**Problem:** Athena costs $5 per TB scanned.

**Solutions:**

**1. Partition Pruning**

```sql
-- Bad: Scans entire table (expensive)
SELECT * FROM cloudtrail
WHERE eventtime > '2024-01-15T00:00:00Z'

-- Good: Partition filters (cheap)
SELECT * FROM cloudtrail
WHERE year = '2024'
  AND month = '01'
  AND day = '15'
  AND eventtime > '2024-01-15T00:00:00Z'
```

**2. Columnar Format (Parquet)**

Convert JSON logs to Parquet:

```bash
# Create Parquet table
aws athena start-query-execution \
  --query-string "
    CREATE TABLE cloudtrail_parquet
    WITH (
      format = 'PARQUET',
      parquet_compression = 'SNAPPY',
      partitioned_by = ARRAY['year', 'month', 'day']
    ) AS
    SELECT * FROM cloudtrail
  " \
  --query-execution-context Database=$DATABASE \
  --work-group $WORKGROUP
```

**Savings:** 80-90% reduction in data scanned

**3. Query Result Reuse**

Enable in Athena workgroup:

```bash
aws athena update-work-group \
  --work-group mantissa-log \
  --configuration-updates "
    ResultConfigurationUpdates={
      OutputLocation=s3://$ATHENA_BUCKET/results/
    },
    ResultReuseConfigurationUpdates={
      Enabled=true,
      MaxAgeInMinutes=60
    }
  "
```

**4. Column Projection**

```sql
-- Bad: Selects all columns
SELECT * FROM cloudtrail WHERE ...

-- Good: Only needed columns
SELECT eventtime, eventname, useridentity.principalid
FROM cloudtrail WHERE ...
```

### S3 Storage Optimization

**1. Lifecycle Policies**

```bash
cat > lifecycle-policy.json << 'EOF'
{
  "Rules": [
    {
      "Id": "TransitionOldLogs",
      "Status": "Enabled",
      "Transitions": [
        {
          "Days": 90,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 365,
          "StorageClass": "GLACIER"
        }
      ],
      "Expiration": {
        "Days": 2555
      }
    }
  ]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
  --bucket $LOGS_BUCKET \
  --lifecycle-configuration file://lifecycle-policy.json
```

**Savings:** 40-70% on storage costs

**2. Intelligent Tiering**

```bash
aws s3api put-bucket-intelligent-tiering-configuration \
  --bucket $LOGS_BUCKET \
  --id ManualTiering \
  --intelligent-tiering-configuration '{
    "Id": "ManualTiering",
    "Status": "Enabled",
    "Tierings": [
      {
        "Days": 90,
        "AccessTier": "ARCHIVE_ACCESS"
      },
      {
        "Days": 180,
        "AccessTier": "DEEP_ARCHIVE_ACCESS"
      }
    ]
  }'
```

### Lambda Optimization

**1. Right-Size Memory**

Test different memory sizes:

```bash
# Test with different memory
for MEMORY in 512 1024 2048; do
  aws lambda update-function-configuration \
    --function-name mantissa-log-detection-engine \
    --memory-size $MEMORY

  # Run test
  aws lambda invoke \
    --function-name mantissa-log-detection-engine \
    response.json

  # Check duration
  aws logs tail /aws/lambda/mantissa-log-detection-engine \
    | grep "Duration"
done
```

Find sweet spot where duration × cost is minimized.

**2. Reserved Concurrency**

For predictable workloads:

```bash
aws lambda put-function-concurrency \
  --function-name mantissa-log-detection-engine \
  --reserved-concurrent-executions 10
```

### DynamoDB Optimization

**1. On-Demand vs Provisioned**

Small/variable load: On-Demand (default)
Large/steady load: Provisioned with auto-scaling

```bash
# Switch to provisioned
aws dynamodb update-table \
  --table-name $STATE_TABLE \
  --billing-mode PROVISIONED \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5

# Enable auto-scaling
aws application-autoscaling register-scalable-target \
  --service-namespace dynamodb \
  --resource-id "table/$STATE_TABLE" \
  --scalable-dimension "dynamodb:table:ReadCapacityUnits" \
  --min-capacity 5 \
  --max-capacity 100
```

**2. TTL for State Data**

Automatically delete old state:

```bash
aws dynamodb update-time-to-live \
  --table-name $STATE_TABLE \
  --time-to-live-specification "Enabled=true, AttributeName=ttl"
```

## Query Performance

### Partition Strategy

**Hourly partitions for high volume:**

```
s3://bucket/cloudtrail/year=2024/month=01/day=15/hour=14/
```

```sql
CREATE EXTERNAL TABLE cloudtrail_hourly (
  ...
)
PARTITIONED BY (
  year STRING,
  month STRING,
  day STRING,
  hour STRING
)
```

**Benefits:**
- Smaller partitions = faster queries
- More granular time filters
- Better parallelization

### Compression

Use Snappy compression for Parquet:

```sql
CREATE TABLE cloudtrail_optimized
WITH (
  format = 'PARQUET',
  parquet_compression = 'SNAPPY'  -- Fast decompression
) AS SELECT * FROM cloudtrail
```

### Query Concurrency

Athena default: 20 concurrent queries
Increase for high volume:

```bash
# Contact AWS Support to increase limits
# Or use multiple workgroups
aws athena create-work-group \
  --name mantissa-log-high-priority \
  --configuration "
    ResultConfiguration={
      OutputLocation=s3://$ATHENA_BUCKET/results/
    }
  "
```

### Caching Layer

Add Redis/ElastiCache for frequently accessed data:

```python
import redis

cache = redis.Redis(host='cache-endpoint', port=6379)

def query_with_cache(sql, ttl=300):
    cache_key = hashlib.md5(sql.encode()).hexdigest()

    # Check cache
    cached = cache.get(cache_key)
    if cached:
        return json.loads(cached)

    # Execute query
    result = athena.execute_query(sql)

    # Cache result
    cache.setex(cache_key, ttl, json.dumps(result))

    return result
```

## High-Volume Environments

### Log Ingestion

**Problem:** CloudTrail delivers logs with delay

**Solutions:**

**1. Kinesis Firehose for Real-Time**

```bash
aws firehose create-delivery-stream \
  --delivery-stream-name cloudtrail-realtime \
  --extended-s3-destination-configuration \
    BucketARN=arn:aws:s3:::$LOGS_BUCKET,\
    Prefix=cloudtrail/,\
    BufferingHints={SizeInMBs=128,IntervalInSeconds=60},\
    CompressionFormat=GZIP,\
    DataFormatConversionConfiguration={
      SchemaConfiguration={
        DatabaseName=$DATABASE,
        TableName=cloudtrail,
        Region=us-east-1
      },
      InputFormatConfiguration={
        Deserializer={OpenXJsonSerDe={}}
      },
      OutputFormatConfiguration={
        Serializer={ParquetSerDe={}}
      }
    }
```

**2. Event-Driven Detection**

Trigger on S3 object creation:

```bash
# Add S3 event notification
aws s3api put-bucket-notification-configuration \
  --bucket $LOGS_BUCKET \
  --notification-configuration '{
    "LambdaFunctionConfigurations": [{
      "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:mantissa-log-detection-engine",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {
          "FilterRules": [{
            "Name": "prefix",
            "Value": "cloudtrail/"
          }]
        }
      }
    }]
  }'
```

### Detection at Scale

**Parallel Rule Execution:**

```python
# In detection engine
import concurrent.futures

def execute_rules_parallel(rules, max_workers=10):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(execute_rule, rule): rule for rule in rules}

        for future in concurrent.futures.as_completed(futures):
            rule = futures[future]
            try:
                result = future.result()
                yield result
            except Exception as e:
                logger.error(f"Rule {rule.name} failed: {e}")
```

**Batch Query Execution:**

```python
# Execute multiple queries in single Athena call
queries = [rule.query for rule in rules]

query_ids = []
for query in queries:
    query_id = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': database},
        WorkGroup=workgroup
    )
    query_ids.append(query_id)

# Poll for results
results = athena.batch_get_query_execution(QueryExecutionIds=query_ids)
```

## Multi-Account Setup

### Centralized Logging

**Spoke Accounts** → **Central Log Account** → **Mantissa Log**

**1. Set up cross-account S3 access:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::central-logs-bucket"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::central-logs-bucket/cloudtrail/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

**2. Configure spoke account CloudTrail:**

```bash
# In each spoke account
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name central-logs-bucket \
  --s3-key-prefix cloudtrail/account-123456789012/ \
  --is-organization-trail \
  --region us-east-1
```

**3. Create Glue tables with account partitions:**

```sql
CREATE EXTERNAL TABLE cloudtrail_multi_account (
  ...
)
PARTITIONED BY (
  account_id STRING,
  year STRING,
  month STRING,
  day STRING
)
```

### Organization-Wide Deployment

Use AWS CloudFormation StackSets:

```bash
aws cloudformation create-stack-set \
  --stack-set-name mantissa-log-org \
  --template-body file://mantissa-log-stackset.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters \
    ParameterKey=CentralLogsBucket,ParameterValue=central-logs-bucket

aws cloudformation create-stack-instances \
  --stack-set-name mantissa-log-org \
  --accounts 123456789012 234567890123 345678901234 \
  --regions us-east-1 \
  --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1
```

## Multi-Region Deployment

### Active-Active Architecture

Deploy Mantissa Log in multiple regions:

```bash
# Deploy to us-east-1
cd infrastructure/aws/terraform
terraform workspace new us-east-1
terraform apply -var="aws_region=us-east-1"

# Deploy to us-west-2
terraform workspace new us-west-2
terraform apply -var="aws_region=us-west-2"
```

### Cross-Region Replication

Replicate logs to secondary region:

```bash
aws s3api put-bucket-replication \
  --bucket $LOGS_BUCKET \
  --replication-configuration '{
    "Role": "arn:aws:iam::123456789012:role/s3-replication-role",
    "Rules": [{
      "Status": "Enabled",
      "Priority": 1,
      "DeleteMarkerReplication": {"Status": "Disabled"},
      "Filter": {},
      "Destination": {
        "Bucket": "arn:aws:s3:::logs-bucket-replica",
        "ReplicationTime": {
          "Status": "Enabled",
          "Time": {"Minutes": 15}
        }
      }
    }]
  }'
```

### Global Table for State

DynamoDB Global Tables:

```bash
aws dynamodb update-table \
  --table-name $STATE_TABLE \
  --replica-updates '[{
    "Create": {
      "RegionName": "us-west-2"
    }
  }]' \
  --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES
```

## Monitoring at Scale

### CloudWatch Metrics

**Custom Metrics:**

```python
import boto3

cloudwatch = boto3.client('cloudwatch')

# Track rules executed
cloudwatch.put_metric_data(
    Namespace='MantissaLog',
    MetricData=[{
        'MetricName': 'RulesExecuted',
        'Value': len(rules),
        'Unit': 'Count',
        'Timestamp': datetime.utcnow()
    }]
)

# Track data scanned
cloudwatch.put_metric_data(
    Namespace='MantissaLog',
    MetricData=[{
        'MetricName': 'DataScannedBytes',
        'Value': query_result['Statistics']['DataScannedInBytes'],
        'Unit': 'Bytes'
    }]
)
```

### Distributed Tracing

Add X-Ray to Lambda functions:

```bash
aws lambda update-function-configuration \
  --function-name mantissa-log-detection-engine \
  --tracing-config Mode=Active
```

```python
# In Lambda function
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

patch_all()

@xray_recorder.capture('execute_rule')
def execute_rule(rule):
    # Function code
    pass
```

## Performance Benchmarks

### Expected Performance

| Metric | Small | Medium | Large |
|--------|-------|--------|-------|
| Detection Cycle | < 30s | < 2m | < 5m |
| Query Latency | < 5s | < 10s | < 30s |
| Alert Delivery | < 1s | < 2s | < 5s |
| Data Scanned/Query | < 100MB | < 1GB | < 10GB |

### Optimization Targets

- Athena query execution: < 10s
- Lambda cold start: < 3s
- Alert routing latency: < 2s
- End-to-end (detection → alert): < 60s

## Capacity Planning

### Calculate Resources

**Events per month:** 50M
**Rules:** 50
**Detection frequency:** 5 minutes

**Athena queries/month:**
- 50 rules × 12 per hour × 24 hours × 30 days = 432,000 queries

**Data scanned (with partitioning):**
- 50M events × 500 bytes = 25GB raw
- With Parquet: 25GB × 0.2 = 5GB
- Per query (5 min window): 5GB / (12 × 24 × 30) = 580KB
- Total scanned: 432,000 × 580KB = 250GB/month

**Cost estimate:**
- Athena: 250GB × $5/TB = $1.25
- S3: 25GB × $0.023 = $0.58
- Lambda: 432,000 × $0.0000002 = $0.09
- DynamoDB: Variable, ~$5-10
- **Total: ~$7-12/month**

### Scaling Checklist

- [ ] Enable partition pruning in all queries
- [ ] Convert high-volume tables to Parquet
- [ ] Set up S3 lifecycle policies
- [ ] Configure DynamoDB auto-scaling
- [ ] Enable Athena query result reuse
- [ ] Right-size Lambda memory
- [ ] Implement query caching
- [ ] Monitor and optimize slow queries
- [ ] Set up cost alerts
- [ ] Review and disable low-value rules
