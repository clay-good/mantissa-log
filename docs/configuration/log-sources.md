# Log Sources Configuration Guide

This guide covers configuring all supported log sources for Mantissa Log.

## Overview

Mantissa Log supports multiple log sources:

- **AWS Native**: CloudTrail, VPC Flow Logs, GuardDuty, CloudWatch Logs
- **Custom Applications**: JSON-formatted application logs
- **Third-Party**: Logs from external security tools

All logs are:
1. Written to S3 buckets (organized by source and date)
2. Cataloged in AWS Glue (schema discovery)
3. Queried via Amazon Athena (SQL engine)
4. Analyzed by detection rules

## AWS CloudTrail

CloudTrail records AWS API activity and account events.

### Automatic Setup

The deployment script automatically creates and configures CloudTrail:

```bash
# CloudTrail is set up during deployment
bash scripts/deploy.sh
```

### Manual Setup

If you need to configure CloudTrail manually:

```bash
# Get logs bucket
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')
REGION="us-east-1"
TRAIL_NAME="mantissa-log-trail"

# Create trail
aws cloudtrail create-trail \
  --name $TRAIL_NAME \
  --s3-bucket-name $LOGS_BUCKET \
  --s3-key-prefix cloudtrail/ \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --region $REGION

# Start logging
aws cloudtrail start-logging \
  --name $TRAIL_NAME \
  --region $REGION
```

### Verify CloudTrail

```bash
# Check trail status
aws cloudtrail get-trail-status --name $TRAIL_NAME

# Should show: "IsLogging": true

# Check for log files
aws s3 ls s3://$LOGS_BUCKET/cloudtrail/ --recursive | head -10
```

### Example Queries

```sql
-- Failed login attempts
SELECT
    useridentity.principalid,
    sourceipaddress,
    eventtime,
    errorcode,
    errormessage
FROM cloudtrail
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL
  AND year = '2024'
  AND month = '01'
ORDER BY eventtime DESC
LIMIT 100;

-- Root account activity
SELECT
    eventtime,
    eventname,
    sourceipaddress,
    requestparameters
FROM cloudtrail
WHERE useridentity.type = 'Root'
  AND year = '2024'
  AND month = '01'
ORDER BY eventtime DESC;
```

## VPC Flow Logs

VPC Flow Logs capture network traffic metadata for your VPCs.

### Enable VPC Flow Logs

```bash
# Get logs bucket
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')

# Enable flow logs for a VPC
VPC_ID="vpc-12345678"

aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination "arn:aws:s3:::$LOGS_BUCKET/vpc-flow-logs/"
```

## AWS GuardDuty

GuardDuty provides intelligent threat detection findings.

### Enable GuardDuty

```bash
# Enable GuardDuty detector
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
```

## Custom Application Logs

Add your own application logs to Mantissa Log.

### Requirements

Logs must be:
- JSON format (one object per line)
- Written to the Mantissa Log S3 bucket
- Organized by date for partitioning

### Example Log Format

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "ERROR",
  "service": "api-gateway",
  "user_id": "user123",
  "request_id": "req-456",
  "method": "POST",
  "path": "/api/orders",
  "status_code": 500,
  "error_message": "Database connection failed",
  "duration_ms": 1234,
  "source_ip": "192.168.1.100"
}
```
