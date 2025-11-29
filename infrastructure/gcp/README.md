# Mantissa Log - GCP Infrastructure

This directory contains Terraform configuration for deploying Mantissa Log on Google Cloud Platform (GCP).

## Overview

Mantissa Log on GCP uses the following services:

- **Cloud Storage**: Log data lake with lifecycle policies
- **BigQuery**: SQL query engine for log analysis
- **Cloud Functions (2nd gen)**: Serverless log collection and processing
- **Firestore**: State management and checkpoints
- **Secret Manager**: Secure credential storage
- **Pub/Sub**: Alert routing and event streaming
- **Cloud Scheduler**: Scheduled log collection
- **Cloud Run**: Serverless execution platform for functions

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GCP Cloud Logging                        │
│         (Audit Logs, VPC Flow, Firewall, GKE)              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │  Cloud Scheduler       │
        │  (Hourly trigger)      │
        └────────────┬───────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │  Cloud Function        │
        │  (Log Collector)       │
        └────┬──────────┬────────┘
             │          │
    ┌────────┘          └────────┐
    ▼                            ▼
┌─────────────┐          ┌──────────────┐
│  Firestore  │          │Cloud Storage │
│(Checkpoints)│          │  (Data Lake) │
└─────────────┘          └──────┬───────┘
                                │
                                ▼
                        ┌───────────────┐
                        │   BigQuery    │
                        │(External      │
                        │ Tables)       │
                        └───────────────┘
```

## Prerequisites

1. **GCP Account** with billing enabled
2. **GCP Project** with required APIs enabled
3. **Terraform** >= 1.5.0
4. **gcloud CLI** installed and authenticated

### Required GCP APIs

The Terraform configuration automatically enables these APIs:

- Cloud Functions API
- Cloud Build API
- BigQuery API
- Cloud Storage API
- Secret Manager API
- Pub/Sub API
- Cloud Scheduler API
- Cloud Logging API
- Firestore API

## Deployment

### 1. Initialize GCP Project

```bash
# Set your GCP project ID
export GCP_PROJECT_ID="your-project-id"

# Authenticate with GCP
gcloud auth login
gcloud auth application-default login

# Set default project
gcloud config set project $GCP_PROJECT_ID
```

### 2. Create Terraform Backend (Optional)

```bash
# Create GCS bucket for Terraform state
gsutil mb -p $GCP_PROJECT_ID -l us-central1 gs://${GCP_PROJECT_ID}-terraform-state

# Enable versioning
gsutil versioning set on gs://${GCP_PROJECT_ID}-terraform-state
```

Create `backend.tf`:

```hcl
terraform {
  backend "gcs" {
    bucket = "your-project-id-terraform-state"
    prefix = "mantissa-log/state"
  }
}
```

### 3. Configure Variables

Copy and edit the variables file:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
project_id  = "your-project-id"
region      = "us-central1"
environment = "production"
```

### 4. Deploy Infrastructure

```bash
# Navigate to terraform directory
cd infrastructure/gcp/terraform

# Initialize Terraform
terraform init

# Review planned changes
terraform plan

# Apply configuration
terraform apply
```

### 5. Verify Deployment

```bash
# Check Cloud Functions
gcloud functions list --gen2 --region=us-central1

# Check BigQuery datasets
bq ls

# Check Cloud Storage buckets
gsutil ls

# Check Cloud Scheduler jobs
gcloud scheduler jobs list --location=us-central1

# Test function invocation (manual)
gcloud functions call mantissa-gcp-logging-collector-XXXX \
  --region=us-central1 \
  --gen2
```

## Configuration

### Environment Variables (Cloud Function)

The GCP Cloud Logging Collector function uses these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `GCP_PROJECT_ID` | GCP project ID to collect logs from | (set by Terraform) |
| `GCS_BUCKET` | Cloud Storage bucket for log output | (set by Terraform) |
| `LOG_TYPES` | Comma-separated list of log types | `audit,vpc_flow,firewall,gke` |
| `COLLECTION_INTERVAL_HOURS` | Hours of logs to collect per run | `1` |

To modify, update `infrastructure/gcp/terraform/cloud_functions.tf`

### Collection Schedule

Default: Hourly collection (`0 * * * *`)

To modify schedule, update Cloud Scheduler job in `cloud_functions.tf`

### Storage Lifecycle

Cloud Storage lifecycle policies (configured in `main.tf`):

- **0-30 days**: Standard storage (hot)
- **30-90 days**: Nearline storage (warm)
- **90-365 days**: Coldline storage (cold)
- **>365 days**: Deleted

## Querying Logs with BigQuery

### Example Queries

```sql
-- Recent audit log failures
SELECT
  timestamp,
  event_action,
  user_email,
  source_ip,
  event_outcome
FROM
  `project.mantissa_logs_XXXX.gcp_audit_normalized`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
  AND event_outcome = 'failure'
ORDER BY timestamp DESC
LIMIT 100;

-- VPC flow traffic summary
SELECT
  source_ip,
  destination_ip,
  destination_port,
  SUM(network_bytes) as total_bytes,
  COUNT(*) as flow_count
FROM
  `project.mantissa_logs_XXXX.gcp_vpc_flow_normalized`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY source_ip, destination_ip, destination_port
ORDER BY total_bytes DESC
LIMIT 50;
```

## Cost Estimation

Estimated monthly costs for a typical deployment:

| Service | Usage | Monthly Cost |
|---------|-------|--------------|
| Cloud Storage | 100GB avg, with lifecycle policies | $2-5 |
| BigQuery | 1TB scanned/month | $5 |
| Cloud Functions | 720 invocations/month @ 512MB, 3min avg | $3-5 |
| Firestore | Checkpoint writes (minimal) | <$1 |
| Cloud Logging API | First 50GB free | $0 |
| Cloud Scheduler | 1 job | <$1 |

**Total: $15-20/month** for typical small-medium workload

## Monitoring

### Cloud Functions Metrics

View in Cloud Console key metrics:
- Invocations per minute
- Execution time
- Memory usage
- Error rate

### Cloud Logging

```bash
# View function logs
gcloud functions logs read mantissa-gcp-logging-collector-XXXX \
  --region=us-central1 \
  --limit=50
```

## Troubleshooting

### Function Execution Errors

Check function logs for common issues:
- Permission denied: Check service account IAM roles
- Timeout: Reduce collection interval or increase timeout
- Out of memory: Increase memory allocation to 1GB

### No Logs Collected

Verify Cloud Logging has data:
```bash
gcloud logging read "timestamp>=\"$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')\"" --limit=10
```

## Security Best Practices

1. Use minimal IAM roles for service accounts
2. Deploy inside VPC Service Controls perimeter (optional)
3. Use private GCS buckets with uniform access
4. Store sensitive values in Secret Manager
5. Enable audit logging for all resources

## Cleanup

To destroy all resources:

```bash
# WARNING: This will delete all logs and infrastructure
terraform destroy
```

## Multi-Cloud Integration

To collect GCP logs into AWS Mantissa Log deployment, use the AWS Lambda collector at `src/aws/lambda/gcp_logging_collector_handler.py` for cross-cloud collection.

## References

- [GCP Cloud Functions Documentation](https://cloud.google.com/functions/docs)
- [BigQuery External Tables](https://cloud.google.com/bigquery/docs/external-tables)
- [GCP Cloud Logging](https://cloud.google.com/logging/docs)
- [Terraform GCP Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
