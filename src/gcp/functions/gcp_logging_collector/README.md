# GCP Cloud Logging Collector - Cloud Function

Native GCP Cloud Function for collecting GCP Cloud Logging entries and storing them in Cloud Storage for BigQuery analysis.

## Overview

This Cloud Function collects logs from GCP Cloud Logging API and stores them in Cloud Storage in both raw and normalized (ECS) formats for analysis with BigQuery.

## Supported Log Types

- **Cloud Audit Logs**: Admin Activity, Data Access, System Event logs
- **VPC Flow Logs**: Network traffic flow records
- **Firewall Logs**: VPC firewall allow/deny decisions
- **GKE Audit Logs**: Kubernetes API server audit logs

## Architecture

```
Cloud Scheduler (cron)
      |
      v
Cloud Function (this code)
      |
      +-- Cloud Logging API (read logs)
      |
      +-- Cloud Storage (write raw + normalized logs)
      |
      +-- Firestore (checkpoint tracking)

BigQuery External Tables
      |
      v
Cloud Storage (gs://bucket/gcp_logging/...)
```

## Deployment

### Prerequisites

1. GCP Project with required APIs enabled:
   - Cloud Functions API
   - Cloud Logging API
   - Cloud Storage API
   - Firestore API
   - Cloud Scheduler API

2. Service Account with permissions:
   - `roles/logging.viewer` (read logs)
   - `roles/storage.objectCreator` (write to GCS)
   - `roles/datastore.user` (Firestore checkpoints)

3. Cloud Storage bucket for log output

### Deploy via gcloud

```bash
# Set variables
export GCP_PROJECT_ID="your-project-id"
export GCS_BUCKET="your-logs-bucket"
export FUNCTION_NAME="gcp-logging-collector"
export REGION="us-central1"

# Deploy HTTP-triggered function
gcloud functions deploy $FUNCTION_NAME \
  --gen2 \
  --runtime=python311 \
  --region=$REGION \
  --source=. \
  --entry-point=collect_gcp_logs \
  --trigger-http \
  --memory=512MB \
  --timeout=540s \
  --set-env-vars GCP_PROJECT_ID=$GCP_PROJECT_ID,GCS_BUCKET=$GCS_BUCKET,LOG_TYPES=audit,vpc_flow,firewall,gke,COLLECTION_INTERVAL_HOURS=1

# Create Cloud Scheduler job to trigger every hour
gcloud scheduler jobs create http gcp-logging-collector-job \
  --location=$REGION \
  --schedule="0 * * * *" \
  --uri="https://${REGION}-${GCP_PROJECT_ID}.cloudfunctions.net/${FUNCTION_NAME}" \
  --http-method=POST \
  --oidc-service-account-email="${GCP_PROJECT_ID}@appspot.gserviceaccount.com"
```

### Deploy via Terraform

```hcl
resource "google_cloudfunctions2_function" "gcp_logging_collector" {
  name        = "gcp-logging-collector"
  location    = var.region
  description = "Collects GCP Cloud Logging entries"

  build_config {
    runtime     = "python311"
    entry_point = "collect_gcp_logs"
    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    available_memory   = "512M"
    timeout_seconds    = 540
    environment_variables = {
      GCP_PROJECT_ID            = var.project_id
      GCS_BUCKET                = google_storage_bucket.logs.name
      LOG_TYPES                 = "audit,vpc_flow,firewall,gke"
      COLLECTION_INTERVAL_HOURS = "1"
    }
    service_account_email = google_service_account.functions.email
  }
}

resource "google_cloud_scheduler_job" "gcp_logging_collector" {
  name        = "gcp-logging-collector-job"
  region      = var.region
  description = "Triggers GCP Cloud Logging collection"
  schedule    = "0 * * * *"  # Every hour
  time_zone   = "UTC"

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.gcp_logging_collector.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.functions.email
    }
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GCP_PROJECT_ID` | Yes | - | GCP project ID to collect logs from |
| `GCS_BUCKET` | Yes | - | Cloud Storage bucket name for output |
| `LOG_TYPES` | No | `audit,vpc_flow,firewall,gke` | Comma-separated list of log types to collect |
| `COLLECTION_INTERVAL_HOURS` | No | `1` | Hours of logs to collect per run |

## Output Structure

### Cloud Storage Layout

```
gs://your-bucket/
├── gcp_logging/
│   ├── audit/
│   │   ├── raw/
│   │   │   └── YYYY/MM/DD/HH/
│   │   │       └── logs_YYYYMMDD_HHMMSS.json
│   │   └── normalized/
│   │       └── YYYY/MM/DD/HH/
│   │           └── logs_YYYYMMDD_HHMMSS.json
│   ├── vpc_flow/
│   │   ├── raw/...
│   │   └── normalized/...
│   ├── firewall/
│   │   ├── raw/...
│   │   └── normalized/...
│   └── gke/
│       ├── raw/...
│       └── normalized/...
```

### Firestore Checkpoints

Collection checkpoints are stored in Firestore:

```
checkpoints/
├── gcp_logging_audit
├── gcp_logging_vpc_flow
├── gcp_logging_firewall
└── gcp_logging_gke
```

Each document contains:
```json
{
  "last_timestamp": "2025-01-28T10:00:00Z",
  "updated_at": "2025-01-28T11:00:05Z",
  "log_type": "audit",
  "project_id": "your-project-id"
}
```

## Monitoring

### Cloud Functions Metrics

Monitor function performance in Cloud Console:
- Invocations
- Execution time
- Memory usage
- Error rate

### Logs

View function logs:
```bash
gcloud functions logs read $FUNCTION_NAME --region=$REGION --limit=50
```

### Cost Estimation

Assuming 1 million log entries per day:

- Cloud Functions: ~$0.50/day (hourly execution, 512MB, 2-5 min avg)
- Cloud Storage: ~$0.02/GB/month
- Firestore: ~$0.01/day (checkpoint writes)
- Cloud Logging API: Free (first 50GB/month)

Total: ~$20-30/month for typical workload

## Integration with BigQuery

After deploying this function, configure BigQuery external tables to query the collected logs:

```sql
-- See infrastructure/gcp/terraform/gcp_logging_tables.tf for full table schemas

-- Query normalized audit logs
SELECT
  timestamp,
  event_action,
  user_email,
  source_ip
FROM
  `project.mantissa_logs.gcp_audit_normalized`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
  AND event_outcome = 'failure'
ORDER BY timestamp DESC
LIMIT 100;
```

## Troubleshooting

### Permission Denied

Ensure service account has required roles:
```bash
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/logging.viewer"
```

### Function Timeout

Increase timeout or reduce `COLLECTION_INTERVAL_HOURS`:
```bash
gcloud functions deploy $FUNCTION_NAME \
  --timeout=540s \
  --set-env-vars COLLECTION_INTERVAL_HOURS=1
```

### No Logs Collected

Check Cloud Logging has data:
```bash
gcloud logging read "timestamp>=\"$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')\"" --limit=10
```

## Local Development

Test function locally:

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GCP_PROJECT_ID="your-project-id"
export GCS_BUCKET="your-bucket"
export LOG_TYPES="audit"
export COLLECTION_INTERVAL_HOURS="1"

# Run with Functions Framework
functions-framework --target=collect_gcp_logs --debug
```

Test HTTP endpoint:
```bash
curl -X POST http://localhost:8080/
```

## Security Considerations

1. **Service Account**: Use dedicated service account with minimal permissions
2. **VPC-SC**: Deploy function inside VPC Service Controls perimeter for added security
3. **Private GCS**: Use private Cloud Storage bucket with uniform bucket-level access
4. **Secrets**: Store sensitive values in Secret Manager, not environment variables
5. **Audit**: Enable Cloud Audit Logs for the function itself

## References

- [GCP Cloud Logging API](https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)
- [Cloud Functions (2nd gen)](https://cloud.google.com/functions/docs/2nd-gen/overview)
- [BigQuery External Tables](https://cloud.google.com/bigquery/docs/external-tables)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
