# Multi-Region Deployment Guide

This guide covers deploying Mantissa Log across multiple regions for high availability, disaster recovery, and reduced latency.

## Overview

Mantissa Log supports multi-region deployment on all three cloud providers:
- **AWS**: Active-passive or active-active with DynamoDB Global Tables and S3 Cross-Region Replication
- **Azure**: Active-passive with Cosmos DB geo-replication and Traffic Manager
- **GCP**: Active-passive with Cloud Storage replication and Cloud Load Balancing

## Architecture Patterns

### Active-Passive (Recommended for Cost Optimization)

```
                    ┌─────────────────┐
                    │  Global DNS /   │
                    │  Load Balancer  │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
      ┌───────▼───────┐            ┌───────▼───────┐
      │ Primary Region │            │Secondary Region│
      │   (Active)    │            │   (Standby)    │
      │               │            │                │
      │ ┌───────────┐ │   sync     │ ┌───────────┐  │
      │ │   Data    │◄├────────────┤►│   Data    │  │
      │ │   Store   │ │            │ │   Store   │  │
      │ └───────────┘ │            │ └───────────┘  │
      │               │            │                │
      │ ┌───────────┐ │            │ ┌───────────┐  │
      │ │  Compute  │ │            │ │  Compute  │  │
      │ │  (Hot)    │ │            │ │  (Cold)   │  │
      │ └───────────┘ │            │ └───────────┘  │
      └───────────────┘            └────────────────┘
```

**Characteristics:**
- Primary region handles all traffic
- Secondary region receives replicated data
- Failover triggered manually or via health checks
- Lower cost (secondary compute can be scaled down)

### Active-Active (Recommended for Low Latency)

```
                    ┌─────────────────┐
                    │  Global DNS /   │
                    │  Load Balancer  │
                    │  (Geo-routing)  │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
      ┌───────▼───────┐            ┌───────▼───────┐
      │ Region 1 (US) │            │ Region 2 (EU) │
      │   (Active)    │            │   (Active)    │
      │               │            │                │
      │ ┌───────────┐ │  bi-dir    │ ┌───────────┐  │
      │ │   Data    │◄├────────────┤►│   Data    │  │
      │ │   Store   │ │   sync     │ │   Store   │  │
      │ └───────────┘ │            │ └───────────┘  │
      │               │            │                │
      │ ┌───────────┐ │            │ ┌───────────┐  │
      │ │  Compute  │ │            │ │  Compute  │  │
      │ │  (Hot)    │ │            │ │  (Hot)    │  │
      │ └───────────┘ │            │ └───────────┘  │
      └───────────────┘            └────────────────┘
```

**Characteristics:**
- Both regions handle traffic based on geo-proximity
- Bi-directional data replication
- Higher complexity for conflict resolution
- Higher cost but lower latency globally

## AWS Multi-Region Deployment

### Prerequisites

1. AWS accounts with appropriate permissions
2. Terraform >= 1.5.0
3. AWS CLI configured with credentials

### Step 1: Configure Regions

Edit `infrastructure/aws/terraform/environments/prod-multi-region.tfvars`:

```hcl
# Multi-region configuration
primary_region   = "us-east-1"
secondary_region = "us-west-2"

failover_strategy = "active-passive"  # or "active-active"

# Enable replication features
enable_dynamodb_global_tables = true
enable_s3_cross_region_replication = true
enable_route53_health_checks = true

# Environment
environment = "prod"
project     = "mantissa-log"
```

### Step 2: Deploy Global Resources

```bash
cd infrastructure/aws/terraform

# Initialize with S3 backend
terraform init -backend-config=environments/prod-backend.tfvars

# Plan global resources (Route 53, CloudFront)
terraform plan \
  -target=module.global \
  -var-file=environments/prod-multi-region.tfvars

# Apply global resources
terraform apply \
  -target=module.global \
  -var-file=environments/prod-multi-region.tfvars
```

### Step 3: Deploy Primary Region

```bash
# Deploy primary region
terraform apply \
  -target=module.region_primary \
  -var-file=environments/prod-multi-region.tfvars
```

### Step 4: Deploy Secondary Region

```bash
# Deploy secondary region
terraform apply \
  -target=module.region_secondary \
  -var-file=environments/prod-multi-region.tfvars
```

### Step 5: Enable Replication

After both regions are deployed:

```bash
# Apply full configuration to enable cross-region resources
terraform apply \
  -var-file=environments/prod-multi-region.tfvars
```

### AWS Multi-Region Components

| Component | Primary Region | Secondary Region | Replication Method |
|-----------|---------------|-----------------|-------------------|
| S3 Logs Bucket | Active writes | Replica | S3 CRR |
| DynamoDB State | Active | Global Table | DynamoDB Streams |
| Lambda Functions | Running | Running (reduced) | N/A (code deploy) |
| Athena | Active | Active | Shared Glue Catalog |
| API Gateway | Active | Standby | N/A |
| Cognito | Active | Standby | N/A |

### Failover Procedure (AWS)

**Automatic Failover (with Route 53 Health Checks):**
1. Route 53 health check detects primary region failure
2. DNS automatically routes to secondary region
3. Secondary Lambda functions handle traffic
4. DynamoDB Global Tables ensure state consistency

**Manual Failover:**
```bash
# Update Route 53 to point to secondary
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456 \
  --change-batch file://failover-to-secondary.json

# Scale up secondary region compute
aws lambda update-function-configuration \
  --function-name mantissa-detection-engine \
  --region us-west-2 \
  --memory-size 1024 \
  --reserved-concurrent-executions 100
```

## Azure Multi-Region Deployment

### Prerequisites

1. Azure subscription with appropriate permissions
2. Terraform >= 1.5.0
3. Azure CLI configured

### Step 1: Configure Regions

Edit `infrastructure/azure/terraform/environments/prod-multi-region.tfvars`:

```hcl
# Multi-region configuration
primary_location   = "eastus"
secondary_location = "westus2"

failover_strategy = "active-passive"

# Enable replication
cosmos_multi_region_write = false  # true for active-active
storage_replication_type  = "GRS"  # Geo-redundant storage

# Environment
environment = "prod"
project     = "mantissa-log"
```

### Step 2: Deploy with Traffic Manager

```bash
cd infrastructure/azure/terraform

terraform init
terraform apply -var-file=environments/prod-multi-region.tfvars
```

### Azure Multi-Region Components

| Component | Primary Region | Secondary Region | Replication Method |
|-----------|---------------|-----------------|-------------------|
| Storage Account | Active writes | GRS replica | Azure Storage GRS |
| Cosmos DB | Active | Read replica | Cosmos DB geo-rep |
| Functions | Running | Running (reduced) | N/A |
| Synapse | Active | Backup/restore | Manual |
| API Management | Active | Standby | N/A |

### Failover Procedure (Azure)

```bash
# Initiate Cosmos DB failover
az cosmosdb failover-priority-change \
  --name mantissa-cosmos \
  --resource-group mantissa-rg \
  --failover-policies "westus2=0" "eastus=1"

# Update Traffic Manager
az network traffic-manager endpoint update \
  --name primary-endpoint \
  --profile-name mantissa-tm \
  --resource-group mantissa-rg \
  --type azureEndpoints \
  --endpoint-status Disabled
```

## GCP Multi-Region Deployment

### Prerequisites

1. GCP project with appropriate permissions
2. Terraform >= 1.5.0
3. gcloud CLI configured

### Step 1: Configure Regions

Edit `infrastructure/gcp/terraform/environments/prod-multi-region.tfvars`:

```hcl
# Multi-region configuration
primary_region   = "us-central1"
secondary_region = "us-east1"

failover_strategy = "active-passive"

# Enable replication
bigquery_location      = "US"  # Multi-region dataset
storage_dual_region    = true
firestore_multi_region = false  # Limited support

# Environment
environment = "prod"
project     = "mantissa-log"
```

### Step 2: Deploy with Cloud Load Balancing

```bash
cd infrastructure/gcp/terraform

terraform init
terraform apply -var-file=environments/prod-multi-region.tfvars
```

### GCP Multi-Region Components

| Component | Primary Region | Secondary Region | Replication Method |
|-----------|---------------|-----------------|-------------------|
| Cloud Storage | Active writes | Dual-region | GCS dual-region |
| BigQuery | Multi-region | Multi-region | US/EU location |
| Firestore | Active | N/A | Single region only |
| Cloud Functions | Running | Running (reduced) | N/A |
| Pub/Sub | Active | Active | Global by default |

### Failover Procedure (GCP)

```bash
# Update Cloud Load Balancer backend
gcloud compute backend-services update mantissa-backend \
  --global \
  --no-enable-cdn

# Update backend group weights
gcloud compute backend-services update-backend mantissa-backend \
  --global \
  --network-endpoint-group=mantissa-neg-secondary \
  --network-endpoint-group-region=us-east1 \
  --balancing-mode=RATE \
  --max-rate-per-endpoint=100
```

## Cost Considerations

### Active-Passive Cost Estimate

| Component | Primary | Secondary | Monthly Cost Impact |
|-----------|---------|-----------|-------------------|
| Compute | Full capacity | 10% capacity | +10% base compute |
| Storage | Full | Replica | +100% storage |
| Data Transfer | Normal | Replication | +$0.02/GB |
| Database | Full | Replica | +50-100% database |

**Estimated additional cost: 30-50% of single-region**

### Active-Active Cost Estimate

| Component | Region 1 | Region 2 | Monthly Cost Impact |
|-----------|----------|----------|-------------------|
| Compute | Full capacity | Full capacity | +100% compute |
| Storage | Full | Full | +100% storage |
| Data Transfer | Normal | Bi-directional | +$0.04/GB |
| Database | Full (writes) | Full (writes) | +100-200% database |

**Estimated additional cost: 80-120% of single-region**

## Monitoring Multi-Region Deployments

### CloudWatch Dashboard (AWS)

Create a multi-region dashboard:

```bash
aws cloudwatch put-dashboard \
  --dashboard-name MantissaMultiRegion \
  --dashboard-body file://dashboards/multi-region.json
```

### Key Metrics to Monitor

1. **Replication Lag**
   - DynamoDB: `ReplicationLatency`
   - S3: CRR metrics
   - Cosmos DB: `ReplicationLatency`

2. **Health Check Status**
   - Route 53 health check status
   - Traffic Manager endpoint health
   - Cloud Load Balancer backend health

3. **Cross-Region Data Transfer**
   - S3 CRR bytes transferred
   - DynamoDB stream records
   - Storage account egress

4. **Regional Utilization**
   - Lambda invocations per region
   - API Gateway requests per region
   - Function execution count per region

## Disaster Recovery Procedures

### RTO and RPO Targets

| Tier | RPO | RTO | Strategy |
|------|-----|-----|----------|
| Tier 1 (Critical) | < 1 minute | < 15 minutes | Active-Active |
| Tier 2 (Important) | < 15 minutes | < 1 hour | Active-Passive (hot) |
| Tier 3 (Standard) | < 1 hour | < 4 hours | Active-Passive (warm) |

### Recovery Runbook

1. **Detect Failure**
   - Monitor health check alerts
   - Validate primary region unavailability

2. **Initiate Failover**
   - Update DNS/Load Balancer routing
   - Scale up secondary region compute
   - Verify data consistency

3. **Validate Recovery**
   - Test API endpoints
   - Verify detection rules are executing
   - Check alert routing

4. **Communicate**
   - Notify stakeholders
   - Update status page
   - Log incident details

5. **Plan Failback**
   - Monitor primary region recovery
   - Plan data sync if needed
   - Schedule failback window

## Troubleshooting

### Common Issues

**Replication Lag Too High**
- Check network connectivity between regions
- Verify IAM permissions for replication
- Review throughput limits

**Inconsistent State After Failover**
- Check last sync timestamp
- Review conflict resolution logs
- Manually reconcile if needed

**High Cross-Region Costs**
- Review data transfer patterns
- Consider caching frequently accessed data
- Optimize replication filters

## Next Steps

1. Start with active-passive for cost optimization
2. Monitor replication metrics for 2 weeks
3. Test failover procedure quarterly
4. Consider active-active only if latency requirements demand it
