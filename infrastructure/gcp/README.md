# Mantissa Log - Google Cloud Platform Implementation

This document outlines the planned implementation of Mantissa Log on Google Cloud Platform.

## GCP Architecture Overview

### Core Components

- **Cloud Storage**: Log storage and archival
- **BigQuery**: SQL query engine for log analysis
- **Cloud Functions**: Serverless compute for detection engine and LLM integration
- **Cloud Scheduler**: Scheduled execution of detection rules
- **Secret Manager**: Secure storage for API keys and credentials
- **Identity Platform**: User authentication and authorization
- **Firestore**: State management for detection engine and query sessions
- **Cloud Pub/Sub**: Event routing for alerts

## Component Mapping: AWS to GCP

| AWS Service | GCP Equivalent | Purpose |
|------------|----------------|---------|
| S3 | Cloud Storage | Log storage |
| Athena | BigQuery | SQL query engine |
| Glue Data Catalog | BigQuery metadata | Table schemas and partitions |
| Lambda | Cloud Functions | Serverless compute |
| EventBridge | Cloud Scheduler | Scheduled rule execution |
| Secrets Manager | Secret Manager | Credential storage |
| Cognito | Identity Platform | User authentication |
| DynamoDB | Firestore or Cloud Spanner | State storage |
| API Gateway | Cloud Endpoints | REST API |
| CloudFront | Cloud CDN | Web interface delivery |
| SNS/SQS | Cloud Pub/Sub | Alert routing |

## GCP Log Sources

### Native GCP Logs

1. **Cloud Audit Logs**
   - Admin Activity logs
   - Data Access logs
   - System Event logs
   - Policy Denied logs

2. **VPC Flow Logs**
   - Network traffic metadata
   - Similar structure to AWS VPC Flow Logs

3. **Security Command Center**
   - Security findings and vulnerabilities
   - Comparable to AWS GuardDuty

4. **Cloud Logging**
   - Application logs
   - Custom log exports
   - Container logs from GKE

## Implementation Plan

### Phase 1: Storage and Query Layer (8 weeks)

Objectives:
- Set up Cloud Storage buckets with lifecycle policies
- Create BigQuery datasets and tables
- Implement log export from Cloud Logging
- Develop query execution layer

Deliverables:
- Terraform modules for GCP infrastructure
- BigQuery table schemas
- Data ingestion pipelines
- Query execution API

### Phase 2: Detection Engine (6 weeks)

Objectives:
- Port detection engine to Cloud Functions
- Implement Cloud Scheduler triggers
- Set up Firestore for state management
- Adapt detection rules for BigQuery SQL

Deliverables:
- Cloud Functions for detection engine
- Cloud Scheduler jobs
- Detection rule format adapters
- State management layer

### Phase 3: Web Interface Adaptation (4 weeks)

Objectives:
- Adapt web interface for GCP endpoints
- Configure Identity Platform
- Set up Cloud CDN
- Implement GCP-specific features

Deliverables:
- Updated web application
- Authentication flow with Identity Platform
- Deployment scripts
- GCP-specific UI components

### Phase 4: Full Feature Parity (6 weeks)

Objectives:
- Complete all AWS features
- Implement alert routing
- Add LLM integration
- Performance optimization

Deliverables:
- Alert routing to Slack, PagerDuty, etc.
- LLM query generation for BigQuery
- Performance benchmarks
- Cost optimization

## Shared Code Utilization

### 100% Reusable

- Parsers: Cloud-agnostic
- Detection logic: No changes needed
- Alert routing: Works with any cloud provider
- LLM layer: 90% reusable (different schema context)

### New Implementation Required

- Infrastructure: New Terraform modules
- Query execution: BigQuery API vs Athena API
- Authentication: Identity Platform vs Cognito
- State management: Firestore vs DynamoDB
