# Mantissa Log Architecture

This document provides a comprehensive overview of the Mantissa Log system architecture, component interactions, and data flow.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MANTISSA LOG ARCHITECTURE                           │
│                    "Separate the Signal from the Noise"                     │
└─────────────────────────────────────────────────────────────────────────────┘


                        ┌─────────────────────────────┐
                        │    Web Interface (React)    │
                        │  ┌───────────────────────┐  │
                        │  │  Natural Language     │  │
                        │  │  Query Input          │  │
                        │  ├───────────────────────┤  │
                        │  │  Detection Rules      │  │
                        │  │  Management           │  │
                        │  ├───────────────────────┤  │
                        │  │  Alert Dashboard      │  │
                        │  ├───────────────────────┤  │
                        │  │  Settings &           │  │
                        │  │  Integrations         │  │
                        │  └───────────────────────┘  │
                        └──────────────┬──────────────┘
                                       │
                                       │ HTTPS API Calls
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           API GATEWAY LAYER                                 │
│                     (AWS API Gateway + Lambda)                              │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│  LLM Query Layer  │ │ Detection       │ │ Alert Router        │
│  (Lambda)         │ │ Engine          │ │ (Lambda)            │
│                   │ │ (Lambda)        │ │                     │
│ ┌───────────────┐ │ │                 │ │ ┌─────────────────┐ │
│ │ NL Parser     │ │ │ ┌─────────────┐ │ │ │ Slack Handler   │ │
│ ├───────────────┤ │ │ │ Rule        │ │ │ ├─────────────────┤ │
│ │ Schema        │ │ │ │ Executor    │ │ │ │ PagerDuty       │ │
│ │ Context       │ │ │ ├─────────────┤ │ │ ├─────────────────┤ │
│ ├───────────────┤ │ │ │ State       │ │ │ │ Email Handler   │ │
│ │ SQL Generator │ │ │ │ Manager     │ │ │ ├─────────────────┤ │
│ ├───────────────┤ │ │ ├─────────────┤ │ │ │ Jira Handler    │ │
│ │ Query         │ │ │ │ Alert       │ │ │ ├─────────────────┤ │
│ │ Validator     │ │ │ │ Generator   │ │ │ │ Teams Handler   │ │
│ └───────────────┘ │ │ └─────────────┘ │ │ ├─────────────────┤ │
└─────────┬─────────┘ └────────┬────────┘ │ │ Webhook Handler │ │
          │                    │          │ └─────────────────┘ │
          │                    │          └──────────┬──────────┘
          │                    │                     │
          └────────────┬───────┴─────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │      AWS ATHENA             │
         │    (Query Engine)           │
         │                             │
         │  SQL queries against        │
         │  partitioned log data       │
         └──────────────┬──────────────┘
                        │
                        ▼
         ┌─────────────────────────────┐
         │   AWS GLUE DATA CATALOG     │
         │    (Schema Registry)        │
         │                             │
         │  ┌───────────────────────┐  │
         │  │ cloudtrail_logs       │  │
         │  ├───────────────────────┤  │
         │  │ vpc_flow_logs         │  │
         │  ├───────────────────────┤  │
         │  │ guardduty_findings    │  │
         │  ├───────────────────────┤  │
         │  │ application_logs      │  │
         │  ├───────────────────────┤  │
         │  │ normalized_auth_view  │  │
         │  ├───────────────────────┤  │
         │  │ normalized_network    │  │
         │  └───────────────────────┘  │
         └──────────────┬──────────────┘
                        │
                        ▼
         ┌─────────────────────────────┐
         │      S3 DATA LAKE           │
         │   (Log Storage Layer)       │
         │                             │
         │  Partitioned by date:       │
         │  s3://mantissa-logs/        │
         │    ├── cloudtrail/          │
         │    │   └── year/month/day/  │
         │    ├── flowlogs/            │
         │    │   └── year/month/day/  │
         │    ├── guardduty/           │
         │    │   └── year/month/day/  │
         │    └── application/         │
         │        └── year/month/day/  │
         │                             │
         │  Lifecycle Policies:        │
         │  - Hot: 30 days (Standard)  │
         │  - Warm: 11 months (IA)     │
         │  - Delete: After 1 year     │
         └──────────────┬──────────────┘
                        │
                        │
    ┌───────────────────┼───────────────────┬───────────────────┐
    │                   │                   │                   │
    ▼                   ▼                   ▼                   ▼
┌─────────┐      ┌─────────────┐     ┌───────────┐      ┌─────────────┐
│CloudTrail│     │VPC Flow Logs│     │ GuardDuty │      │ Application │
│  Logs    │     │             │     │ Findings  │      │    Logs     │
└─────────┘      └─────────────┘     └───────────┘      └─────────────┘
```

## Supporting Services

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SUPPORTING SERVICES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐ │
│  │ EventBridge     │  │ Secrets Manager │  │ DynamoDB                    │ │
│  │ (Scheduler)     │  │ (Credentials)   │  │ (State & Alert Dedup)       │ │
│  │                 │  │                 │  │                             │ │
│  │ Triggers        │  │ - Slack tokens  │  │ - Alert history             │ │
│  │ detection       │  │ - PagerDuty key │  │ - Detection state           │ │
│  │ engine on       │  │ - SMTP creds    │  │ - Query cache               │ │
│  │ schedule        │  │ - API keys      │  │ - Session management        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘ │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐ │
│  │ CloudWatch      │  │ IAM Roles       │  │ Cognito                     │ │
│  │ (Monitoring)    │  │ (Least         │  │ (Authentication)            │ │
│  │                 │  │  Privilege)     │  │                             │ │
│  │ System health   │  │                 │  │ User management for         │ │
│  │ metrics and     │  │ Scoped per      │  │ web interface               │ │
│  │ alerting        │  │ component       │  │                             │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### Storage Layer (S3)

The S3 data lake is the foundation of Mantissa Log. All log data flows into S3 buckets organized by:

- **Log type**: cloudtrail, flowlogs, guardduty, application
- **Date partition**: year/month/day for efficient querying
- **Lifecycle policies**: Hot (30 days Standard), Warm (11 months IA), Cold (delete after 1 year)

Encryption is enforced at rest (SSE-S3 or SSE-KMS) and all buckets block public access.

### Catalog Layer (AWS Glue)

AWS Glue Data Catalog acts as the schema registry, defining table structures and partitions:

- **Tables**: Map S3 paths to queryable structures
- **Partitions**: Enable efficient date-based queries
- **Views**: Normalized schemas across different log types
- **Crawlers**: Automatically discover new partitions (optional)

### Query Layer (Amazon Athena)

Athena provides serverless SQL query capability over S3 data:

- **Pay-per-query**: Only charged for data scanned
- **Standard SQL**: Familiar query language
- **Partitioning**: Reduces scan costs dramatically
- **Result caching**: Repeated queries are free

### Detection Engine (Lambda)

The detection engine runs scheduled queries based on YAML rule definitions:

1. EventBridge triggers Lambda on schedule (e.g., every 5 minutes)
2. Lambda loads enabled detection rules
3. For each rule, constructs time-windowed SQL query
4. Executes query via Athena
5. Compares results against rule thresholds
6. Generates alerts if thresholds exceeded
7. Deduplicates using DynamoDB
8. Routes alerts to configured destinations

### LLM Query Layer (Lambda)

Converts natural language queries into safe SQL:

1. Receives user query from web interface
2. Loads schema context from Glue Catalog
3. Constructs prompt with schema and query
4. Calls LLM (Claude, GPT, or Bedrock)
5. Validates generated SQL (read-only, allowed tables)
6. Executes validated query via Athena
7. Returns results to user
8. Optionally saves query as detection rule

### Alert Router (Lambda)

Receives alerts and distributes to configured destinations:

1. Receives alert from detection engine
2. Enriches alert with additional context
3. Formats alert for each destination
4. Delivers via configured handlers:
   - Slack webhooks
   - PagerDuty events API
   - Email via SES
   - Jira issue creation
   - Microsoft Teams webhooks
   - Generic webhooks

## Data Flow

### Ingestion Flow

```
AWS Service → S3 Bucket → Glue Partition → Athena Table
```

Logs automatically flow from AWS services (CloudTrail, VPC Flow Logs, GuardDuty) into designated S3 buckets with date-based partitioning.

### Detection Flow

```
EventBridge Timer
    ↓
Detection Engine Lambda
    ↓
Load Rules from S3/Config
    ↓
For Each Rule:
    ↓
Generate SQL Query
    ↓
Execute via Athena
    ↓
Compare Against Threshold
    ↓
If Exceeded:
    ↓
Check DynamoDB for Duplicate
    ↓
If New:
    ↓
Generate Alert Object
    ↓
Send to Alert Router
    ↓
Route to Destinations
```

### Query Flow

```
User Types Natural Language Query
    ↓
Web Interface → API Gateway
    ↓
LLM Query Lambda
    ↓
Load Schema from Glue
    ↓
Construct Prompt
    ↓
Call LLM Provider
    ↓
Receive Generated SQL
    ↓
Validate SQL Safety
    ↓
Execute via Athena
    ↓
Return Results to User
    ↓
User Can Save as Detection Rule
```

## Security Architecture

### Authentication & Authorization

- **Web Interface**: Cognito user pools with MFA support
- **API Gateway**: JWT token validation on all requests
- **IAM Roles**: Least privilege for each Lambda function
- **Service-to-Service**: IAM roles, no access keys

### Data Protection

- **At Rest**: S3 SSE encryption, DynamoDB encryption, encrypted Lambda env vars
- **In Transit**: HTTPS/TLS for all API calls, encrypted S3 transfer
- **Secrets**: AWS Secrets Manager for all credentials and API keys

### Input Validation

- **SQL Validation**: Only SELECT allowed, table allowlist, no DDL/DML
- **Query Limits**: Timeouts, result size limits, rate limiting
- **Input Sanitization**: All user inputs validated and sanitized

## Scalability

### Vertical Scaling

- **Lambda**: Automatic scaling, configure memory allocation
- **Athena**: Scales automatically, optimize with partitioning
- **S3**: Unlimited storage capacity
- **DynamoDB**: On-demand or provisioned capacity

### Cost Optimization

- **S3 Lifecycle**: Transition to IA storage after 30 days
- **Athena Partitioning**: Reduces data scanned per query
- **Lambda Cold Starts**: Use provisioned concurrency for critical functions
- **Query Caching**: Athena caches results for 24 hours

## Multi-Cloud Vision

The architecture separates cloud-specific code (30%) from shared logic (70%):

**Shared Components:**
- Parser library
- Detection rule format
- Alert routing logic
- LLM prompt engineering
- Web interface

**Cloud-Specific:**
- Infrastructure templates (Terraform/CloudFormation)
- Storage configuration (S3/GCS/Blob)
- Query engine adapters (Athena/BigQuery/Synapse)
- IAM/permissions setup
- Serverless function wrappers

Future releases will add GCP and Azure support by implementing cloud-specific adapters while reusing shared components.

## Monitoring & Observability

### CloudWatch Metrics

- Lambda invocation counts, durations, errors
- Athena query execution times
- API Gateway request counts and latencies
- S3 bucket sizes and request counts

### CloudWatch Logs

- Lambda execution logs (structured JSON)
- API Gateway access logs
- Athena query history

### Alarms

- Lambda error rate thresholds
- Athena query failures
- S3 bucket permission changes
- Unusual query patterns

### Audit Trail

All administrative actions logged:
- Rule modifications
- Query executions
- Alert acknowledgments
- Configuration changes

## Deployment Architecture

### Environments

- **Development**: Single region, minimal resources, relaxed timeouts
- **Staging**: Production-like, limited retention, lower scale
- **Production**: Multi-AZ, full monitoring, production retention policies

### Infrastructure as Code

Terraform modules for each component enable:
- Version-controlled infrastructure
- Reproducible deployments
- Easy environment creation
- Modular component deployment

## Component Interaction Diagram

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│   Web    │ HTTPS   │   API    │  IAM    │ Lambda   │
│Interface │────────▶│ Gateway  │────────▶│Functions │
└──────────┘         └──────────┘         └────┬─────┘
                                               │
                     ┌─────────────────────────┼────────────┐
                     │                         │            │
                     ▼                         ▼            ▼
              ┌──────────┐             ┌──────────┐  ┌──────────┐
              │  Athena  │             │ DynamoDB │  │ Secrets  │
              │          │             │          │  │ Manager  │
              └────┬─────┘             └──────────┘  └──────────┘
                   │
                   ▼
              ┌──────────┐
              │   Glue   │
              │ Catalog  │
              └────┬─────┘
                   │
                   ▼
              ┌──────────┐
              │    S3    │
              │Data Lake │
              └──────────┘
```

## Next Steps

- [Deployment Guide](deployment/aws-deployment.md)
- [Configuration Guide](configuration/detection-rules.md)
- [Operations Runbook](operations/runbook.md)
