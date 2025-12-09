# Mantissa Log

**"Separate the Signal from the Noise"**

Open-source log aggregation platform with a natural language query interface. Query logs using plain English instead of complex query languages.

## What is Mantissa Log?

Mantissa Log is a **cloud-native log aggregation platform with an AI-powered natural language query interface**. Instead of learning complex query languages, you ask questions in plain English:

- *"When was the last time root was used?"*
- *"Show me all failed logins from outside the US this week"*
- *"List all S3 buckets created in the last 24 hours"*

The system translates your questions into optimized SQL, executes them across your cloud data lake, and returns results. It maintains conversation context and shows query costs before execution.

**Built for log aggregation with a focus on security detections.**

---

## Current Implementation Status

| Cloud Provider | Status | Notes |
|----------------|--------|-------|
| **AWS** | Infrastructure Complete | 14 Terraform modules, 25 Lambda handlers, full API |
| **GCP** | Infrastructure Complete | Cloud Functions, BigQuery integration, Cloud Run frontend |
| **Azure** | Infrastructure Complete | Azure Functions, Synapse Analytics, Static Web Apps |

**Important**: While infrastructure code is complete, no production deployments have been independently verified. Test thoroughly before production use.

---

## Cost Comparison (Theoretical)

**Traditional SIEM (Splunk/Datadog/Sumo Logic):**
- Typical cost: $150,000-$300,000/year for enterprise

**Mantissa Log on AWS (1 TB/day ingestion estimate):**
- S3 storage: ~$8,400/year
- Athena queries: ~$9,100/year (depends on query patterns)
- Lambda execution: ~$2,400/year
- DynamoDB: ~$600/year
- LLM API calls: ~$3,000/year (highly variable)
- **Estimated Total: ~$23,500/year**

**Disclaimer**: These are rough estimates. Actual costs depend heavily on query patterns, data volume, LLM usage, and optimization. You should run your own cost analysis.

---

## Features

### Natural Language Query Interface
- Ask questions in plain English
- LLM converts to SQL (Athena, BigQuery, or Synapse depending on cloud)
- Shows estimated cost before execution
- Maintains conversation context for follow-up questions
- Supports multiple LLM providers: Claude, GPT-4, Gemini, AWS Bedrock, Azure OpenAI, GCP Vertex AI
- LLM query pattern caching to reduce API calls (AWS: DynamoDB, GCP: Firestore, Azure: Cosmos DB)

### Detection Engine
- 591 pre-built Sigma detection rules
- Sigma rules auto-convert to cloud-specific SQL
- Scheduled detection execution via EventBridge/Cloud Scheduler
- Alert deduplication and state management

### Alert Routing
- Slack, PagerDuty, Jira, Email, and Webhook integrations
- LLM-powered alert enrichment with 5W1H context
- PII/PHI redaction for external destinations
- Configurable severity-based routing

### Data Collectors
- **Cloud Native**: AWS CloudTrail, VPC Flow Logs, GuardDuty, GCP Audit Logs, Azure Activity Logs
- **Identity**: Okta, Google Workspace, Microsoft 365, Duo Security
- **Endpoints**: CrowdStrike Falcon, Jamf Pro
- **Collaboration**: Slack Audit Logs
- **SaaS**: Snowflake, Salesforce, 1Password
- **DevOps**: GitHub Enterprise, Kubernetes Audit Logs, Docker

### Web Interface
- React-based dashboard with Tailwind CSS
- Query builder with SQL visualization
- Detection rule management
- Integration configuration wizards

---

## Limitations (Read Before Using)

### What This Project Is NOT

1. **Not Production-Verified**: No known production deployments. Infrastructure is complete but untested at scale.

2. **Not a Complete SIEM Replacement**: Lacks many enterprise SIEM features:
   - No dashboards or visualizations (by design - use external BI tools)
   - No case management (use Jira, ServiceNow, etc.)
   - No SOAR/automated remediation
   - No threat intelligence platform integration
   - No compliance reporting

3. **Not Managed/SaaS**: You deploy and manage all infrastructure yourself. Requires cloud infrastructure expertise.

4. **Not Multi-Tenant**: Single-tenant architecture only. Each deployment serves one organization.

5. **Not High-Availability by Default**: Basic infrastructure without HA/DR configuration. You must add this.

### Technical Limitations

- **Test Suite**: Current test results show 77 failures and 12 errors out of ~1,075 tests. Most are assertion updates for parser edge cases, but you should investigate before production use.

- **LLM Dependency**: Requires LLM API keys. Query quality depends on model capability. API costs are unpredictable.

- **LLM Provider Configuration**: Each provider requires specific credentials and configuration. Vertex AI requires GCP project setup and IAM permissions. Azure OpenAI requires an Azure OpenAI resource with deployed models.

- **SQL Generation**: LLM-generated SQL may occasionally be incorrect or suboptimal. Always review before executing expensive queries.

- **Cold Starts**: Serverless architecture has cold start latency. First query of a session may be slow.

- **Query Limits**: Maximum 10,000 rows returned. 120-second query timeout. Deep subqueries limited to 3 levels.

- **No Real-Time Streaming**: Batch-based log ingestion. Minimum detection latency is your polling interval (typically 5-15 minutes).

- **Schema Changes**: Adding new log sources requires manual Glue/BigQuery table creation.

- **Browser Support**: Modern browsers only. No mobile optimization.

- **GCP Function Count**: GCP has 5 Cloud Functions vs 25 AWS Lambda handlers. GCP uses a consolidated collector design rather than individual functions per source.

- **Jira Description Format**: Jira tickets use Atlassian Document Format (ADF) which may not render wiki markup as expected in all Jira versions.

- **No Log Retention Management**: You must configure S3/GCS/Azure Blob lifecycle policies separately. No built-in log rotation or archival.

- **No User Management UI**: User management requires direct Cognito/Identity Platform/Azure AD configuration. No admin UI for user provisioning.

- **Single Region**: Infrastructure templates deploy to a single region. Multi-region requires manual configuration.

- **No IP Geolocation**: MaxMind GeoIP integration is not implemented. IP-based geographic queries require external enrichment.

- **No Threat Intelligence**: VirusTotal, AbuseIPDB, and other threat intel integrations return placeholder data. You must implement your own TI lookups or use external services.

- **Hardcoded Pricing**: Cloud cost estimates use hardcoded 2024 pricing constants. Actual costs may differ from estimates.

- **Generic Exception Handling**: Some error handlers catch broad exceptions which may mask specific failure causes. Check logs for detailed errors.

- **DLQ Retry Logic**: Dead letter queue handler logs failures but does not implement automatic retry. Manual intervention required for failed messages.

- **Placeholder Enrichment Functions**: IP reputation, user context, and geolocation lookups in alert enrichment return placeholder data. Integrate with your own data sources.

- **Suppression Analytics**: The `get_suppression_stats()` function in alert deduplication returns placeholder data. Requires a separate suppression log table to track actual suppression counts.

- **Web UI Profile/Security Settings**: The Settings page has placeholder components for Profile Settings and Security Settings marked "coming soon". User management is done via Cognito/Identity Platform/Azure AD directly.

- **View Recent Failures Modal**: The integration health status "View Recent Failures" button is not implemented. Check CloudWatch/Cloud Logging for failure details.

- **Hardcoded User ID**: Some frontend components use a hardcoded `userId: 'current-user'` instead of getting it from the auth context. Works for single-user deployments but may cause issues in multi-user scenarios.

### Operational Concerns

- **Cost Unpredictability**: Athena/BigQuery charges per data scanned. Poorly optimized queries can be expensive.

- **Secret Management**: You manage API keys and credentials. Security is your responsibility.

- **Updates**: No automatic updates. You pull and deploy changes manually.

- **Support**: Community support only. No SLA, no vendor backing.

- **Import Path Sensitivity**: Some Lambda handlers use `sys.path` manipulation for imports. Deployment packaging must preserve directory structure.

- **Test Configuration**: pytest.ini references a legacy `lambda_functions` directory path. Coverage reports may not include all Lambda handler code. Update paths if needed.

- **Redacted Sender Placeholder**: The `_send_to_integration()` method in `redacted_sender.py` returns a placeholder success response instead of actually sending alerts. PII/PHI redaction is applied but payloads are not forwarded to integrations. You must integrate with the validators or implement actual sending.

- **Print Statements for Logging**: 99 instances of `print()` are used instead of proper logging across 25 files in `src/shared/`. Errors logged this way may not appear in CloudWatch/Cloud Logging. Consider replacing with `logging.error()` for production.

- **Google Gemini Token Estimation**: Token counts for Google Gemini use `word_count * 1.3` estimation. Actual token usage differs significantly. Cost calculations for Gemini will be inaccurate.

---

## Environment Variables

### Core Configuration (All Clouds)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LLM_PROVIDER` | LLM provider to use (`bedrock`, `anthropic`, `openai`, `google`, `azure_openai`, `vertex_ai`) | `bedrock` (AWS), `google` (GCP), `openai` (Azure) | Yes |
| `MAX_RESULT_ROWS` | Maximum rows returned from queries | `1000` | No |
| `ENABLE_ENRICHMENT` | Enable LLM-powered alert enrichment | `true` | No |
| `ENABLE_LLM_CACHE` | Enable LLM query pattern caching | `true` | No |
| `SCHEMA_VERSION` | Schema version for cache invalidation | `v1` | No |
| `RULES_PATH` | Path to Sigma detection rules | `rules/sigma` | No |

### AWS-Specific

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AWS_REGION` | AWS region | `us-east-1` | Yes |
| `ATHENA_DATABASE` | Athena database name | `mantissa_logs` | Yes |
| `ATHENA_OUTPUT_LOCATION` | S3 location for Athena query results | - | Yes |
| `ATHENA_OUTPUT_BUCKET` | S3 bucket for Athena results | `mantissa-log-athena-results` | No |
| `STATE_TABLE` | DynamoDB table for state management | `mantissa-log-state` | No |
| `QUERY_CACHE_TABLE` | DynamoDB table for LLM query caching | `mantissa-log-query-cache` | No |
| `CONVERSATION_TABLE` | DynamoDB table for conversation sessions | `mantissa-log-conversation-sessions` | No |
| `S3_BUCKET` | S3 bucket for log storage | `mantissa-log-data` | Yes |
| `SECRETS_PREFIX` | Prefix for Secrets Manager secrets | `mantissa-log` | No |

### GCP-Specific

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GCP_PROJECT_ID` or `GOOGLE_CLOUD_PROJECT` | GCP project ID | - | Yes |
| `BIGQUERY_DATASET` | BigQuery dataset name | `mantissa_logs` | Yes |
| `GCS_BUCKET` | GCS bucket for log storage | - | Yes |
| `ALERT_TOPIC` | Pub/Sub topic for alerts | - | Yes |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON | - | Yes (if not on GCP) |
| `VERTEX_AI_LOCATION` | Vertex AI region | `us-central1` | No |
| `VERTEX_AI_MODEL` | Vertex AI model name | `gemini-1.5-pro` | No |

### Azure-Specific

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SYNAPSE_WORKSPACE_NAME` | Synapse workspace name | - | Yes |
| `SYNAPSE_DATABASE` | Synapse database name | `mantissa_logs` | Yes |
| `SYNAPSE_SERVER_NAME` | Synapse server name | - | Yes (if not serverless) |
| `COSMOS_CONNECTION_STRING` | Cosmos DB connection string | - | Yes |
| `KEY_VAULT_URL` | Azure Key Vault URL | - | Yes |
| `STORAGE_ACCOUNT_NAME` | Storage account name | - | Yes |
| `STORAGE_CONNECTION_STRING` | Storage connection string | - | Yes |
| `ALERT_TOPIC_ENDPOINT` | Event Grid topic endpoint | - | Yes |
| `ALERT_TOPIC_KEY` | Event Grid topic key | - | Yes |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | - | Yes (if using Azure OpenAI) |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | - | Yes (if using Azure OpenAI) |
| `AZURE_OPENAI_DEPLOYMENT` | Azure OpenAI deployment name | `gpt-4` | No |
| `AZURE_OPENAI_API_VERSION` | Azure OpenAI API version | `2024-02-15-preview` | No |

### LLM Provider Configuration

| Variable | Provider | Description | Required |
|----------|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Anthropic | Claude API key | Yes (if using Anthropic) |
| `OPENAI_API_KEY` | OpenAI | GPT-4 API key | Yes (if using OpenAI) |
| `GOOGLE_API_KEY` | Google | Gemini API key | Yes (if using Google) |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI | Azure OpenAI key | Yes (if using Azure OpenAI) |
| `GOOGLE_CLOUD_PROJECT` | Vertex AI | GCP project ID | Yes (if using Vertex AI) |

### Collector-Specific (Examples)

| Variable | Collector | Description |
|----------|-----------|-------------|
| `OKTA_ORG_URL` | Okta | Okta organization URL |
| `OKTA_API_TOKEN` | Okta | Okta API token |
| `GITHUB_ENTERPRISE` | GitHub | GitHub Enterprise name |
| `GITHUB_ORG` | GitHub | GitHub organization |
| `DUO_INTEGRATION_KEY` | Duo | Duo integration key |
| `DUO_API_HOSTNAME` | Duo | Duo API hostname |
| `SALESFORCE_INSTANCE_URL` | Salesforce | Salesforce instance URL |
| `TENANT_ID` | Microsoft 365 | Azure AD tenant ID |

---

## Deployment

### Prerequisites

- AWS/GCP/Azure account with appropriate permissions
- Terraform >= 1.5
- Python >= 3.11
- Node.js >= 18
- LLM API key (Anthropic, OpenAI, Google, or AWS Bedrock access)

### AWS Deployment

```bash
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log

# Configure backend and environment
cd infrastructure/aws/terraform
cp backend.tf.example backend.tf
cp environments/dev.tfvars.example environments/dev.tfvars
# Edit backend.tf with your S3 bucket for state
# Edit environments/dev.tfvars with your configuration

# Initialize and deploy
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars

# Deploy Lambda code
cd ../../..
bash scripts/deploy.sh
```

### GCP Deployment

```bash
cd infrastructure/gcp/terraform
cp backend.tf.example backend.tf
cp environments/dev.tfvars.example environments/dev.tfvars
# Edit environments/dev.tfvars with your GCP project ID and configuration
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars

bash scripts/deploy-gcp.sh
```

### Azure Deployment

```bash
cd infrastructure/azure/terraform
cp backend.tf.example backend.tf
cp environments/dev.tfvars.example environments/dev.tfvars
# Edit environments/dev.tfvars with your Azure AD admin and Synapse password
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars

bash scripts/deploy-azure.sh
```

---

## Project Structure

```
mantissa-log/
|-- src/
|   |-- shared/           # Cloud-agnostic core (parsers, detection, LLM, alerting)
|   |-- aws/              # AWS Lambda handlers and Athena integration
|   |-- gcp/              # GCP Cloud Functions and BigQuery integration
|   |-- azure/            # Azure Functions and Synapse integration
|-- infrastructure/
|   |-- aws/terraform/    # 14 Terraform modules for AWS
|   |-- gcp/terraform/    # GCP Terraform configuration
|   |-- azure/terraform/  # Azure Terraform configuration
|-- web/                  # React frontend application
|-- rules/sigma/          # 591 Sigma detection rules
|-- tests/                # Unit, integration, and E2E tests (39 files)
|-- scripts/              # Deployment and utility scripts
|-- docs/                 # Documentation
```

---

## Component Counts

| Component | Count |
|-----------|-------|
| AWS Lambda Handlers | 25 |
| Azure Functions | 16 (12 collectors + 4 core) |
| GCP Cloud Functions | 5 (4 core + consolidated collector) |
| LLM Providers | 6 |
| Alert Handlers | 5 |
| Sigma Detection Rules | 591 |
| Log Source Parsers | 22 |
| Test Files | 39 |
| AWS Terraform Modules | 12 |

---

## Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
PYTHONPATH=. pytest tests/ -v

# Current test status:
# - Passed: ~964
# - Failed: 77 (mostly parser assertion updates)
# - Errors: 12 (QueryConfig signature changes)
# - Skipped: 22
```

---

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [AWS Deployment](docs/deployment/aws-deployment.md)
- [Multi-Cloud Deployment](docs/deployment/multi-cloud.md)
- [Pre-Deployment Checklist](docs/deployment/pre-deployment-checklist.md)
- [Detection Rules](docs/configuration/detection-rules.md)
- [Alert Routing Configuration](docs/configuration/alert-routing.md)
- [LLM Provider Setup](docs/configuration/llm-configuration.md)
- [Collector Secrets Configuration](docs/configuration/collector-secrets.md)
- [API Reference](docs/api/api-reference.md)
- [Operations Runbook](docs/operations/runbook.md)
- [Contributing Guide](docs/development/contributing.md)

---

## Architecture

```
User Question --> LLM Provider --> SQL Generation --> Validation -->
Cost Estimate --> Athena/BigQuery/Synapse --> Results --> UI

Detection Rule --> Sigma Converter --> Cloud-Specific SQL -->
Scheduled Execution --> Alert Generation --> Enrichment -->
Routing --> Slack/PagerDuty/Email/Webhook
```

### Key Design Decisions

1. **Serverless**: Lambda/Cloud Functions for cost efficiency and scaling
2. **No Dashboards**: Use natural language queries instead of stale dashboards
3. **No Case Management**: Alerts create tickets in external systems (Jira, etc.)
4. **Sigma Format**: Industry-standard detection rules for multi-cloud portability
5. **LLM-First**: Natural language is the primary interface, not a feature

---

## What's NOT Included (By Design)

- **Dashboards/Visualizations**: Use adhoc queries or external BI tools
- **Case Management**: Use Jira, ServiceNow, Rootly, etc.
- **SOAR/Automated Remediation**: Out of scope for security and liability reasons
- **Threat Intelligence Platform**: Integrate with existing TI feeds via log ingestion
- **On-Premises Support**: Cloud-native focus only
- **Real-Time ML Streaming**: Serverless architecture not suited for streaming ML

---

## Contributing

Contributions welcome. Please read the contributing guidelines before submitting PRs.

- Report bugs via GitHub Issues
- Security vulnerabilities: See SECURITY.md
- Pull requests require review and passing tests

---

## License

This project is licensed under the MIT License. See LICENSE for details.

---

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The maintainers are not responsible for any damages, costs, or security incidents resulting from use of this software.

Security tools should be thoroughly tested and validated in your environment before production use. This project has not been audited by third-party security firms.
