# Mantissa Log

**Separate the Signal from the Noise**

An open-source, cloud-native SIEM built on serverless infrastructure and natural language queries. Deploy to AWS, GCP, or Azure for a fraction of the cost of commercial alternatives.

---

## The Problem

Security teams face a broken tooling landscape:

**SIEMs are prohibitively expensive.** Splunk, Datadog, and Sumo Logic charge $150,000-$300,000/year for enterprise deployments. Pricing is indexed to data volume, so costs scale faster than budgets. Teams are forced to choose which logs to ingest, creating blind spots.

**Query languages are a bottleneck.** Analysts spend more time writing SPL, KQL, or Lucene than actually investigating threats. Every SIEM has its own query syntax, and cross-platform correlation requires expertise in multiple languages.

**Identity attacks are the #1 initial access vector.** Over 80% of breaches involve compromised credentials, yet most SIEMs treat identity logs as just another data source with no behavioral analysis, no cross-provider correlation, and no understanding of what "normal" looks like for a given user.

**Log source failures go undetected.** When a collector silently stops sending data, every detection rule that depends on that source becomes a blind spot. Most SIEMs have no built-in health monitoring for log sources.

**Open-source alternatives are incomplete.** Existing open-source SIEMs require you to run Elasticsearch clusters, manage complex infrastructure, and still lack natural language queries, identity threat detection, and automated response.

---

## How Mantissa Log Solves This

### Ask questions in plain English
No query language to learn. Ask _"Show me all failed logins from outside the US this week"_ and get results. The system translates questions into optimized SQL, shows estimated query cost, and maintains conversation context for follow-ups. 8 LLM providers supported (Anthropic Claude, OpenAI GPT-4, Google Gemini, AWS Bedrock, Azure OpenAI, GCP Vertex AI).

### Run on serverless for ~$23,500/year
No clusters to manage. Lambda functions, cloud data lakes (S3/GCS/Blob), and serverless query engines (Athena/BigQuery/Synapse) mean you pay for what you use. At 1 TB/day ingestion, estimated annual cost is roughly $23,500 compared to $150,000+ for commercial SIEMs.

### Detect identity threats across providers
Behavioral baselines for every user across Okta, Azure AD, Google Workspace, Duo, and Microsoft 365. Detects impossible travel, credential stuffing, MFA fatigue, privilege escalation chains, and session hijacking. 8-stage identity attack kill chain tracking with weighted risk scoring (0-100).

### Monitor log source health
Automatic detection when log sources stop sending data, have unexpected gaps, or show abnormal volume changes. Per-source latency and silence thresholds, z-score volume anomaly detection against learned baselines, and gap detection at sub-window granularity.

### Deploy to any cloud
Cloud-agnostic core with native adapters for AWS, GCP, and Azure. Terraform modules for all three providers. Same detection rules, same parsers, same alerting logic regardless of where you deploy.

### Detect threats with 647 pre-built rules
Sigma-format detection rules that auto-convert to cloud-specific SQL. Covers AWS, GCP, Azure, Okta, GitHub, Kubernetes, and more. 49 rules purpose-built for identity threat detection. Write new rules in natural language or Sigma YAML.

### Respond automatically
Convert incident response plans into executable playbooks. Terminate sessions, disable accounts, block IPs, create tickets, and notify teams. Approval workflows for dangerous actions. Full audit trail.

---

## Architecture

```
+-----------------------------------------------------------------+
|                        MANTISSA LOG                             |
+-----------------------------------------------------------------+
|                                                                 |
|  +------------------+  +------------------+  +-----------------+|
|  |      SIEM        |  |  OBSERVABILITY   |  |     SOAR        ||
|  |  (Core Module)   |  |   (APM Module)   |  | (Response)      ||
|  +------------------+  +------------------+  +-----------------+|
|  | - Log Collection |  | - OTLP Receiver  |  | - Playbooks     ||
|  | - NL Queries     |  | - Metrics/Traces |  | - IR Plan Parse ||
|  | - Sigma Rules    |  | - Service Maps   |  | - Auto Response ||
|  | - Alerting       |  | - Trace Viewer   |  | - Approvals     ||
|  | - ITDR           |  | - APM Alerts     |  | - Action Buttons||
|  +------------------+  +------------------+  +-----------------+|
|         |                     |                     |           |
|         +---------------------+---------------------+           |
|                               |                                 |
|                    +--------------------+                       |
|                    |   Shared Services  |                       |
|                    | - Query Engine     |                       |
|                    | - Alert Router     |                       |
|                    | - LLM Providers    |                       |
|                    | - Health Monitor   |                       |
|                    | - Storage (S3/BQ)  |                       |
|                    +--------------------+                       |
+-----------------------------------------------------------------+
```

Mantissa Log is modular. Deploy only what you need:

| Mode | Modules | Terraform Flags |
|------|---------|-----------------|
| **SIEM Only** | Core (collection, queries, detection, alerting, ITDR) | `enable_apm=false`, `enable_soar=false` |
| **SIEM + Observability** | Core + APM (OTLP traces, metrics, service maps) | `enable_apm=true`, `enable_soar=false` |
| **Full Platform** | All (+ automated response, playbooks, approvals) | `enable_apm=true`, `enable_soar=true` |

---

## Features

### Natural Language Query Interface
- Plain English to SQL (Athena, BigQuery, or Synapse)
- Cost estimates before query execution
- Conversation context for follow-up questions
- 8 LLM providers: Anthropic Claude, OpenAI GPT-4, Google Gemini, AWS Bedrock, Azure OpenAI, GCP Vertex AI
- Query caching to reduce LLM API costs

### Identity Threat Detection & Response (ITDR)
- Behavioral baselines with 14-day learning period
- Anomaly detection: impossible travel, unusual login times, new devices/locations
- Credential attacks: brute force, password spray, credential stuffing, MFA fatigue
- Privilege monitoring: escalation chains, self-privilege grants, dormant account activation
- Session security: hijacking, token theft, concurrent session anomalies
- Cross-provider correlation across Okta, Azure AD, Google Workspace, Duo, M365
- 8-stage identity attack kill chain tracking
- Risk scoring: weighted multi-factor model (0-100)

### Log Source Health Monitoring
- Detects when log sources stop sending data or have unexpected gaps
- Per-source latency and silence thresholds tuned to each upstream API
- Z-score volume anomaly detection against learned hourly baselines
- Gap detection at 5-minute bucket granularity
- Multi-cloud state storage (DynamoDB, Firestore, Cosmos DB)
- Collector-reported counts with data lake query fallback

### Detection Engine
- 647 pre-built Sigma detection rules (49 ITDR-specific)
- Automatic Sigma-to-SQL conversion for each cloud platform
- Scheduled detection via EventBridge / Cloud Scheduler / Timer Triggers
- Alert deduplication and state management
- Detection tuning with false positive feedback

### Alert Routing
- 7 integrations: Slack, PagerDuty, Jira, Email, ServiceNow, Microsoft Teams, Webhook
- LLM-powered alert enrichment with 5W1H context
- PII/PHI redaction for external destinations
- Severity-based routing and escalation

### Observability / APM
- OpenTelemetry-compatible trace and metrics ingestion (OTLP)
- Distributed tracing with parent-child span relationships
- Service dependency map auto-generated from trace data
- Trace waterfall visualization
- APM-specific Sigma rules for latency spikes and error rates
- NL queries for APM: _"Why is checkout slow?"_

### SOAR (Automated Response)
- Playbook management: create, edit, version, deploy
- IR plan import: upload markdown/YAML, auto-convert to playbooks
- Alert action buttons: isolate host, disable user, block IP
- Approval workflows for dangerous actions
- Full execution tracking and audit trail

### Context Enrichment
- IP geolocation (MaxMind GeoIP2, IPInfo)
- Threat intelligence (VirusTotal, AbuseIPDB)
- User context (Google Workspace, Azure AD, Okta directory)
- Asset context (AWS, Azure, GCP native inventory)

### Data Collectors (25+ sources)
- **Cloud**: AWS CloudTrail, VPC Flow Logs, GuardDuty, GCP Audit Logs, Azure Activity Logs
- **Identity**: Okta, Google Workspace, Microsoft 365, Duo Security
- **Endpoints**: CrowdStrike Falcon, Jamf Pro
- **SaaS**: Snowflake, Salesforce, 1Password, Slack Audit Logs
- **DevOps**: GitHub Enterprise, Kubernetes Audit Logs, Docker

### Web Interface
- React 18 with Vite, Tailwind CSS, Zustand
- ITDR dashboard with attack timeline and geographic visualization
- User risk profiles with activity timelines
- Behavioral baseline viewer
- Detection rule management
- APM trace viewer and service map

---

## Quick Start

### Prerequisites

- AWS, GCP, or Azure account with appropriate permissions
- Terraform >= 1.5
- Python >= 3.11
- Node.js >= 18
- LLM API key (Anthropic, OpenAI, Google, or cloud-native)

### AWS Deployment

```bash
git clone https://github.com/clay-good/mantissa-log.git
cd mantissa-log

# Configure Terraform
cd infrastructure/aws/terraform
cp backend.tf.example backend.tf
cp environments/dev.tfvars.example environments/dev.tfvars
# Edit files with your configuration

# Deploy infrastructure
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars

# Deploy Lambda code
cd ../../..
bash scripts/deploy.sh
```

See [docs/deployment/](docs/deployment/) for GCP and Azure deployment instructions.

---

## Project Structure

```
mantissa-log/
├── src/
│   ├── shared/              # Cloud-agnostic core modules
│   │   ├── alerting/        # Alert routing (7 integrations)
│   │   ├── auth/            # Authentication middleware
│   │   ├── detection/       # Detection engine, Sigma conversion
│   │   ├── enrichment/      # Geo, threat intel, user context
│   │   ├── health/          # Log source health monitoring
│   │   ├── identity/        # ITDR module (behavioral analysis)
│   │   ├── llm/             # LLM providers (8) and query generation
│   │   ├── parsers/         # Log parsers (25+ sources)
│   │   ├── soar/            # Playbooks and automated response
│   │   ├── apm/             # APM/observability detection
│   │   ├── redaction/       # PII/PHI redaction
│   │   ├── models/          # Data models and identity mappers
│   │   └── cost/            # Query cost estimation
│   ├── aws/                 # AWS Lambda handlers
│   ├── gcp/                 # GCP Cloud Functions
│   ├── azure/               # Azure Functions
│   ├── api/                 # REST API layer
│   └── collectors/          # Log source collectors
├── web/                     # React 18 frontend
├── infrastructure/          # Terraform IaC (AWS, GCP, Azure)
├── rules/
│   ├── sigma/               # 647 Sigma detection rules
│   └── playbooks/           # SOAR playbook definitions
├── tests/                   # Unit, integration, and rule tests
├── docs/                    # Documentation (28 guides)
└── scripts/                 # Deployment and utility scripts
```

---

## Cost Comparison

**Traditional SIEM (Splunk/Datadog/Sumo Logic):**
Typical cost: $150,000-$300,000/year for enterprise

**Mantissa Log on AWS (1 TB/day ingestion estimate):**

| Component | Annual Cost |
|-----------|------------|
| S3 storage | ~$8,400 |
| Athena queries | ~$9,100 |
| Lambda execution | ~$2,400 |
| DynamoDB | ~$600 |
| LLM API calls | ~$3,000 |
| **Total** | **~$23,500** |

These are rough estimates. Actual costs depend on query patterns, data volume, LLM usage, and optimization.

---

## Testing

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run all tests
PYTHONPATH=. pytest tests/ -v

# Run specific categories
pytest tests/unit/ -v                    # Unit tests
pytest tests/integration/ -v             # Integration tests
pytest tests/unit/identity/ -v           # ITDR tests
pytest tests/rules/ -v                   # Rule validation
```

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | First-time setup and your first query |
| [Quick Start Tutorial](docs/tutorials/quick-start-with-samples.md) | Hands-on walkthrough with sample data |
| [AWS Deployment](docs/deployment/aws-deployment.md) | Complete AWS deployment guide |
| [Multi-Cloud Deployment](docs/deployment/multi-cloud.md) | GCP and Azure deployment |
| [Detection Rules](docs/configuration/detection-rules.md) | Writing and managing Sigma rules |
| [Alert Routing](docs/configuration/alert-routing.md) | Slack, PagerDuty, Jira, Email setup |
| [LLM Configuration](docs/configuration/llm-configuration.md) | Provider setup and tuning |
| [Log Sources](docs/configuration/log-sources.md) | Collector configuration |
| [Operations Runbook](docs/operations/runbook.md) | Day-to-day operational procedures |
| [API Reference](docs/api/api-reference.md) | REST API endpoints |
| [Architecture](docs/architecture/architecture.md) | System design overview |
| [Contributing](docs/development/contributing.md) | Code contribution guide |

Full documentation index: [docs/README.md](docs/README.md)

---

## Environment Variables

See [docs/configuration/](docs/configuration/) for the complete reference. Key variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `LLM_PROVIDER` | LLM provider (`anthropic`, `openai`, `bedrock`, etc.) | Yes |
| `CORS_ALLOWED_ORIGIN` | Allowed CORS origin (set for security) | Yes (prod) |
| `ATHENA_DATABASE` / `BIGQUERY_DATASET` / `SYNAPSE_DATABASE` | Query database | Yes |
| `STATE_TABLE` | State storage table/collection/container | Yes |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / etc. | LLM credentials | Yes |

---

## Limitations

### Status
This project is in **alpha** (v0.1.0). No known production deployments at scale. Infrastructure is complete but real-world performance at volume is unvalidated.

### Technical Limitations
- **LLM dependency**: Requires LLM API keys. Query quality depends on model capability. LLM-generated SQL may occasionally be incorrect.
- **Baseline cold start**: Behavioral analysis requires 14 days of historical data. New deployments have no baseline — all users appear anomalous initially.
- **Batch-based detection**: Serverless architecture processes events in batches, not real-time. Minimum latency equals your polling interval (typically 5-15 minutes).
- **Cold starts**: Serverless functions have cold start latency (3-10 seconds for first request).
- **Single-tenant**: Each deployment serves one organization.
- **No built-in dashboards**: Uses natural language queries instead. Integrate external BI tools if you need visual dashboards.
- **No case management**: Integrate with Jira, ServiceNow, etc. for case tracking.

### Security Configuration Required
- Set `CORS_ALLOWED_ORIGIN` (default `*` is insecure)
- Configure API Gateway authorizer (Cognito/Identity Platform)
- Move API keys from environment variables to Secrets Manager/Key Vault for production
- Never enable `MANTISSA_DEV_MODE=true` in production

---

## Component Summary

| Component | Count |
|-----------|-------|
| Python source files | 339 |
| Sigma detection rules | 647 (49 ITDR-specific) |
| LLM providers | 8 |
| Alert integrations | 7 |
| Log source parsers | 25+ |
| Identity providers | 5 |
| Cloud platforms | 3 (AWS, GCP, Azure) |
| Terraform modules | 14 (AWS) + GCP + Azure |
| React pages | 11 |
| Documentation files | 28 |
| Test files | 83 |
