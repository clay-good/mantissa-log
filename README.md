# Mantissa Log

**"Separate the Signal from the Noise"**

Open-source, cloud-native SIEM platform with natural language query interface and identity threat detection.

## What is Mantissa Log?

Mantissa Log is a **serverless Security Information and Event Management (SIEM) platform** that combines:

1. **Natural Language Queries**: Ask questions in plain English instead of learning complex query languages
2. **Identity Threat Detection & Response (ITDR)**: Behavioral analysis and threat detection for identity providers
3. **Multi-Cloud Architecture**: Deployable to AWS, GCP, or Azure with cloud-agnostic core components
4. **Cost-Efficient Design**: Uses serverless compute and cloud data lakes instead of expensive indexing

### Example Queries

```
"When was the last time root was used?"
"Show me all failed logins from outside the US this week"
"List all S3 buckets created in the last 24 hours"
"Which users have the most MFA failures this month?"
```

The system translates questions into optimized SQL, estimates query costs, executes against your cloud data lake, and returns results with conversation context.

---

## Deployment Modes

Mantissa Log is modular. Deploy only what you need:

```
+------------------------------------------------------------------+
|                        MANTISSA LOG                              |
+------------------------------------------------------------------+
|                                                                  |
|  +------------------+  +------------------+  +------------------+|
|  |      SIEM        |  |  OBSERVABILITY   |  |      SOAR        ||
|  |  (Core Module)   |  |   (APM Module)   |  | (Response Module)||
|  +------------------+  +------------------+  +------------------+|
|  | - Log Collection |  | - OTLP Receiver  |  | - Playbooks      ||
|  | - NL Queries     |  | - Metrics/Traces |  | - IR Plan Parse  ||
|  | - Sigma Rules    |  | - Service Maps   |  | - Auto Response  ||
|  | - Alerting       |  | - Trace Viewer   |  | - Approvals      ||
|  | - ITDR           |  | - APM Alerts     |  | - Action Buttons ||
|  +------------------+  +------------------+  +------------------+|
|         |                     |                     |           |
|         +---------------------+---------------------+           |
|                               |                                 |
|                    +--------------------+                       |
|                    |   Shared Services  |                       |
|                    | - Query Engine     |                       |
|                    | - Alert Router     |                       |
|                    | - LLM Providers    |                       |
|                    | - Storage (S3/BQ)  |                       |
|                    +--------------------+                       |
+------------------------------------------------------------------+
```

### Choose Your Deployment

| Option | Modules | Best For | Terraform Flags |
|--------|---------|----------|-----------------|
| **SIEM Only** | Core | Security teams wanting log aggregation and threat detection | `enable_apm=false`, `enable_soar=false` |
| **SIEM + Observability** | Core + APM | Teams wanting unified security and performance monitoring | `enable_apm=true`, `enable_soar=false` |
| **Full Platform** | All | Mature security teams wanting end-to-end automation | `enable_apm=true`, `enable_soar=true` |

See [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for detailed setup instructions.

---

## Cost Comparison

**Traditional SIEM (Splunk/Datadog/Sumo Logic):**
- Typical cost: $150,000-$300,000/year for enterprise

**Mantissa Log on AWS (1 TB/day ingestion estimate):**
- S3 storage: ~$8,400/year
- Athena queries: ~$9,100/year (depends on query patterns)
- Lambda execution: ~$2,400/year
- DynamoDB: ~$600/year
- LLM API calls: ~$3,000/year (highly variable)
- **Estimated Total: ~$23,500/year**

**Disclaimer**: These are rough estimates based on 2024 pricing. Actual costs depend heavily on query patterns, data volume, LLM usage, and optimization. Run your own cost analysis before deployment.

---

## Features

### Natural Language Query Interface
- Plain English questions converted to SQL (Athena, BigQuery, or Synapse)
- Cost estimates shown before query execution
- Conversation context for follow-up questions
- 8 LLM providers supported: Anthropic Claude, OpenAI GPT-4, Google Gemini, AWS Bedrock, Azure OpenAI, GCP Vertex AI
- Query caching to reduce LLM API costs

### Identity Threat Detection & Response (ITDR)
- **Behavioral Baselines**: 14-day learning period for user behavior profiling
- **Anomaly Detection**: Impossible travel, unusual login times, new devices/locations, volume spikes
- **Credential Attack Detection**: Brute force, password spray, credential stuffing, MFA fatigue/bypass
- **Privilege Monitoring**: Escalation chains, self-privilege grants, dormant account activation
- **Session Security**: Hijacking detection, token theft, concurrent session anomalies
- **Cross-Provider Correlation**: Unified detection across Okta, Azure AD, Google Workspace, Duo, Microsoft 365
- **Kill Chain Tracking**: 8-stage identity attack progression detection
- **Risk Scoring**: Weighted multi-factor risk model (0-100 scale)

### Detection Engine
- 640 pre-built Sigma detection rules (including 49 ITDR-specific rules)
- Automatic Sigma-to-SQL conversion for each cloud platform
- Scheduled detection execution via EventBridge/Cloud Scheduler/Timer Triggers
- Alert deduplication and state management
- Detection tuning with false positive feedback

### Alert Routing
- 7 integrations: Slack, PagerDuty, Jira, Email, ServiceNow, Microsoft Teams, Webhook
- LLM-powered alert enrichment with 5W1H context
- PII/PHI redaction for external destinations
- Severity-based routing and escalation rules
- SOAR playbook triggering on alert creation

### Observability/APM
- **OTLP Receiver**: OpenTelemetry-compatible trace and metrics ingestion
- **Distributed Tracing**: Store and query trace spans with parent-child relationships
- **Metrics Collection**: Gauges, counters, histograms, and summaries
- **Service Map**: Auto-generated dependency graph from trace data
- **Trace Viewer**: Waterfall timeline visualization for trace inspection
- **APM Detection Rules**: Sigma-format rules for latency spikes, error rates, and anomalies
- **NL Queries for APM**: Ask "Why is checkout slow?" and get answers

### SOAR (Security Orchestration, Automation, and Response)
- **Playbook Management**: Create, edit, version, and deploy response playbooks
- **IR Plan Import**: Upload markdown/YAML incident response plans, auto-convert to playbooks
- **Alert Action Buttons**: Quick actions on alerts (isolate host, disable user, block IP)
- **Approval Workflow**: Dangerous actions require explicit approval before execution
- **Execution Tracking**: Real-time visibility into playbook execution status
- **Action Logging**: Complete audit trail of all automated actions

### Context Enrichment
- IP Geolocation (MaxMind GeoIP2, IPInfo)
- Threat Intelligence (VirusTotal, AbuseIPDB)
- User Context (Google Workspace, Azure AD, Okta directory lookups)
- Asset Context (AWS, Azure, GCP native inventory)
- Peer Group Comparison for anomaly context

### Data Collectors (25+ sources)
- **Cloud Native**: AWS CloudTrail, VPC Flow Logs, GuardDuty, GCP Audit Logs, Azure Activity Logs
- **Identity**: Okta, Google Workspace, Microsoft 365, Duo Security
- **Endpoints**: CrowdStrike Falcon, Jamf Pro
- **Collaboration**: Slack Audit Logs
- **SaaS**: Snowflake, Salesforce, 1Password
- **DevOps**: GitHub Enterprise, Kubernetes Audit Logs, Docker

### Web Interface
- React 18 with Vite, Tailwind CSS, and Zustand state management
- ITDR dashboard with attack timeline and geographic visualization
- User risk profiles with activity timelines
- Behavioral baseline viewer
- Detection rule management
- Integration configuration wizards

---

## Limitations

### What This Project Is NOT

1. **Not Production-Verified**: No known production deployments at scale. Infrastructure is complete but real-world performance is unvalidated.

2. **Not a Complete SIEM Replacement**: Missing enterprise features:
   - No built-in dashboards or visualizations (use external BI tools)
   - No case management (integrate with Jira, ServiceNow, etc.)
   - No SOAR/automated remediation (by design - security concern)
   - No compliance reporting frameworks
   - No user provisioning UI

3. **Not Managed/SaaS**: You deploy and manage all infrastructure. Requires cloud infrastructure expertise (Terraform, serverless, IAM).

4. **Not Multi-Tenant**: Single-tenant architecture only. Each deployment serves one organization.

5. **Not High-Availability by Default**: Basic infrastructure without HA/DR. You must add this yourself.

### Technical Limitations

#### LLM and Query Limitations
- **LLM Dependency**: Requires LLM API keys. Query quality depends on model capability.
- **LLM Cost Unpredictability**: API costs vary significantly based on query complexity and volume.
- **SQL Generation Accuracy**: LLM-generated SQL may occasionally be incorrect or suboptimal. Review expensive queries before execution.
- **Query Limits**: Maximum 10,000 rows returned, 120-second timeout, 3-level subquery depth.
- **Hardcoded Pricing**: Cost estimates use 2024 pricing constants. Actual cloud costs may differ.

#### Identity Threat Detection Limitations
- **Baseline Cold Start**: Behavioral analysis requires 14 days of historical data. New deployments have no baseline data - all users appear anomalous initially.
- **Provider API Dependencies**: ITDR response actions require valid API credentials for each identity provider (Okta, Azure AD, etc.).
- **Response Actions Not Fully Implemented**: Provider action classes exist but contain placeholder implementations for some actions. Requires API credentials and testing before production use.
- **No Real-Time Streaming**: Batch-based detection with minimum latency of your polling interval (typically 5-15 minutes).
- **Cross-Provider Correlation Requires All Providers**: To detect cross-provider attacks, you must have collectors configured for multiple identity providers.

#### Infrastructure Limitations
- **Cold Starts**: Serverless architecture has cold start latency (3-10 seconds for first request).
- **Single Region**: Terraform deploys to a single region. Multi-region requires manual configuration.
- **Schema Changes**: Adding new log sources requires manual Glue/BigQuery table creation.
- **No Log Retention UI**: Configure S3/GCS/Azure Blob lifecycle policies separately.

#### Frontend Limitations
- **Modern Browsers Only**: No IE11 or legacy browser support.
- **No Mobile Optimization**: Desktop-first design.
- **Web UI Auth**: Falls back to 'anonymous' if authentication not configured.

#### Enrichment Limitations
- **API Keys Required**: Geolocation requires MaxMind or IPInfo keys. Threat intel requires VirusTotal/AbuseIPDB keys. Without keys, enrichment returns limited data.
- **Rate Limits**: External API rate limits may affect enrichment during high-volume alerts.

#### Testing Limitations
- **Tests Are Structural**: Many tests verify code structure and mocking rather than actual cloud API behavior.
- **No Load Testing**: Performance at scale is untested.
- **Integration Tests Require Credentials**: Some integration tests require actual cloud credentials to run.
- **Test-Implementation Sync**: The test suite has 1695 tests total with ~84% passing (1421 pass, 149 fail, 125 skipped, 0 errors). The ITDR (Identity Threat Detection) module is fully functional with passing enrichment, baseline comparison, risk scoring, and session tracking tests. Risk scoring includes full factor weighting, decay, trend analysis, and score breakdown. Session tracking includes complete anomaly detection (IP change, geo change, device change, duration anomalies), concurrent session detection, and session lifecycle management. The APM/Observability module has full OTLP trace and metric parsing with correct data model integration. The SOAR module has complete interface compatibility with proper playbook/step parameter handling, async execution engine, approval workflows, and branching logic. The IR plan parser now supports YAML and markdown formats with LLM-assisted parsing. Remaining failures are primarily integration pipeline tests requiring infrastructure setup.

#### APM Limitations
- **No Automatic Trace Alerting**: APM data requires explicit detection rules to generate alerts.
- **Service Map Minimum Volume**: Service dependency map requires minimum trace volume to be meaningful.
- **No Real-Time Streaming**: Traces processed in batches, not real-time.
- **OpenTelemetry Only**: OTLP format required; other APM formats not supported.

#### SOAR Limitations
- **Not a Full Workflow Engine**: Simple linear playbook execution, not a complex workflow orchestrator.
- **Custom Actions Require Code**: Adding new action types requires Python code.
- **Provider Credentials Required**: Actions like "disable user" require valid identity provider API credentials.
- **Approval Timeouts**: Pending approvals expire after configured timeout (default 1 hour).
- **No Rollback**: Actions cannot be automatically undone if playbook fails midway.

### Security Configuration Required

- **CORS Origin**: Must set `CORS_ALLOWED_ORIGIN` environment variable. Default is `*` (insecure).
- **API Gateway Authorizer**: Lambda handlers expect JWT claims from API Gateway. Configure Cognito/Identity Platform authorizer.
- **Secrets Management**: Some handlers read API keys from environment variables. Move to Secrets Manager/Key Vault for production.
- **Dev Mode**: `MANTISSA_DEV_MODE=true` bypasses authentication. Never enable in production.

### Operational Concerns

- **Cost Unpredictability**: Athena/BigQuery charges per data scanned. Unoptimized queries can be expensive.
- **No Automatic Updates**: You pull and deploy changes manually.
- **Community Support Only**: No SLA, no vendor backing, no guaranteed response times.
- **Import Path Sensitivity**: Lambda packaging must preserve directory structure for imports.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Interface                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ NL Query     │  │ ITDR         │  │ Detection    │               │
│  │ Interface    │  │ Dashboard    │  │ Management   │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
└─────────┼─────────────────┼─────────────────┼───────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         API Layer                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ Query API    │  │ Identity API │  │ Rules API    │               │
│  │ (LLM → SQL)  │  │ (Risk/Base)  │  │ (CRUD)       │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
└─────────┼─────────────────┼─────────────────┼───────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Processing Layer                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ LLM Engine   │  │ ITDR Engine  │  │ Detection    │               │
│  │ (8 providers)│  │ (Behavioral) │  │ Engine       │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ Enrichment   │  │ Correlation  │  │ Alert        │               │
│  │ (Geo/TI/User)│  │ (Kill Chain) │  │ Routing      │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Data Layer                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ Data Lake    │  │ State Store  │  │ Baseline     │               │
│  │ (S3/GCS/Blob)│  │ (DynamoDB/   │  │ Store        │               │
│  │              │  │  Firestore)  │  │              │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
          ▲                 ▲                 ▲
          │                 │                 │
┌─────────────────────────────────────────────────────────────────────┐
│                      Collectors (25+)                                │
│  Cloud │ Identity │ Endpoints │ SaaS │ DevOps                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Serverless**: Lambda/Cloud Functions for cost efficiency and auto-scaling
2. **No Dashboards**: Natural language queries replace static dashboards
3. **No Case Management**: Alerts create tickets in external systems (Jira, ServiceNow)
4. **Sigma Format**: Industry-standard rules for multi-cloud portability
5. **LLM-First**: Natural language is the primary interface
6. **Cloud-Agnostic Core**: Shared logic with cloud-specific adapters

---

## Project Structure

```
mantissa-log/
├── src/
│   ├── shared/              # Cloud-agnostic core (264 Python files)
│   │   ├── alerting/        # Alert routing (7 handlers)
│   │   ├── auth/            # Authentication middleware
│   │   ├── detection/       # Detection engine, Sigma conversion
│   │   ├── enrichment/      # Geolocation, threat intel, user context
│   │   ├── identity/        # ITDR module (24+ files)
│   │   │   ├── baseline/    # User behavioral baselines
│   │   │   ├── correlation/ # Kill chain, cross-provider
│   │   │   ├── detections/  # Threat detectors
│   │   │   ├── enrichment/  # Identity alert enrichment
│   │   │   ├── escalation/  # Severity escalation
│   │   │   ├── response/    # Auto-response actions
│   │   │   └── templates/   # Alert templates
│   │   ├── llm/             # LLM providers (8), caching, query gen
│   │   ├── parsers/         # Log parsers (25+)
│   │   ├── redaction/       # PII/PHI redaction
│   │   └── models/          # Data models including identity mappers
│   ├── aws/                 # AWS Lambda handlers (45)
│   ├── gcp/                 # GCP Cloud Functions (10)
│   └── azure/               # Azure Functions (20+)
├── web/                     # React frontend (11 pages, 50+ components)
├── infrastructure/          # Terraform IaC (120+ files)
│   ├── aws/terraform/       # AWS modules (14)
│   ├── gcp/terraform/       # GCP configuration
│   └── azure/terraform/     # Azure configuration
├── rules/sigma/             # 640 Sigma detection rules
├── tests/                   # Test suite (74 files)
│   ├── unit/                # Unit tests (49 files)
│   ├── integration/         # Integration tests (13 files)
│   ├── fixtures/            # Test data and scenarios
│   └── rules/               # Rule validation suite
├── docs/                    # Documentation (25 files)
└── scripts/                 # Deployment scripts
```

---

## Component Counts

| Component | Count |
|-----------|-------|
| Python Source Files | 335 |
| AWS Lambda Handlers | 37 |
| GCP Cloud Functions | 10 |
| Azure Functions | 20+ |
| LLM Providers | 8 |
| Alert Handlers | 7 |
| Sigma Detection Rules | 647 (49 ITDR-specific) |
| Log Source Parsers | 25+ |
| Identity Providers Supported | 5 (Okta, Azure AD, Google Workspace, Duo, M365) |
| Test Files | 83 |
| Total Tests | 1695 (1421 passing, 149 failing, 125 skipped) |
| Test Coverage | ~84% pass rate |
| Terraform Modules | 14 (AWS) + GCP + Azure |
| Documentation Files | 28 |
| Web Pages | 11 |
| React Components | 100+ (SOAR, APM, Identity dashboards) |

---

## Quick Start

### Prerequisites

- AWS/GCP/Azure account with appropriate permissions
- Terraform >= 1.5
- Python >= 3.11
- Node.js >= 18
- LLM API key (Anthropic, OpenAI, Google, or cloud-native)

### AWS Deployment

```bash
git clone https://github.com/your-org/mantissa-log.git
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

See [docs/deployment/](docs/deployment/) for GCP and Azure instructions.

---

## Testing

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run all tests
PYTHONPATH=. pytest tests/ -v

# Run specific test categories
pytest tests/unit/ -v                    # Unit tests
pytest tests/integration/ -v             # Integration tests
pytest tests/unit/identity/ -v           # ITDR tests only
pytest tests/rules/ -v                   # Rule validation
```

---

## Documentation

- [Getting Started](docs/getting-started.md)
- [AWS Deployment](docs/deployment/aws-deployment.md)
- [GCP Deployment](docs/deployment/gcp-deployment.md)
- [Azure Deployment](docs/deployment/azure-deployment.md)
- [Multi-Cloud Guide](docs/deployment/multi-cloud.md)
- [Detection Rules](docs/configuration/detection-rules.md)
- [Alert Routing](docs/configuration/alert-routing.md)
- [LLM Configuration](docs/configuration/llm-configuration.md)
- [Operations Runbook](docs/operations/runbook.md)
- [API Reference](docs/api/api-reference.md)

---

## Environment Variables

See [docs/configuration/](docs/configuration/) for complete environment variable reference. Key variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `LLM_PROVIDER` | LLM provider (`anthropic`, `openai`, `bedrock`, etc.) | Yes |
| `CORS_ALLOWED_ORIGIN` | Allowed CORS origin (set for security) | Yes (prod) |
| `ATHENA_DATABASE` / `BIGQUERY_DATASET` / `SYNAPSE_DATABASE` | Query database | Yes |
| `STATE_TABLE` / Firestore collection / Cosmos container | State storage | Yes |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / etc. | LLM credentials | Yes |

---

## Product Modes

### Mode 1: SIEM (Log Aggregation + Query + Detection + Alerting)

- Collect logs from 25+ sources
- Query with natural language or SQL
- Detect threats with Sigma rules
- Alert to Slack, PagerDuty, Jira, etc.
- **Terraform:** `enable_apm=false`, `enable_soar=false`

### Mode 2: SIEM + Observability (Add APM/Tracing)

Everything in Mode 1, plus:
- Collect metrics and traces via OpenTelemetry
- Visualize service dependencies
- Query application performance with NL
- Detect latency and error anomalies
- **Terraform:** `enable_apm=true`, `enable_soar=false`

### Mode 3: Full Platform (Add Automated Response)

Everything in Modes 1 and 2, plus:
- Convert IR plans to executable playbooks
- Auto-respond to alerts with Lambda functions
- One-click actions: isolate host, disable user, block IP
- Approval workflow for dangerous actions
- **Terraform:** `enable_apm=true`, `enable_soar=true`

---

## Inputs and Outputs by Feature

### Feature 1: Log Aggregation (SIEM Core)

**INPUTS:**
- API credentials for log sources (Okta, Azure AD, AWS CloudTrail, etc.)
- Collector configuration (which sources to collect from)
- Collection schedule (how often to pull logs)

**OUTPUTS:**
- Raw logs stored in S3/GCS/Azure Blob (partitioned by date/hour)
- Normalized log data queryable via Athena/BigQuery/Synapse
- Glue/BigQuery tables for each log source

**STORAGE FORMAT:**
- NDJSON (newline-delimited JSON) files
- Partitioned: `{source}/raw/{YYYY}/{MM}/{DD}/{HH}/`
- Retention: Configurable via S3 lifecycle policies

### Feature 2: Natural Language Query Interface

**INPUTS:**
- Natural language questions (English)
  - "Show me failed logins in the last 24 hours"
  - "Which users accessed S3 buckets from unusual IPs?"
  - "Why is the checkout service slow?" (if APM enabled)

**OUTPUTS:**
- SQL query (Athena/BigQuery/Synapse compatible)
- Query results (JSON array of matching records)
- Query explanation (natural language description)
- Query cost estimate (data scanned, estimated cost)

**LLM PROVIDERS SUPPORTED:**
- AWS Bedrock (Claude) - default
- Anthropic API (Claude)
- OpenAI (GPT-4)
- Azure OpenAI
- Google Vertex AI (Gemini)
- Google AI (Gemini)

### Feature 3: Detection Rules (Sigma)

**INPUTS (choose one):**
- Natural language description: "Alert when a user fails login 5+ times in 10 minutes"
- Manual Sigma YAML rule file
- Import existing Sigma rules from community

**OUTPUTS:**
- Sigma YAML rule file (stored in `/rules/sigma/`)
- Cloud-specific SQL query (auto-generated from Sigma)
- Detection schedule (EventBridge/Cloud Scheduler rule)

**SIGMA RULE FORMAT (output example):**
```yaml
title: Brute Force Login Attempts
id: abc123-def456-...
status: stable
level: high
description: Detects multiple failed login attempts
logsource:
  product: okta
  service: authentication
detection:
  selection:
    outcome: FAILURE
  condition: selection | count() by user_email > 5
  timeframe: 10m
```

### Feature 4: Alerting

**INPUTS:**
- Detection rule triggers (from Sigma rules)
- Alert destination configuration (Slack webhook, PagerDuty key, etc.)
- Severity routing rules (critical→PagerDuty, medium→Slack)

**OUTPUTS:**
- Formatted alerts to 7 destinations:
  - Slack (Block Kit format)
  - PagerDuty (Events API v2)
  - Email (SMTP/SES)
  - Microsoft Teams (Webhook)
  - Jira (Ticket creation)
  - ServiceNow (Incident creation)
  - Custom Webhook (JSON payload)
- Alert history (stored in DynamoDB)
- Alert deduplication and correlation

### Feature 5: Observability/APM (Optional Module)

**INPUTS:**
- OpenTelemetry data via OTLP protocol:
  - `POST /v1/traces` (distributed traces)
  - `POST /v1/metrics` (application metrics)
- Supported formats: JSON, Protobuf

**OUTPUTS:**
- Trace data stored in S3 (partitioned)
- Metric data stored in S3 (partitioned)
- Service dependency map (JSON for visualization)
- Trace waterfall visualization data
- APM-specific Sigma rules (latency, error rate detection)

**APM QUERY EXAMPLES:**
- "Why is checkout slow?" → Latency analysis SQL
- "Show error traces in the last hour" → Error trace query
- "What services call payment-api?" → Service map query

### Feature 6: SOAR - Automated Response (Optional Module)

**INPUTS (choose one):**
- Natural language description: "When credential compromise is detected, terminate sessions, revoke tokens, and create a Jira ticket"
- Markdown IR (Incident Response) plan document
- Manual Playbook YAML file

**OUTPUTS:**
- Playbook YAML file (stored in `/rules/playbooks/`)
- Python Lambda code (auto-generated, deployable)
- Execution logs (full audit trail)
- Approval requests (for dangerous actions)

**PLAYBOOK YAML FORMAT (output example):**
```yaml
id: playbook-cred-001
name: Credential Compromise Response
version: 1.0.0
trigger:
  type: alert
  conditions:
    severity: [critical, high]
    rule_patterns: [credential_*, brute_force*]
steps:
  - id: terminate_sessions
    action_type: terminate_sessions
    parameters:
      user_id: "{{ alert.metadata.user_email }}"
  - id: create_ticket
    action_type: create_ticket
    provider: jira
    parameters:
      summary: "Credential Compromise: {{ alert.metadata.user_email }}"
```

**SUPPORTED RESPONSE ACTIONS:**
- `terminate_sessions` (Okta, Azure AD, Google Workspace)
- `disable_account`
- `force_password_reset`
- `revoke_tokens`
- `block_ip` (AWS WAF, Cloudflare)
- `isolate_host` (CrowdStrike)
- `create_ticket` (Jira, ServiceNow)
- `notify` (Slack, PagerDuty, Email)

### Summary: What the NL Interface Generates

| Natural Language Input | Output Format |
|----------------------|---------------|
| "Show me failed logins..." | SQL Query + Results |
| "Detect brute force attacks..." | Sigma YAML Rule |
| "When X happens, do Y..." | Playbook YAML + Python Lambda |
| "Why is service slow?" | SQL Query + Results (APM) |

---

## What's NOT Included (By Design)

- **Dashboards/Visualizations**: Use natural language queries or external BI tools
- **Case Management**: Integrate with Jira, ServiceNow, Rootly, etc.
- **On-Premises Support**: Cloud-native architecture only
- **Real-Time ML Streaming**: Serverless batch processing only
- **Full SOAR Platform**: Basic playbooks only, not enterprise workflow orchestration

---

## Contributing

See [docs/development/contributing.md](docs/development/contributing.md) for contribution guidelines.

---

## License

[MIT License](LICENSE)

---

## Acknowledgments

- [Sigma](https://github.com/SigmaHQ/sigma) for detection rule format
- [MITRE ATT&CK](https://attack.mitre.org/) for threat framework mappings
