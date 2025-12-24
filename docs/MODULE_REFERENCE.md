# Mantissa Log Module Reference

Technical reference for all Mantissa Log modules and their components.

---

## SIEM Module (Core)

The SIEM module provides log aggregation, natural language querying, threat detection, and alerting.

### Collectors

| Source | Type | Status | File |
|--------|------|--------|------|
| AWS CloudTrail | Cloud | Stable | `src/shared/parsers/cloudtrail.py` |
| AWS VPC Flow Logs | Cloud | Stable | `src/shared/parsers/vpc_flow.py` |
| AWS GuardDuty | Cloud | Stable | `src/shared/parsers/guardduty.py` |
| AWS Config | Cloud | Stable | `src/shared/parsers/aws_config.py` |
| AWS S3 Access Logs | Cloud | Stable | `src/shared/parsers/s3_access.py` |
| GCP Audit Logs | Cloud | Stable | `src/shared/parsers/gcp_audit.py` |
| GCP VPC Flow Logs | Cloud | Stable | `src/shared/parsers/gcp_vpc_flow.py` |
| Azure Activity Logs | Cloud | Stable | `src/shared/parsers/azure_activity.py` |
| Azure AD Sign-in Logs | Identity | Stable | `src/shared/parsers/azure_ad.py` |
| Okta System Log | Identity | Stable | `src/shared/parsers/okta.py` |
| Google Workspace | Identity | Stable | `src/shared/parsers/google_workspace.py` |
| Microsoft 365 | Identity | Stable | `src/shared/parsers/microsoft_365.py` |
| Duo Security | Identity | Stable | `src/shared/parsers/duo.py` |
| CrowdStrike Falcon | Endpoint | Stable | `src/shared/parsers/crowdstrike.py` |
| Jamf Pro | Endpoint | Stable | `src/shared/parsers/jamf.py` |
| Slack Audit | SaaS | Stable | `src/shared/parsers/slack_audit.py` |
| GitHub Enterprise | DevOps | Stable | `src/shared/parsers/github.py` |
| Kubernetes Audit | DevOps | Stable | `src/shared/parsers/kubernetes.py` |
| Docker | DevOps | Stable | `src/shared/parsers/docker.py` |
| Snowflake | SaaS | Stable | `src/shared/parsers/snowflake.py` |
| Salesforce | SaaS | Stable | `src/shared/parsers/salesforce.py` |
| 1Password | SaaS | Stable | `src/shared/parsers/onepassword.py` |
| Syslog | Generic | Stable | `src/shared/parsers/syslog.py` |
| CEF | Generic | Stable | `src/shared/parsers/cef.py` |
| JSON Lines | Generic | Stable | `src/shared/parsers/json_lines.py` |

### Detection Engine

**Location:** `src/shared/detection/`

**How Sigma Rules Are Processed:**

1. **Rule Loading** (`rule_loader.py`)
   - Loads YAML rules from `/rules/sigma/`
   - Validates against Sigma schema
   - Indexes by rule ID, tags, and log source

2. **SQL Conversion** (`sigma_converter.py`)
   - Converts Sigma detection logic to SQL
   - Platform-specific adapters for Athena, BigQuery, Synapse
   - Handles wildcards, regex, aggregations

3. **Scheduled Execution** (`scheduler.py`)
   - EventBridge rules trigger detection Lambda
   - Configurable time windows (5m, 15m, 1h, 24h)
   - Parallel execution for independent rules

4. **Result Processing** (`engine.py`)
   - Executes SQL against data lake
   - Filters false positives based on tuning
   - Creates alerts for matches

**Key Files:**
- `src/shared/detection/engine.py` - Main detection engine
- `src/shared/detection/sigma_converter.py` - Sigma to SQL
- `src/shared/detection/rule_loader.py` - Rule management
- `src/shared/detection/scheduler.py` - Execution scheduling

### Alert Router

**Location:** `src/shared/alerting/`

**Supported Destinations:**

| Destination | Handler | Configuration |
|-------------|---------|---------------|
| Slack | `slack_handler.py` | Webhook URL, channel |
| PagerDuty | `pagerduty_handler.py` | Routing key, severity mapping |
| Email | `email_handler.py` | SMTP settings or SES |
| Microsoft Teams | `teams_handler.py` | Webhook URL |
| Jira | `jira_handler.py` | Instance URL, project, credentials |
| ServiceNow | `servicenow_handler.py` | Instance URL, credentials |
| Webhook | `webhook_handler.py` | URL, headers, authentication |

**Alert Flow:**
1. Detection engine creates alert
2. Alert enriched with context (geo, threat intel, user info)
3. PII redacted for external destinations
4. Routed based on severity/tags to configured destinations
5. Stored in DynamoDB for history

**Key Files:**
- `src/shared/alerting/router.py` - Main routing logic
- `src/shared/alerting/enricher.py` - Alert enrichment
- `src/shared/alerting/handlers/` - Destination handlers

### Query Interface

**Location:** `src/shared/llm/`

**NL to SQL Capabilities:**

1. **Question Understanding**
   - Extracts entities (users, IPs, time ranges)
   - Identifies intent (search, aggregate, compare)
   - Maps to available tables and columns

2. **SQL Generation**
   - Generates platform-specific SQL (Athena, BigQuery, Synapse)
   - Applies time range filters
   - Adds appropriate JOINs

3. **Query Optimization**
   - Partition pruning for cost efficiency
   - Column projection
   - Limit clauses

4. **Result Formatting**
   - JSON response with results
   - Natural language summary
   - Cost estimate

**LLM Providers:**
- Anthropic Claude (`anthropic_provider.py`)
- OpenAI GPT-4 (`openai_provider.py`)
- AWS Bedrock (`bedrock_provider.py`)
- Azure OpenAI (`azure_openai_provider.py`)
- Google Vertex AI (`vertex_provider.py`)
- Google AI (`google_ai_provider.py`)

**Key Files:**
- `src/shared/llm/query_generator.py` - NL to SQL
- `src/shared/llm/providers/` - LLM provider implementations
- `src/shared/llm/schema_context.py` - Table schema for context

### ITDR (Identity Threat Detection & Response)

**Location:** `src/shared/identity/`

**Components:**

1. **Behavioral Baselines** (`baseline/`)
   - 14-day learning period
   - Tracks: login times, locations, devices, volumes
   - Peer group comparison

2. **Anomaly Detection** (`detections/`)
   - Impossible travel
   - Unusual login times
   - New device/location
   - Volume spikes

3. **Credential Attack Detection**
   - Brute force
   - Password spray
   - Credential stuffing
   - MFA fatigue/bypass

4. **Privilege Monitoring**
   - Escalation chains
   - Self-privilege grants
   - Dormant account activation

5. **Kill Chain Tracking** (`correlation/`)
   - 8-stage progression detection
   - Cross-provider correlation

---

## Observability/APM Module

The APM module adds distributed tracing, metrics collection, and service map visualization.

### OTLP Receiver

**Location:** `src/shared/apm/` and `src/aws/apm/`

**Endpoints:**

| Endpoint | Method | Content-Type | Description |
|----------|--------|--------------|-------------|
| `/v1/traces` | POST | application/json, application/x-protobuf | Receive trace spans |
| `/v1/metrics` | POST | application/json, application/x-protobuf | Receive metrics |

**Limits:**
- Max batch size: 10,000 spans/metrics
- Max payload: 5MB
- Request timeout: 30 seconds

**Processing Flow:**
1. Receive OTLP data via API Gateway
2. Parse JSON or Protobuf format
3. Convert to internal data model
4. Partition and write to S3
5. Update service map cache

**Key Files:**
- `src/shared/apm/otlp_parser.py` - OTLP parsing
- `src/shared/apm/models.py` - Data models
- `src/aws/apm/trace_receiver.py` - Lambda handler
- `src/aws/apm/metrics_receiver.py` - Lambda handler

### Data Models

**Trace Event:**
```python
@dataclass
class TraceEvent:
    trace_id: str           # 32-char hex
    span_id: str            # 16-char hex
    parent_span_id: str     # Optional
    name: str               # Operation name
    service_name: str       # Service identifier
    start_time: datetime
    end_time: datetime
    duration_ms: int
    status_code: str        # OK, ERROR
    attributes: Dict        # Custom attributes
```

**Metric Event:**
```python
@dataclass
class MetricEvent:
    name: str               # Metric name
    type: str               # gauge, counter, histogram, summary
    value: float
    timestamp: datetime
    service_name: str
    attributes: Dict
    # For histograms
    bucket_counts: List[int]
    bucket_boundaries: List[float]
```

### Service Map

**Location:** `src/shared/apm/service_map.py`

**How It's Generated:**
1. Analyze trace spans for parent-child relationships
2. Extract service-to-service calls
3. Calculate:
   - Call frequency
   - Average latency
   - Error rates
4. Build dependency graph
5. Cache for 5 minutes

**API Response:**
```json
{
  "nodes": [
    {
      "id": "api-gateway",
      "service_name": "api-gateway",
      "request_count": 1000,
      "avg_latency_ms": 50,
      "error_rate": 0.01
    }
  ],
  "edges": [
    {
      "source": "api-gateway",
      "target": "user-service",
      "call_count": 500,
      "avg_latency_ms": 25
    }
  ]
}
```

**Refresh Rate:** 5 minutes (configurable)

### APM Queries

**Example NL Queries:**

| Query | Generated SQL (simplified) |
|-------|---------------------------|
| "Why is checkout slow?" | `SELECT * FROM traces WHERE service='checkout' ORDER BY duration_ms DESC` |
| "Show error traces today" | `SELECT * FROM traces WHERE status='ERROR' AND date=today()` |
| "What services call payment?" | `SELECT DISTINCT parent_service FROM traces WHERE service='payment'` |
| "P99 latency for user-service" | `SELECT percentile(duration_ms, 0.99) FROM traces WHERE service='user-service'` |

### APM Detection Rules

APM rules use Sigma format with `logsource.product: apm`:

```yaml
title: High Error Rate - Payment Service
id: apm-error-payment-001
status: stable
level: high
logsource:
  product: apm
  service: traces
detection:
  selection:
    service_name: "payment-service"
    status_code: "ERROR"
  condition: selection | count() > 100
  timeframe: 5m
tags:
  - apm
  - error-rate
```

---

## SOAR Module

The SOAR module provides playbook management and automated response capabilities.

### Playbook Format

**Location:** `/rules/playbooks/`

**YAML Schema:**

```yaml
# Required fields
name: string              # Display name
version: string           # Semantic version
status: active|inactive|draft

# Trigger configuration
trigger:
  type: alert|schedule|manual
  conditions:
    rule_id: string|pattern    # Optional
    severity: list             # Optional
    tags: list                 # Optional

# Response steps
steps:
  - id: string               # Unique step ID
    name: string             # Display name
    action_type: string      # Action to execute
    description: string      # Optional
    parameters: object       # Action-specific
    requires_approval: bool  # Default: false
    approval_timeout_seconds: int
    depends_on: list         # Step IDs
    condition: string        # Jinja2 expression
    on_failure: stop|continue
    timeout_seconds: int

# Metadata
tags: list
metadata:
  author: string
  created_at: datetime
  compliance: list
```

### Supported Actions

| Action Type | Provider | Parameters |
|-------------|----------|------------|
| `disable_user` | Okta, Azure AD, Google | `user_id`, `reason` |
| `enable_user` | Okta, Azure AD, Google | `user_id` |
| `revoke_sessions` | Okta, Azure AD, Google | `user_id`, `include_refresh_tokens` |
| `reset_password` | Okta, Azure AD | `user_id`, `send_notification` |
| `revoke_api_keys` | Multiple | `user_id`, `scope` |
| `block_ip` | AWS WAF, Cloudflare | `ip_address`, `duration`, `zones` |
| `unblock_ip` | AWS WAF, Cloudflare | `ip_address`, `zones` |
| `block_domain` | DNS | `domain`, `block_type` |
| `isolate_host` | CrowdStrike | `host_id`, `isolation_level` |
| `unisolate_host` | CrowdStrike | `host_id` |
| `collect_forensics` | Multiple | `host_id`, `collection_type` |
| `create_ticket` | Jira, ServiceNow | `system`, `project`, `title`, `description` |
| `update_ticket` | Jira, ServiceNow | `ticket_id`, `status`, `comment` |
| `send_notification` | Slack, PagerDuty, Email | `channel`/`service`, `message` |
| `run_query` | Internal | `query`, `store_results_as` |
| `run_script` | Internal | `script`, `args` |
| `update_asset` | Internal | `asset_id`, `status`, `tags` |

### IR Plan Parser

**Location:** `src/shared/soar/ir_parser.py`

**Supported Formats:**
- Markdown (`.md`)
- Plain text (`.txt`)
- YAML (`.yml`, `.yaml`)

**Markdown Structure:**
```markdown
# Playbook Name

## Trigger
Description of when to run

## Steps
1. **Step Name** - Action description
2. **Next Step** - Another action
```

**Parsing Process:**
1. Extract headings and structure
2. Send to LLM for interpretation
3. Map actions to supported action types
4. Generate parameter templates
5. Validate against schema
6. Output playbook YAML

### Code Generator

**Location:** `src/shared/soar/code_generator.py`

**Generated Lambda Structure:**
```python
# Auto-generated from playbook: {playbook_name}
# Version: {version}
# Generated at: {timestamp}

import json
import logging
from typing import Dict, Any

logger = logging.getLogger()

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """Execute playbook steps."""
    alert = event.get('alert', {})
    execution_id = event.get('execution_id')

    results = []

    # Step 1: {step_name}
    try:
        result = execute_step_1(alert)
        results.append({'step': 'step-1', 'status': 'success', 'result': result})
    except Exception as e:
        results.append({'step': 'step-1', 'status': 'error', 'error': str(e)})
        # on_failure: stop
        return {'status': 'failed', 'results': results}

    # ... more steps ...

    return {'status': 'completed', 'results': results}
```

**Safety Validations:**
- No arbitrary code execution
- Action types must be in allowlist
- Parameter templates sanitized
- Secrets fetched from Secrets Manager

### Approval Workflow

**Location:** `src/shared/soar/approval.py`

**Configuration:**
```python
@dataclass
class ApprovalConfig:
    required_for: List[str]       # Action types requiring approval
    approvers: List[str]          # User IDs or groups
    notification_channel: str     # Slack channel
    timeout_seconds: int          # Default: 3600
    auto_approve_after_timeout: bool  # Default: False
```

**Flow:**
1. Step marked `requires_approval: true`
2. Create approval request in DynamoDB
3. Send notification to approvers
4. Wait for approval or timeout
5. If approved: execute step
6. If denied/timeout: skip step (or fail based on config)

### Execution Engine

**Location:** `src/shared/soar/executor.py`

**Execution Flow:**
1. Load playbook from storage
2. Validate trigger conditions match
3. Create execution record
4. Process steps in order (respecting `depends_on`)
5. For each step:
   - Check condition (skip if false)
   - Check approval (wait if required)
   - Execute action
   - Log result
   - Handle failure per `on_failure`
6. Update execution status
7. Send completion notification

**Timeout Handling:**
- Per-step timeout (default: 300s)
- Overall execution timeout (default: 3600s)
- Approval timeout (default: 3600s)

**Retry Policy:**
- No automatic retries (by design)
- Failed steps can be manually retried
- Partial executions can be resumed

---

## Shared Services

### Query Executors

**Location:** `src/shared/query/`

| Executor | File | Cloud |
|----------|------|-------|
| Athena | `athena_executor.py` | AWS |
| BigQuery | `bigquery_executor.py` | GCP |
| Synapse | `synapse_executor.py` | Azure |

**Common Interface:**
```python
class QueryExecutor(ABC):
    @abstractmethod
    def execute(self, sql: str, parameters: Dict = None) -> QueryResult:
        pass

    @abstractmethod
    def estimate_cost(self, sql: str) -> CostEstimate:
        pass
```

### Storage

**S3 Partitioning Scheme:**
```
s3://bucket/
├── logs/
│   ├── cloudtrail/
│   │   └── year=2024/month=01/day=15/hour=14/
│   ├── okta/
│   │   └── year=2024/month=01/day=15/hour=14/
│   └── ...
├── traces/
│   └── year=2024/month=01/day=15/hour=14/
├── metrics/
│   └── year=2024/month=01/day=15/hour=14/
└── playbooks/
    └── playbook-id/version/
```

### LLM Provider Interface

**Location:** `src/shared/llm/providers/`

**Common Interface:**
```python
class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 4096) -> str:
        pass

    @abstractmethod
    def generate_with_schema(self, prompt: str, schema: Dict) -> Dict:
        pass
```

**Configuration:**
```python
LLM_CONFIG = {
    'provider': 'bedrock',  # or anthropic, openai, etc.
    'model': 'claude-3-sonnet',
    'max_tokens': 4096,
    'temperature': 0.0,
    'cache_enabled': True,
    'cache_ttl_seconds': 3600
}
```

---

## API Reference

### SIEM APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/query` | POST | Execute NL query |
| `/rules` | GET | List detection rules |
| `/rules/{id}` | GET/PUT/DELETE | Manage rule |
| `/alerts` | GET | List alerts |
| `/alerts/{id}` | GET | Get alert details |

### APM APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/traces` | POST | Ingest traces |
| `/v1/metrics` | POST | Ingest metrics |
| `/apm/service-map` | GET | Get service map |
| `/apm/traces/{trace_id}` | GET | Get trace details |

### SOAR APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/playbooks` | GET/POST | List/create playbooks |
| `/playbooks/{id}` | GET/PUT/DELETE | Manage playbook |
| `/playbooks/{id}/execute` | POST | Execute playbook |
| `/executions` | GET | List executions |
| `/executions/{id}` | GET | Get execution details |
| `/approvals/{id}/approve` | POST | Approve action |
| `/approvals/{id}/deny` | POST | Deny action |

### Config API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/config` | GET | Get enabled features |

Response:
```json
{
  "features": {
    "siem": true,
    "apm": true,
    "soar": true
  },
  "version": "1.0.0"
}
```
