# Mantissa Log Source Code

This directory contains all application source code for Mantissa Log.

## Directory Structure

```
src/
├── shared/              # Cloud-agnostic core modules (~70% of code)
│   ├── alerting/        # Alert routing to 7 destinations
│   ├── apm/             # APM/observability detection rules
│   ├── auth/            # Authentication middleware
│   ├── conversation/    # NL query conversation context
│   ├── cost/            # Query cost estimation
│   ├── detection/       # Detection engine, Sigma-to-SQL conversion
│   ├── enrichment/      # Geo, threat intel, user, asset enrichment
│   ├── health/          # Log source health monitoring
│   ├── identity/        # ITDR (behavioral analysis, risk scoring)
│   ├── integrations/    # External service integrations
│   ├── llm/             # 8 LLM provider adapters, query generation
│   ├── models/          # Data models and identity mappers
│   ├── parsers/         # 25+ log source parsers
│   ├── redaction/       # PII/PHI redaction
│   ├── scheduled/       # Scheduled task handlers
│   ├── soar/            # Playbooks, IR plans, automated response
│   └── utils/           # Shared utilities
├── aws/                 # AWS Lambda handlers
├── gcp/                 # GCP Cloud Functions + BigQuery
├── azure/               # Azure Functions + Synapse
├── api/                 # REST API endpoints
└── collectors/          # Log source collector implementations
```

## Architecture

The codebase is split into two layers:

### 1. Shared Layer (~70% of code)

Cloud-agnostic components that work across all platforms:

- **parsers/**: Log parsing and normalization for 25+ sources
- **detection/**: Detection engine core, Sigma rule conversion, query execution
- **identity/**: ITDR behavioral baselines, risk scoring, kill chain tracking
- **health/**: Log source health monitoring, anomaly detection, gap detection
- **llm/**: LLM query generation, validation, caching across 8 providers
- **alerting/**: Alert routing, enrichment, PII redaction
- **soar/**: Playbook execution, IR plan parsing, approval workflows
- **enrichment/**: Geolocation, threat intelligence, user/asset context

These components have no cloud-specific dependencies and can be reused across AWS, GCP, and Azure.

### 2. Cloud-Specific Layer (~30% of code)

Platform-specific adapters and serverless function handlers:

- **aws/**: Lambda handlers, Glue schemas, Athena query execution
- **gcp/**: Cloud Function handlers, BigQuery integration
- **azure/**: Azure Function handlers, Synapse query execution

These components wrap cloud services and call the shared layer for business logic.

## Development Guidelines

When adding new features:

1. Implement business logic in `shared/` if cloud-agnostic
2. Create cloud-specific adapters in provider directories
3. Ensure shared code has no cloud SDK imports at module level (use lazy imports)
4. Write tests for both shared and cloud-specific code
5. Follow the existing multi-cloud patterns (see `shared/identity/baseline_store.py` for the canonical example)

## Standards

- **Python 3.11+**
- **Type hints**: Required for function signatures
- **Docstrings**: Google-style for public functions
- **Testing**: pytest for unit and integration tests
- **Formatting**: black (line-length 100), isort

## Import Rules

Shared code should only import from:
- Python standard library
- Third-party libraries with no cloud dependencies
- Other shared modules
- Cloud SDKs via lazy imports inside methods (not at module level)

Cloud-specific code can import:
- Shared modules
- Cloud provider SDKs (boto3, google-cloud-*, azure-*)
- Cloud-specific third-party libraries
