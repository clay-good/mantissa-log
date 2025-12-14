# Mantissa Log Documentation

## Quick Links

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | First-time setup and your first query |
| [Quick Start with Samples](tutorials/quick-start-with-samples.md) | Hands-on tutorial with sample data |
| [AWS Deployment](deployment/aws-deployment.md) | Complete AWS deployment guide |
| [Multi-Cloud](deployment/multi-cloud.md) | GCP and Azure deployment |
| [Troubleshooting](deployment/troubleshooting.md) | Common issues and solutions |

---

## Documentation Index

### Deployment

| Guide | Description |
|-------|-------------|
| [Prerequisites](deployment/prerequisites.md) | Required tools and permissions |
| [AWS Deployment](deployment/aws-deployment.md) | Step-by-step AWS deployment |
| [Multi-Cloud](deployment/multi-cloud.md) | GCP BigQuery and Azure Synapse |
| [Multi-Region](deployment/multi-region.md) | High availability setup |
| [Pre-Deployment Checklist](deployment/pre-deployment-checklist.md) | Verification before deploy |
| [Quick Reference](deployment/quick-reference.md) | Common commands cheatsheet |
| [CI/CD Automation](deployment/automation.md) | GitHub Actions setup |
| [Troubleshooting](deployment/troubleshooting.md) | Debugging deployment issues |

### Configuration

| Guide | Description |
|-------|-------------|
| [Detection Rules](configuration/detection-rules.md) | Writing Sigma detection rules |
| [Alert Routing](configuration/alert-routing.md) | Slack, PagerDuty, Jira, Email setup |
| [LLM Providers](configuration/llm-configuration.md) | Claude, GPT-4, Gemini, Bedrock |
| [Log Sources](configuration/log-sources.md) | CloudTrail, VPC Flow, etc. |
| [Collector Secrets](configuration/collector-secrets.md) | API keys and credentials |

### Operations

| Guide | Description |
|-------|-------------|
| [Runbook](operations/runbook.md) | Day-to-day operational procedures |
| [Scaling](operations/scaling.md) | Performance tuning and scaling |

### Reference

| Document | Description |
|----------|-------------|
| [API Reference](api/api-reference.md) | REST API endpoints |
| [Architecture](architecture/architecture.md) | System design overview |
| [System Integration](architecture/system-integration.md) | Component interactions |

### Development

| Guide | Description |
|-------|-------------|
| [Local Setup](development/local-setup.md) | Development environment |
| [Testing](development/testing.md) | Running and writing tests |
| [Contributing](development/contributing.md) | Code contribution guide |
| [CI/CD](development/cicd.md) | Pipeline configuration |

---

## Key Features

### Natural Language Queries
Ask questions in plain English instead of writing SQL:
- *"Show me failed login attempts in the last 24 hours"*
- *"Which users created new IAM roles this week?"*
- *"List S3 buckets with public access"*

### 591 Detection Rules
Pre-built Sigma rules for AWS, GCP, Azure, Okta, GitHub, and more. Rules auto-convert to cloud-specific SQL.

### Multi-Cloud Support
- **AWS**: Lambda + Athena + S3
- **GCP**: Cloud Functions + BigQuery + GCS
- **Azure**: Functions + Synapse + Blob Storage

### Smart Alerting
Route alerts to Slack, PagerDuty, Jira, Email, ServiceNow, or Teams with automatic PII redaction.

### Context Enrichment
- IP Geolocation (MaxMind GeoIP2)
- Threat Intelligence (VirusTotal, AbuseIPDB)
- User Context (Google Workspace, Azure AD, Okta)
- Asset Inventory (AWS, Azure, GCP native)

---

## Cost Estimate

| Component | Monthly Cost |
|-----------|-------------|
| S3 Storage (1TB/day) | ~$700 |
| Athena Queries | ~$760 |
| Lambda | ~$200 |
| DynamoDB | ~$50 |
| LLM API | ~$250 |
| **Total** | **~$23,500/year** |

*Compare to traditional SIEM: $150,000-$300,000/year*

---

## Support

- [GitHub Issues](https://github.com/anthropics/claude-code/issues)
- [Troubleshooting Guide](deployment/troubleshooting.md)
