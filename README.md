# Mantissa Log

**"Separate the Signal from the Noise"**

Open source, cloud-native SIEM with LLM-powered intelligence. Free forever.

## Overview

Mantissa Log is an open source SIEM toolkit that democratizes enterprise security monitoring. Built on cloud-native primitives with LLM-powered analysis, it provides powerful log analysis, detection engineering, and intelligent alerting at a fraction of the cost of commercial SIEM solutions.

### The Problem

Modern SIEMs like Splunk and Datadog charge $150,000+ annually for fundamentally simple systems: log storage, query engines, parsers, and alerting logic. Cloud providers offer all these primitives at commodity prices, but teams don't realize they can assemble them without paying enterprise vendors.

### The Solution

Mantissa Log provides everything needed to build a modern, intelligent SIEM using cloud-native services. A team can achieve equivalent functionality for approximately $30,000 annually using AWS, GCP, or Azure services assembled thoughtfully - with AI-powered features that commercial SIEMs don't offer.

In mathematics, the **mantissa** is the part of a logarithm that contains the significant digits - the actual value separate from magnitude. The "exponent" represents massive volumes of raw log data. The "mantissa" represents the significant findings extracted from that noise.

Mantissa Log takes enormous quantities of raw data and uses AI to extract what's actually significant. The name captures our core mission: finding precision and value in the noise.

## Key Features

### Multi-Cloud Support
- **AWS**: Athena, S3, Lambda, Glue, EventBridge
- **GCP**: BigQuery, Cloud Storage, Cloud Functions
- **Azure**: Synapse Analytics, Blob Storage, Azure Functions
- Deploy to any cloud with the same detection rules

### Sigma Detection Rules
- **Industry-standard format**: Write rules once, run anywhere
- **90+ pre-built rules** covering MITRE ATT&CK techniques
- **Multi-cloud portability**: Sigma rules auto-convert to Athena SQL, BigQuery, or Synapse T-SQL
- **Community rules**: Import from SigmaHQ repository (2000+ rules)

### LLM-Powered Intelligence

Mantissa Log uses LLMs in three ways:

1. **Natural Language Queries**: Ask questions about your logs in plain English
   - "Show me all failed login attempts from outside the US in the last 24 hours"
   - System generates SQL, executes, and returns results
   - Supports follow-up questions with conversational context

2. **LLM-Enriched Alerts**: When a detection fires, the alert is enriched with:
   - 5W1H Summary (Who, What, When, Where, Why, How)
   - Behavioral Context (is this normal for this user/entity?)
   - Baseline Deviation Analysis (statistical comparison to 30-day history)
   - Detection Explainer (why this rule matters, MITRE ATT&CK mapping)
   - Recommended Actions (investigation and remediation steps)

3. **Self-Learning Detection Engineer** (Coming Soon):
   - Weekly analysis of detection rule performance
   - HIGH CONFIDENCE tuning suggestions via Jira tickets
   - Learns from ticket resolution to improve future recommendations

### Cloud-Native + SaaS Log Sources

Supported data sources:

| Category | Sources |
|----------|---------|
| **Cloud Providers** | AWS CloudTrail, VPC Flow Logs, GuardDuty, GCP Audit Logs, Azure Activity Logs |
| **Identity** | Okta, Google Workspace, Microsoft 365 / Azure AD, Duo Security |
| **Endpoints** | CrowdStrike Falcon, Jamf Pro |
| **Collaboration** | Slack Audit Logs, Microsoft Teams |
| **Data** | Snowflake, Salesforce |
| **DevOps** | GitHub Enterprise, GitLab, Kubernetes Audit Logs |
| **Containers** | Docker, containerd |

### Bring Your Own LLM Keys

Configure your preferred LLM provider in Settings:
- **Anthropic Claude**: claude-3-5-sonnet, claude-3-opus, claude-3-haiku
- **OpenAI GPT**: gpt-4-turbo, gpt-4, gpt-3.5-turbo
- **Google Gemini**: gemini-1.5-pro, gemini-1.5-flash
- **AWS Bedrock**: Claude models via IAM role (no API key needed)

API keys stored securely in AWS Secrets Manager with KMS encryption.

### Alert Routing

Route enriched alerts to external systems:
- **Slack**: Webhook integration with channel routing
- **Jira**: Auto-create tickets with priority mapping
- **PagerDuty**: Events API v2 integration
- **Email**: SMTP or SES
- **Custom Webhooks**: Any HTTP endpoint

### PII/PHI Redaction

Automatic redaction of sensitive data before sending to external systems:
- Email addresses, phone numbers, SSNs, credit cards
- IP addresses, AWS access keys
- Custom regex patterns
- Full raw logs preserved in storage for authorized queries

### Cost Projection

Before creating a scheduled detection, see projected monthly costs:
- Athena query costs based on data scanned
- Lambda execution costs
- DynamoDB state storage costs
- Historical comparison and optimization suggestions

## Architecture

```
                    +------------------+
                    |   Web Interface  |
                    |   (React + Vite) |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   API Gateway    |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
+--------v--------+ +--------v--------+ +--------v--------+
|  LLM Query      | |  Detection      | |  Alert Router   |
|  Handler        | |  Engine         | |  + Enrichment   |
|                 | |                 | |                 |
| - NL to SQL     | | - Sigma Rules   | | - LLM Enricher  |
| - Conversation  | | - Multi-Cloud   | | - PII Redaction |
| - Cost Estimate | | - Scheduling    | | - Integrations  |
+-----------------+ +-----------------+ +-----------------+
         |                   |                   |
         +-------------------+-------------------+
                             |
              +--------------v--------------+
              |        Query Executor       |
              |  (Athena / BigQuery / Synapse)
              +--------------+--------------+
                             |
              +--------------v--------------+
              |     Data Lake (S3 / GCS)    |
              |   Partitioned by date/hour  |
              +-----------------------------+
```

## What Mantissa Log Is NOT

Mantissa Log is intentionally focused. It does NOT include:

- **Dashboards or Reports**: Use scheduled NL queries to Slack instead
- **Case Management**: Alerts create tickets in Jira/ServiceNow; manage cases there
- **SOAR/Remediation**: No automated blocking or policy changes (use dedicated SOAR tools)
- **Threat Intelligence Platform**: Integrate with existing TI sources via log ingestion
- **On-Prem Log Sources**: Focus on cloud-native + SaaS only

## Quick Start

### Prerequisites

**Required:**
- AWS account with administrator access
- Terraform >= 1.5
- Python 3.11+
- AWS CLI v2
- Node.js >= 18

**Optional:**
- LLM API keys (Anthropic, OpenAI, or Google - if not using AWS Bedrock)

### Deployment (Automated)

The fastest way to deploy Mantissa Log:

```bash
# Clone the repository
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log

# Run the deployment script
bash scripts/deploy.sh
```

The script will:
1. Check prerequisites
2. Prompt for configuration (environment, region, LLM provider)
3. Create Terraform state bucket
4. Package Lambda functions
5. Deploy infrastructure with Terraform
6. Configure CloudTrail logging
7. Create admin user for web interface
8. Run smoke tests
9. Deploy web application to CloudFront
10. Display deployment summary with URLs

**Deployment time:** 10-15 minutes

### Manual Deployment

For more control over the deployment process:

```bash
# 1. Deploy infrastructure
cd infrastructure/aws/terraform
cp backend.tf.example backend.tf
# Edit backend.tf with your S3 bucket

cp environments/dev.tfvars.example environments/dev.tfvars
# Edit dev.tfvars with your configuration

terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars

# Save outputs
terraform output -json > ../../../terraform-outputs.json

# 2. Package Lambda functions
cd ../../..
bash scripts/package-lambdas.sh

# 3. Deploy web interface
bash scripts/deploy-web.sh
```

See [AWS Deployment Guide](docs/deployment/aws-deployment.md) for detailed instructions.

### First Steps

After deployment completes:

1. **Access Web Interface**: Open the CloudFront URL from deployment output
2. **Log In**: Use the admin credentials you created during deployment
3. **Configure LLM Provider**: Settings > LLM Configuration
   - If using AWS Bedrock: No additional setup needed
   - If using Anthropic/OpenAI/Google: Add your API key
4. **Set Up Integrations**: Settings > Integrations
   - Configure Slack webhook for alerts
   - Set up Jira for ticketing (optional)
   - Add PagerDuty integration (optional)
5. **Enable Detection Rules**: Rules > Browse pre-built rules > Enable
6. **Try a Natural Language Query**:
   - "Show me all root account logins in the last 7 days"
   - "Find failed authentication attempts from outside the US"
   - "List all S3 buckets created in the past 24 hours"

### Verify Deployment

Run smoke tests to verify everything is working:

```bash
bash scripts/smoke-test.sh terraform-outputs.json
```

Expected output:
```
Tests Passed: 18
Tests Failed: 0

All smoke tests passed!
```

## Detection Rule Coverage

Mantissa Log includes 90+ Sigma rules covering:

| MITRE Tactic | Coverage |
|--------------|----------|
| Initial Access | Brute force, SSO abuse, SAML attacks |
| Execution | Lambda/Cloud Functions, container exec |
| Persistence | IAM backdoors, login profile creation |
| Privilege Escalation | AssumeRole abuse, role modification |
| Defense Evasion | CloudTrail/GuardDuty/Config disabled |
| Credential Access | Key creation, credential exposure |
| Discovery | Bucket enumeration, secrets listing |
| Lateral Movement | Cross-account access, VPN tunneling |
| Collection | Data export, snapshot exfiltration |
| Exfiltration | S3 data transfer, unusual outbound ports |
| Impact | Encryption disabled, ransomware indicators |

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [Architecture Overview](docs/architecture.md)
- [AWS Deployment](docs/deployment/aws-deployment.md)
- [GCP Deployment](docs/deployment/gcp-deployment.md)
- [Azure Deployment](docs/deployment/azure-deployment.md)
- [Writing Sigma Rules](docs/configuration/sigma-rules.md)
- [Alert Routing](docs/configuration/alert-routing.md)
- [LLM Configuration](docs/configuration/llm-configuration.md)
- [API Reference](docs/api/api-reference.md)
- [Contributing Guide](docs/development/contributing.md)

## Project Structure

```
mantissa-log/
├── infrastructure/
│   ├── aws/terraform/       # AWS deployment
│   ├── gcp/terraform/       # GCP deployment
│   └── azure/terraform/     # Azure deployment
├── src/
│   ├── shared/              # Cross-cloud shared code
│   │   ├── alerts/          # Alert enrichment, routing
│   │   ├── detection/       # Sigma converter, executors
│   │   ├── llm/             # LLM providers, query generation
│   │   ├── parsers/         # Log parsers (CloudTrail, Okta, etc.)
│   │   └── redaction/       # PII/PHI redaction
│   ├── aws/                 # AWS-specific (Lambda handlers)
│   ├── gcp/                 # GCP-specific (Cloud Functions)
│   └── azure/               # Azure-specific (Azure Functions)
├── rules/
│   └── sigma/               # Sigma detection rules
│       ├── aws/             # AWS CloudTrail, VPC Flow
│       ├── gcp/             # GCP Audit, Workspace
│       ├── m365/            # Microsoft 365
│       └── kubernetes/      # Kubernetes audit logs
├── web/                     # React web interface
│   └── src/
│       ├── components/      # UI components
│       └── pages/           # Page views
├── tests/                   # Unit and integration tests
├── scripts/                 # Deployment and utility scripts
└── docs/                    # Documentation
```

## Target Users

- Security teams at startups and mid-size companies who cannot afford enterprise SIEM pricing
- Detection engineers who want to prototype without worrying about ingestion costs
- Security practitioners who value transparency and want to understand their tools
- Organizations seeking to eliminate vendor lock-in for security data
- Teams wanting AI-powered security analysis without the AI vendor markup
