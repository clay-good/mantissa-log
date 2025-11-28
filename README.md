# Mantissa Log

**"Separate the Signal from the Noise"**

## Overview

Mantissa Log is an open source SIEM toolkit that democratizes enterprise security monitoring. Built on cloud-native primitives, it provides powerful log analysis, detection engineering, and alerting capabilities at a fraction of the cost of commercial SIEM solutions.

### Why "Mantissa Log"?

In mathematics, the **mantissa** is the part of a logarithm that contains the significant digits - the actual value separate from magnitude. Similarly, Mantissa Log extracts the significant security insights from massive volumes of raw log data stored in cheap cloud storage. The name captures our core mission: finding precision and value in the noise.

### The Problem

Modern SIEMs like Datadog and Splunk charge $150,000+ annually for what are fundamentally simple systems: log storage, query engines, parsers, and alerting logic. Cloud providers offer all these primitives at commodity prices, but teams don't realize they can assemble them without paying enterprise SIEM vendors.

### The Solution

Mantissa Log exposes this truth by providing everything needed to build a modern, powerful SIEM using cloud-native services. A team can achieve equivalent functionality for approximately $30,000 annually using thoughtfully assembled AWS services.

## Key Features

- **Cost-Effective**: Build enterprise SIEM capabilities at 20% of traditional vendor costs
- **Cloud-Native**: Leverage AWS services (S3, Athena, Lambda, Glue) for scalability and reliability
- **Natural Language Queries**: Use LLMs to translate plain English into SQL queries against your logs
- **Detection Engineering**: Write detection rules in simple YAML format with built-in rule library
- **Flexible Alerting**: Route alerts to Slack, PagerDuty, email, Jira, Teams, or custom webhooks
- **Transparent & Auditable**: Fully open source - understand and customize every component
- **Multi-Cloud Ready**: Architecture designed for future GCP and Azure support

## Architecture

Mantissa Log uses a layered architecture:

1. **Storage Layer**: S3 data lake with intelligent partitioning and lifecycle policies
2. **Catalog Layer**: AWS Glue for schema management and data discovery
3. **Query Layer**: AWS Athena for SQL analytics over petabyte-scale data
4. **Detection Layer**: Scheduled Lambda functions executing YAML-defined detection rules
5. **LLM Layer**: Natural language to SQL translation for ad-hoc investigations
6. **Alert Layer**: Multi-channel notification routing with enrichment and deduplication
7. **Web Interface**: React-based UI for queries, rule management, and alert dashboards

See [docs/architecture.md](docs/architecture.md) for detailed architecture diagrams and data flow.

## Target Users

- Security teams at startups and mid-size companies who cannot afford enterprise SIEM pricing
- Detection engineers who want to prototype without worrying about ingestion costs
- Security practitioners who value transparency and want to understand their tools
- Organizations seeking to eliminate vendor lock-in for security data

## Quick Start

```bash
# Clone the repository
git clone https://github.com/clay-good/mantissa-log.git
cd mantissa-log

# Set up development environment
./scripts/setup-dev.sh

# Deploy to AWS (requires AWS CLI configured)
cd infrastructure/aws/terraform
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars
```

For detailed deployment instructions, see [docs/getting-started.md](docs/getting-started.md).

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [Architecture Overview](docs/architecture.md)
- [AWS Deployment Guide](docs/deployment/aws-deployment.md)
- [Writing Detection Rules](docs/configuration/detection-rules.md)
- [Alert Routing Configuration](docs/configuration/alert-routing.md)
- [API Reference](docs/api/api-reference.md)
- [Development Guide](docs/development/local-setup.md)

