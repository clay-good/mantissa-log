# Mantissa Log Documentation

## Quick Links

- [Getting Started](getting-started.md)
- [Architecture Overview](architecture/architecture.md)
- [AWS Deployment](deployment/aws-deployment.md)
- [Detection Rules](configuration/detection-rules.md)
- [Alert Routing](configuration/alert-routing.md)
- [Operations Runbook](operations/runbook.md)

## Documentation Structure

```
docs/
├── getting-started.md          # Quick start guide
├── architecture/               # System design
├── deployment/                 # Cloud deployment guides
├── configuration/              # Component configuration
├── features/                   # Feature documentation
├── operations/                 # Runbooks and scaling
├── development/                # Contributing and testing
├── tutorials/                  # Step-by-step guides
└── api/                        # API reference
```

## By Topic

**Deployment**
- [AWS Deployment](deployment/aws-deployment.md)
- [Multi-Cloud](deployment/multi-cloud.md)
- [Pre-Deployment Checklist](deployment/pre-deployment-checklist.md)
- [Troubleshooting](deployment/troubleshooting.md)

**Configuration**
- [Detection Rules](configuration/detection-rules.md)
- [Alert Routing](configuration/alert-routing.md)
- [LLM Providers](configuration/llm-configuration.md)
- [Collector Secrets](configuration/collector-secrets.md)
- [Log Sources](configuration/log-sources.md)

**Features**
- [Natural Language Queries](features/conversational-context.md)
- [Sigma Rules](features/sigma-rules.md)
- [PII/PHI Redaction](features/pii-phi-redaction.md)
- [Cost Projection](features/cost-projection.md)
- [Integration Wizards](features/integration-wizards.md)

**Development**
- [Local Setup](development/local-setup.md)
- [Testing](development/testing.md)
- [Contributing](development/contributing.md)
- [CI/CD](development/cicd.md)
