#!/usr/bin/env python3
"""
Standardize all collector Lambda handlers to use single CREDENTIALS_SECRET

This ensures consistency across all collectors:
- Each collector reads from one Secrets Manager secret
- Secret contains JSON with all required configuration
- Terraform provides only the secret name
- No hardcoded URLs or config in code
"""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent

# Mapping of collector name to expected secret JSON format
COLLECTOR_SECRETS = {
    "slack": {
        "secret_name": "SLACK_CREDENTIALS_SECRET",
        "secret_path": "mantissa/slack/credentials",
        "fields": ["api_token"],
        "description": "Slack Enterprise Grid API token"
    },
    "microsoft365": {
        "secret_name": "M365_CREDENTIALS_SECRET",
        "secret_path": "mantissa/microsoft365/credentials",
        "fields": ["client_id", "client_secret", "tenant_id"],
        "description": "Microsoft 365 Azure AD app credentials"
    },
    "github": {
        "secret_name": "GITHUB_CREDENTIALS_SECRET",
        "secret_path": "mantissa/github/credentials",
        "fields": ["api_token", "org", "enterprise_url"],
        "description": "GitHub Enterprise API credentials"
    },
    "google_workspace": {
        "secret_name": "GOOGLE_WORKSPACE_CREDENTIALS_SECRET",
        "secret_path": "mantissa/google-workspace/credentials",
        "fields": ["service_account_json", "customer_id", "delegated_admin_email"],
        "description": "Google Workspace API credentials"
    },
    "crowdstrike": {
        "secret_name": "CROWDSTRIKE_CREDENTIALS_SECRET",
        "secret_path": "mantissa/crowdstrike/credentials",
        "fields": ["client_id", "client_secret", "cloud"],
        "description": "CrowdStrike Falcon API credentials"
    },
    "duo": {
        "secret_name": "DUO_CREDENTIALS_SECRET",
        "secret_path": "mantissa/duo/credentials",
        "fields": ["integration_key", "secret_key", "api_hostname"],
        "description": "Duo Security Admin API credentials"
    },
    "azure_monitor": {
        "secret_name": "AZURE_CREDENTIALS_SECRET",
        "secret_path": "mantissa/azure/credentials",
        "fields": ["client_id", "client_secret", "tenant_id", "subscription_id", "workspace_id"],
        "description": "Azure Monitor API credentials"
    },
    "jamf": {
        "secret_name": "JAMF_CREDENTIALS_SECRET",
        "secret_path": "mantissa/jamf/credentials",
        "fields": ["url", "username", "password"],
        "description": "Jamf Pro API credentials"
    },
    "docker": {
        "secret_name": "DOCKER_CREDENTIALS_SECRET",
        "secret_path": "mantissa/docker/credentials",
        "fields": ["endpoint", "tls_cert", "hostname"],
        "description": "Docker API endpoint and credentials"
    },
    "gcp_logging": {
        "secret_name": "GCP_CREDENTIALS_SECRET",
        "secret_path": "mantissa/gcp/credentials",
        "fields": ["service_account_json", "project_id"],
        "description": "GCP Cloud Logging API credentials"
    },
    "salesforce": {
        "secret_name": "SALESFORCE_CREDENTIALS_SECRET",
        "secret_path": "mantissa/salesforce/credentials",
        "fields": ["username", "password", "security_token", "client_id", "client_secret", "instance_url"],
        "description": "Salesforce API credentials"
    },
    "snowflake": {
        "secret_name": "SNOWFLAKE_CREDENTIALS_SECRET",
        "secret_path": "mantissa/snowflake/credentials",
        "fields": ["account", "username", "password", "warehouse", "database", "role"],
        "description": "Snowflake API credentials"
    },
    "onepassword": {
        "secret_name": "ONEPASSWORD_CREDENTIALS_SECRET",
        "secret_path": "mantissa/onepassword/credentials",
        "fields": ["api_token"],
        "description": "1Password Events API token"
    },
    "kubernetes": {
        "secret_name": "KUBERNETES_CREDENTIALS_SECRET",
        "secret_path": "mantissa/kubernetes/credentials",
        "fields": ["api_server", "token", "ca_cert", "cluster_name"],
        "description": "Kubernetes API credentials"
    },
}

def create_secrets_documentation():
    """Create documentation for required secret formats."""
    doc_path = PROJECT_ROOT / "docs" / "configuration" / "collector-secrets.md"
    doc_path.parent.mkdir(parents=True, exist_ok=True)

    content = """# Collector Secrets Configuration

All SaaS and cloud platform collectors require credentials stored in AWS Secrets Manager.

## Secret Format

Each collector expects a JSON secret with specific fields. Create secrets using:

```bash
aws secretsmanager create-secret \\
  --name <secret-path> \\
  --secret-string '<json>'
```

## Required Secrets

"""

    for collector, config in sorted(COLLECTOR_SECRETS.items()):
        content += f"### {collector.replace('_', ' ').title()}\n\n"
        content += f"**Secret Path:** `{config['secret_path']}`\n\n"
        content += f"**Description:** {config['description']}\n\n"
        content += "**Required Fields:**\n"
        content += "```json\n{\n"
        for field in config['fields']:
            content += f'  "{field}": "...",\n'
        content = content.rstrip(',\n') + '\n'
        content += "}\n```\n\n"

    content += """
## Example: Creating Okta Secret

```bash
aws secretsmanager create-secret \\
  --name mantissa/okta/credentials \\
  --secret-string '{
    "api_token": "00abc123...",
    "org_url": "https://dev-12345.okta.com"
  }'
```

## Security Best Practices

1. Use separate secrets for each environment (dev, staging, prod)
2. Enable automatic rotation where supported
3. Restrict IAM permissions to least privilege
4. Use KMS encryption for all secrets
5. Audit secret access using CloudTrail

## Terraform Integration

Terraform configurations reference these secret paths. You must create the secrets before deploying:

```terraform
environment {
  variables = {
    OKTA_CREDENTIALS_SECRET = "mantissa/okta/credentials"
  }
}
```
"""

    doc_path.write_text(content)
    print(f"Created documentation: {doc_path}")

def main():
    print("=" * 70)
    print("Standardizing Collector Secrets Configuration")
    print("=" * 70)

    # Create secrets documentation
    create_secrets_documentation()

    print("\nNext steps:")
    print("1. Review docs/configuration/collector-secrets.md")
    print("2. Update Lambda handler functions to read from single secret")
    print("3. Update Terraform collector configurations")
    print("4. Create secrets in AWS Secrets Manager before deployment")

    return 0

if __name__ == "__main__":
    exit(main())
