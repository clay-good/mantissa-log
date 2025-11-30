# Collector Secrets Configuration

All SaaS and cloud platform collectors require credentials stored in AWS Secrets Manager.

## Secret Format

Each collector expects a JSON secret with specific fields. Create secrets using:

```bash
aws secretsmanager create-secret \
  --name <secret-path> \
  --secret-string '<json>'
```

## Required Secrets

### Azure Monitor

**Secret Path:** `mantissa/azure/credentials`

**Description:** Azure Monitor API credentials

**Required Fields:**
```json
{
  "client_id": "...",
  "client_secret": "...",
  "tenant_id": "...",
  "subscription_id": "...",
  "workspace_id": "..."
}
```

### Crowdstrike

**Secret Path:** `mantissa/crowdstrike/credentials`

**Description:** CrowdStrike Falcon API credentials

**Required Fields:**
```json
{
  "client_id": "...",
  "client_secret": "...",
  "cloud": "..."
}
```

### Docker

**Secret Path:** `mantissa/docker/credentials`

**Description:** Docker API endpoint and credentials

**Required Fields:**
```json
{
  "endpoint": "...",
  "tls_cert": "...",
  "hostname": "..."
}
```

### Duo

**Secret Path:** `mantissa/duo/credentials`

**Description:** Duo Security Admin API credentials

**Required Fields:**
```json
{
  "integration_key": "...",
  "secret_key": "...",
  "api_hostname": "..."
}
```

### Gcp Logging

**Secret Path:** `mantissa/gcp/credentials`

**Description:** GCP Cloud Logging API credentials

**Required Fields:**
```json
{
  "service_account_json": "...",
  "project_id": "..."
}
```

### Github

**Secret Path:** `mantissa/github/credentials`

**Description:** GitHub Enterprise API credentials

**Required Fields:**
```json
{
  "api_token": "...",
  "org": "...",
  "enterprise_url": "..."
}
```

### Google Workspace

**Secret Path:** `mantissa/google-workspace/credentials`

**Description:** Google Workspace API credentials

**Required Fields:**
```json
{
  "service_account_json": "...",
  "customer_id": "...",
  "delegated_admin_email": "..."
}
```

### Jamf

**Secret Path:** `mantissa/jamf/credentials`

**Description:** Jamf Pro API credentials

**Required Fields:**
```json
{
  "url": "...",
  "username": "...",
  "password": "..."
}
```

### Kubernetes

**Secret Path:** `mantissa/kubernetes/credentials`

**Description:** Kubernetes API credentials

**Required Fields:**
```json
{
  "api_server": "...",
  "token": "...",
  "ca_cert": "...",
  "cluster_name": "..."
}
```

### Microsoft365

**Secret Path:** `mantissa/microsoft365/credentials`

**Description:** Microsoft 365 Azure AD app credentials

**Required Fields:**
```json
{
  "client_id": "...",
  "client_secret": "...",
  "tenant_id": "..."
}
```

### Onepassword

**Secret Path:** `mantissa/onepassword/credentials`

**Description:** 1Password Events API token

**Required Fields:**
```json
{
  "api_token": "..."
}
```

### Salesforce

**Secret Path:** `mantissa/salesforce/credentials`

**Description:** Salesforce API credentials

**Required Fields:**
```json
{
  "username": "...",
  "password": "...",
  "security_token": "...",
  "client_id": "...",
  "client_secret": "...",
  "instance_url": "..."
}
```

### Slack

**Secret Path:** `mantissa/slack/credentials`

**Description:** Slack Enterprise Grid API token

**Required Fields:**
```json
{
  "api_token": "..."
}
```

### Snowflake

**Secret Path:** `mantissa/snowflake/credentials`

**Description:** Snowflake API credentials

**Required Fields:**
```json
{
  "account": "...",
  "username": "...",
  "password": "...",
  "warehouse": "...",
  "database": "...",
  "role": "..."
}
```


## Example: Creating Okta Secret

```bash
aws secretsmanager create-secret \
  --name mantissa/okta/credentials \
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
