# Detection Rules

647 pre-built Sigma detection rules and SOAR playbook definitions for Mantissa Log.

## Directory Structure

```
rules/
├── sigma/                    # 647 Sigma YAML detection rules
│   ├── aws/                  # AWS CloudTrail, GuardDuty rules
│   ├── azure/                # Azure Activity Log rules
│   ├── azure_monitor/        # Azure Monitor rules
│   ├── gcp/                  # GCP Audit Log rules
│   ├── gcp_logging/          # GCP Cloud Logging rules
│   ├── okta/                 # Okta identity rules
│   ├── google_workspace/     # Google Workspace rules
│   ├── microsoft365/         # Microsoft 365 rules
│   ├── m365/                 # Microsoft 365 (additional)
│   ├── duo/                  # Duo Security rules
│   ├── crowdstrike/          # CrowdStrike endpoint rules
│   ├── github/               # GitHub audit log rules
│   ├── kubernetes/           # Kubernetes audit log rules
│   ├── docker/               # Docker runtime rules
│   ├── slack/                # Slack audit log rules
│   ├── onepassword/          # 1Password rules
│   ├── salesforce/           # Salesforce rules
│   ├── jamf/                 # Jamf Pro rules
│   ├── common/               # Cross-source detection rules
│   └── apm/                  # APM/observability detection rules
├── playbooks/                # SOAR playbook definitions
└── examples/                 # Example rule templates
```

## Rule Format

Detection rules use the [Sigma](https://github.com/SigmaHQ/sigma) format. Mantissa Log automatically converts Sigma rules to cloud-specific SQL (Athena, BigQuery, or Synapse) at detection time.

```yaml
title: Brute Force Login Attempts
id: abc123-def456-...
status: stable
level: high
description: Detects multiple failed login attempts indicating brute force
logsource:
  product: okta
  service: authentication
detection:
  selection:
    outcome: FAILURE
  condition: selection | count() by user_email > 5
  timeframe: 10m
tags:
  - attack.credential_access
  - attack.t1110
falsepositives:
  - Users who legitimately forget passwords
```

## Rule Categories

| Category | Description |
|----------|-------------|
| Identity (ITDR) | Credential attacks, privilege escalation, session hijacking (49 rules) |
| AWS | CloudTrail, GuardDuty, VPC Flow Logs |
| Azure | Activity Logs, Azure Monitor |
| GCP | Audit Logs, Cloud Logging |
| SaaS | Okta, Google Workspace, M365, Slack, Salesforce, 1Password |
| Endpoints | CrowdStrike, Jamf |
| DevOps | GitHub, Kubernetes, Docker |
| APM | Latency spikes, error rates, anomalies |

## Testing Rules

```bash
# Validate all rules
python scripts/validate-rules.py

# Validate Sigma-specific rules
python scripts/validate-sigma-rules.py

# Test a single rule (dry run - print SQL)
python scripts/test-rule.py rules/sigma/okta/brute_force_login.yml --mode dry-run

# Test against Athena
python scripts/test-rule.py rules/sigma/okta/brute_force_login.yml \
  --mode test \
  --database mantissa_log \
  --output-location s3://your-bucket/athena-results/

# Backtest over historical data
python scripts/test-rule.py rules/sigma/okta/brute_force_login.yml \
  --mode backtest \
  --days-back 7
```

## Writing New Rules

Rules can be created in three ways:

1. **Natural language**: Ask the NL interface to create a rule from a description
2. **Sigma YAML**: Write a standard Sigma rule file manually
3. **Import**: Import existing rules from the SigmaHQ community repository

Place new rules in the appropriate source-type subdirectory under `rules/sigma/`.

## SOAR Playbooks

Playbooks define automated response actions triggered by alerts. See `playbooks/` for examples.

```yaml
id: playbook-cred-001
name: Credential Compromise Response
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
```
