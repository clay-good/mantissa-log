# SOAR Playbooks

This directory contains Security Orchestration, Automation, and Response (SOAR) playbooks that define automated workflows for responding to security incidents.

## Directory Structure

```
playbooks/
├── README.md                    # This file
├── {playbook_id}.yml           # Current version of each playbook
├── versions/
│   └── {playbook_id}/
│       ├── 1.0.0.yml           # Version history
│       └── 1.1.0.yml
└── archive/
    └── {playbook_id}.yml       # Deleted playbooks
```

## Playbook YAML Format

```yaml
# Unique identifier (UUID recommended)
id: "pb-credential-compromise-001"

# Human-readable name
name: "Credential Compromise Response"

# Detailed description
description: |
  Automated response playbook for handling credential compromise alerts.
  Terminates active sessions, forces password reset, and notifies security team.

# Semantic version
version: "1.0.0"

# Author information
author: "Security Team"

# Timestamps (ISO 8601)
created: "2025-01-27T00:00:00Z"
modified: "2025-01-27T00:00:00Z"

# Whether this playbook is active
enabled: true

# Tags for categorization
tags:
  - credential
  - identity
  - itdr
  - automated

# Trigger configuration
trigger:
  trigger_type: alert  # alert, manual, scheduled, webhook
  conditions:
    severity:
      - high
      - critical
    rule_patterns:
      - "*credential*"
      - "*brute_force*"
      - "*impossible_travel*"
    tags:
      - identity

# Playbook steps
steps:
  - id: step_1
    name: "Terminate Active Sessions"
    action_type: terminate_sessions
    provider: okta  # or "auto" to detect from alert
    parameters:
      user_email: "{{ alert.metadata.user_email }}"
      reason: "Security incident - credential compromise"
    on_success: step_2
    on_failure: step_error

  - id: step_2
    name: "Force Password Reset"
    action_type: force_password_reset
    provider: auto
    parameters:
      user_email: "{{ alert.metadata.user_email }}"
    requires_approval: true
    approval_roles:
      - security_analyst
      - security_manager
    on_success: step_3
    on_failure: step_error

  - id: step_3
    name: "Create Incident Ticket"
    action_type: create_ticket
    provider: jira
    parameters:
      project: "SEC"
      issue_type: "Incident"
      summary: "Credential Compromise - {{ alert.metadata.user_email }}"
      description: |
        Alert: {{ alert.title }}
        User: {{ alert.metadata.user_email }}
        Source IP: {{ alert.metadata.source_ip }}
        Time: {{ alert.timestamp }}
      priority: "High"
    on_success: step_4

  - id: step_4
    name: "Notify Security Team"
    action_type: notify
    provider: slack
    parameters:
      channel: "#security-alerts"
      message: |
        :warning: *Credential Compromise Response Executed*
        User: {{ alert.metadata.user_email }}
        Actions taken:
        - Sessions terminated
        - Password reset initiated
        - Ticket created: {{ steps.step_3.output.ticket_id }}

  - id: step_error
    name: "Notify on Error"
    action_type: notify
    provider: slack
    parameters:
      channel: "#security-alerts"
      message: |
        :x: *Playbook Error*
        Playbook: Credential Compromise Response
        Error: {{ error }}
```

## Action Types

### Identity Actions

| Action Type | Description | Required Parameters |
|-------------|-------------|---------------------|
| `terminate_sessions` | End user sessions | `user_email` or `user_id` |
| `disable_account` | Disable user account | `user_email` or `user_id` |
| `enable_account` | Re-enable user account | `user_email` or `user_id` |
| `force_password_reset` | Require password change | `user_email` or `user_id` |
| `revoke_tokens` | Revoke OAuth/API tokens | `user_email` or `user_id` |

### Network Actions

| Action Type | Description | Required Parameters |
|-------------|-------------|---------------------|
| `block_ip` | Block IP address | `ip_address`, `duration` (optional) |
| `unblock_ip` | Remove IP block | `ip_address` |
| `isolate_host` | Network isolation | `host_id` or `hostname` |
| `unisolate_host` | Remove isolation | `host_id` or `hostname` |

### Notification Actions

| Action Type | Description | Required Parameters |
|-------------|-------------|---------------------|
| `notify` | Send notification | `channel` or `email`, `message` |
| `create_ticket` | Create ticket | `project`, `summary`, `description` |

### Investigation Actions

| Action Type | Description | Required Parameters |
|-------------|-------------|---------------------|
| `run_query` | Execute query | `query` or `query_template` |
| `webhook` | Call external API | `url`, `method`, `body` |
| `custom` | Custom Lambda code | `lambda_arn` or inline `code` |

## Jinja2 Template Syntax

Playbook parameters support Jinja2 templates for dynamic values:

### Available Context Variables

```jinja2
{# Alert data #}
{{ alert.id }}
{{ alert.rule_id }}
{{ alert.rule_name }}
{{ alert.severity }}
{{ alert.title }}
{{ alert.description }}
{{ alert.timestamp }}
{{ alert.tags }}

{# Alert metadata (varies by alert type) #}
{{ alert.metadata.user_email }}
{{ alert.metadata.user_id }}
{{ alert.metadata.source_ip }}
{{ alert.metadata.destination_ip }}
{{ alert.metadata.hostname }}

{# Previous step outputs #}
{{ steps.step_1.output.session_count }}
{{ steps.step_2.output.success }}
{{ steps.step_3.output.ticket_id }}

{# Execution context #}
{{ execution.id }}
{{ execution.started_at }}
{{ execution.trigger_type }}

{# Error information (in error handlers) #}
{{ error }}
{{ failed_step }}
```

### Conditional Logic

```jinja2
{# Simple conditionals #}
{% if alert.severity == 'critical' %}
channel: "#security-critical"
{% else %}
channel: "#security-alerts"
{% endif %}

{# Default values #}
{{ alert.metadata.user_email | default('unknown') }}

{# Filters #}
{{ alert.title | upper }}
{{ alert.metadata.source_ip | default('N/A') }}
```

## Trigger Types

### Alert Trigger

Automatically executed when matching alerts are generated:

```yaml
trigger:
  trigger_type: alert
  conditions:
    severity:
      - high
      - critical
    rule_patterns:
      - "*brute_force*"
      - "aws-*-suspicious*"
    tags:
      - identity
      - credential
```

### Manual Trigger

Executed manually by users:

```yaml
trigger:
  trigger_type: manual
  conditions: {}
```

### Scheduled Trigger

Executed on a schedule:

```yaml
trigger:
  trigger_type: scheduled
  conditions:
    schedule: "rate(1 hour)"  # or "cron(0 * * * ? *)"
```

### Webhook Trigger

Executed via external webhook:

```yaml
trigger:
  trigger_type: webhook
  conditions:
    secret: "${WEBHOOK_SECRET}"  # Environment variable reference
```

## Approval Workflow

Steps with `requires_approval: true` pause execution until approved:

```yaml
steps:
  - id: dangerous_step
    name: "Disable Account"
    action_type: disable_account
    requires_approval: true
    approval_roles:
      - security_analyst
      - security_manager
    timeout_seconds: 3600  # 1 hour timeout for approval
```

Approvers receive a notification with:
- Action details
- Alert context
- Approve/Deny buttons
- Expiration time

## Version Naming

Use semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes to step IDs or flow
- **MINOR**: New steps or features
- **PATCH**: Bug fixes or parameter changes

Example: `1.2.3`

## Creating a New Playbook

1. Copy an existing playbook as a template
2. Generate a unique ID: `pb-{category}-{name}-{number}`
3. Define steps with unique IDs
4. Set appropriate triggers
5. Mark dangerous actions with `requires_approval: true`
6. Test with dry run: `mantissa playbook run --dry-run {playbook_id}`
7. Deploy: `mantissa playbook deploy {playbook_id}`

## Best Practices

1. **Always include error handling**: Add a `step_error` for notification
2. **Use approval for dangerous actions**: `disable_account`, `block_ip`, etc.
3. **Keep playbooks focused**: One incident type per playbook
4. **Document parameters**: Use clear, descriptive names
5. **Test before deploying**: Use dry run mode
6. **Version incrementally**: Don't skip versions
7. **Tag appropriately**: Helps with filtering and auditing

## Provider Configuration

Providers are configured in the main Mantissa configuration:

```yaml
# mantissa.yml
soar:
  providers:
    okta:
      api_token: "${OKTA_API_TOKEN}"
      domain: "${OKTA_DOMAIN}"
    crowdstrike:
      client_id: "${CS_CLIENT_ID}"
      client_secret: "${CS_CLIENT_SECRET}"
    jira:
      url: "${JIRA_URL}"
      username: "${JIRA_USERNAME}"
      api_token: "${JIRA_API_TOKEN}"
    slack:
      webhook_url: "${SLACK_WEBHOOK_URL}"
```
