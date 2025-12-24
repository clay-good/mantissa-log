"""LLM Prompts for IR Plan Parsing.

This module contains prompt templates for parsing Incident Response (IR) plans
into structured playbook actions using LLM assistance.
"""

# Main extraction prompt for parsing complete IR plans
IR_PLAN_EXTRACTION_PROMPT = """You are a security automation expert parsing an Incident Response (IR) plan into structured, executable actions.

## Available Action Types

| Action Type | Description | Required Parameters |
|------------|-------------|---------------------|
| terminate_sessions | End user sessions | user_email or user_id |
| disable_account | Disable user account | user_email or user_id |
| enable_account | Re-enable user account | user_email or user_id |
| force_password_reset | Require password change | user_email or user_id |
| revoke_tokens | Revoke OAuth/API tokens | user_email or user_id |
| block_ip | Block IP address | ip_address, duration (optional) |
| unblock_ip | Remove IP block | ip_address |
| isolate_host | Network isolation | host_id or hostname |
| unisolate_host | Remove isolation | host_id or hostname |
| notify | Send notification | channel or email, message |
| create_ticket | Create ticket | project, summary, description |
| run_query | Execute investigation query | query |
| webhook | Call external API | url, method, body |
| custom | Custom action | description |

## Dynamic Value Templates

Use Jinja2 templates for values that should come from the alert or context:
- {{ alert.metadata.user_email }} - User's email from alert
- {{ alert.metadata.source_ip }} - Source IP from alert
- {{ alert.metadata.hostname }} - Hostname from alert
- {{ alert.rule_name }} - Name of triggered rule
- {{ alert.severity }} - Alert severity
- {{ alert.title }} - Alert title

## Output Format

Return a JSON object with the following structure:
```json
{
  "name": "Playbook name derived from the plan",
  "description": "Brief description of what the playbook does",
  "steps": [
    {
      "id": "step_1",
      "name": "Human readable step name",
      "action_type": "one of the action types above",
      "provider": "auto or specific provider (okta, crowdstrike, jira, slack)",
      "parameters": {
        "param_name": "value or {{ template }}"
      },
      "requires_approval": true/false,
      "depends_on": ["step_id"] or null,
      "on_failure": "step_id for error handling or null"
    }
  ],
  "error_handler": {
    "id": "error_step",
    "name": "Error notification",
    "action_type": "notify",
    "parameters": {...}
  }
}
```

## Guidelines

1. Preserve the logical order of steps from the IR plan
2. Identify steps that should require human approval (account disabling, IP blocking)
3. Add notification steps for team awareness
4. Include error handling for critical actions
5. Use templates for dynamic values that come from the triggering alert
6. If a step is ambiguous, use "custom" action type with a description

## IR Plan to Parse

{plan_text}

## Response

Return only the JSON object, no additional text:"""


# Prompt for classifying a single action description
ACTION_CLASSIFICATION_PROMPT = """Classify this security response action into one of the available action types.

## Available Action Types
- terminate_sessions: End user sessions, log out users
- disable_account: Disable, deactivate, or suspend user accounts
- enable_account: Re-enable or reactivate user accounts
- force_password_reset: Force password change, reset credentials
- revoke_tokens: Revoke OAuth tokens, API keys, access tokens
- block_ip: Block IP address, firewall rule, ban IP
- unblock_ip: Unblock IP address, remove firewall rule
- isolate_host: Isolate host, quarantine machine, contain endpoint
- unisolate_host: Remove isolation, restore network access
- notify: Send notification, alert team, page on-call, email
- create_ticket: Create ticket, open incident, Jira, ServiceNow
- run_query: Run investigation query, search logs, investigate
- webhook: Call external API, webhook, HTTP request
- custom: Other actions that don't fit above categories

## Action Description
{action_description}

## Response Format
Return only the action type as a single word (e.g., "terminate_sessions"):"""


# Prompt for extracting parameters from action description
PARAMETER_EXTRACTION_PROMPT = """Extract structured parameters from this security action description.

## Action Type: {action_type}

## Expected Parameters for {action_type}:
{expected_params}

## Action Description
{action_description}

## Alert Context (use templates for dynamic values)
The action will be triggered by an alert. Use these Jinja2 templates for values that should come from the alert:
- {{ alert.metadata.user_email }} - User's email
- {{ alert.metadata.user_id }} - User's ID
- {{ alert.metadata.source_ip }} - Source IP address
- {{ alert.metadata.hostname }} - Hostname
- {{ alert.metadata.device_id }} - Device ID
- {{ alert.title }} - Alert title
- {{ alert.severity }} - Alert severity (critical, high, medium, low)
- {{ alert.rule_name }} - Detection rule name

## Response Format
Return a JSON object with the parameters:
```json
{
  "param_name": "value or {{ template }}"
}
```

Response:"""


# Expected parameters for each action type
EXPECTED_PARAMETERS = {
    "terminate_sessions": """
- user_email: Email of user whose sessions should be terminated (or use {{ alert.metadata.user_email }})
- user_id: Alternative to user_email
- reason: Reason for termination (optional)""",

    "disable_account": """
- user_email: Email of user account to disable (or use {{ alert.metadata.user_email }})
- user_id: Alternative to user_email
- reason: Reason for disabling (optional)""",

    "enable_account": """
- user_email: Email of user account to enable
- user_id: Alternative to user_email""",

    "force_password_reset": """
- user_email: Email of user (or use {{ alert.metadata.user_email }})
- user_id: Alternative to user_email
- notify_user: Whether to notify the user (true/false)
- message: Custom message to user (optional)""",

    "revoke_tokens": """
- user_email: Email of user whose tokens should be revoked
- user_id: Alternative to user_email
- token_types: Types of tokens to revoke (oauth, api_key, all)""",

    "block_ip": """
- ip_address: IP address to block (or use {{ alert.metadata.source_ip }})
- duration: How long to block (e.g., "24h", "7d", "permanent")
- reason: Reason for blocking""",

    "unblock_ip": """
- ip_address: IP address to unblock""",

    "isolate_host": """
- hostname: Hostname to isolate (or use {{ alert.metadata.hostname }})
- host_id: Alternative to hostname
- reason: Reason for isolation""",

    "unisolate_host": """
- hostname: Hostname to unisolate
- host_id: Alternative to hostname""",

    "notify": """
- channel: Slack channel (e.g., #security-alerts)
- email: Email address (alternative to channel)
- message: Notification message (can include templates)
- severity: Message severity/color""",

    "create_ticket": """
- project: Project key (e.g., SEC, INCIDENT)
- summary: Ticket title/summary
- description: Detailed description
- priority: Ticket priority (High, Medium, Low)
- assignee: Assignee email (optional)
- labels: List of labels (optional)""",

    "run_query": """
- query: SQL or natural language query
- time_range: Time range for query (e.g., "last 24 hours")
- save_results: Whether to save results (true/false)""",

    "webhook": """
- url: Webhook URL
- method: HTTP method (GET, POST, PUT)
- headers: HTTP headers (optional)
- body: Request body (optional, can include templates)""",

    "custom": """
- description: Description of the custom action
- code: Optional Python code snippet
- lambda_arn: ARN of Lambda to invoke (optional)""",
}


# Prompt for determining step dependencies
STEP_DEPENDENCY_PROMPT = """Analyze these playbook steps and determine their execution order and dependencies.

## Steps
{steps_json}

## Guidelines
1. Steps that must complete before others should have depends_on set
2. Steps that can run in parallel should not have dependencies on each other
3. Error notification steps should be set as on_failure for critical steps
4. Steps with dangerous actions (disable_account, block_ip, isolate_host) should have requires_approval: true

## Response Format
Return a JSON array with updated steps including:
- depends_on: List of step IDs that must complete first
- on_success: Step ID to run on success (or null for next step)
- on_failure: Step ID to run on failure (or null for error handler)
- requires_approval: true if step needs human approval

Response:"""


# Few-shot examples for IR plan parsing
IR_PLAN_EXAMPLES = [
    {
        "input": """
## Credential Compromise Response

1. Immediately terminate all active sessions for the compromised user
2. Force a password reset
3. Notify the security team via Slack
4. Create an incident ticket in Jira
""",
        "output": {
            "name": "Credential Compromise Response",
            "description": "Automated response for credential compromise incidents",
            "steps": [
                {
                    "id": "step_1",
                    "name": "Terminate Active Sessions",
                    "action_type": "terminate_sessions",
                    "provider": "auto",
                    "parameters": {
                        "user_email": "{{ alert.metadata.user_email }}",
                        "reason": "Credential compromise detected"
                    },
                    "requires_approval": False,
                    "on_failure": "error_notify"
                },
                {
                    "id": "step_2",
                    "name": "Force Password Reset",
                    "action_type": "force_password_reset",
                    "provider": "auto",
                    "parameters": {
                        "user_email": "{{ alert.metadata.user_email }}",
                        "notify_user": True
                    },
                    "requires_approval": True,
                    "depends_on": ["step_1"],
                    "on_failure": "error_notify"
                },
                {
                    "id": "step_3",
                    "name": "Notify Security Team",
                    "action_type": "notify",
                    "provider": "slack",
                    "parameters": {
                        "channel": "#security-alerts",
                        "message": "Credential compromise response executed for {{ alert.metadata.user_email }}"
                    },
                    "depends_on": ["step_2"]
                },
                {
                    "id": "step_4",
                    "name": "Create Incident Ticket",
                    "action_type": "create_ticket",
                    "provider": "jira",
                    "parameters": {
                        "project": "SEC",
                        "summary": "Credential Compromise - {{ alert.metadata.user_email }}",
                        "description": "Alert: {{ alert.title }}\\nUser: {{ alert.metadata.user_email }}",
                        "priority": "High"
                    },
                    "depends_on": ["step_3"]
                },
                {
                    "id": "error_notify",
                    "name": "Error Notification",
                    "action_type": "notify",
                    "provider": "slack",
                    "parameters": {
                        "channel": "#security-alerts",
                        "message": "Playbook error: {{ error }}"
                    }
                }
            ]
        }
    },
    {
        "input": """
# Malware Detection Response

When malware is detected on an endpoint:
- Isolate the infected host immediately
- Block the source IP if external
- Create a P1 incident ticket
- Page the incident response team
""",
        "output": {
            "name": "Malware Detection Response",
            "description": "Automated response for malware detection incidents",
            "steps": [
                {
                    "id": "step_1",
                    "name": "Isolate Infected Host",
                    "action_type": "isolate_host",
                    "provider": "crowdstrike",
                    "parameters": {
                        "hostname": "{{ alert.metadata.hostname }}",
                        "reason": "Malware detected"
                    },
                    "requires_approval": True,
                    "on_failure": "error_notify"
                },
                {
                    "id": "step_2",
                    "name": "Block Source IP",
                    "action_type": "block_ip",
                    "provider": "firewall",
                    "parameters": {
                        "ip_address": "{{ alert.metadata.source_ip }}",
                        "duration": "24h",
                        "reason": "Malware C2 communication"
                    },
                    "requires_approval": True,
                    "on_failure": "error_notify"
                },
                {
                    "id": "step_3",
                    "name": "Create P1 Incident",
                    "action_type": "create_ticket",
                    "provider": "jira",
                    "parameters": {
                        "project": "SEC",
                        "summary": "MALWARE: {{ alert.metadata.hostname }}",
                        "priority": "Critical"
                    },
                    "depends_on": ["step_1"]
                },
                {
                    "id": "step_4",
                    "name": "Page IR Team",
                    "action_type": "notify",
                    "provider": "pagerduty",
                    "parameters": {
                        "severity": "critical",
                        "message": "Malware incident requires immediate attention"
                    },
                    "depends_on": ["step_3"]
                },
                {
                    "id": "error_notify",
                    "name": "Error Notification",
                    "action_type": "notify",
                    "provider": "slack",
                    "parameters": {
                        "channel": "#security-critical",
                        "message": "CRITICAL: Malware response playbook failed: {{ error }}"
                    }
                }
            ]
        }
    }
]
