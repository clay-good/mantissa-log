# Integration Setup Wizards Feature

Guided setup workflows for alert and ticketing integrations with validation and testing.

## Overview

The Integration Wizards feature provides step-by-step setup flows for integrating Mantissa Log with external alerting and ticketing systems. Each wizard validates configuration, tests connectivity, and securely stores credentials.

## Supported Integrations

### 1. Slack
- Incoming Webhooks for alert notifications
- Channel-specific routing
- Custom message formatting
- Severity-based filtering

### 2. Jira
- Automatic ticket creation
- Project and issue type selection
- Priority mapping by severity
- Field customization

### 3. PagerDuty
- Event API v2 integration
- Incident triggering
- Severity-based urgency
- Deduplication support

### 4. Custom Webhooks
- HTTPS POST/PUT endpoints
- Custom headers for authentication
- Flexible payload templates
- Any HTTP-based integration

## Implementation

### Backend Components

#### 1. Integration Validators ([src/shared/integrations/validators.py](../../src/shared/integrations/validators.py))

Validates integration configurations before saving.

**Classes:**
- `ValidationResult` - Dataclass for validation results
- `IntegrationValidator` - Base validator class
- `SlackValidator` - Validates Slack webhooks
- `JiraValidator` - Validates Jira API access
- `PagerDutyValidator` - Validates PagerDuty integration keys
- `WebhookValidator` - Validates custom webhooks
- `IntegrationValidatorFactory` - Factory for creating validators

**Validation Flow:**
```python
from integrations.validators import IntegrationValidatorFactory

# Validate Slack configuration
result = IntegrationValidatorFactory.validate('slack', {
    'webhook_url': 'https://hooks.slack.com/services/...',
    'channel': '#security-alerts'
})

if result.success:
    print(f"Success: {result.message}")
    print(f"Details: {result.details}")
else:
    print(f"Error: {result.message}")
    print(f"Code: {result.error_code}")
```

**Slack Validation:**
- Checks webhook URL format (must start with `https://hooks.slack.com/`)
- Validates channel format (must start with #)
- Sends test message to webhook
- Returns success/failure with latency

**Jira Validation:**
- Tests authentication with API token
- Verifies project access
- Fetches project metadata
- Returns project name and key

**PagerDuty Validation:**
- Sends test event to Events API v2
- Validates integration key
- Returns dedup key on success

**Webhook Validation:**
- Checks URL uses HTTPS
- Validates HTTP method (POST/PUT only)
- Sends test request with custom headers
- Verifies 2xx status code response

#### 2. Integration Wizard API ([src/aws/api/integration_wizard.py](../../src/aws/api/integration_wizard.py))

Provides API endpoints for wizard workflows.

**Endpoints:**

`POST /api/integrations/validate`
```json
Request:
{
  "type": "slack",
  "config": {
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#alerts"
  }
}

Response:
{
  "success": true,
  "message": "Successfully sent test message to Slack",
  "details": {"response": "ok"},
  "error_code": null
}
```

`POST /api/integrations/wizard/{type}/save`
```json
Request:
{
  "userId": "user-123",
  "name": "Slack Security Alerts",
  "config": {
    "webhook_url": "https://hooks.slack.com/...",
    "channel": "#security-alerts"
  },
  "severity_filter": ["critical", "high"],
  "enabled": true
}

Response:
{
  "integration_id": "slack-2024-11-27T10:30:00Z",
  "message": "Slack integration saved successfully",
  "integration": {...}
}
```

`POST /api/integrations/wizard/jira/projects`
```json
Request:
{
  "url": "https://your-domain.atlassian.net",
  "email": "user@example.com",
  "api_token": "token"
}

Response:
{
  "projects": [
    {"key": "PROJ", "name": "Project Name", "id": "10000"},
    ...
  ]
}
```

**Security:**
- Sensitive fields stored in AWS Secrets Manager
- API tokens never stored in DynamoDB
- Secret reference stored instead
- KMS encryption for all secrets

**Secret Storage Pattern:**
```
Secret ID: mantissa-log/users/{user_id}/integrations/{type}

Contents:
{
  "webhook_url": "https://hooks.slack.com/...",  // for Slack
  "api_token": "ATATT...",                        // for Jira
  "integration_key": "abc123..."                   // for PagerDuty
}
```

### Frontend Components

#### 1. SlackWizard ([web/src/components/wizards/SlackWizard.jsx](../../web/src/components/wizards/SlackWizard.jsx))

3-step wizard for Slack integration setup.

**Step 1: Create Slack App**
- Instructions with numbered steps
- Links to Slack API portal
- Webhook URL input
- Channel selection (optional)
- Bot username and icon customization

**Step 2: Test Connection**
- Send test message button
- Real-time validation feedback
- Success: Shows checkmark and latency
- Error: Shows error message with details
- Auto-advances to Step 3 on success

**Step 3: Alert Routing**
- Severity filter selection (checkboxes)
  - Critical
  - High
  - Medium
  - Low
  - Info
- Configuration summary
- Save button

**Features:**
- Progress indicators (1/2/3 steps)
- Monochrome design with step circles
- Completed steps show checkmark
- Current step highlighted
- Error handling with AlertCircle icon
- Loading states for async operations

#### 2. JiraWizard ([web/src/components/wizards/JiraWizard.jsx](../../web/src/components/wizards/JiraWizard.jsx))

3-step wizard for Jira integration setup.

**Step 1: Jira Credentials**
- Instructions for generating API token
- Jira URL input
- Email input
- API token input (password field, monospace)
- Fetches projects on Next

**Step 2: Project Configuration**
- Project dropdown (fetched from Jira API)
- Issue type selection (Bug, Task, Story, Incident)
- Test connection button
- Validation feedback
- Auto-advances on success

**Step 3: Priority Mapping**
- Map alert severity to Jira priority
  - Critical → Highest
  - High → High
  - Medium → Medium
  - Low → Low
  - Info → Lowest
- Configuration summary
- Save button

**Features:**
- Dynamic project fetching from Jira API
- Priority mapping customization
- Connection validation before save
- Monochrome dropdowns and selects

#### 3. PagerDutyWizard ([web/src/components/wizards/PagerDutyWizard.jsx](../../web/src/components/wizards/PagerDutyWizard.jsx))

Simplified wizard for PagerDuty integration.

**Features:**
- Integration key input (password field)
- Instructions for finding key
- Test connection button
- Sends test event to PagerDuty
- Displays dedup key on success
- Save button

**Design:**
- Single-page wizard (no steps)
- Monochrome cards
- Clear error messages
- Loading states

#### 4. WebhookWizard ([web/src/components/wizards/WebhookWizard.jsx](../../web/src/components/wizards/WebhookWizard.jsx))

Flexible wizard for custom webhooks.

**Features:**
- Webhook URL input (must be HTTPS)
- HTTP method selection (POST/PUT)
- Custom headers builder
  - Add header button
  - Remove header button
  - Headers displayed in monochrome badges
- Test webhook button
- Sends test payload
- Displays HTTP status code
- Save button

**Headers Management:**
- Key-value input fields
- Add button to append header
- Remove button for each header
- Headers stored in config object
- Sent with all requests

## User Workflows

### Slack Setup Workflow

**1. User clicks "Add Integration" → "Slack"**

**2. Step 1: Create Webhook**
```
User navigates to api.slack.com/apps
Creates new app "Mantissa Log"
Enables Incoming Webhooks
Adds webhook to workspace
Selects #security-alerts channel
Copies webhook URL: https://hooks.slack.com/services/T.../B.../X...
```

**3. Paste Webhook in Wizard**
```
Webhook URL: https://hooks.slack.com/services/T.../B.../X...
Channel: #security-alerts (optional override)
Username: Mantissa Log
Icon: :shield:
```

**4. Click Next → Step 2: Test**
```
Clicks "Send Test Message"
System validates:
  ✓ URL format correct
  ✓ Test message sent successfully
  ✓ Slack responded with "ok" (200ms latency)
Auto-advances to Step 3
```

**5. Step 3: Configure Severity Filter**
```
Select severity levels:
  ✓ Critical
  ✓ High
  ☐ Medium
  ☐ Low
  ☐ Info

Clicks "Complete Setup"
Integration saved with ID: slack-2024-11-27T10:30:00Z
```

**6. Integration Active**
```
Slack integration now appears in Settings > Integrations
Shows "Configured" badge with green checkmark
Health status: Healthy
Last tested: 2 minutes ago
```

### Jira Setup Workflow

**1. User clicks "Add Integration" → "Jira"**

**2. Step 1: Generate API Token**
```
User navigates to id.atlassian.com/manage-profile/security/api-tokens
Clicks "Create API token"
Names it "Mantissa Log"
Copies token immediately
```

**3. Enter Credentials**
```
Jira URL: https://acme.atlassian.net
Email: security@acme.com
API Token: ATATT3xFfG...
```

**4. Click Next → Fetch Projects**
```
System makes API call to Jira
Fetches all accessible projects
Displays in dropdown:
  - Security Engineering (SEC)
  - SecOps (SOPS)
  - Infrastructure (INFRA)
```

**5. Step 2: Select Project**
```
Project: Security Engineering (SEC)
Issue Type: Bug
Clicks "Test Connection"
```

**6. Validation**
```
System validates:
  ✓ Authentication successful
  ✓ Project SEC accessible
  ✓ Project name: "Security Engineering"
Auto-advances to Step 3
```

**7. Step 3: Priority Mapping**
```
Critical → Highest
High → High
Medium → Medium
Low → Low
Info → Lowest

Clicks "Complete Setup"
```

**8. Integration Saved**
```
Jira integration active
API token stored in Secrets Manager: mantissa-log/users/user-123/integrations/jira
Preferences stored in DynamoDB
Health status: Healthy
```

## Security

### Credential Storage

**What Gets Stored Where:**

| Integration | Secret Manager | DynamoDB |
|-------------|----------------|----------|
| Slack | `webhook_url` | `channel`, `username`, `icon_emoji` |
| Jira | `api_token` | `url`, `email`, `project_key`, `issue_type` |
| PagerDuty | `integration_key` | `severity` |
| Webhook | `headers` | `url`, `method` |

**Secret Manager Format:**
```json
{
  "SecretId": "mantissa-log/users/user-123/integrations/slack",
  "SecretString": "{\"webhook_url\":\"https://hooks.slack.com/...\"}",
  "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/...",
  "VersionId": "abc-123"
}
```

**DynamoDB Integration Item:**
```json
{
  "user_id": "user-123",
  "integration_id": "slack-2024-11-27T10:30:00Z",
  "type": "slack",
  "name": "Slack Security Alerts",
  "config": {
    "webhook_url": "STORED_IN_SECRETS_MANAGER",
    "channel": "#security-alerts",
    "username": "Mantissa Log",
    "icon_emoji": ":shield:"
  },
  "severity_filter": ["critical", "high"],
  "enabled": true,
  "health_status": "healthy",
  "last_test": "2024-11-27T10:30:05Z",
  "created_at": "2024-11-27T10:30:00Z",
  "updated_at": "2024-11-27T10:30:00Z"
}
```

### Validation Before Save

All integrations MUST pass validation before saving:

```python
# Backend validation flow
def save_integration(user_id, integration_type, data):
    config = data['config']

    # Validate first
    result = IntegrationValidatorFactory.validate(integration_type, config)
    if not result.success:
        return error_response(f'Validation failed: {result.message}', 400)

    # Extract secrets
    secret_fields = get_secret_fields(integration_type)
    secrets = {k: config[k] for k in secret_fields if k in config}

    # Store secrets
    store_secret(f'mantissa-log/users/{user_id}/integrations/{integration_type}', secrets)

    # Store config (with secrets replaced)
    for field in secret_fields:
        config[field] = 'STORED_IN_SECRETS_MANAGER'

    # Save to DynamoDB
    table.put_item(Item={...})
```

## UI Design (Monochrome)

### Wizard Progress Indicators

**Step Circles:**
```
Completed: bg-mono-950 dark:bg-mono-50 (filled circle with checkmark)
Current:   border-mono-950 dark:border-mono-50 (outlined circle with number)
Future:    border-mono-300 dark:border-mono-700 (light outlined circle)
```

**Progress Line:**
```
Completed: bg-mono-950 dark:bg-mono-50 (thick line)
Future:    bg-mono-300 dark:border-mono-700 (thin line)
```

### Test Results

**Success State:**
```
Background: mono-100/mono-850
Border: mono-300/mono-700
Icon: Check (mono-900/mono-100)
Text: mono-900/mono-100
```

**Error State:**
```
Background: mono-150/mono-850
Border: mono-300/mono-700
Icon: X (mono-700/mono-300)
Text: mono-700/mono-300
```

### Buttons

**Primary (Next, Save, Test):**
```
Background: mono-950/mono-50
Text: mono-50/mono-950
Hover: mono-800/mono-200
Disabled: opacity-30
```

**Secondary (Back, Cancel):**
```
Background: transparent
Border: mono-300/mono-700
Text: mono-900/mono-100
Hover: mono-100/mono-850
```

## Testing

### Backend Tests

```python
def test_slack_validator():
    validator = SlackValidator()

    # Test valid webhook
    result = validator.validate({
        'webhook_url': 'https://hooks.slack.com/services/T.../B.../X...',
        'channel': '#alerts'
    })
    assert result.success == True

def test_jira_project_fetch():
    response = client.post('/api/integrations/wizard/jira/projects', json={
        'url': 'https://test.atlassian.net',
        'email': 'test@test.com',
        'api_token': 'token'
    })
    assert response.status_code == 200
    assert 'projects' in response.json()

def test_integration_save():
    response = client.post('/api/integrations/wizard/slack/save', json={
        'userId': 'user-123',
        'name': 'Test Slack',
        'config': {'webhook_url': 'https://hooks.slack.com/...'},
        'severity_filter': ['critical'],
        'enabled': True
    })
    assert response.status_code == 200
    assert 'integration_id' in response.json()
```

### Frontend Tests

```javascript
test('Slack wizard completes 3 steps', async () => {
  const { user } = render(<SlackWizard userId="test" onComplete={jest.fn()} />);

  // Step 1
  await user.type(screen.getByPlaceholderText(/webhook/i), 'https://hooks.slack.com/services/...');
  await user.click(screen.getByText('Next'));

  // Step 2
  await user.click(screen.getByText('Send Test Message'));
  await waitFor(() => expect(screen.getByText(/success/i)).toBeInTheDocument());

  // Step 3 (auto-advanced)
  expect(screen.getByText('Alert Routing')).toBeInTheDocument();
  await user.click(screen.getByLabelText('Critical'));
  await user.click(screen.getByText('Complete Setup'));

  expect(onComplete).toHaveBeenCalled();
});
```

## Future Enhancements

### 1. Integration Health Monitoring
- Periodic health checks for each integration
- Alert on integration failures
- Automatic retry with exponential backoff
- Health status dashboard

### 2. Additional Integrations
- Microsoft Teams webhooks
- Splunk HTTP Event Collector
- Datadog events API
- ServiceNow incident creation

### 3. Template Library
- Pre-built message templates
- Customizable alert formatting
- Variable substitution
- Conditional formatting

### 4. Bulk Operations
- Test all integrations at once
- Bulk enable/disable
- Mass configuration updates
- Export/import configurations

## Documentation

- [Integration Validators](../../src/shared/integrations/validators.py)
- [Integration Wizard API](../../src/aws/api/integration_wizard.py)
- [SlackWizard Component](../../web/src/components/wizards/SlackWizard.jsx)
- [JiraWizard Component](../../web/src/components/wizards/JiraWizard.jsx)
- [PagerDutyWizard Component](../../web/src/components/wizards/PagerDutyWizard.jsx)
- [WebhookWizard Component](../../web/src/components/wizards/WebhookWizard.jsx)
