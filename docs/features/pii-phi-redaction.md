# PII/PHI Redaction Feature

Automatic redaction of personally identifiable information (PII) and protected health information (PHI) from alert payloads sent to external integrations.

## Overview

The PII/PHI Redaction feature ensures that sensitive information is automatically removed from alert payloads before they are sent to external integrations like Slack, Jira, PagerDuty, Email, and custom webhooks.

**CRITICAL**: Redaction is **ONLY** applied to integration payloads. Raw logs stored in S3/Athena and query results displayed in the UI are **NEVER** modified. This preserves the full investigative value of the original data while protecting sensitive information from being sent to third-party systems.

## Why This Matters

### Compliance Requirements

- **HIPAA**: Protected Health Information (PHI) must be safeguarded
- **PCI-DSS**: Credit card information cannot be sent to unauthorized systems
- **GDPR**: Personal data requires protection and minimization
- **SOC 2**: Sensitive data handling must be controlled

### Risk Reduction

- Prevents accidental PII exposure in Slack channels
- Limits sensitive data in Jira tickets that may have broad access
- Reduces compliance scope for ticketing/alerting platforms
- Maintains audit trail of what was redacted

## Architecture

### Components

1. **PIIRedactor** ([src/shared/redaction/pii_redactor.py](../../src/shared/redaction/pii_redactor.py))
   - Core redaction engine with regex patterns
   - Supports text and structured data (dicts, lists)
   - Configurable patterns per user
   - Optional hashing for correlation

2. **RedactedIntegrationSender** ([src/shared/integrations/redacted_sender.py](../../src/shared/integrations/redacted_sender.py))
   - Integration wrapper that applies redaction
   - Loads user configuration from DynamoDB
   - Builds integration-specific payloads
   - Logs redaction audit trail

3. **RedactionSettings Component** ([web/src/components/Settings/RedactionSettings.jsx](../../web/src/components/Settings/RedactionSettings.jsx))
   - UI for configuring redaction rules
   - Enable/disable specific pattern types
   - Add custom regex patterns
   - Test redaction with sample text

### Data Flow

```
Alert Triggered
    ↓
Build Integration Payload (email, SSN, phone numbers included)
    ↓
Load User's Redaction Config from DynamoDB
    ↓
Apply PII/PHI Redaction to Payload
    ↓
Log Redaction Audit to DynamoDB
    ↓
Send Redacted Payload to Integration (Slack, Jira, etc.)
    ↓
Original Alert Data Stored Unmodified in S3/Athena
```

## Supported Redaction Patterns

### Email Addresses

**Pattern**: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`

**Examples**:
- `user@example.com` → `[EMAIL_REDACTED]`
- `john.doe+tag@company.co.uk` → `[EMAIL_REDACTED]`

**Default**: Enabled

### Phone Numbers

**Pattern**: US and international formats

**Examples**:
- `(555) 123-4567` → `[PHONE_REDACTED]`
- `555-123-4567` → `[PHONE_REDACTED]`
- `+1-555-123-4567` → `[PHONE_REDACTED]`
- `5551234567` → `[PHONE_REDACTED]`

**Default**: Enabled

### Social Security Numbers

**Pattern**: SSN with or without dashes, validates against invalid ranges

**Examples**:
- `123-45-6789` → `[SSN_REDACTED]`
- `123456789` → `[SSN_REDACTED]`

**Notes**:
- Excludes invalid SSNs (000, 666, 900-999 prefixes)
- Validates area and group numbers

**Default**: Enabled

### Credit Card Numbers

**Pattern**: Visa, MasterCard, Amex, Discover, Diners Club, JCB

**Examples**:
- `4111-1111-1111-1111` → `[CARD_REDACTED]`
- `5555-5555-5555-4444` → `[CARD_REDACTED]`
- `3782-822463-10005` → `[CARD_REDACTED]` (Amex)
- `4111111111111111` → `[CARD_REDACTED]` (no dashes)

**Default**: Enabled

### IP Addresses

**Pattern**: IPv4 and IPv6 addresses

**Examples**:
- `192.168.1.1` → `[IP_REDACTED]`
- `10.0.0.1` → `[IP_REDACTED]`
- `2001:0db8:85a3::8a2e:0370:7334` → `[IP_REDACTED]`

**Default**: **Disabled**

**Reasoning**: IP addresses often provide critical security context (source of attack, compromised system, etc.). Redacting them may remove valuable information for incident response. Users can enable if required by policy.

### MAC Addresses

**Pattern**: Hardware addresses in various formats

**Examples**:
- `00:1B:44:11:3A:B7` → `[MAC_REDACTED]`
- `00-1B-44-11-3A-B7` → `[MAC_REDACTED]`

**Default**: Disabled

### Medical Record Numbers

**Pattern**: MRN/Medical Record identifiers

**Examples**:
- `MRN: AB123456` → `[MRN_REDACTED]`
- `Medical Record: XY987654` → `Medical [MRN_REDACTED]`

**Default**: Enabled

### Custom Patterns

Users can define custom regex patterns for organization-specific sensitive data:

**Example Custom Patterns**:
- Employee IDs: `\bEMP-\d{6}\b` → `[EMP_ID_REDACTED]`
- Customer IDs: `\bCUST-\d{8}\b` → `[CUSTOMER_ID_REDACTED]`
- Internal account numbers
- API keys/tokens
- Custom identifier formats

## Configuration

### Settings UI

Navigate to **Settings > PII/PHI Redaction** to configure redaction:

#### Master Toggle

Enable/disable redaction globally for all integrations.

#### Pattern Selection

Check/uncheck individual pattern types:
- ☑ Email Addresses
- ☑ Phone Numbers
- ☑ Social Security Numbers
- ☑ Credit Card Numbers
- ☐ IP Addresses (disabled by default)
- ☐ MAC Addresses
- ☑ Medical Record Numbers

#### Advanced Options

**Include Hash of Redacted Values**:
- When enabled, appends a hash to redacted values
- Enables correlation across multiple alerts
- Example: `user@example.com` → `[EMAIL_REDACTED]:a1b2c3d4`
- Same email always produces same hash

#### Custom Patterns

Add organization-specific patterns:

1. **Description**: Employee ID
2. **Regular Expression**: `\bEMP-\d{6}\b`
3. **Replacement Text**: `[EMP_ID_REDACTED]`
4. Click "Add Custom Pattern"

#### Test Redaction

Before saving, test your configuration:

1. Enter sample text with PII/PHI
2. Click "Test Redaction"
3. View redacted output and types detected
4. Adjust configuration if needed
5. Save Configuration

### Backend Storage

**User Settings** (DynamoDB: `mantissa-log-user-settings`):
```json
{
  "user_id": "user-123",
  "setting_type": "redaction",
  "config": {
    "enabled": true,
    "enabledPatterns": ["email", "phone", "ssn", "credit_card", "medical_record"],
    "hashRedactedValues": false,
    "customPatterns": [
      {
        "regex": "\\bEMP-\\d{6}\\b",
        "replacement": "[EMP_ID_REDACTED]",
        "description": "Employee ID"
      }
    ]
  },
  "created_at": "2024-11-28T10:00:00Z",
  "updated_at": "2024-11-28T10:30:00Z"
}
```

## Integration-Specific Behavior

### Slack

**Fields Redacted**:
- `text` - Main message text
- `blocks` - Block kit content
- `attachments` - Legacy attachments

**Fields Preserved**:
- `channel` - Channel ID/name
- `username` - Bot username
- `icon_emoji` - Bot icon

**Example**:
```python
# Original payload
{
  "text": "User john@example.com triggered alert",
  "channel": "#security-alerts",
  "blocks": [{"text": "SSN: 123-45-6789"}]
}

# Redacted payload
{
  "text": "User [EMAIL_REDACTED] triggered alert",
  "channel": "#security-alerts",
  "blocks": [{"text": "SSN: [SSN_REDACTED]"}]
}
```

### Jira

**Fields Redacted**:
- `summary` - Issue title
- `description` - Issue description
- `fields.*` - Custom fields

**Fields Preserved**:
- `project` - Project key
- `issuetype` - Issue type
- `priority` - Priority level

**Example**:
```python
# Original
{
  "fields": {
    "summary": "Alert from user@example.com",
    "description": "Phone: 555-123-4567\nCard: 4111-1111-1111-1111",
    "project": {"key": "SEC"}
  }
}

# Redacted
{
  "fields": {
    "summary": "Alert from [EMAIL_REDACTED]",
    "description": "Phone: [PHONE_REDACTED]\nCard: [CARD_REDACTED]",
    "project": {"key": "SEC"}
  }
}
```

### PagerDuty

**Fields Redacted**:
- `payload.summary` - Incident summary
- `payload.details` - Additional details
- `payload.custom_details` - Custom fields

**Fields Preserved**:
- `routing_key` - Integration key
- `payload.severity` - Urgency level
- `payload.source` - Event source

### Email

**Fields Redacted**:
- `subject` - Email subject line
- `body` - Email body (plain text)
- `html` - HTML email body

**Fields Preserved**:
- `to` - Recipient list
- `cc` - CC recipients
- `from` - Sender address

### Custom Webhooks

**Behavior**: All fields are redacted by default

Users can configure which fields to redact by specifying in webhook configuration.

## Redaction API

### Python Usage

```python
from src.shared.redaction.pii_redactor import create_redactor

# Create redactor with default config
redactor = create_redactor()

# Redact text
text = "Contact user@example.com at 555-123-4567"
redacted = redactor.redact_text(text)
# Result: "Contact [EMAIL_REDACTED] at [PHONE_REDACTED]"

# Redact dictionary
data = {
    'user': 'john@example.com',
    'phone': '555-123-4567',
    'message': 'SSN: 123-45-6789'
}
redacted_data = redactor.redact_dict(data)
# Result: {
#   'user': '[EMAIL_REDACTED]',
#   'phone': '[PHONE_REDACTED]',
#   'message': 'SSN: [SSN_REDACTED]'
# }

# Redact integration payload
payload = {
    'text': 'Alert from user@example.com',
    'channel': '#security'
}
redacted_payload = redactor.redact_integration_payload('slack', payload)

# Get redaction summary
summary = redactor.get_redaction_summary()
# Result: {
#   'total_redactions': 3,
#   'types_redacted': ['email', 'phone', 'ssn'],
#   'enabled_patterns': [...]
# }
```

### Custom Configuration

```python
from src.shared.redaction.pii_redactor import create_redactor, RedactionType

# Custom config
config = {
    'enabled_patterns': [
        RedactionType.EMAIL,
        RedactionType.PHONE,
        RedactionType.IP_ADDRESS  # Enable IP redaction
    ],
    'hash_redacted_values': True,  # Enable hashing
    'custom_patterns': [
        {
            'regex': r'\bEMP-\d{6}\b',
            'replacement': '[EMP_ID_REDACTED]',
            'description': 'Employee ID'
        }
    ]
}

redactor = create_redactor(config)
```

### Integration Sender

```python
from src.shared.integrations.redacted_sender import send_redacted_alert

# Send alert with automatic redaction
response = send_redacted_alert(
    user_id='user-123',
    integration_type='slack',
    alert_data={
        'rule_name': 'Failed Login Detection',
        'severity': 'high',
        'timestamp': '2024-11-28T10:00:00Z',
        'description': 'User john@example.com failed login',
        'details': {'phone': '555-123-4567'}
    },
    integration_config={
        'webhook_url': 'https://hooks.slack.com/...',
        'channel': '#security-alerts'
    }
)
```

## Audit Trail

### Redaction Audit Log

Every redaction is logged to DynamoDB for audit purposes.

**Table**: `mantissa-log-redaction-audit`

**Schema**:
```json
{
  "user_id": "user-123",
  "timestamp": "2024-11-28T10:30:00Z",
  "integration_type": "slack",
  "rule_id": "failed-login-detection",
  "alert_id": "alert-xyz789",
  "redaction_summary": {
    "total_redactions": 2,
    "types_redacted": ["email", "phone"],
    "enabled_patterns": ["email", "phone", "ssn", "credit_card"]
  },
  "ttl": 1740307200  // 90 days retention
}
```

**Retention**: 90 days (automatic cleanup via TTL)

### Querying Audit Logs

```python
import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('mantissa-log-redaction-audit')

# Get redaction history for user
response = table.query(
    KeyConditionExpression=Key('user_id').eq('user-123') &
                          Key('timestamp').between('2024-11-01', '2024-11-30')
)

for item in response['Items']:
    print(f"Alert {item['alert_id']}: "
          f"{len(item['redaction_summary']['types_redacted'])} types redacted")
```

## Testing

### Unit Tests

Comprehensive test suite at [tests/unit/test_pii_redaction.py](../../tests/unit/test_pii_redaction.py)

**Run tests**:
```bash
pytest tests/unit/test_pii_redaction.py -v
```

**Test Coverage**:
- ✅ Email redaction (single, multiple, plus-addressing, subdomains)
- ✅ Phone number redaction (dashes, parentheses, international)
- ✅ SSN redaction (with/without dashes, invalid SSN rejection)
- ✅ Credit card redaction (Visa, MC, Amex, no dashes)
- ✅ IP address redaction (IPv4, IPv6, default disabled)
- ✅ Medical record number redaction
- ✅ Dictionary redaction (nested, lists, specific fields)
- ✅ Integration payload redaction (Slack, Jira, PagerDuty, Email, Webhook)
- ✅ Custom patterns
- ✅ Hashed redaction
- ✅ Redaction summary and tracking
- ✅ Edge cases (None, empty, non-string values)

### Manual Testing

Use the Settings UI test feature:

1. Navigate to **Settings > PII/PHI Redaction**
2. Configure desired patterns
3. Enter test text in "Sample Text" field:
   ```
   User john.doe@example.com called from (555) 123-4567
   SSN: 123-45-6789
   Card: 4111-1111-1111-1111
   IP: 192.168.1.1
   MRN: AB123456
   ```
4. Click "Test Redaction"
5. Verify output shows appropriate redactions
6. Check "Redacted Types" badges

## Performance Considerations

### Regex Efficiency

All patterns are pre-compiled using Python's `re.compile()` for optimal performance.

**Benchmark** (sample 1KB text with 5 PII instances):
- First redaction: ~2ms
- Subsequent redactions: <0.5ms (compiled patterns cached)

### Payload Size Impact

Redaction typically reduces payload size since replacement tokens are shorter than original values:

**Example**:
- Original: `john.doe+notifications@company-subdomain.com` (45 chars)
- Redacted: `[EMAIL_REDACTED]` (16 chars)
- Savings: 29 chars (64%)

### Caching

User redaction configurations are cached in memory by the `RedactedIntegrationSender` instance. For Lambda functions, this provides ~1 second cache lifetime per container.

## Security Considerations

### Regex Limitations

**Important**: Regex patterns are heuristic-based and may have false positives/negatives:

**False Positives** (redacted but not actual PII):
- Number sequences that match SSN pattern: `123-45-6789` in non-PII context
- Domain names that look like emails

**False Negatives** (PII not detected):
- Obfuscated formats: `user [at] example [dot] com`
- Non-standard international phone formats
- Novel PII formats not covered by patterns

**Mitigation**:
- Use custom patterns for organization-specific formats
- Regularly review audit logs
- Test with real alert samples
- Consider conservative approach (more redaction)

### Data Retention

**Redacted Data**: Sent to integrations, retention controlled by third-party
**Original Data**: Stored in S3, retention per bucket lifecycle policy
**Audit Logs**: 90 days in DynamoDB

### Compliance Notes

This feature assists with compliance but does not guarantee it. Organizations should:
- Review patterns against their specific requirements
- Test with actual sensitive data formats
- Maintain audit trail
- Document data handling procedures
- Regular compliance audits

## Troubleshooting

### PII Not Being Redacted

**Check**:
1. Is redaction enabled in Settings?
2. Is the specific pattern type enabled?
3. Does the PII match the regex pattern?
4. Test in Settings UI with sample text

**Debug**:
```python
redactor = create_redactor()
text = "your PII here"
result = redactor.redact_text(text, track=True)
summary = redactor.get_redaction_summary()
print(summary)  # Shows what was redacted
```

### Too Much Redaction

**Solution**:
1. Disable overly broad patterns (e.g., IP addresses)
2. Adjust custom patterns to be more specific
3. Use negative lookahead in regex to exclude certain formats

### Integration Errors After Enabling Redaction

**Check**:
1. View audit logs to see what was redacted
2. Ensure integration can handle redacted content
3. Test with sample payload in Settings UI
4. Verify integration validators still pass

### Performance Issues

**Solutions**:
1. Reduce number of custom patterns
2. Optimize regex patterns (avoid backtracking)
3. Consider disabling unused pattern types
4. Check payload sizes

## Future Enhancements

### Planned Features

1. **Contextual Redaction**
   - Preserve security-relevant IPs while redacting user IPs
   - Intelligent field detection (e.g., "source_ip" vs "user_ip")

2. **Machine Learning Detection**
   - Trained model to detect PII beyond regex patterns
   - Context-aware redaction decisions

3. **Tokenization**
   - Replace PII with reversible tokens
   - Enable de-tokenization for authorized systems

4. **Redaction Templates**
   - Pre-configured templates for industries (Healthcare, Finance, etc.)
   - One-click compliance profiles

5. **Real-time Redaction Preview**
   - Preview redacted alerts before sending
   - Approve/reject redactions interactively

6. **Expanded Patterns**
   - Passport numbers
   - Driver's license numbers
   - Bank account numbers
   - International identifiers (NHS numbers, SIN, etc.)

## References

### Related Documentation

- [Integration Wizards](integration-wizards.md)
- [Alert Configuration](../configuration/alerts.md)
- [Security Best Practices](../operations/security.md)

### Standards & Compliance

- [HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [GDPR Article 5](https://gdpr-info.eu/art-5-gdpr/) (Data Minimization)

### Code References

- Redaction Module: [src/shared/redaction/pii_redactor.py](../../src/shared/redaction/pii_redactor.py)
- Integration Sender: [src/shared/integrations/redacted_sender.py](../../src/shared/integrations/redacted_sender.py)
- Settings UI: [web/src/components/Settings/RedactionSettings.jsx](../../web/src/components/Settings/RedactionSettings.jsx)
- Tests: [tests/unit/test_pii_redaction.py](../../tests/unit/test_pii_redaction.py)
