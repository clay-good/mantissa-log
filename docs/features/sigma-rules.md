# Sigma Detection Rules

Mantissa Log supports industry-standard Sigma detection rules alongside the legacy custom SQL format. Sigma provides cloud-agnostic detection logic that automatically converts to the appropriate SQL dialect for your deployment platform.

## What is Sigma?

Sigma is an open-source, generic signature format for SIEM systems. It allows you to write detection rules once and convert them to multiple backend formats (Athena, BigQuery, Splunk, Elasticsearch, etc.).

**Benefits:**
- Write once, run anywhere (AWS, GCP, Azure)
- Access 2000+ community detection rules
- No SQL expertise required
- Standardized MITRE ATT&CK mapping
- Easy to review and collaborate on

## Rule Format Comparison

### Sigma Format

```yaml
title: AWS Console Login Brute Force
id: aws-cloudtrail-brute-force-login-001
status: stable
description: Detects multiple failed console login attempts from the same IP
author: Mantissa Security Team
date: 2025-01-27

logsource:
  product: aws
  service: cloudtrail

detection:
  selection_failed:
    eventName: ConsoleLogin
    errorCode:
      - Failed authentication
      - InvalidPassword
  timeframe: 15m
  condition: selection_failed | count(sourceIPAddress) by sourceIPAddress >= 10

fields:
  - sourceIPAddress
  - userIdentity.principalId
  - eventTime

falsepositives:
  - Users legitimately forgetting passwords

level: high

tags:
  - attack.credential_access
  - attack.t1110.001
```

### Legacy Format (Still Supported)

```yaml
name: Brute Force Login Attempts
description: Detects multiple failed login attempts
enabled: true
severity: high

query: |
  SELECT sourceipaddress, COUNT(*) as count
  FROM cloudtrail
  WHERE eventname = 'ConsoleLogin'
    AND errorcode IN ('Failed authentication', 'InvalidPassword')
    AND eventtime > CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
  GROUP BY sourceipaddress
  HAVING COUNT(*) >= 10

threshold:
  count: 1
  window: 15m
```

## Directory Structure

```
rules/
├── sigma/                    # New Sigma format rules
│   ├── aws/
│   │   ├── cloudtrail/
│   │   ├── guardduty/
│   │   └── vpc_flow/
│   ├── gcp/
│   ├── azure/
│   ├── kubernetes/
│   └── okta/
└── legacy/                   # Legacy SQL format rules (deprecated)
    ├── authentication/
    ├── network/
    └── cloud/
```

## Writing Sigma Rules

### Basic Structure

Every Sigma rule must include:

1. **Metadata:** title, id, status, description, author, date
2. **Logsource:** Defines the log source (product, service, category)
3. **Detection:** Detection logic with conditions
4. **Level:** Severity (critical, high, medium, low, informational)

### Logsource Examples

**AWS CloudTrail:**
```yaml
logsource:
  product: aws
  service: cloudtrail
```

**GCP Cloud Logging:**
```yaml
logsource:
  product: gcp
  service: gcp.audit
```

**Kubernetes:**
```yaml
logsource:
  product: kubernetes
  service: audit
```

### Detection Logic

**Simple Selection:**
```yaml
detection:
  selection:
    eventName: DeleteBucket
    eventSource: s3.amazonaws.com
  condition: selection
```

**Multiple Conditions:**
```yaml
detection:
  selection_root:
    userIdentity.type: Root
  selection_actions:
    eventName|startswith:
      - Create
      - Delete
      - Put
  filter:
    eventName: GetCallerIdentity
  condition: selection_root and selection_actions and not filter
```

**Aggregation (Count):**
```yaml
detection:
  selection:
    eventName: ConsoleLogin
    errorCode: Failed authentication
  timeframe: 15m
  condition: selection | count(sourceIPAddress) by sourceIPAddress >= 10
```

**Field Modifiers:**
```yaml
detection:
  selection:
    eventName|contains: Policy        # Contains substring
    sourceIPAddress|cidr: 10.0.0.0/8  # CIDR match
    userAgent|startswith: aws-cli     # Starts with
    errorCode|endswith: Denied        # Ends with
  condition: selection
```

### MITRE ATT&CK Tagging

Tag rules with MITRE ATT&CK techniques:

```yaml
tags:
  - attack.credential_access    # Tactic
  - attack.t1110                # Technique
  - attack.t1110.001            # Sub-technique
```

### False Positives

Document known false positive scenarios:

```yaml
falsepositives:
  - Initial account setup
  - Legitimate admin activity
  - Automated infrastructure tools
```

## Multi-Cloud Support

The same Sigma rule automatically converts to different SQL dialects:

**Athena (AWS):**
```sql
SELECT sourceIPAddress, COUNT(*) as count
FROM cloudtrail
WHERE eventName = 'ConsoleLogin'
  AND errorCode IN ('Failed authentication', 'InvalidPassword')
  AND eventtime > CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
GROUP BY sourceIPAddress
HAVING COUNT(*) >= 10
```

**BigQuery (GCP):**
```sql
SELECT sourceIPAddress, COUNT(*) as count
FROM cloudtrail
WHERE eventName = 'ConsoleLogin'
  AND errorCode IN ('Failed authentication', 'InvalidPassword')
  AND eventtime > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 15 MINUTE)
GROUP BY sourceIPAddress
HAVING COUNT(*) >= 10
```

**Synapse (Azure):**
```sql
SELECT sourceIPAddress, COUNT(*) as count
FROM cloudtrail
WHERE eventName = 'ConsoleLogin'
  AND errorCode IN ('Failed authentication', 'InvalidPassword')
  AND eventtime > DATEADD(MINUTE, -15, GETUTCDATE())
GROUP BY sourceIPAddress
HAVING COUNT(*) >= 10
```

## Using Sigma Rules

### Rule Loader Configuration

```python
from src.shared.detection.rule import RuleLoader

# Initialize with Sigma support
loader = RuleLoader(
    rules_path="rules",
    schema_path="rules/schema.json",
    backend_type="athena"  # or "bigquery", "synapse"
)

# Load all rules (both Sigma and legacy)
rules = loader.load_all_rules()

# Load specific rule
rule = loader.load_rule("rules/sigma/aws/cloudtrail/brute_force_login.yml")
```

### Backend Types

- `athena`: AWS Athena (Presto SQL)
- `bigquery`: GCP BigQuery (Standard SQL)
- `synapse`: Azure Synapse Analytics (T-SQL)

The RuleLoader automatically detects the rule format and converts Sigma rules to SQL using the appropriate backend.

## Importing Community Rules

You can import rules from the official Sigma repository:

```bash
# Clone SigmaHQ repository
git clone https://github.com/SigmaHQ/sigma.git

# Copy relevant rules
cp sigma/rules/cloud/aws/cloudtrail/*.yml rules/sigma/aws/cloudtrail/
```

**Note:** Community rules may require customization for your log schema and table names.

## Converting Legacy Rules to Sigma

Use the helper function to convert existing rules:

```python
from src.shared.detection.sigma_converter import convert_legacy_to_sigma
import yaml

# Load legacy rule
with open("rules/legacy/authentication/brute_force_login.yaml") as f:
    legacy_rule = yaml.safe_load(f)

# Convert to Sigma format
sigma_rule = convert_legacy_to_sigma(legacy_rule)

# Save as Sigma rule
with open("rules/sigma/aws/cloudtrail/brute_force_login.yml", "w") as f:
    yaml.dump(sigma_rule, f)
```

**Important:** The detection logic (SQL to Sigma conditions) requires manual conversion. The helper provides a template.

## Validation

Validate Sigma rules before deployment:

```python
from src.shared.detection.sigma_converter import SigmaRuleConverter

converter = SigmaRuleConverter(backend_type="athena")

is_valid, errors = converter.validate_conversion(
    "rules/sigma/aws/cloudtrail/brute_force_login.yml"
)

if not is_valid:
    print("Validation errors:", errors)
```

## Testing Rules

Test Sigma rules against sample data:

```python
from src.shared.detection.engine import DetectionEngine
from src.shared.detection.rule import RuleLoader
from src.aws.athena.executor import AthenaQueryExecutor

# Setup
loader = RuleLoader(rules_path="rules/sigma", backend_type="athena")
executor = AthenaQueryExecutor(
    database="security_logs",
    output_location="s3://my-bucket/query-results/"
)
engine = DetectionEngine(loader, executor)

# Execute rule
rule = loader.load_rule("rules/sigma/aws/cloudtrail/brute_force_login.yml")
result = engine.execute_rule(rule)

print(f"Triggered: {result.triggered}")
print(f"Results: {result.results}")
```

## Best Practices

1. **Use descriptive IDs:** `aws-cloudtrail-brute-force-login-001`
2. **Version control:** Track rule changes in git
3. **Document false positives:** Help future analysts
4. **Test before deploying:** Validate against historical data
5. **Tag with MITRE ATT&CK:** Enable threat hunting
6. **Keep updated:** Monitor SigmaHQ for rule updates
7. **Customize for your environment:** Adjust thresholds and conditions

## Migration Timeline

- **Phase 1 (Current):** Dual format support - both Sigma and legacy work
- **Phase 2 (Q2 2025):** Convert all built-in rules to Sigma
- **Phase 3 (Q3 2025):** Import 100+ community rules
- **Phase 4 (Q4 2025):** Deprecate legacy format
- **Phase 5 (Q1 2026):** Remove legacy format support

## Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [pySigma Documentation](https://github.com/SigmaHQ/pySigma)
- [Sigma Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## Support

For questions or issues with Sigma rules:
- GitHub Issues: [mantissa-log/issues](https://github.com/mantissa-log/issues)
- Community: [Sigma Slack](https://github.com/SigmaHQ/sigma#community)
