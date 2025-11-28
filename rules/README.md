# Mantissa Log Detection Rules

This directory contains detection rules for the Mantissa Log security platform.

## Directory Structure

```
rules/
├── authentication/    # Authentication and access-related detections
├── network/          # Network traffic and connection detections
├── cloud/            # Cloud configuration and security detections
└── README.md         # This file
```

## Rule Format

Detection rules are defined in YAML format with the following structure:

```yaml
name: "Rule Name"
description: "What this rule detects"
enabled: true
severity: "critical|high|medium|low|info"
category: "authentication|network|cloud|data|compliance|threat"

query: |
  SELECT ...
  FROM ...
  WHERE ...

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1110"
  tags:
    - "tag1"
    - "tag2"
  false_positives:
    - "Known FP scenario 1"
  response_actions:
    - "Action to take 1"
    - "Action to take 2"
  references:
    - "https://example.com/doc"
```

### Required Fields

- `name`: Human-readable rule name
- `description`: Detailed description of what the rule detects
- `enabled`: Boolean indicating if rule is active
- `severity`: One of: critical, high, medium, low, info
- `category`: Rule category
- `query`: SQL query to execute (Athena-compatible)
- `threshold`: Detection threshold configuration
  - `count`: Minimum number of matches to trigger alert
  - `window`: Time window for threshold (e.g., "5m", "1h", "1d")

### Optional Fields

- `metadata`: Additional rule metadata
  - `mitre_attack`: List of MITRE ATT&CK technique IDs
  - `tags`: List of tags for categorization
  - `false_positives`: Known false positive scenarios
  - `response_actions`: Recommended response actions
  - `references`: Links to documentation

## Available Tables

Rules can query the following Athena tables:

- `cloudtrail`: AWS CloudTrail API events
- `vpc_flow_logs`: VPC Flow Logs network traffic
- `guardduty_findings`: AWS GuardDuty threat findings

## Testing Rules

### Dry Run (Print SQL)

```bash
python3 scripts/test-rule.py rules/authentication/brute_force_login.yaml --mode dry-run
```

### Test Run (Execute Against Athena)

```bash
python3 scripts/test-rule.py rules/authentication/brute_force_login.yaml \
  --mode test \
  --database mantissa_log \
  --output-location s3://my-bucket/athena-results/
```

### Backtest (Historical Analysis)

```bash
python3 scripts/test-rule.py rules/authentication/brute_force_login.yaml \
  --mode backtest \
  --database mantissa_log \
  --output-location s3://my-bucket/athena-results/ \
  --days-back 7
```

## Rule Validation

```bash
python3 scripts/validate-rules.py
```

This checks:
- Schema compliance
- SQL syntax
- Best practices
- Duplicate detection
