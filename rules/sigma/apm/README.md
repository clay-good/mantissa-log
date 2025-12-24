# APM Detection Rules

This directory contains Sigma-format detection rules for Application Performance Monitoring (APM) anomalies. These rules detect latency spikes, error rate increases, service failures, and other performance-related issues.

## Rule Format

APM rules follow the standard Sigma rule format with APM-specific extensions:

```yaml
title: Rule Title
id: apm-traces-rule-name-001
status: stable|experimental
description: Detailed description of what the rule detects
author: Author Name
date: YYYY-MM-DD
modified: YYYY-MM-DD

logsource:
  product: apm
  service: traces|metrics

detection:
  selection:
    # Field selectors
  timeframe: 5m
  condition: selection | aggregate functions

fields:
  - field1
  - field2

falsepositives:
  - Known false positive scenarios

level: critical|high|medium|low

tags:
  - tag1
  - tag2
```

## Available Detection Functions

### Aggregate Functions

| Function | Description | Example |
|----------|-------------|---------|
| `count(*)` | Count all matching spans | `count(*) > 100` |
| `count(field='value')` | Count spans with specific field value | `count(status='error')` |
| `p50(field)` | 50th percentile (median) | `p50(duration_ms) > 500` |
| `p95(field)` | 95th percentile | `p95(duration_ms) > 2000` |
| `p99(field)` | 99th percentile | `p99(duration_ms) > 5000` |
| `avg(field)` | Average value | `avg(duration_ms) > 1000` |
| `sum(field)` | Sum of values | `sum(request_bytes) > 1000000` |
| `min(field)` | Minimum value | `min(duration_ms) < 1` |
| `max(field)` | Maximum value | `max(duration_ms) > 30000` |
| `rate(field)` | Rate calculation | `rate(count) > 100/min` |

### Field Selectors

| Selector | Description | Example |
|----------|-------------|---------|
| `field: value` | Exact match | `kind: server` |
| `field\|contains: value` | Contains substring | `operation_name\|contains: 'db.'` |
| `field\|startswith: value` | Starts with | `service_name\|startswith: 'api-'` |
| `field\|endswith: value` | Ends with | `operation_name\|endswith: '.get'` |
| `field\|re: regex` | Regex match | `attributes.http.url\|re: '^https://'` |

## Available Fields

### Span Fields (traces)

| Field | Type | Description |
|-------|------|-------------|
| `trace_id` | string | Unique trace identifier |
| `span_id` | string | Unique span identifier |
| `parent_span_id` | string | Parent span identifier |
| `service_name` | string | Name of the service |
| `operation_name` | string | Name of the operation |
| `kind` | enum | Span kind: server, client, producer, consumer, internal |
| `status` | enum | Span status: ok, error, unset |
| `status_message` | string | Error message if status is error |
| `duration_ms` | integer | Span duration in milliseconds |
| `start_time` | timestamp | Span start time |
| `end_time` | timestamp | Span end time |

### Common Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `attributes.http.method` | string | HTTP method (GET, POST, etc.) |
| `attributes.http.url` | string | Full request URL |
| `attributes.http.status_code` | integer | HTTP response status code |
| `attributes.http.route` | string | HTTP route pattern |
| `attributes.db.system` | string | Database system (postgres, mysql, etc.) |
| `attributes.db.statement` | string | Database query statement |
| `attributes.db.operation` | string | Database operation (SELECT, INSERT, etc.) |
| `attributes.error.type` | string | Error type or exception class |
| `attributes.error.message` | string | Error message |

## Timeframe Options

Rules can specify a timeframe for detection:

- `1m` - 1 minute
- `5m` - 5 minutes
- `15m` - 15 minutes
- `1h` - 1 hour
- `24h` - 24 hours

## Baseline Comparisons

Some rules support baseline comparisons:

```yaml
detection:
  baseline_comparison: true
  timeframe: 5m
  condition: |
    Request count deviates more than 2 standard deviations from baseline.
```

Baselines are calculated from historical data (typically 7-day rolling average at the same hour).

## Rule Severity Levels

| Level | Description | SLA Impact |
|-------|-------------|------------|
| `critical` | Immediate action required | Pages on-call |
| `high` | High priority issue | Alerts team channel |
| `medium` | Moderate issue | Creates ticket |
| `low` | Informational | Logged for review |

## Creating Custom Rules

### Example: High Error Rate on Specific Endpoint

```yaml
title: High Error Rate on Payment Endpoint
id: apm-traces-payment-errors-001
status: stable
description: Detects elevated error rate on payment processing endpoints
author: Your Team
date: 2025-01-27

logsource:
  product: apm
  service: traces

detection:
  selection:
    kind: server
    operation_name|contains: 'payment'
  timeframe: 5m
  condition: selection | aggregate by service_name where (count(status='error') / count(*)) > 0.01

fields:
  - service_name
  - operation_name
  - error_rate
  - attributes.http.status_code

falsepositives:
  - Payment provider outages

level: critical

tags:
  - payment
  - errors
  - business-critical
```

### Example: Slow Critical Path

```yaml
title: Critical Path Latency SLO Breach
id: apm-traces-critical-path-slo-001
status: stable
description: Detects when critical user-facing paths exceed SLO latency targets
author: Your Team
date: 2025-01-27

logsource:
  product: apm
  service: traces

detection:
  selection:
    kind: server
    operation_name:
      - 'POST /api/checkout'
      - 'GET /api/search'
      - 'POST /api/login'
  timeframe: 5m
  condition: selection | aggregate by operation_name where p99(duration_ms) > 500

fields:
  - operation_name
  - p99_duration_ms
  - request_count

level: high

tags:
  - slo
  - critical-path
```

## Threshold Configuration

Default thresholds can be customized per environment:

| Metric | Default | Production | Staging |
|--------|---------|------------|---------|
| P95 Latency | 2000ms | 1000ms | 5000ms |
| Error Rate | 5% | 1% | 10% |
| Service Down | 5min | 2min | 10min |

Override thresholds in your deployment configuration:

```yaml
apm_detection:
  thresholds:
    latency_p95_ms: 1000
    error_rate_percent: 1
    service_down_minutes: 2
```

## Integration

APM detection rules integrate with the Mantissa alerting system:

1. Rules are evaluated against incoming trace data
2. Matching rules generate alerts
3. Alerts are routed to configured destinations (Slack, PagerDuty, etc.)
4. Alert metadata includes trace context for investigation

## Maintenance

- Review and update thresholds quarterly
- Archive rules that no longer apply
- Document business justification for custom rules
- Test rules in staging before production deployment
