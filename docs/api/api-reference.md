# API Reference

This document provides complete API reference for Mantissa Log.

## Base URL

```
https://{api-id}.execute-api.{region}.amazonaws.com/prod
```

Get your API endpoint from deployment outputs:

```bash
API_ENDPOINT=$(cat terraform-outputs.json | jq -r '.api_endpoint.value')
```

## Authentication

All API requests require authentication using JWT tokens from AWS Cognito.

### Obtaining a Token

**1. Get Cognito credentials from deployment:**

```bash
USER_POOL_ID=$(cat terraform-outputs.json | jq -r '.user_pool_id.value')
CLIENT_ID=$(cat terraform-outputs.json | jq -r '.user_pool_client_id.value')
```

**2. Authenticate with Cognito:**

```bash
aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id $CLIENT_ID \
  --auth-parameters USERNAME=user@example.com,PASSWORD=YourPassword123! \
  --query 'AuthenticationResult.IdToken' \
  --output text
```

**3. Use token in requests:**

```bash
TOKEN="eyJraWQiOiJ..."

curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me failed logins"}'
```

### Token Refresh

Tokens expire after 1 hour. Use the refresh token to get a new token:

```bash
REFRESH_TOKEN="your-refresh-token"

aws cognito-idp initiate-auth \
  --auth-flow REFRESH_TOKEN_AUTH \
  --client-id $CLIENT_ID \
  --auth-parameters REFRESH_TOKEN=$REFRESH_TOKEN \
  --query 'AuthenticationResult.IdToken' \
  --output text
```

### Authorization Header Format

```
Authorization: Bearer {id-token}
```

## Query Endpoints

### POST /query

Generate SQL from natural language question.

**Request:**

```json
{
  "question": "Show me failed login attempts in the last hour",
  "session_id": "optional-session-id",
  "execute": false,
  "include_explanation": false
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| question | string | Yes | Natural language question |
| session_id | string | No | Session ID for conversational queries |
| execute | boolean | No | Execute query immediately (default: false) |
| include_explanation | boolean | No | Include SQL explanation (default: false) |

**Response:**

```json
{
  "query_id": "q-abc123def456",
  "sql": "SELECT eventtime, useridentity.principalid, sourceipaddress FROM cloudtrail WHERE eventname = 'ConsoleLogin' AND errorcode IS NOT NULL AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '1' HOUR) AS VARCHAR)",
  "explanation": "This query selects failed console login attempts...",
  "warnings": [],
  "session_id": "session-123",
  "results": null
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me failed login attempts in the last hour",
    "execute": false,
    "include_explanation": true
  }'
```

**Response with execution:**

```bash
curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me root account activity today",
    "execute": true
  }'
```

```json
{
  "query_id": "q-xyz789",
  "sql": "SELECT * FROM cloudtrail WHERE useridentity.type = 'Root' AND year = '2024' AND month = '01' AND day = '15'",
  "results": {
    "status": "SUCCEEDED",
    "rows": [
      {
        "eventtime": "2024-01-15T10:30:00Z",
        "eventname": "ConsoleLogin",
        "sourceipaddress": "203.0.113.42"
      }
    ],
    "row_count": 1,
    "data_scanned_bytes": 1048576
  }
}
```

### POST /query/{query_id}/execute

Execute a previously generated SQL query.

**Request:**

No request body required.

**Response:**

```json
{
  "query_id": "q-abc123def456",
  "status": "RUNNING",
  "execution_id": "exec-xyz789"
}
```

**Example:**

```bash
QUERY_ID="q-abc123def456"

curl -X POST "$API_ENDPOINT/query/$QUERY_ID/execute" \
  -H "Authorization: Bearer $TOKEN"
```

### GET /query/{query_id}/results

Get results of an executed query.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| page | integer | No | Page number (default: 1) |
| page_size | integer | No | Results per page (default: 100, max: 1000) |

**Response:**

```json
{
  "query_id": "q-abc123def456",
  "status": "SUCCEEDED",
  "results": {
    "columns": [
      {"name": "eventtime", "type": "varchar"},
      {"name": "eventname", "type": "varchar"},
      {"name": "sourceipaddress", "type": "varchar"}
    ],
    "rows": [
      ["2024-01-15T10:30:00Z", "ConsoleLogin", "203.0.113.42"],
      ["2024-01-15T10:31:00Z", "ConsoleLogin", "203.0.113.43"]
    ],
    "row_count": 2,
    "data_scanned_bytes": 1048576,
    "execution_time_ms": 1234
  },
  "pagination": {
    "page": 1,
    "page_size": 100,
    "total_rows": 2,
    "total_pages": 1
  }
}
```

**Example:**

```bash
curl -X GET "$API_ENDPOINT/query/$QUERY_ID/results?page=1&page_size=50" \
  -H "Authorization: Bearer $TOKEN"
```

**Status Values:**

- `QUEUED`: Query submitted but not started
- `RUNNING`: Query executing
- `SUCCEEDED`: Query completed successfully
- `FAILED`: Query failed
- `CANCELLED`: Query was cancelled

## Rules Endpoints

### GET /rules

List all detection rules.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| enabled | boolean | No | Filter by enabled status |
| severity | string | No | Filter by severity (critical, high, medium, low, info) |
| category | string | No | Filter by category |
| page | integer | No | Page number |
| page_size | integer | No | Results per page |

**Response:**

```json
{
  "rules": [
    {
      "rule_id": "root-account-activity",
      "name": "Root Account Activity",
      "description": "Detects any use of AWS root account credentials",
      "enabled": true,
      "severity": "critical",
      "category": "access",
      "last_modified": "2024-01-15T10:00:00Z",
      "last_execution": "2024-01-15T14:30:00Z",
      "execution_count": 1234,
      "alert_count": 5
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_rules": 25,
    "total_pages": 1
  }
}
```

**Example:**

```bash
curl -X GET "$API_ENDPOINT/rules?enabled=true&severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

### GET /rules/{rule_id}

Get details of a specific rule.

**Response:**

```json
{
  "rule_id": "root-account-activity",
  "name": "Root Account Activity",
  "description": "Detects any use of AWS root account credentials",
  "enabled": true,
  "severity": "critical",
  "category": "access",
  "query": "SELECT eventtime, useridentity.principalid FROM cloudtrail WHERE useridentity.type = 'Root'",
  "threshold": {
    "count": 1,
    "window": "5m"
  },
  "metadata": {
    "mitre_attack": ["T1078.004"],
    "tags": ["aws", "cloudtrail", "root-account"]
  },
  "statistics": {
    "last_execution": "2024-01-15T14:30:00Z",
    "execution_count": 1234,
    "alert_count": 5,
    "avg_execution_time_ms": 567,
    "false_positive_rate": 0.02
  }
}
```

**Example:**

```bash
RULE_ID="root-account-activity"

curl -X GET "$API_ENDPOINT/rules/$RULE_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### POST /rules

Create a new detection rule.

**Request:**

```json
{
  "name": "High Error Rate",
  "description": "Detects elevated error rates in application logs",
  "enabled": true,
  "severity": "high",
  "category": "application",
  "query": "SELECT COUNT(*) as errors FROM app_logs WHERE level = 'ERROR' AND timestamp > CURRENT_TIMESTAMP - INTERVAL '5' MINUTE",
  "threshold": {
    "count": 100,
    "window": "5m"
  },
  "metadata": {
    "tags": ["application", "errors"]
  }
}
```

**Response:**

```json
{
  "rule_id": "high-error-rate",
  "name": "High Error Rate",
  "created": "2024-01-15T15:00:00Z",
  "status": "created"
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/rules" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High Error Rate",
    "description": "Detects elevated error rates",
    "enabled": true,
    "severity": "high",
    "category": "application",
    "query": "SELECT COUNT(*) FROM app_logs WHERE level = '\''ERROR'\''",
    "threshold": {
      "count": 100,
      "window": "5m"
    }
  }'
```

### PUT /rules/{rule_id}

Update an existing rule.

**Request:**

```json
{
  "enabled": false,
  "threshold": {
    "count": 200,
    "window": "10m"
  }
}
```

**Response:**

```json
{
  "rule_id": "high-error-rate",
  "updated": "2024-01-15T15:05:00Z",
  "status": "updated"
}
```

**Example:**

```bash
curl -X PUT "$API_ENDPOINT/rules/$RULE_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "threshold": {
      "count": 200,
      "window": "10m"
    }
  }'
```

### DELETE /rules/{rule_id}

Delete a rule.

**Response:**

```json
{
  "rule_id": "high-error-rate",
  "deleted": "2024-01-15T15:10:00Z",
  "status": "deleted"
}
```

**Example:**

```bash
curl -X DELETE "$API_ENDPOINT/rules/$RULE_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### POST /rules/{rule_id}/enable

Enable a disabled rule.

**Response:**

```json
{
  "rule_id": "high-error-rate",
  "enabled": true,
  "updated": "2024-01-15T15:15:00Z"
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/rules/$RULE_ID/enable" \
  -H "Authorization: Bearer $TOKEN"
```

### POST /rules/{rule_id}/disable

Disable an enabled rule.

**Response:**

```json
{
  "rule_id": "high-error-rate",
  "enabled": false,
  "updated": "2024-01-15T15:20:00Z"
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/rules/$RULE_ID/disable" \
  -H "Authorization: Bearer $TOKEN"
```

### POST /rules/{rule_id}/test

Test run a rule without generating alerts.

**Request:**

```json
{
  "time_range": {
    "start": "2024-01-15T00:00:00Z",
    "end": "2024-01-15T23:59:59Z"
  }
}
```

**Response:**

```json
{
  "rule_id": "high-error-rate",
  "test_execution_id": "test-xyz789",
  "matches": 3,
  "sample_results": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "error_count": 150
    }
  ],
  "execution_time_ms": 1234,
  "data_scanned_bytes": 1048576,
  "would_alert": true
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/rules/$RULE_ID/test" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "time_range": {
      "start": "2024-01-15T00:00:00Z",
      "end": "2024-01-15T23:59:59Z"
    }
  }'
```

## Alerts Endpoints

### GET /alerts

List alerts.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| severity | string | No | Filter by severity |
| status | string | No | Filter by status (open, acknowledged, resolved) |
| start_time | string | No | Filter by time range start (ISO 8601) |
| end_time | string | No | Filter by time range end (ISO 8601) |
| rule_id | string | No | Filter by rule |
| page | integer | No | Page number |
| page_size | integer | No | Results per page |

**Response:**

```json
{
  "alerts": [
    {
      "alert_id": "alert-20240115-001",
      "title": "Root Account Activity",
      "severity": "critical",
      "category": "access",
      "status": "open",
      "rule_name": "Root Account Activity",
      "timestamp": "2024-01-15T10:30:00Z",
      "source": "cloudtrail",
      "evidence": {
        "user": "root",
        "ip": "203.0.113.42",
        "action": "ConsoleLogin"
      }
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_alerts": 123,
    "total_pages": 3
  }
}
```

**Example:**

```bash
curl -X GET "$API_ENDPOINT/alerts?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN"
```

### GET /alerts/{alert_id}

Get details of a specific alert.

**Response:**

```json
{
  "alert_id": "alert-20240115-001",
  "title": "Root Account Activity",
  "description": "Root account was used to login to the AWS console",
  "severity": "critical",
  "category": "access",
  "status": "open",
  "rule_name": "Root Account Activity",
  "rule_id": "root-account-activity",
  "timestamp": "2024-01-15T10:30:00Z",
  "source": "cloudtrail",
  "evidence": {
    "eventtime": "2024-01-15T10:30:00Z",
    "eventname": "ConsoleLogin",
    "useridentity": {
      "type": "Root",
      "principalid": "123456789012"
    },
    "sourceipaddress": "203.0.113.42",
    "useragent": "Mozilla/5.0..."
  },
  "enrichment": {
    "geolocation": {
      "country": "United States",
      "city": "San Francisco",
      "lat": 37.7749,
      "lon": -122.4194
    },
    "related_alerts": [
      {
        "alert_id": "alert-20240115-002",
        "title": "Unusual API Activity",
        "timestamp": "2024-01-15T10:35:00Z"
      }
    ]
  },
  "metadata": {
    "mitre_attack": ["T1078.004"],
    "references": []
  },
  "destinations_notified": ["slack", "pagerduty"],
  "acknowledged_by": null,
  "acknowledged_at": null,
  "resolved_by": null,
  "resolved_at": null
}
```

**Example:**

```bash
ALERT_ID="alert-20240115-001"

curl -X GET "$API_ENDPOINT/alerts/$ALERT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### POST /alerts/{alert_id}/acknowledge

Acknowledge an alert.

**Request:**

```json
{
  "note": "Investigating this alert"
}
```

**Response:**

```json
{
  "alert_id": "alert-20240115-001",
  "status": "acknowledged",
  "acknowledged_by": "user@example.com",
  "acknowledged_at": "2024-01-15T11:00:00Z"
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/alerts/$ALERT_ID/acknowledge" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "note": "Investigating this alert"
  }'
```

### POST /alerts/{alert_id}/resolve

Resolve an alert.

**Request:**

```json
{
  "resolution": "False positive - authorized root account usage",
  "note": "Confirmed with infrastructure team"
}
```

**Response:**

```json
{
  "alert_id": "alert-20240115-001",
  "status": "resolved",
  "resolved_by": "user@example.com",
  "resolved_at": "2024-01-15T11:30:00Z",
  "resolution": "False positive - authorized root account usage"
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/alerts/$ALERT_ID/resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resolution": "False positive - authorized root account usage",
    "note": "Confirmed with infrastructure team"
  }'
```

## Health Monitoring Endpoints

Endpoints for monitoring the health of log sources, triggering on-demand checks, managing configurations, and viewing volume history.

### GET /health/sources

List the current health status of all monitored log sources.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Comma-separated status filter (e.g., `SILENT,DELAYED`) |

**Response:**

```json
{
  "sources": [
    {
      "source_type": "okta",
      "status": "HEALTHY",
      "last_event_timestamp": "2026-01-15T10:05:00+00:00",
      "last_check_timestamp": "2026-01-15T10:10:00+00:00",
      "event_count_current_window": 142,
      "baseline_hourly_volume": 150.0,
      "baseline_hourly_stddev": 25.0,
      "consecutive_failures": 0,
      "config": {
        "source_type": "okta",
        "enabled": true,
        "expected_max_latency_seconds": 300,
        "silence_threshold_seconds": 3600
      }
    }
  ],
  "total": 21
}
```

**Example:**

```bash
# List all sources
curl -H "Authorization: Bearer $TOKEN" "$API_ENDPOINT/health/sources"

# Filter by status
curl -H "Authorization: Bearer $TOKEN" "$API_ENDPOINT/health/sources?status=SILENT,DELAYED"
```

### GET /health/sources/{source_type}

Get detailed health information for a specific log source.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `source_type` | string | Log source identifier (e.g., `okta`, `cloudtrail`) |

**Response:**

```json
{
  "source_type": "okta",
  "state": {
    "source_type": "okta",
    "tenant_id": "default",
    "status": "HEALTHY",
    "last_event_timestamp": "2026-01-15T10:05:00+00:00",
    "last_check_timestamp": "2026-01-15T10:10:00+00:00",
    "event_count_current_window": 142,
    "event_count_previous_window": 138,
    "baseline_hourly_volume": 150.0,
    "baseline_hourly_stddev": 25.0,
    "consecutive_failures": 0,
    "gap_windows": [],
    "metadata": {}
  },
  "config": {
    "source_type": "okta",
    "enabled": true,
    "expected_max_latency_seconds": 300,
    "silence_threshold_seconds": 3600
  },
  "baseline": {
    "hourly_volume": 150.0,
    "hourly_stddev": 25.0
  }
}
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" "$API_ENDPOINT/health/sources/okta"
```

### POST /health/sources/{source_type}/check

Trigger an on-demand health check for a specific source.

**Response:**

```json
{
  "source_type": "okta",
  "old_status": "HEALTHY",
  "new_status": "HEALTHY",
  "event_count_current": 142,
  "event_count_previous": 138,
  "last_event_timestamp": "2026-01-15T10:05:00+00:00",
  "baseline_volume": 150.0,
  "baseline_stddev": 25.0,
  "z_score": -0.32,
  "consecutive_failures": 0,
  "gap_windows": [],
  "should_alert": false,
  "detail_message": "Last event 5m ago — within expected latency"
}
```

**Example:**

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "$API_ENDPOINT/health/sources/okta/check"
```

### PUT /health/sources/{source_type}/config

Update the health monitoring configuration for a source. Merges overrides with the existing configuration.

**Request Body:**

```json
{
  "expected_max_latency_seconds": 600,
  "silence_threshold_seconds": 7200,
  "volume_anomaly_stddev_threshold": 2.5,
  "alert_destinations": ["pagerduty", "slack"]
}
```

**Response:**

```json
{
  "source_type": "okta",
  "config": {
    "source_type": "okta",
    "enabled": true,
    "expected_max_latency_seconds": 600,
    "silence_threshold_seconds": 7200,
    "volume_anomaly_stddev_threshold": 2.5,
    "alert_destinations": ["pagerduty", "slack"]
  },
  "message": "Configuration updated for okta"
}
```

**Example:**

```bash
curl -X PUT "$API_ENDPOINT/health/sources/okta/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_max_latency_seconds": 600,
    "silence_threshold_seconds": 7200
  }'
```

### GET /health/sources/{source_type}/history

Get volume history for a source over a time range.

**Query Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `start_time` | string | No | 24h ago | ISO 8601 start time |
| `end_time` | string | No | now | ISO 8601 end time |
| `granularity` | string | No | `hour` | `hour` or `day` |

**Response:**

```json
{
  "source_type": "okta",
  "start_time": "2026-01-14T10:00:00+00:00",
  "end_time": "2026-01-15T10:00:00+00:00",
  "granularity": "hour",
  "baseline": {
    "hourly_volume": 150.0,
    "hourly_stddev": 25.0
  },
  "history": [
    {"timestamp": "2026-01-14T10:00:00+00:00", "event_count": 148},
    {"timestamp": "2026-01-14T11:00:00+00:00", "event_count": 155}
  ],
  "current_state": {
    "status": "HEALTHY",
    "event_count_current_window": 142,
    "last_event_timestamp": "2026-01-15T10:05:00+00:00"
  },
  "gap_windows": []
}
```

**Example:**

```bash
# Last 24 hours, hourly granularity
curl -H "Authorization: Bearer $TOKEN" \
  "$API_ENDPOINT/health/sources/okta/history"

# Last 7 days, daily granularity
curl -H "Authorization: Bearer $TOKEN" \
  "$API_ENDPOINT/health/sources/okta/history?granularity=day&start_time=2026-01-08T00:00:00Z"
```

### POST /health/sources/{source_type}/acknowledge

Acknowledge a health alert and suppress further alerts for the specified duration.

**Request Body:**

```json
{
  "suppression_duration_seconds": 7200,
  "notes": "Investigating Okta API outage - ticket INC-1234"
}
```

**Response:**

```json
{
  "source_type": "okta",
  "acknowledged_by": "user@example.com",
  "acknowledged_at": "2026-01-15T10:15:00+00:00",
  "suppression_until": "2026-01-15T12:15:00+00:00",
  "notes": "Investigating Okta API outage - ticket INC-1234",
  "message": "Health alert for okta acknowledged. Alerts suppressed until 2026-01-15 12:15:00 UTC."
}
```

**Example:**

```bash
curl -X POST "$API_ENDPOINT/health/sources/okta/acknowledge" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "suppression_duration_seconds": 7200,
    "notes": "Investigating Okta API outage"
  }'
```

### GET /health/summary

Get an aggregate health summary across all monitored sources.

**Response:**

```json
{
  "total_sources_monitored": 21,
  "status_counts": {
    "HEALTHY": 18,
    "DELAYED": 1,
    "SILENT": 1,
    "VOLUME_ANOMALY": 0,
    "UNKNOWN": 1
  },
  "longest_unhealthy": [
    {
      "source_type": "guardduty",
      "status": "SILENT",
      "consecutive_failures": 8,
      "unhealthy_duration_seconds": 14400.0
    },
    {
      "source_type": "salesforce",
      "status": "DELAYED",
      "consecutive_failures": 2,
      "unhealthy_duration_seconds": 600.0
    }
  ],
  "approaching_silence_threshold": [
    {
      "source_type": "salesforce",
      "seconds_until_silent": 750,
      "last_event_age_seconds": 2850,
      "silence_threshold_seconds": 3600
    }
  ],
  "checked_at": "2026-01-15T10:15:00+00:00"
}
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" "$API_ENDPOINT/health/summary"
```

## Error Responses

All endpoints return errors in a consistent format.

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "severity",
      "issue": "Must be one of: critical, high, medium, low, info"
    },
    "request_id": "req-abc123"
  }
}
```

### HTTP Status Codes

| Status | Description |
|--------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid or missing token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

### Error Codes

| Code | Description |
|------|-------------|
| AUTHENTICATION_REQUIRED | Missing Authorization header |
| INVALID_TOKEN | JWT token is invalid or expired |
| INSUFFICIENT_PERMISSIONS | User lacks required permissions |
| VALIDATION_ERROR | Request validation failed |
| RESOURCE_NOT_FOUND | Requested resource doesn't exist |
| RESOURCE_ALREADY_EXISTS | Resource with same ID exists |
| QUERY_EXECUTION_FAILED | Query execution error |
| RATE_LIMIT_EXCEEDED | Too many requests |
| INTERNAL_ERROR | Server error |

### Example Error Responses

**401 Unauthorized:**

```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "JWT token has expired",
    "request_id": "req-xyz789"
  }
}
```

**400 Bad Request:**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid query parameters",
    "details": {
      "page_size": "Must be between 1 and 1000"
    },
    "request_id": "req-abc456"
  }
}
```

**404 Not Found:**

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Alert not found",
    "details": {
      "alert_id": "alert-invalid"
    },
    "request_id": "req-def789"
  }
}
```

## Rate Limits

API requests are rate limited per user:

| Endpoint | Rate Limit |
|----------|------------|
| POST /query | 60 requests/minute |
| GET /query/{id}/results | 120 requests/minute |
| POST /rules | 10 requests/minute |
| All other endpoints | 100 requests/minute |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705329600
```

## Pagination

List endpoints support pagination:

**Request:**

```
GET /alerts?page=2&page_size=50
```

**Response:**

```json
{
  "alerts": [...],
  "pagination": {
    "page": 2,
    "page_size": 50,
    "total_items": 250,
    "total_pages": 5,
    "has_next": true,
    "has_previous": true
  }
}
```

## Complete Examples

### Query Workflow

```bash
# 1. Authenticate
TOKEN=$(aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id $CLIENT_ID \
  --auth-parameters USERNAME=user@example.com,PASSWORD=Pass123! \
  --query 'AuthenticationResult.IdToken' \
  --output text)

# 2. Generate SQL
RESPONSE=$(curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me failed logins today"}')

QUERY_ID=$(echo $RESPONSE | jq -r '.query_id')
SQL=$(echo $RESPONSE | jq -r '.sql')

echo "Generated SQL: $SQL"

# 3. Execute query
curl -X POST "$API_ENDPOINT/query/$QUERY_ID/execute" \
  -H "Authorization: Bearer $TOKEN"

# 4. Wait for completion (poll every 2 seconds)
while true; do
  STATUS=$(curl -X GET "$API_ENDPOINT/query/$QUERY_ID/results" \
    -H "Authorization: Bearer $TOKEN" \
    | jq -r '.status')

  if [ "$STATUS" = "SUCCEEDED" ]; then
    break
  elif [ "$STATUS" = "FAILED" ]; then
    echo "Query failed"
    exit 1
  fi

  sleep 2
done

# 5. Get results
curl -X GET "$API_ENDPOINT/query/$QUERY_ID/results" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.results.rows'
```

### Rule Management Workflow

```bash
# Create rule
RULE_ID=$(curl -X POST "$API_ENDPOINT/rules" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Rule",
    "description": "Test detection rule",
    "enabled": false,
    "severity": "low",
    "category": "test",
    "query": "SELECT COUNT(*) FROM cloudtrail",
    "threshold": {"count": 1, "window": "5m"}
  }' \
  | jq -r '.rule_id')

# Test rule
curl -X POST "$API_ENDPOINT/rules/$RULE_ID/test" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"time_range": {"start": "2024-01-15T00:00:00Z", "end": "2024-01-15T23:59:59Z"}}'

# Enable rule
curl -X POST "$API_ENDPOINT/rules/$RULE_ID/enable" \
  -H "Authorization: Bearer $TOKEN"

# Update threshold
curl -X PUT "$API_ENDPOINT/rules/$RULE_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"threshold": {"count": 10, "window": "10m"}}'
```

### Alert Investigation Workflow

```bash
# List recent critical alerts
curl -X GET "$API_ENDPOINT/alerts?severity=critical&status=open&page_size=10" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.alerts'

# Get alert details
ALERT_ID="alert-20240115-001"
curl -X GET "$API_ENDPOINT/alerts/$ALERT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'

# Acknowledge alert
curl -X POST "$API_ENDPOINT/alerts/$ALERT_ID/acknowledge" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"note": "Investigating"}'

# Resolve alert
curl -X POST "$API_ENDPOINT/alerts/$ALERT_ID/resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resolution": "False positive", "note": "Authorized activity"}'
```
