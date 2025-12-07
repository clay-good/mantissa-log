# Cost Projection Feature

Real-time cost estimation for detection rules based on query performance metrics and execution frequency.

## Overview

The Cost Projection feature provides users with accurate monthly cost estimates when creating detection rules. This helps users make informed decisions about detection frequency and optimization.

## Implementation

### Backend Components

#### 1. Cost Calculator ([src/shared/utils/cost_calculator.py](../../src/shared/utils/cost_calculator.py))

Python module for calculating AWS service costs:

**Classes:**
- `QueryMetrics` - Dataclass for query execution metrics
- `ScheduleConfig` - Dataclass for schedule configuration
- `CostBreakdown` - Dataclass for detailed cost breakdown
- `CostCalculator` - Main calculator class

**Cost Components:**
- Athena query costs: $5 per TB scanned
- Lambda execution costs: $0.0000166667 per GB-second
- DynamoDB write costs: $1.25 per million writes
- SNS/Alert delivery costs: $0.50 per million requests

**Example Usage:**
```python
from cost_calculator import CostCalculator, QueryMetrics, ScheduleConfig

# Create calculator
calculator = CostCalculator()

# Define metrics
metrics = QueryMetrics(
    data_scanned_bytes=262144000,  # 250 MB
    execution_time_ms=2300,
    result_count=15
)

# Define schedule
schedule = ScheduleConfig(interval_minutes=5)  # Every 5 minutes

# Calculate costs
breakdown = calculator.calculate_total_cost(
    query_metrics=metrics,
    schedule=schedule,
    lambda_memory_mb=512,
    estimated_alerts_per_month=10,
    alert_destinations=['slack', 'email']
)

# Format report
report = calculator.format_cost_report(breakdown, metrics, schedule)
print(f"Total Monthly Cost: ${report['total_monthly_cost']}")
```

#### 2. Cost Estimation API ([src/aws/api/cost_estimation.py](../../src/aws/api/cost_estimation.py))

Lambda function exposing cost calculation via HTTP API.

**Endpoint:** `POST /api/cost-estimate`

**Request:**
```json
{
  "queryMetrics": {
    "dataScannedBytes": 262144000,
    "executionTimeMs": 2300,
    "resultCount": 15
  },
  "schedule": "rate(5 minutes)",
  "lambdaMemoryMb": 512,
  "estimatedAlertsPerMonth": 10,
  "alertDestinations": ["slack", "email"]
}
```

**Response:**
```json
{
  "total_monthly_cost": 0.14,
  "breakdown": {
    "query_execution": {
      "cost": 0.11,
      "data_scanned_mb": 250.0,
      "runs_per_month": 8640,
      "description": "8,640 executions × 250.00MB"
    },
    "lambda_execution": {
      "cost": 0.02,
      "avg_duration_sec": 2.3,
      "memory_mb": 512,
      "executions": 8640,
      "description": "2.30s @ 512MB"
    },
    "state_storage": {
      "cost": 0.01,
      "write_requests": 8640,
      "description": "8,640 DynamoDB writes"
    },
    "alert_delivery": {
      "cost": 0.0,
      "description": "Estimated based on alert frequency"
    }
  },
  "notes": [
    "Costs are estimates based on AWS US-East-1 pricing",
    "Actual costs may vary based on data growth and alert frequency",
    "Query optimization can significantly reduce costs"
  ]
}
```

### Frontend Components

#### 1. CostProjection Component ([web/src/components/CostProjection.jsx](../../web/src/components/CostProjection.jsx))

Displays cost breakdown with monochrome design.

**Features:**
- Total monthly cost display
- Detailed cost breakdown with progress bars
- High-cost warning indicator
- Cost-efficient badge for low costs
- Informational notes
- Loading state animation
- Dark mode support

**Props:**
```typescript
{
  costData: {
    total_monthly_cost: number;
    breakdown: object;
    notes: string[];
  };
  loading: boolean;
}
```

**Design:**
- Monochrome color scheme (no color-coding)
- Clean typography and spacing
- Animated progress bars
- Responsive layout

#### 2. Cost Projection Hook ([web/src/hooks/useCostProjection.js](../../web/src/hooks/useCostProjection.js))

React Query hook for fetching cost estimates.

**Usage:**
```javascript
import { useCostProjection } from '../hooks/useCostProjection';

const { data: costData, isLoading } = useCostProjection({
  queryMetrics: {
    dataScannedBytes: 262144000,
    executionTimeMs: 2300,
    resultCount: 15
  },
  schedule: 'rate(5 minutes)',
  alertDestinations: ['slack', 'email'],
  enabled: true
});
```

**Features:**
- Automatic refetch on param changes
- 5-minute cache time
- Client-side fallback calculation
- Error handling

#### 3. DetectionRuleWizardV2 ([web/src/components/DetectionRuleWizardV2.jsx](../../web/src/components/DetectionRuleWizardV2.jsx))

Updated wizard with integrated cost projection.

**New Features:**
- Step 2 includes live cost estimation
- Cost updates when schedule changes
- Monochrome design throughout
- Smooth animations
- Dark mode support

## Cost Calculation Details

### Athena Query Costs

```
data_scanned_tb = data_scanned_bytes / (1024^4)
total_tb_per_month = data_scanned_tb * executions_per_month
query_cost = total_tb_per_month * $5.00
```

**Example:**
- Data scanned: 250 MB per query
- Execution: Every 5 minutes (8,640 times/month)
- Total data: 250 MB × 8,640 = 2,160 GB = 2.11 TB
- Cost: 2.11 TB × $5 = $10.55/month

### Lambda Execution Costs

```
execution_time_seconds = execution_time_ms / 1000
memory_gb = memory_mb / 1024
gb_seconds = execution_time_seconds * memory_gb
compute_cost = gb_seconds * executions_per_month * $0.0000166667
request_cost = executions_per_month * $0.0000002
total_lambda_cost = compute_cost + request_cost
```

**Example:**
- Duration: 2.3 seconds
- Memory: 512 MB (0.5 GB)
- Executions: 8,640/month
- GB-seconds: 2.3s × 0.5 GB = 1.15 GB-seconds
- Compute: 1.15 × 8,640 × $0.0000166667 = $0.17
- Requests: 8,640 × $0.0000002 = $0.001
- Total: $0.17/month

### DynamoDB Storage Costs

```
total_writes = executions_per_month
storage_cost = total_writes * $0.00000125
```

**Example:**
- Executions: 8,640/month
- Cost: 8,640 × $0.00000125 = $0.01/month

### Total Cost Example

For a detection rule running every 5 minutes:

```
Query Execution:    $10.55
Lambda Execution:   $ 0.17
State Storage:      $ 0.01
Alert Delivery:     $ 0.00
------------------------
Total:              $10.73/month
```

## Cost Optimization Strategies

### 1. Optimize Query Efficiency

**Partition Pruning:**
```sql
-- Bad: Scans all data
SELECT * FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'

-- Good: Only scans last 24 hours
SELECT * FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND year = '2024' AND month = '11' AND day = '27'
```

**Savings:** 99% reduction in data scanned if querying 1 day vs 1 year

### 2. Adjust Detection Frequency

| Schedule | Executions/Month | Cost Multiplier |
|----------|------------------|-----------------|
| Every 5 min | 8,640 | 1.0x |
| Every 15 min | 2,880 | 0.33x |
| Every 30 min | 1,440 | 0.17x |
| Hourly | 720 | 0.08x |
| Every 6 hours | 120 | 0.01x |

**Recommendation:** Match frequency to threat severity
- Critical threats: 5-15 minutes
- High threats: 30 minutes - 1 hour
- Medium threats: 1-6 hours
- Low threats: Daily

### 3. Use Result Caching

Enable Athena query result caching for repeated queries:
- Saves on data scanning costs
- 24-hour cache TTL
- Free for cached results

### 4. Aggregate Before Alerting

Instead of alerting on every match, aggregate:

```yaml
# Expensive: Alert on every failed login
threshold: 1

# Optimized: Alert only if 10+ in one run
threshold: 10
```

This doesn't reduce query costs but reduces alert delivery overhead.

## Monitoring Actual Costs

### CloudWatch Metrics

Track actual costs vs. projections:

```python
# Log actual query metrics
cloudwatch.put_metric_data(
    Namespace='MantissaLog',
    MetricData=[
        {
            'MetricName': 'QueryDataScanned',
            'Value': data_scanned_bytes,
            'Unit': 'Bytes',
            'Dimensions': [
                {'Name': 'RuleName', 'Value': rule_name}
            ]
        },
        {
            'MetricName': 'QueryDuration',
            'Value': execution_time_ms,
            'Unit': 'Milliseconds',
            'Dimensions': [
                {'Name': 'RuleName', 'Value': rule_name}
            ]
        }
    ]
)
```

### Cost Alerts

Set up budget alerts in AWS Budgets:

```python
# Alert if monthly cost exceeds projection by 20%
budgets.create_budget(
    AccountId='123456789012',
    Budget={
        'BudgetName': f'mantissa-log-{rule_name}',
        'BudgetLimit': {
            'Amount': str(projected_cost * 1.2),
            'Unit': 'USD'
        },
        'TimeUnit': 'MONTHLY',
        'BudgetType': 'COST'
    },
    NotificationsWithSubscribers=[
        {
            'Notification': {
                'NotificationType': 'ACTUAL',
                'ComparisonOperator': 'GREATER_THAN',
                'Threshold': 100.0
            },
            'Subscribers': [
                {
                    'SubscriptionType': 'EMAIL',
                    'Address': 'admin@company.com'
                }
            ]
        }
    ]
)
```

## UI Design

### Monochrome Cost Display

The cost projection uses a monochrome design with:

**Light Mode:**
- White background
- Black text for emphasis
- Gray progress bars
- Subtle borders

**Dark Mode:**
- Dark gray background
- White text
- Light gray progress bars
- High contrast borders

**No Color-Coding:**
- High costs indicated by icon, not color
- Progress bars use grayscale
- Status indicators use shapes/icons

### Animation

- Fade-in on load
- Smooth progress bar animations
- Slide transitions between steps

## Testing

### Unit Tests

```python
# Test cost calculator
def test_query_cost_calculation():
    calculator = CostCalculator()
    cost = calculator.calculate_query_cost(
        data_scanned_bytes=250 * 1024 * 1024,  # 250 MB
        executions_per_month=8640
    )
    assert cost > 0
    assert cost < 1.0  # Should be less than $1 for 250MB
```

### Integration Tests

```python
# Test API endpoint
def test_cost_estimation_api():
    response = client.post('/api/cost-estimate', json={
        'queryMetrics': {
            'dataScannedBytes': 262144000,
            'executionTimeMs': 2300,
            'resultCount': 15
        },
        'schedule': 'rate(5 minutes)'
    })

    assert response.status_code == 200
    data = response.json()
    assert 'total_monthly_cost' in data
    assert data['total_monthly_cost'] > 0
```

## Future Enhancements

1. **Historical Cost Tracking**
   - Track actual vs. projected costs over time
   - Display cost trends
   - Identify cost anomalies

2. **Cost Optimization Suggestions**
   - Automatic recommendations
   - Query rewriting suggestions
   - Schedule optimization

3. **Cost Budgets**
   - Set monthly budgets per rule
   - Alert when approaching limit
   - Automatic rule disabling

4. **Multi-Cloud Cost Comparison**
   - Compare AWS, GCP, Azure costs
   - Recommend most cost-effective platform
   - Migration cost analysis

## Documentation

- [Cost Calculator Source](../../src/shared/utils/cost_calculator.py)
- [Cost Estimation API](../../src/aws/api/cost_estimation.py)
- [CostProjection Component](../../web/src/components/CostProjection.jsx)
- [Detection Rule Wizard V2](../../web/src/components/DetectionRuleWizardV2.jsx)
