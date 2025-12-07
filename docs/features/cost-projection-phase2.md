# Cost Projection and Tracking - Phase 2 Implementation

Complete cost estimation and tracking system for detection rules with real-time projections, optimization suggestions, and actual cost monitoring.

## Overview

Phase 2 builds upon the foundation with a complete cost management system that includes:
- Advanced cost calculator with detailed breakdowns
- Real-time cost projection in detection wizard
- Cost range scenarios (low/medium/high alert volumes)
- Automated optimization suggestions
- Actual cost tracking and comparison to projections
- Cost monitoring dashboard

## Architecture

### Backend Services

1. **Cost Calculator** ([src/shared/cost/calculator.py](../../src/shared/cost/calculator.py))
   - Core calculation engine
   - Schedule expression parser
   - Optimization suggestion generator

2. **Cost Projection API** ([src/aws/api/cost_projection.py](../../src/aws/api/cost_projection.py))
   - REST endpoints for cost operations
   - Integration with Cost Calculator
   - Cost tracking data persistence

3. **Cost Tracker** (part of calculator.py)
   - Records actual execution costs
   - Compares actual vs projected
   - Generates variance reports

### Frontend Components

1. **CostProjectionV2** ([web/src/components/CostProjectionV2.jsx](../../web/src/components/CostProjectionV2.jsx))
   - Real-time cost display
   - Expandable breakdowns
   - Cost range scenarios
   - Optimization suggestions

2. **DetectionRuleWizardV3** ([web/src/components/DetectionRuleWizardV3.jsx](../../web/src/components/DetectionRuleWizardV3.jsx))
   - 4-step wizard with cost in Step 2
   - Live cost updates as schedule changes
   - Integrated CostProjectionV2 component

3. **CostTracking** ([web/src/components/CostTracking.jsx](../../web/src/components/CostTracking.jsx))
   - Dashboard for monitoring all rules
   - Actual vs projected comparison
   - Status indicators (on track/over/under budget)

## Pricing Model (AWS us-east-1, 2024)

```python
ATHENA_PRICE_PER_TB = 5.00
LAMBDA_PRICE_PER_GB_SECOND = 0.0000166667
LAMBDA_PRICE_PER_REQUEST = 0.0000002
DYNAMODB_WRITE_PRICE_PER_MILLION = 1.25
DYNAMODB_READ_PRICE_PER_MILLION = 0.25
SQS_PRICE_PER_MILLION = 0.40
SNS_PRICE_PER_MILLION = 0.50
```

## Complete Cost Calculation Example

**Scenario**: Detection rule running every 5 minutes

**Input**:
```json
{
  "query_stats": {
    "data_scanned_bytes": 262144000,
    "execution_time_ms": 2300,
    "result_count": 5
  },
  "schedule_expression": "rate(5 minutes)",
  "estimated_alerts_per_month": 10
}
```

**Calculation Process**:

1. **Parse Schedule**: `rate(5 minutes)` = 8,640 executions/month
2. **Calculate Athena Cost**:
   - Data per run: 250 MB = 0.000244 TB
   - Monthly data: 0.000244 TB × 8,640 = 2.11 TB
   - Cost: 2.11 TB × $5.00 = $10.55
3. **Calculate Lambda Cost**:
   - GB-seconds per run: (2.3s) × (0.5 GB) = 1.15
   - Monthly GB-seconds: 1.15 × 8,640 = 9,936
   - Compute: 9,936 × $0.0000166667 = $0.166
   - Requests: 8,640 × $0.0000002 = $0.001
   - Total: $0.167
4. **Calculate DynamoDB Cost**:
   - Reads: 8,640 (get rule each execution)
   - Writes: 8,660 (8,640 updates + 10 alerts + 10 dedup)
   - Read cost: (8,640 / 1M) × $0.25 = $0.002
   - Write cost: (8,660 / 1M) × $1.25 = $0.011
   - Total: $0.013
5. **Calculate Alert Delivery Cost**:
   - SQS: (10 / 1M) × $0.40 = negligible
   - Lambda: 10 × ($0.0000002 + $0.000004267) = $0.000047
   - Total: $0.000047

**Output**:
```json
{
  "breakdown": {
    "query_execution": {
      "athena": {
        "monthly_cost": 10.55
      },
      "lambda": {
        "monthly_cost": 0.17
      }
    },
    "state_storage": {
      "dynamodb": {
        "monthly_cost": 0.01
      }
    },
    "alert_delivery": {
      "monthly_cost": 0.0
    }
  },
  "total_monthly_cost": 10.73,
  "executions_per_month": 8640,
  "cost_per_execution": 0.001242
}
```

## API Reference

### POST /api/cost/project/detection

Project monthly cost for a detection rule.

**Request**:
```json
{
  "query_stats": {
    "data_scanned_bytes": 262144000,
    "execution_time_ms": 2300,
    "result_count": 5
  },
  "schedule_expression": "rate(5 minutes)",
  "estimated_alerts_per_month": 10
}
```

**Response**: See complete calculation example above

### POST /api/cost/project/query

Calculate cost for a single query execution.

**Request**:
```json
{
  "data_scanned_bytes": 262144000,
  "execution_time_ms": 2300
}
```

**Response**:
```json
{
  "athena_cost": 0.00000119,
  "lambda_cost": 0.00001922,
  "total_cost": 0.00002041,
  "data_scanned_gb": 0.244
}
```

### POST /api/cost/estimate-range

Get cost estimates for different alert volumes.

**Response**:
```json
{
  "scenarios": {
    "low": { "alerts_per_month": 5, "total_monthly_cost": 10.72 },
    "medium": { "alerts_per_month": 20, "total_monthly_cost": 10.73 },
    "high": { "alerts_per_month": 100, "total_monthly_cost": 10.75 }
  },
  "baseline_cost": 10.72,
  "worst_case_cost": 10.75
}
```

### POST /api/cost/optimizations

Get optimization suggestions.

**Response**:
```json
{
  "suggestions": [
    {
      "category": "data_scanning",
      "severity": "high",
      "title": "Large amount of data scanned",
      "description": "Query scans 1.5 GB per execution",
      "recommendation": "Add partition filters (e.g., WHERE dt >= DATE_SUB(CURRENT_DATE, 7))"
    }
  ]
}
```

### GET /api/cost/actual

Get actual costs for a rule.

**Query Parameters**:
- `user_id`: User ID
- `rule_id`: Detection rule ID
- `days`: Time period (default: 30)

**Response**:
```json
{
  "rule_id": "rule-abc-456",
  "period_days": 30,
  "executions": 8650,
  "total_cost": 10.45,
  "avg_cost_per_execution": 0.001208,
  "projected_monthly_cost": 10.45
}
```

### GET /api/cost/compare

Compare actual vs projected costs.

**Response**:
```json
{
  "rule_id": "rule-abc-456",
  "projected_monthly_cost": 10.73,
  "actual_monthly_cost": 10.45,
  "variance": -0.28,
  "variance_percent": -2.61,
  "status": "on_track"
}
```

Status values:
- `on_track`: Variance within ±20%
- `over_budget`: Variance > +20%
- `under_budget`: Variance < -20%

## Optimization Suggestions

The system automatically generates suggestions based on:

### 1. Data Scanning (High Priority)

**Trigger**: data_scanned_gb > 1.0

**Suggestion**:
```json
{
  "category": "data_scanning",
  "severity": "high",
  "title": "Large amount of data scanned",
  "description": "Query scans 2.5 GB per execution",
  "recommendation": "Add partition filters (e.g., WHERE dt >= DATE_SUB(CURRENT_DATE, 7)) to reduce data scanned"
}
```

**Impact**: Can reduce costs by 90%+ with proper partitioning

### 2. Execution Frequency (Medium Priority)

**Trigger**: executions_per_month > 10,000

**Suggestion**:
```json
{
  "category": "frequency",
  "severity": "medium",
  "title": "High execution frequency",
  "description": "Rule executes 17,280 times per month",
  "recommendation": "Consider reducing frequency if real-time detection is not critical"
}
```

**Impact**: Halving frequency cuts costs in half

### 3. Query Performance (Medium Priority)

**Trigger**: execution_time_ms > 5000

**Suggestion**:
```json
{
  "category": "performance",
  "severity": "medium",
  "title": "Slow query execution",
  "description": "Query takes 7.5 seconds to execute",
  "recommendation": "Optimize query with appropriate filters, partitions, and column selection"
}
```

**Impact**: Faster queries = lower Lambda costs

### 4. High Cost Alert

**Trigger**: total_monthly_cost > $10.00

**Suggestion**:
```json
{
  "category": "cost",
  "severity": "high",
  "title": "High monthly cost",
  "description": "Projected monthly cost is $42.50",
  "recommendation": "Consider optimizing query or reducing execution frequency"
}
```

## User Workflows

### Workflow 1: Create Detection with Cost Awareness

See [complete walkthrough](../../docs/features/cost-projection.md#user-workflows)

Key steps:
1. Run ad-hoc query → Get query stats
2. Click "Save as Detection"
3. Configure schedule → See live cost projection
4. Review optimization suggestions
5. Adjust schedule if needed
6. Create rule with projected cost stored

### Workflow 2: Monitor Costs

See [Cost Tracking Dashboard](../../docs/features/cost-projection.md#workflow-2-monitor-and-optimize-costs)

Key steps:
1. View dashboard with all rules
2. Identify over-budget rules
3. Investigate causes (data growth, etc.)
4. Apply optimizations
5. Monitor improvements

## Database Schema

### cost-tracking Table

```
Partition Key: user_id (String)
Sort Key: record_id (String) = "{rule_id}#{timestamp}"

Attributes:
{
  "user_id": "user-123",
  "record_id": "rule-abc-456#2024-11-27T10:30:00.000Z",
  "rule_id": "rule-abc-456",
  "timestamp": "2024-11-27T10:30:00Z",
  "data_scanned_bytes": 260000000,
  "execution_time_ms": 2250,
  "athena_cost": 0.00000117,
  "lambda_cost": 0.00001875,
  "total_cost": 0.00001992
}

GSI: rule-costs-index
  PK: rule_id
  SK: timestamp

TTL: timestamp + 90 days
```

## Testing

### Backend Tests

```python
def test_calculate_detection_cost():
    calculator = CostCalculator()

    result = calculator.calculate_detection_cost(
        query_stats={
            'data_scanned_bytes': 262144000,
            'execution_time_ms': 2300,
            'result_count': 5
        },
        schedule_expression='rate(5 minutes)',
        estimated_alerts_per_month=10
    )

    assert result['total_monthly_cost'] > 0
    assert result['executions_per_month'] == 8640
    assert 'breakdown' in result

def test_optimization_suggestions():
    calculator = CostCalculator()

    suggestions = calculator.get_optimization_suggestions(
        query_stats={'data_scanned_bytes': 2147483648, 'execution_time_ms': 6000},
        cost_breakdown={'total_monthly_cost': 42.50, 'executions_per_month': 8640}
    )

    assert len(suggestions) > 0
    high_severity = [s for s in suggestions if s['severity'] == 'high']
    assert len(high_severity) > 0
```

### Frontend Tests

```javascript
test('CostProjectionV2 displays cost breakdown', async () => {
  render(
    <CostProjectionV2
      queryStats={mockQueryStats}
      scheduleExpression="rate(5 minutes)"
      estimatedAlerts={10}
    />
  );

  await waitFor(() => {
    expect(screen.getByText(/Projected Monthly Cost/)).toBeInTheDocument();
    expect(screen.getByText(/\$10\.73/)).toBeInTheDocument();
  });
});
```

## Implementation Files

- [calculator.py](../../src/shared/cost/calculator.py) - Core calculation engine (560 lines)
- [cost_projection.py](../../src/aws/api/cost_projection.py) - API endpoints (170 lines)
- [CostProjectionV2.jsx](../../web/src/components/CostProjectionV2.jsx) - UI component (320 lines)
- [DetectionRuleWizardV3.jsx](../../web/src/components/DetectionRuleWizardV3.jsx) - Wizard integration (420 lines)
- [CostTracking.jsx](../../web/src/components/CostTracking.jsx) - Monitoring dashboard (280 lines)

## Future Enhancements

1. **Cost Alerts**: Email notifications when exceeding budget
2. **Auto-optimization**: Automatically adjust schedules to stay within budget
3. **Cost Forecasting**: Predict future costs based on data growth trends
4. **Budget Management**: Set per-rule or total budgets with enforcement
5. **Cost Attribution**: Tag-based cost allocation for multi-team environments

## Related Documentation

- [Phase 1 Documentation](./cost-projection.md)
- [System Integration](../architecture/system-integration.md)
- [Detection Rules](./query-to-rule-conversion.md)
