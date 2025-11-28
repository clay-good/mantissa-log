import { useState, useEffect } from 'react';
import { DollarSign, TrendingUp, AlertTriangle, Info } from 'lucide-react';

export default function CostProjectionV2({ queryStats, scheduleExpression, estimatedAlerts = 10, onChange }) {
  const [costData, setCostData] = useState(null);
  const [costRange, setCostRange] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showBreakdown, setShowBreakdown] = useState(false);

  useEffect(() => {
    if (queryStats && scheduleExpression) {
      calculateCost();
    }
  }, [queryStats, scheduleExpression, estimatedAlerts]);

  const calculateCost = async () => {
    try {
      setLoading(true);
      setError(null);

      const costResponse = await fetch('/api/cost/project/detection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query_stats: queryStats,
          schedule_expression: scheduleExpression,
          estimated_alerts_per_month: estimatedAlerts
        })
      });

      if (!costResponse.ok) throw new Error('Failed to calculate cost');
      const cost = await costResponse.json();
      setCostData(cost);

      const rangeResponse = await fetch('/api/cost/estimate-range', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query_stats: queryStats,
          schedule_expression: scheduleExpression
        })
      });

      if (rangeResponse.ok) {
        const range = await rangeResponse.json();
        setCostRange(range);
      }

      const suggestionsResponse = await fetch('/api/cost/optimizations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query_stats: queryStats,
          cost_breakdown: cost
        })
      });

      if (suggestionsResponse.ok) {
        const data = await suggestionsResponse.json();
        setSuggestions(data.suggestions || []);
      }

      if (onChange) onChange(cost);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 6
    }).format(amount);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high':
        return 'text-mono-900 dark:text-mono-100';
      case 'medium':
        return 'text-mono-700 dark:text-mono-300';
      default:
        return 'text-mono-600 dark:text-mono-400';
    }
  };

  const getCostStatusColor = (cost) => {
    if (cost > 10) return 'text-mono-900 dark:text-mono-100';
    if (cost > 5) return 'text-mono-700 dark:text-mono-300';
    return 'text-mono-600 dark:text-mono-400';
  };

  if (loading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center p-8">
          <div className="animate-spin h-8 w-8 border-2 border-mono-300 dark:border-mono-700 border-t-mono-900 dark:border-t-mono-100 rounded-full"></div>
          <span className="ml-3 text-mono-600 dark:text-mono-400">Calculating cost projection...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700">
        <div className="flex items-center">
          <AlertTriangle className="w-5 h-5 text-mono-700 dark:text-mono-300" />
          <span className="ml-2 text-sm text-mono-700 dark:text-mono-300">{error}</span>
        </div>
      </div>
    );
  }

  if (!costData) {
    return null;
  }

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 flex items-center">
            <DollarSign className="w-5 h-5 mr-2" />
            Projected Monthly Cost
          </h3>
          <button
            onClick={() => setShowBreakdown(!showBreakdown)}
            className="text-sm text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
          >
            {showBreakdown ? 'Hide' : 'Show'} Breakdown
          </button>
        </div>

        <div className="mb-6">
          <div className={`text-4xl font-bold ${getCostStatusColor(costData.total_monthly_cost)}`}>
            {formatCurrency(costData.total_monthly_cost)}
            <span className="text-sm text-mono-600 dark:text-mono-400 font-normal ml-2">/month</span>
          </div>
          <div className="text-sm text-mono-600 dark:text-mono-400 mt-2">
            {costData.executions_per_month.toLocaleString()} executions per month
          </div>
          <div className="text-sm text-mono-600 dark:text-mono-400">
            {formatCurrency(costData.cost_per_execution)} per execution
          </div>
        </div>

        {showBreakdown && (
          <div className="space-y-4 pt-4 border-t border-mono-300 dark:border-mono-700">
            <div>
              <h4 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">Query Execution</h4>
              <div className="space-y-2 ml-4">
                <div className="flex justify-between text-sm">
                  <span className="text-mono-700 dark:text-mono-300">Athena</span>
                  <div className="text-right">
                    <div className="text-mono-900 dark:text-mono-100 font-mono">
                      {formatCurrency(costData.breakdown.query_execution.athena.monthly_cost)}
                    </div>
                    <div className="text-xs text-mono-600 dark:text-mono-400">
                      {formatBytes(costData.breakdown.query_execution.athena.data_scanned_bytes)} scanned per run
                    </div>
                  </div>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-mono-700 dark:text-mono-300">Lambda</span>
                  <div className="text-right">
                    <div className="text-mono-900 dark:text-mono-100 font-mono">
                      {formatCurrency(costData.breakdown.query_execution.lambda.monthly_cost)}
                    </div>
                    <div className="text-xs text-mono-600 dark:text-mono-400">
                      {costData.breakdown.query_execution.lambda.execution_time_ms}ms avg, {costData.breakdown.query_execution.lambda.memory_mb}MB
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">State Storage</h4>
              <div className="space-y-2 ml-4">
                <div className="flex justify-between text-sm">
                  <span className="text-mono-700 dark:text-mono-300">DynamoDB</span>
                  <div className="text-right">
                    <div className="text-mono-900 dark:text-mono-100 font-mono">
                      {formatCurrency(costData.breakdown.state_storage.dynamodb.monthly_cost)}
                    </div>
                    <div className="text-xs text-mono-600 dark:text-mono-400">
                      {costData.breakdown.state_storage.dynamodb.read_requests.toLocaleString()} reads, {costData.breakdown.state_storage.dynamodb.write_requests.toLocaleString()} writes
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">Alert Delivery</h4>
              <div className="space-y-2 ml-4">
                <div className="flex justify-between text-sm">
                  <span className="text-mono-700 dark:text-mono-300">SQS + Lambda</span>
                  <div className="text-right">
                    <div className="text-mono-900 dark:text-mono-100 font-mono">
                      {formatCurrency(costData.breakdown.alert_delivery.monthly_cost)}
                    </div>
                    <div className="text-xs text-mono-600 dark:text-mono-400">
                      Assumes {costData.breakdown.alert_delivery.estimated_alerts} alerts/month
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {costRange && (
        <div className="card">
          <h4 className="font-semibold text-mono-900 dark:text-mono-100 mb-3 flex items-center">
            <TrendingUp className="w-4 h-4 mr-2" />
            Cost Range Scenarios
          </h4>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Low</div>
              <div className="text-lg font-semibold text-mono-900 dark:text-mono-100">
                {formatCurrency(costRange.scenarios.low.total_monthly_cost)}
              </div>
              <div className="text-xs text-mono-600 dark:text-mono-400">
                {costRange.scenarios.low.alerts_per_month} alerts/mo
              </div>
            </div>
            <div className="text-center">
              <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Medium</div>
              <div className="text-lg font-semibold text-mono-900 dark:text-mono-100">
                {formatCurrency(costRange.scenarios.medium.total_monthly_cost)}
              </div>
              <div className="text-xs text-mono-600 dark:text-mono-400">
                {costRange.scenarios.medium.alerts_per_month} alerts/mo
              </div>
            </div>
            <div className="text-center">
              <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">High</div>
              <div className="text-lg font-semibold text-mono-900 dark:text-mono-100">
                {formatCurrency(costRange.scenarios.high.total_monthly_cost)}
              </div>
              <div className="text-xs text-mono-600 dark:text-mono-400">
                {costRange.scenarios.high.alerts_per_month} alerts/mo
              </div>
            </div>
          </div>
        </div>
      )}

      {suggestions.length > 0 && (
        <div className="card bg-mono-100 dark:bg-mono-850">
          <h4 className="font-semibold text-mono-900 dark:text-mono-100 mb-3 flex items-center">
            <Info className="w-4 h-4 mr-2" />
            Optimization Suggestions
          </h4>
          <div className="space-y-3">
            {suggestions.map((suggestion, index) => (
              <div
                key={index}
                className="p-3 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg"
              >
                <div className="flex items-start justify-between mb-1">
                  <div className={`font-semibold text-sm ${getSeverityColor(suggestion.severity)}`}>
                    {suggestion.title}
                  </div>
                  <div className="text-xs text-mono-600 dark:text-mono-400 uppercase">
                    {suggestion.severity}
                  </div>
                </div>
                <div className="text-sm text-mono-700 dark:text-mono-300 mb-2">
                  {suggestion.description}
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400 bg-mono-100 dark:bg-mono-850 p-2 rounded border border-mono-300 dark:border-mono-700">
                  {suggestion.recommendation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-xs text-mono-600 dark:text-mono-400 p-3 bg-mono-100 dark:bg-mono-850 rounded-lg border border-mono-300 dark:border-mono-700">
        <strong>Note:</strong> Actual costs may vary based on data growth, alert frequency, and query optimization.
        Pricing based on AWS us-east-1 as of 2024.
      </div>
    </div>
  );
}
