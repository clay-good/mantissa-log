import { useState, useEffect } from 'react';
import { DollarSign, TrendingDown, AlertTriangle, Info, ChevronDown, ChevronUp } from 'lucide-react';

export default function CostProjection({
  queryString,
  userId,
  intervalMinutes = 5,
  estimatedAlerts = 10,
  onOptimize
}) {
  const [projection, setProjection] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showBreakdown, setShowBreakdown] = useState(false);
  const [showOptimizations, setShowOptimizations] = useState(false);

  useEffect(() => {
    if (queryString && userId) {
      loadCostProjection();
    }
  }, [queryString, userId, intervalMinutes]);

  const loadCostProjection = async () => {
    setLoading(true);

    try {
      const response = await fetch('/api/cost/estimate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          query: queryString,
          interval_minutes: intervalMinutes,
          estimated_alerts_per_month: estimatedAlerts
        })
      });

      if (!response.ok) {
        throw new Error('Failed to load cost projection');
      }

      const data = await response.json();
      setProjection(data.projection);
    } catch (err) {
      console.error('Error loading cost projection:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card p-4">
        <div className="flex items-center text-mono-600 dark:text-mono-400">
          <DollarSign className="w-5 h-5 mr-2 animate-pulse" />
          <span>Calculating cost projection...</span>
        </div>
      </div>
    );
  }

  if (!projection) {
    return null;
  }

  const severityColor = getSeverityColor(projection.total_monthly_cost_usd);
  const hasOptimizations = projection.optimization_suggestions?.length > 0;

  return (
    <div className="space-y-4">
      {/* Main Cost Display */}
      <div className="card p-4">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center">
            <DollarSign className="w-5 h-5 mr-2 text-mono-600 dark:text-mono-400" />
            <h3 className="font-semibold text-mono-950 dark:text-mono-50">
              Projected Monthly Cost
            </h3>
          </div>

          <div className="text-right">
            <div className={`text-2xl font-bold font-mono ${severityColor}`}>
              ${projection.total_monthly_cost_usd.toFixed(2)}
            </div>
            <div className="text-xs text-mono-600 dark:text-mono-400">
              per month
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-3 gap-4 pt-3 border-t border-mono-200 dark:border-mono-800">
          <div>
            <div className="text-xs text-mono-600 dark:text-mono-400 mb-1">
              Data Scanned
            </div>
            <div className="text-sm font-mono text-mono-900 dark:text-mono-50">
              {projection.avg_data_scanned_mb.toFixed(0)} MB
              <span className="text-xs text-mono-500 dark:text-mono-500 ml-1">per run</span>
            </div>
          </div>

          <div>
            <div className="text-xs text-mono-600 dark:text-mono-400 mb-1">
              Executions
            </div>
            <div className="text-sm font-mono text-mono-900 dark:text-mono-50">
              {projection.executions_per_month.toLocaleString()}
              <span className="text-xs text-mono-500 dark:text-mono-500 ml-1">per month</span>
            </div>
          </div>

          <div>
            <div className="text-xs text-mono-600 dark:text-mono-400 mb-1">
              Avg Runtime
            </div>
            <div className="text-sm font-mono text-mono-900 dark:text-mono-50">
              {(projection.avg_execution_time_ms / 1000).toFixed(1)}s
              <span className="text-xs text-mono-500 dark:text-mono-500 ml-1">per run</span>
            </div>
          </div>
        </div>

        {/* Breakdown Toggle */}
        <button
          onClick={() => setShowBreakdown(!showBreakdown)}
          className="w-full mt-4 flex items-center justify-center text-sm text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
        >
          {showBreakdown ? (
            <>
              <ChevronUp className="w-4 h-4 mr-1" />
              Hide Cost Breakdown
            </>
          ) : (
            <>
              <ChevronDown className="w-4 h-4 mr-1" />
              Show Cost Breakdown
            </>
          )}
        </button>

        {/* Detailed Breakdown */}
        {showBreakdown && (
          <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-800 space-y-3">
            <div className="text-sm font-semibold text-mono-950 dark:text-mono-50 mb-3">
              Monthly Cost Breakdown
            </div>

            <CostItem
              label="Athena Query Execution"
              amount={projection.athena_cost_monthly_usd}
              details={`${(projection.avg_data_scanned_mb * projection.executions_per_month / 1024).toFixed(1)} GB scanned total`}
            />

            <CostItem
              label="Lambda Execution"
              amount={projection.lambda_cost_monthly_usd}
              details={`${projection.lambda_memory_mb} MB memory × ${projection.executions_per_month.toLocaleString()} runs`}
            />

            <CostItem
              label="State Storage (DynamoDB)"
              amount={projection.dynamodb_cost_monthly_usd}
              details={`${projection.dynamodb_writes_per_month.toLocaleString()} write requests`}
            />

            <CostItem
              label="Alert Delivery"
              amount={projection.alert_delivery_cost_usd}
              details={`~${projection.estimated_alerts_per_month} alerts via Slack/Email (typically free)`}
            />

            <div className="pt-3 border-t border-mono-200 dark:border-mono-800">
              <div className="flex justify-between items-center">
                <span className="font-semibold text-mono-950 dark:text-mono-50">
                  Total Monthly Cost
                </span>
                <span className={`text-lg font-bold font-mono ${severityColor}`}>
                  ${projection.total_monthly_cost_usd.toFixed(2)}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Optimization Suggestions */}
      {hasOptimizations && (
        <div className="card p-4 border-l-4 border-mono-400 dark:border-mono-600">
          <button
            onClick={() => setShowOptimizations(!showOptimizations)}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center">
              <TrendingDown className="w-5 h-5 mr-2 text-mono-700 dark:text-mono-300" />
              <h3 className="font-semibold text-mono-950 dark:text-mono-50">
                Cost Optimization Opportunities
              </h3>
              {projection.optimization_potential_usd > 0 && (
                <span className="ml-2 px-2 py-0.5 bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-50 text-xs font-mono rounded">
                  Save up to ${projection.optimization_potential_usd.toFixed(2)}/mo
                </span>
              )}
            </div>
            {showOptimizations ? (
              <ChevronUp className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            )}
          </button>

          {showOptimizations && (
            <div className="mt-4 space-y-3">
              {projection.optimization_suggestions.map((suggestion, index) => (
                <div
                  key={index}
                  className="p-3 bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded text-sm"
                >
                  <div className="flex items-start">
                    <Info className="w-4 h-4 mr-2 mt-0.5 text-mono-600 dark:text-mono-400 flex-shrink-0" />
                    <div className="flex-1">
                      <p className="text-mono-900 dark:text-mono-50">{suggestion}</p>
                    </div>
                  </div>
                </div>
              ))}

              {onOptimize && (
                <button
                  onClick={onOptimize}
                  className="btn-secondary w-full mt-3"
                >
                  <TrendingDown className="w-4 h-4 mr-2" />
                  Apply Optimizations
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Cost Warning */}
      {projection.total_monthly_cost_usd > 10 && (
        <div className="card p-4 border-l-4 border-mono-500 dark:border-mono-500">
          <div className="flex items-start">
            <AlertTriangle className="w-5 h-5 mr-2 text-mono-700 dark:text-mono-300 flex-shrink-0" />
            <div>
              <h4 className="font-semibold text-mono-950 dark:text-mono-50 mb-1">
                High Cost Detection
              </h4>
              <p className="text-sm text-mono-700 dark:text-mono-300">
                This detection rule will cost over $10 per month. Consider optimizing the query
                or reducing the execution frequency to control costs.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Interval Cost Comparison */}
      <div className="card p-4">
        <h4 className="text-sm font-semibold text-mono-950 dark:text-mono-50 mb-3">
          Cost by Detection Interval
        </h4>
        <div className="space-y-2">
          {[5, 15, 30, 60].map((interval) => {
            const executions = (30 * 24 * 60) / interval;
            const cost = (projection.total_monthly_cost_usd / projection.executions_per_month) * executions;
            const isCurrent = interval === intervalMinutes;

            return (
              <div
                key={interval}
                className={`flex justify-between items-center p-2 rounded ${
                  isCurrent
                    ? 'bg-mono-200 dark:bg-mono-800 font-semibold'
                    : 'bg-mono-50 dark:bg-mono-900'
                }`}
              >
                <span className="text-sm text-mono-900 dark:text-mono-50">
                  Every {interval} minute{interval > 1 ? 's' : ''}
                  {isCurrent && <span className="ml-2 text-xs text-mono-600 dark:text-mono-400">(current)</span>}
                </span>
                <span className="text-sm font-mono text-mono-900 dark:text-mono-50">
                  ${cost.toFixed(2)}/mo
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Important Notes */}
      <div className="card p-4 bg-mono-50 dark:bg-mono-900">
        <h4 className="text-xs font-semibold text-mono-700 dark:text-mono-300 mb-2">
          Cost Estimation Notes
        </h4>
        <ul className="text-xs text-mono-600 dark:text-mono-400 space-y-1">
          <li>• Based on current AWS pricing: Athena $5/TB, Lambda $0.20/1M requests</li>
          <li>• Actual costs may vary based on data growth and query optimization</li>
          <li>• Historical query performance used when available</li>
          <li>• Alert delivery via Slack/Email is typically free (webhooks)</li>
          <li>• Costs update automatically as your data volume grows</li>
        </ul>
      </div>
    </div>
  );
}

function CostItem({ label, amount, details }) {
  return (
    <div className="flex justify-between items-start">
      <div>
        <div className="text-sm text-mono-900 dark:text-mono-50">{label}</div>
        {details && (
          <div className="text-xs text-mono-600 dark:text-mono-400 mt-0.5">
            {details}
          </div>
        )}
      </div>
      <div className="text-sm font-mono text-mono-900 dark:text-mono-50">
        ${amount.toFixed(4)}
      </div>
    </div>
  );
}

function getSeverityColor(cost) {
  if (cost > 20) return 'text-mono-900 dark:text-mono-100';
  if (cost > 10) return 'text-mono-800 dark:text-mono-200';
  if (cost > 5) return 'text-mono-700 dark:text-mono-300';
  return 'text-mono-600 dark:text-mono-400';
}
