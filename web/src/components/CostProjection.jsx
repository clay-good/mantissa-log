import { DollarSign, TrendingUp, AlertTriangle, Info } from 'lucide-react';

export default function CostProjection({ costData, loading }) {
  if (loading) {
    return (
      <div className="animate-pulse bg-mono-100 dark:bg-mono-850 rounded-lg p-6">
        <div className="h-4 bg-mono-200 dark:bg-mono-800 rounded w-1/3 mb-4"></div>
        <div className="h-8 bg-mono-200 dark:bg-mono-800 rounded w-1/2 mb-2"></div>
        <div className="h-3 bg-mono-200 dark:bg-mono-800 rounded w-2/3"></div>
      </div>
    );
  }

  if (!costData) {
    return null;
  }

  const { total_monthly_cost, breakdown, notes } = costData;
  const isHighCost = total_monthly_cost > 10;

  return (
    <div className="bg-white dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded-lg p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-mono-100 dark:bg-mono-850 rounded-lg">
            <DollarSign className="w-5 h-5 text-mono-700 dark:text-mono-300" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
              Projected Monthly Cost
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Estimated AWS infrastructure costs
            </p>
          </div>
        </div>
        {isHighCost && (
          <div className="flex items-center space-x-2 text-mono-800 dark:text-mono-200">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs font-medium">High Cost</span>
          </div>
        )}
      </div>

      {/* Total Cost */}
      <div className="mb-6 pb-6 border-b border-mono-200 dark:border-mono-800">
        <div className="flex items-baseline space-x-2">
          <span className="text-4xl font-bold text-mono-950 dark:text-mono-50">
            ${total_monthly_cost.toFixed(2)}
          </span>
          <span className="text-sm text-mono-600 dark:text-mono-400">per month</span>
        </div>
        {total_monthly_cost < 1 && (
          <div className="mt-2 inline-flex items-center space-x-1 text-sm text-mono-700 dark:text-mono-300">
            <TrendingUp className="w-4 h-4" />
            <span>Cost-efficient detection rule</span>
          </div>
        )}
      </div>

      {/* Cost Breakdown */}
      <div className="space-y-4 mb-6">
        <h4 className="text-sm font-semibold text-mono-800 dark:text-mono-200 uppercase tracking-wide">
          Cost Breakdown
        </h4>

        {/* Query Execution */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
              Query Execution
            </span>
            <span className="text-sm font-mono text-mono-950 dark:text-mono-50">
              ${breakdown.query_execution.cost.toFixed(2)}
            </span>
          </div>
          <div className="text-xs text-mono-600 dark:text-mono-400">
            {breakdown.query_execution.description}
          </div>
          <div className="w-full bg-mono-150 dark:bg-mono-850 rounded-full h-1.5">
            <div
              className="bg-mono-700 dark:bg-mono-400 h-1.5 rounded-full transition-all duration-500"
              style={{
                width: `${(breakdown.query_execution.cost / total_monthly_cost) * 100}%`
              }}
            ></div>
          </div>
        </div>

        {/* Lambda Execution */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
              Lambda Execution
            </span>
            <span className="text-sm font-mono text-mono-950 dark:text-mono-50">
              ${breakdown.lambda_execution.cost.toFixed(4)}
            </span>
          </div>
          <div className="text-xs text-mono-600 dark:text-mono-400">
            {breakdown.lambda_execution.description}
          </div>
          <div className="w-full bg-mono-150 dark:bg-mono-850 rounded-full h-1.5">
            <div
              className="bg-mono-700 dark:bg-mono-400 h-1.5 rounded-full transition-all duration-500"
              style={{
                width: `${(breakdown.lambda_execution.cost / total_monthly_cost) * 100}%`
              }}
            ></div>
          </div>
        </div>

        {/* State Storage */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
              State Storage (DynamoDB)
            </span>
            <span className="text-sm font-mono text-mono-950 dark:text-mono-50">
              ${breakdown.state_storage.cost.toFixed(4)}
            </span>
          </div>
          <div className="text-xs text-mono-600 dark:text-mono-400">
            {breakdown.state_storage.description}
          </div>
          <div className="w-full bg-mono-150 dark:bg-mono-850 rounded-full h-1.5">
            <div
              className="bg-mono-700 dark:bg-mono-400 h-1.5 rounded-full transition-all duration-500"
              style={{
                width: `${(breakdown.state_storage.cost / total_monthly_cost) * 100}%`
              }}
            ></div>
          </div>
        </div>

        {/* Alert Delivery */}
        {breakdown.alert_delivery.cost > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
                Alert Delivery
              </span>
              <span className="text-sm font-mono text-mono-950 dark:text-mono-50">
                ${breakdown.alert_delivery.cost.toFixed(4)}
              </span>
            </div>
            <div className="text-xs text-mono-600 dark:text-mono-400">
              {breakdown.alert_delivery.description}
            </div>
            <div className="w-full bg-mono-150 dark:bg-mono-850 rounded-full h-1.5">
              <div
                className="bg-mono-700 dark:bg-mono-400 h-1.5 rounded-full transition-all duration-500"
                style={{
                  width: `${(breakdown.alert_delivery.cost / total_monthly_cost) * 100}%`
                }}
              ></div>
            </div>
          </div>
        )}
      </div>

      {/* Notes */}
      {notes && notes.length > 0 && (
        <div className="bg-mono-50 dark:bg-mono-850 rounded-lg p-4 border border-mono-200 dark:border-mono-800">
          <div className="flex items-start space-x-2">
            <Info className="w-4 h-4 text-mono-600 dark:text-mono-400 mt-0.5 flex-shrink-0" />
            <div className="space-y-1">
              {notes.map((note, index) => (
                <p key={index} className="text-xs text-mono-700 dark:text-mono-300">
                  {note}
                </p>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
