import { useState, useEffect } from 'react';
import { DollarSign, TrendingUp, TrendingDown, AlertCircle, RefreshCw } from 'lucide-react';

export default function CostTracking({ userId, rules }) {
  const [costData, setCostData] = useState([]);
  const [totals, setTotals] = useState({ actual: 0, projected: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [days, setDays] = useState(30);

  useEffect(() => {
    if (userId && rules?.length > 0) {
      loadCostData();
    }
  }, [userId, rules, days]);

  const loadCostData = async () => {
    try {
      setLoading(true);
      setError(null);

      const costPromises = rules.map(async (rule) => {
        try {
          const actualResponse = await fetch(
            `/api/cost/actual?user_id=${userId}&rule_id=${rule.rule_id}&days=${days}`
          );

          if (!actualResponse.ok) {
            throw new Error(`Failed to fetch costs for ${rule.name}`);
          }

          const actual = await actualResponse.json();

          const compareResponse = await fetch(
            `/api/cost/compare?user_id=${userId}&rule_id=${rule.rule_id}&projected_cost=${rule.projected_cost || 0}&days=${days}`
          );

          let comparison = null;
          if (compareResponse.ok) {
            comparison = await compareResponse.json();
          }

          return {
            rule,
            actual,
            comparison
          };
        } catch (err) {
          console.error(`Error loading cost for rule ${rule.name}:`, err);
          return {
            rule,
            actual: null,
            comparison: null,
            error: err.message
          };
        }
      });

      const results = await Promise.all(costPromises);
      setCostData(results);

      const totalActual = results.reduce(
        (sum, r) => sum + (r.actual?.projected_monthly_cost || 0),
        0
      );
      const totalProjected = results.reduce(
        (sum, r) => sum + (r.rule?.projected_cost || 0),
        0
      );

      setTotals({ actual: totalActual, projected: totalProjected });

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'on_track':
        return (
          <div className="flex items-center text-xs px-2 py-1 rounded bg-mono-900 dark:bg-mono-100 text-mono-100 dark:text-mono-900">
            On Track
          </div>
        );
      case 'over_budget':
        return (
          <div className="flex items-center text-xs px-2 py-1 rounded bg-mono-800 dark:bg-mono-200 text-mono-100 dark:text-mono-900">
            <AlertCircle className="w-3 h-3 mr-1" />
            Over Budget
          </div>
        );
      case 'under_budget':
        return (
          <div className="flex items-center text-xs px-2 py-1 rounded bg-mono-700 dark:bg-mono-300 text-mono-100 dark:text-mono-900">
            Under Budget
          </div>
        );
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center p-8">
          <RefreshCw className="w-6 h-6 animate-spin text-mono-600 dark:text-mono-400" />
          <span className="ml-3 text-mono-600 dark:text-mono-400">Loading cost data...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700">
        <div className="flex items-center">
          <AlertCircle className="w-5 h-5 text-mono-700 dark:text-mono-300" />
          <span className="ml-2 text-sm text-mono-700 dark:text-mono-300">{error}</span>
        </div>
      </div>
    );
  }

  if (!rules || rules.length === 0) {
    return (
      <div className="card text-center py-8">
        <p className="text-mono-600 dark:text-mono-400">No detection rules to track costs for</p>
      </div>
    );
  }

  const variance = totals.actual - totals.projected;
  const variancePct = totals.projected > 0 ? (variance / totals.projected) * 100 : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">Cost Tracking</h2>
        <div className="flex items-center space-x-2">
          <select
            value={days}
            onChange={(e) => setDays(parseInt(e.target.value))}
            className="input text-sm"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={60}>Last 60 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button onClick={loadCostData} className="btn-secondary">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card">
          <div className="flex items-center mb-2">
            <DollarSign className="w-4 h-4 text-mono-600 dark:text-mono-400 mr-2" />
            <div className="text-xs text-mono-600 dark:text-mono-400 uppercase">Projected Monthly</div>
          </div>
          <div className="text-2xl font-bold text-mono-900 dark:text-mono-100">
            {formatCurrency(totals.projected)}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center mb-2">
            <DollarSign className="w-4 h-4 text-mono-600 dark:text-mono-400 mr-2" />
            <div className="text-xs text-mono-600 dark:text-mono-400 uppercase">Actual Monthly</div>
          </div>
          <div className="text-2xl font-bold text-mono-900 dark:text-mono-100">
            {formatCurrency(totals.actual)}
          </div>
          <div className="text-xs text-mono-600 dark:text-mono-400 mt-1">
            Based on {days} day average
          </div>
        </div>

        <div className="card">
          <div className="flex items-center mb-2">
            {variance >= 0 ? (
              <TrendingUp className="w-4 h-4 text-mono-600 dark:text-mono-400 mr-2" />
            ) : (
              <TrendingDown className="w-4 h-4 text-mono-600 dark:text-mono-400 mr-2" />
            )}
            <div className="text-xs text-mono-600 dark:text-mono-400 uppercase">Variance</div>
          </div>
          <div className={`text-2xl font-bold ${
            variance > 0
              ? 'text-mono-900 dark:text-mono-100'
              : 'text-mono-700 dark:text-mono-300'
          }`}>
            {variance >= 0 ? '+' : ''}{formatCurrency(variance)}
          </div>
          <div className="text-xs text-mono-600 dark:text-mono-400 mt-1">
            {variancePct >= 0 ? '+' : ''}{variancePct.toFixed(1)}%
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
          Cost by Detection Rule
        </h3>

        <div className="space-y-3">
          {costData.map((item, index) => (
            <div
              key={index}
              className="p-4 bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1">
                  <div className="font-semibold text-mono-900 dark:text-mono-100">
                    {item.rule.name}
                  </div>
                  {item.actual && (
                    <div className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                      {item.actual.executions} executions in {days} days
                    </div>
                  )}
                </div>
                {item.comparison && getStatusBadge(item.comparison.status)}
              </div>

              {item.actual ? (
                <div className="grid grid-cols-3 gap-4 mt-3">
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                      Projected
                    </div>
                    <div className="text-sm font-semibold text-mono-900 dark:text-mono-100">
                      {formatCurrency(item.rule.projected_cost || 0)}
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                      Actual
                    </div>
                    <div className="text-sm font-semibold text-mono-900 dark:text-mono-100">
                      {formatCurrency(item.actual.projected_monthly_cost)}
                    </div>
                  </div>

                  {item.comparison && (
                    <div>
                      <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                        Variance
                      </div>
                      <div className={`text-sm font-semibold ${
                        item.comparison.variance >= 0
                          ? 'text-mono-900 dark:text-mono-100'
                          : 'text-mono-700 dark:text-mono-300'
                      }`}>
                        {item.comparison.variance >= 0 ? '+' : ''}{formatCurrency(item.comparison.variance)}
                        <span className="text-xs ml-1">
                          ({item.comparison.variance_percent >= 0 ? '+' : ''}{item.comparison.variance_percent.toFixed(1)}%)
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              ) : item.error ? (
                <div className="text-xs text-mono-600 dark:text-mono-400 mt-2">
                  Error: {item.error}
                </div>
              ) : (
                <div className="text-xs text-mono-600 dark:text-mono-400 mt-2">
                  No cost data available
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="text-xs text-mono-600 dark:text-mono-400 p-3 bg-mono-100 dark:bg-mono-850 rounded-lg border border-mono-300 dark:border-mono-700">
        <strong>Note:</strong> Actual monthly costs are projected based on the selected time period.
        Costs are calculated from actual AWS service usage tracked during detection execution.
      </div>
    </div>
  );
}
