import { useState, useEffect } from 'react';
import { TrendingUp, DollarSign, Zap, Activity, Loader } from 'lucide-react';

export default function LLMUsageAnalytics({ userId }) {
  const [summary, setSummary] = useState(null);
  const [dailyUsage, setDailyUsage] = useState([]);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);

  useEffect(() => {
    loadUsageData();
  }, [userId, days]);

  const loadUsageData = async () => {
    try {
      setLoading(true);

      const [summaryRes, dailyRes] = await Promise.all([
        fetch(`/api/llm-usage/${userId}/summary`),
        fetch(`/api/llm-usage/${userId}/daily?days=${days}`)
      ]);

      const summaryData = await summaryRes.json();
      const dailyData = await dailyRes.json();

      setSummary(summaryData);
      setDailyUsage(dailyData.daily_usage || []);

    } catch (err) {
      console.error('Error loading usage data:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatCost = (cost) => {
    return `$${parseFloat(cost).toFixed(4)}`;
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  if (loading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center py-12">
          <Loader className="w-6 h-6 text-mono-500 animate-spin" />
        </div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="card">
        <p className="text-mono-600 dark:text-mono-400 text-center py-12">
          No usage data available
        </p>
      </div>
    );
  }

  const maxDailyCost = Math.max(...dailyUsage.map(d => d.cost_usd), 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-2">
            LLM Usage Analytics
          </h2>
          <p className="text-mono-600 dark:text-mono-400">
            Track your LLM API usage and costs
          </p>
        </div>

        <select
          value={days}
          onChange={(e) => setDays(parseInt(e.target.value))}
          className="input w-auto"
        >
          <option value="7">Last 7 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
        </select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-mono-100 dark:bg-mono-850 rounded-lg">
              <DollarSign className="w-6 h-6 text-mono-900 dark:text-mono-100" />
            </div>
            <div>
              <p className="text-xs text-mono-600 dark:text-mono-400">Total Cost</p>
              <p className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                {formatCost(summary.total_cost_usd)}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-mono-100 dark:bg-mono-850 rounded-lg">
              <Zap className="w-6 h-6 text-mono-900 dark:text-mono-100" />
            </div>
            <div>
              <p className="text-xs text-mono-600 dark:text-mono-400">Total Requests</p>
              <p className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                {formatNumber(summary.total_requests)}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-mono-100 dark:bg-mono-850 rounded-lg">
              <Activity className="w-6 h-6 text-mono-900 dark:text-mono-100" />
            </div>
            <div>
              <p className="text-xs text-mono-600 dark:text-mono-400">Total Tokens</p>
              <p className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                {formatNumber(summary.total_tokens)}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-mono-100 dark:bg-mono-850 rounded-lg">
              <TrendingUp className="w-6 h-6 text-mono-900 dark:text-mono-100" />
            </div>
            <div>
              <p className="text-xs text-mono-600 dark:text-mono-400">Avg Cost/Request</p>
              <p className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                {formatCost(summary.total_cost_usd / summary.total_requests || 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
            Usage by Provider
          </h3>
          <div className="space-y-3">
            {Object.entries(summary.by_provider || {}).map(([provider, data]) => (
              <div key={provider} className="border-b border-mono-200 dark:border-mono-800 pb-3 last:border-b-0 last:pb-0">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-mono-900 dark:text-mono-100 capitalize">
                    {provider}
                  </span>
                  <span className="text-sm font-mono text-mono-700 dark:text-mono-300">
                    {formatCost(data.cost_usd)}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs text-mono-600 dark:text-mono-400">
                  <span>{formatNumber(data.requests)} requests</span>
                  <span>{formatNumber(data.tokens)} tokens</span>
                </div>
                <div className="mt-2 h-2 bg-mono-100 dark:bg-mono-850 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-mono-900 dark:bg-mono-100"
                    style={{
                      width: `${(data.cost_usd / summary.total_cost_usd) * 100}%`
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
            Usage by Operation
          </h3>
          <div className="space-y-3">
            {Object.entries(summary.by_operation || {}).map(([operation, data]) => (
              <div key={operation} className="border-b border-mono-200 dark:border-mono-800 pb-3 last:border-b-0 last:pb-0">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-mono-900 dark:text-mono-100 capitalize">
                    {operation.replace('_', ' ')}
                  </span>
                  <span className="text-sm font-mono text-mono-700 dark:text-mono-300">
                    {formatCost(data.cost_usd)}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs text-mono-600 dark:text-mono-400">
                  <span>{formatNumber(data.requests)} requests</span>
                  <span>{formatNumber(data.tokens)} tokens</span>
                </div>
                <div className="mt-2 h-2 bg-mono-100 dark:bg-mono-850 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-mono-900 dark:bg-mono-100"
                    style={{
                      width: `${(data.cost_usd / summary.total_cost_usd) * 100}%`
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Daily Usage Trend
        </h3>

        {dailyUsage.length === 0 ? (
          <p className="text-center text-mono-600 dark:text-mono-400 py-8">
            No usage data available for this period
          </p>
        ) : (
          <div className="space-y-2">
            {dailyUsage.map(day => (
              <div key={day.date} className="flex items-center space-x-3">
                <div className="text-xs text-mono-600 dark:text-mono-400 w-24 font-mono">
                  {new Date(day.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                </div>
                <div className="flex-1">
                  <div className="h-8 bg-mono-100 dark:bg-mono-850 rounded overflow-hidden relative">
                    <div
                      className="h-full bg-mono-900 dark:bg-mono-100 transition-all"
                      style={{
                        width: maxDailyCost > 0 ? `${(day.cost_usd / maxDailyCost) * 100}%` : '0%'
                      }}
                    />
                    <div className="absolute inset-0 flex items-center px-2">
                      <span className="text-xs text-mono-900 dark:text-mono-100 font-medium">
                        {formatCost(day.cost_usd)}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400 w-20 text-right font-mono">
                  {formatNumber(day.requests)} req
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Usage by Model
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-mono-200 dark:border-mono-800">
                <th className="text-left py-2 text-xs font-medium text-mono-600 dark:text-mono-400 uppercase">Model</th>
                <th className="text-right py-2 text-xs font-medium text-mono-600 dark:text-mono-400 uppercase">Requests</th>
                <th className="text-right py-2 text-xs font-medium text-mono-600 dark:text-mono-400 uppercase">Tokens</th>
                <th className="text-right py-2 text-xs font-medium text-mono-600 dark:text-mono-400 uppercase">Cost</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(summary.by_model || {}).map(([model, data]) => (
                <tr key={model} className="border-b border-mono-100 dark:border-mono-850 last:border-b-0">
                  <td className="py-3 text-sm text-mono-900 dark:text-mono-100 font-mono">
                    {model}
                  </td>
                  <td className="py-3 text-sm text-mono-700 dark:text-mono-300 text-right font-mono">
                    {formatNumber(data.requests)}
                  </td>
                  <td className="py-3 text-sm text-mono-700 dark:text-mono-300 text-right font-mono">
                    {formatNumber(data.tokens)}
                  </td>
                  <td className="py-3 text-sm text-mono-900 dark:text-mono-100 text-right font-mono font-medium">
                    {formatCost(data.cost_usd)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
