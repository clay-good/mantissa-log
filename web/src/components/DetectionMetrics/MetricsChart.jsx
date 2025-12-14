import { useState, useEffect } from 'react';
import {
  TrendingUp,
  TrendingDown,
  Minus,
  RefreshCw,
  Calendar
} from 'lucide-react';

/**
 * Time-series chart for detection rule metrics.
 * Shows alert count, FP rate, and resolution trends over time.
 */
export default function MetricsChart({
  ruleId = null,
  period = 'day',
  limit = 30,
  height = 200
}) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedMetric, setSelectedMetric] = useState('total_alerts');
  const [hoveredPoint, setHoveredPoint] = useState(null);

  useEffect(() => {
    loadHistory();
  }, [ruleId, period, limit]);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ period, limit: limit.toString() });
      if (ruleId) params.append('rule_id', ruleId);

      const response = await fetch(`/api/detection/metrics/history?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token') || ''}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        // Generate mock data for development
        setData(generateMockHistory(limit, ruleId));
        return;
      }

      const result = await response.json();
      setData(result.history || []);
    } catch (err) {
      console.error('Error loading metrics history:', err);
      setData(generateMockHistory(limit, ruleId));
    } finally {
      setLoading(false);
    }
  };

  const metrics = ruleId
    ? [
        { key: 'total_alerts', label: 'Alerts', color: 'mono-600' },
        { key: 'false_positive_rate', label: 'FP Rate', color: 'amber-500', format: 'percent' },
        { key: 'resolution_rate', label: 'Resolution', color: 'green-500', format: 'percent' },
      ]
    : [
        { key: 'total_alerts', label: 'Total Alerts', color: 'mono-600' },
        { key: 'active_rules', label: 'Active Rules', color: 'blue-500' },
        { key: 'avg_false_positive_rate', label: 'Avg FP Rate', color: 'amber-500', format: 'percent' },
      ];

  const currentMetric = metrics.find(m => m.key === selectedMetric) || metrics[0];

  // Calculate chart dimensions
  const values = data.map(d => d[selectedMetric] || 0);
  const maxValue = Math.max(...values, 1);
  const minValue = Math.min(...values, 0);
  const range = maxValue - minValue || 1;

  // Calculate trend
  const trend = values.length >= 2
    ? ((values[values.length - 1] - values[0]) / (values[0] || 1)) * 100
    : 0;

  const formatValue = (value, metric) => {
    if (metric.format === 'percent') {
      return `${(value * 100).toFixed(1)}%`;
    }
    return value.toLocaleString();
  };

  const formatDate = (isoString) => {
    if (!isoString) return '';
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  if (loading) {
    return (
      <div className="card animate-pulse">
        <div className="h-4 bg-mono-200 dark:bg-mono-700 rounded w-32 mb-4" />
        <div className={`bg-mono-100 dark:bg-mono-800 rounded`} style={{ height }} />
      </div>
    );
  }

  return (
    <div className="card">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-4">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
            {ruleId ? 'Rule Metrics History' : 'Portfolio Metrics History'}
          </h3>
          <div className="flex items-center space-x-1">
            {trend > 5 && <TrendingUp className="w-4 h-4 text-red-500" />}
            {trend < -5 && <TrendingDown className="w-4 h-4 text-green-500" />}
            {trend >= -5 && trend <= 5 && <Minus className="w-4 h-4 text-mono-400" />}
            <span className={`text-sm ${
              trend > 5 ? 'text-red-600' : trend < -5 ? 'text-green-600' : 'text-mono-500'
            }`}>
              {trend > 0 ? '+' : ''}{trend.toFixed(1)}%
            </span>
          </div>
        </div>

        {/* Metric selector */}
        <div className="flex items-center space-x-2">
          {metrics.map((metric) => (
            <button
              key={metric.key}
              onClick={() => setSelectedMetric(metric.key)}
              className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                selectedMetric === metric.key
                  ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-900'
                  : 'bg-mono-100 dark:bg-mono-800 text-mono-600 dark:text-mono-400 hover:bg-mono-200 dark:hover:bg-mono-700'
              }`}
            >
              {metric.label}
            </button>
          ))}
        </div>
      </div>

      {/* Chart */}
      <div className="relative" style={{ height }}>
        {data.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-mono-500">
            No historical data available
          </div>
        ) : (
          <>
            {/* Y-axis labels */}
            <div className="absolute left-0 top-0 bottom-6 w-10 flex flex-col justify-between text-xs text-mono-500">
              <span>{formatValue(maxValue, currentMetric)}</span>
              <span>{formatValue((maxValue + minValue) / 2, currentMetric)}</span>
              <span>{formatValue(minValue, currentMetric)}</span>
            </div>

            {/* Chart area */}
            <div className="ml-12 h-full flex items-end space-x-1 pb-6">
              {data.map((point, index) => {
                const value = point[selectedMetric] || 0;
                const heightPercent = ((value - minValue) / range) * 100;

                return (
                  <div
                    key={index}
                    className="flex-1 flex flex-col items-center justify-end group relative cursor-pointer"
                    onMouseEnter={() => setHoveredPoint(index)}
                    onMouseLeave={() => setHoveredPoint(null)}
                  >
                    {/* Bar */}
                    <div
                      className={`w-full rounded-t transition-all duration-200 ${
                        hoveredPoint === index
                          ? `bg-${currentMetric.color}`
                          : `bg-${currentMetric.color}/70`
                      }`}
                      style={{
                        height: `${Math.max(heightPercent, 2)}%`,
                        backgroundColor: hoveredPoint === index
                          ? getColorClass(currentMetric.color, true)
                          : getColorClass(currentMetric.color, false)
                      }}
                    />

                    {/* Tooltip */}
                    {hoveredPoint === index && (
                      <div className="absolute bottom-full mb-2 z-10 pointer-events-none">
                        <div className="bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-900 text-xs rounded px-2 py-1 whitespace-nowrap shadow-lg">
                          <p className="font-medium">{formatDate(point.period_end)}</p>
                          <p>{currentMetric.label}: {formatValue(value, currentMetric)}</p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* X-axis labels */}
            <div className="ml-12 flex justify-between text-xs text-mono-500">
              <span>{formatDate(data[0]?.period_end)}</span>
              <span>{formatDate(data[data.length - 1]?.period_end)}</span>
            </div>
          </>
        )}
      </div>

      {/* Summary stats */}
      <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-800">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="text-xs text-mono-500">Latest</p>
            <p className="text-lg font-semibold text-mono-900 dark:text-mono-100">
              {formatValue(values[values.length - 1] || 0, currentMetric)}
            </p>
          </div>
          <div>
            <p className="text-xs text-mono-500">Average</p>
            <p className="text-lg font-semibold text-mono-900 dark:text-mono-100">
              {formatValue(
                values.reduce((a, b) => a + b, 0) / (values.length || 1),
                currentMetric
              )}
            </p>
          </div>
          <div>
            <p className="text-xs text-mono-500">Peak</p>
            <p className="text-lg font-semibold text-mono-900 dark:text-mono-100">
              {formatValue(maxValue, currentMetric)}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Get actual color value from Tailwind-style class name
 */
function getColorClass(colorName, isHovered) {
  const colors = {
    'mono-600': isHovered ? '#525252' : '#52525280',
    'mono-400': isHovered ? '#a3a3a3' : '#a3a3a380',
    'blue-500': isHovered ? '#3b82f6' : '#3b82f680',
    'amber-500': isHovered ? '#f59e0b' : '#f59e0b80',
    'green-500': isHovered ? '#22c55e' : '#22c55e80',
    'red-500': isHovered ? '#ef4444' : '#ef444480',
  };
  return colors[colorName] || colors['mono-600'];
}

/**
 * Generate mock history data for development
 */
function generateMockHistory(limit, ruleId) {
  const history = [];
  const now = new Date();

  for (let i = limit - 1; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);

    if (ruleId) {
      // Single rule metrics
      const baseAlerts = 20 + Math.floor(Math.random() * 30);
      const fpRate = 0.05 + Math.random() * 0.25;
      history.push({
        period_end: date.toISOString(),
        total_alerts: baseAlerts + Math.floor(Math.sin(i / 5) * 10),
        false_positive_rate: fpRate,
        resolution_rate: 0.6 + Math.random() * 0.35,
        mean_time_to_resolve: 30 + Math.random() * 120,
      });
    } else {
      // Portfolio metrics
      const baseAlerts = 100 + Math.floor(Math.random() * 150);
      history.push({
        period_end: date.toISOString(),
        total_alerts: baseAlerts + Math.floor(Math.sin(i / 7) * 50),
        active_rules: 15 + Math.floor(Math.random() * 5),
        avg_false_positive_rate: 0.08 + Math.random() * 0.12,
        avg_resolution_rate: 0.65 + Math.random() * 0.25,
      });
    }
  }

  return history;
}
