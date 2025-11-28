import { ArrowUpIcon, ArrowDownIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

const SEVERITY_COLORS = {
  critical: 'bg-severity-critical/10 text-severity-critical border-severity-critical',
  high: 'bg-severity-high/10 text-severity-high border-severity-high',
  medium: 'bg-severity-medium/10 text-severity-medium border-severity-medium',
  low: 'bg-severity-low/10 text-severity-low border-severity-low',
  info: 'bg-severity-info/10 text-severity-info border-severity-info',
}

const STATUS_COLORS = {
  new: 'bg-red-100 text-red-700 border-red-200',
  acknowledged: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  resolved: 'bg-green-100 text-green-700 border-green-200',
}

export default function AlertStats({ stats, isLoading }) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="card animate-pulse">
            <div className="h-4 w-20 rounded bg-gray-200"></div>
            <div className="mt-2 h-8 w-16 rounded bg-gray-200"></div>
          </div>
        ))}
      </div>
    )
  }

  if (!stats) {
    return null
  }

  const severityStats = [
    {
      label: 'Critical',
      count: stats.by_severity?.critical || 0,
      trend: stats.trends?.critical || 0,
      color: 'critical',
    },
    {
      label: 'High',
      count: stats.by_severity?.high || 0,
      trend: stats.trends?.high || 0,
      color: 'high',
    },
    {
      label: 'Medium',
      count: stats.by_severity?.medium || 0,
      trend: stats.trends?.medium || 0,
      color: 'medium',
    },
    {
      label: 'Low',
      count: stats.by_severity?.low || 0,
      trend: stats.trends?.low || 0,
      color: 'low',
    },
  ]

  const statusStats = [
    {
      label: 'New',
      count: stats.by_status?.new || 0,
      trend: stats.trends?.new || 0,
      color: 'new',
    },
    {
      label: 'Acknowledged',
      count: stats.by_status?.acknowledged || 0,
      trend: stats.trends?.acknowledged || 0,
      color: 'acknowledged',
    },
    {
      label: 'Resolved',
      count: stats.by_status?.resolved || 0,
      trend: stats.trends?.resolved || 0,
      color: 'resolved',
    },
  ]

  const renderTrend = (trend) => {
    if (!trend || trend === 0) return null

    const isPositive = trend > 0
    const Icon = isPositive ? ArrowUpIcon : ArrowDownIcon

    return (
      <div
        className={clsx(
          'flex items-center gap-1 text-xs font-medium',
          isPositive ? 'text-red-600' : 'text-green-600'
        )}
      >
        <Icon className="h-3 w-3" />
        {Math.abs(trend)}%
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="mb-4 text-lg font-medium text-gray-900">Alerts by Severity</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {severityStats.map((stat) => (
            <div
              key={stat.label}
              className={clsx(
                'rounded-lg border-l-4 p-4',
                SEVERITY_COLORS[stat.color]
              )}
            >
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">{stat.label}</p>
                {renderTrend(stat.trend)}
              </div>
              <p className="mt-2 text-3xl font-bold">{stat.count}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h3 className="mb-4 text-lg font-medium text-gray-900">Alerts by Status</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {statusStats.map((stat) => (
            <div
              key={stat.label}
              className={clsx(
                'rounded-lg border-l-4 p-4',
                STATUS_COLORS[stat.color]
              )}
            >
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">{stat.label}</p>
                {renderTrend(stat.trend)}
              </div>
              <p className="mt-2 text-3xl font-bold">{stat.count}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="card">
          <p className="text-sm text-gray-600">Total Alerts</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{stats.total || 0}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-600">Avg Response Time</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">
            {stats.avg_response_time || 'N/A'}
          </p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-600">Most Active Rule</p>
          <p className="mt-2 text-sm font-medium text-gray-900">
            {stats.most_active_rule?.name || 'N/A'}
          </p>
          <p className="text-xs text-gray-500">
            {stats.most_active_rule?.count || 0} alerts
          </p>
        </div>
      </div>
    </div>
  )
}
