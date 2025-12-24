import { useState } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import {
  BellAlertIcon,
  ChevronRightIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  MinusIcon,
} from '@heroicons/react/24/outline'

const SEVERITY_STYLES = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
}

const STATUS_STYLES = {
  new: 'bg-red-500',
  acknowledged: 'bg-yellow-500',
  investigating: 'bg-blue-500',
  resolved: 'bg-green-500',
}

function formatTimeAgo(timestamp) {
  if (!timestamp) return 'Unknown'
  const date = new Date(timestamp)
  const now = new Date()
  const diffMs = now - date
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}

function RiskScoreChart({ history }) {
  if (!history || history.length < 2) return null

  const maxScore = Math.max(...history.map((h) => h.score), 100)
  const minScore = Math.min(...history.map((h) => h.score), 0)
  const range = maxScore - minScore || 1

  const width = 200
  const height = 60
  const padding = 4

  const points = history.map((h, i) => {
    const x = padding + (i / (history.length - 1)) * (width - padding * 2)
    const y = height - padding - ((h.score - minScore) / range) * (height - padding * 2)
    return `${x},${y}`
  })

  const pathData = `M ${points.join(' L ')}`

  // Determine trend
  const recentScore = history[history.length - 1]?.score || 0
  const previousScore = history[Math.max(0, history.length - 7)]?.score || recentScore
  const trend = recentScore > previousScore ? 'up' : recentScore < previousScore ? 'down' : 'stable'

  const lineColor = trend === 'up' ? '#EF4444' : trend === 'down' ? '#22C55E' : '#6B7280'

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-mono-500 dark:text-mono-400">Risk Score History (30d)</span>
        <div className={clsx(
          'flex items-center gap-1 text-xs font-medium',
          trend === 'up' ? 'text-red-600' : trend === 'down' ? 'text-green-600' : 'text-mono-500'
        )}>
          {trend === 'up' && <ArrowTrendingUpIcon className="h-3 w-3" />}
          {trend === 'down' && <ArrowTrendingDownIcon className="h-3 w-3" />}
          {trend === 'stable' && <MinusIcon className="h-3 w-3" />}
          {trend === 'up' ? 'Rising' : trend === 'down' ? 'Falling' : 'Stable'}
        </div>
      </div>
      <svg width={width} height={height} className="w-full">
        <defs>
          <linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={lineColor} stopOpacity="0.2" />
            <stop offset="100%" stopColor={lineColor} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path
          d={`${pathData} L ${width - padding},${height - padding} L ${padding},${height - padding} Z`}
          fill="url(#chartGradient)"
        />
        <path d={pathData} fill="none" stroke={lineColor} strokeWidth="2" />
        <circle
          cx={width - padding}
          cy={height - padding - ((recentScore - minScore) / range) * (height - padding * 2)}
          r="3"
          fill={lineColor}
        />
      </svg>
      <div className="flex justify-between text-xs text-mono-400">
        <span>30d ago</span>
        <span>Now: {recentScore}</span>
      </div>
    </div>
  )
}

function AlertItem({ alert }) {
  return (
    <Link
      to={`/identity?incident=${alert.id}`}
      className="block px-4 py-3 hover:bg-mono-50 dark:hover:bg-mono-800/50 transition-colors"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={clsx(
                'inline-flex rounded-full px-2 py-0.5 text-xs font-semibold capitalize',
                SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.medium
              )}
            >
              {alert.severity}
            </span>
            <span className="flex items-center gap-1">
              <span
                className={clsx(
                  'h-2 w-2 rounded-full',
                  STATUS_STYLES[alert.status] || STATUS_STYLES.new
                )}
              />
              <span className="text-xs text-mono-500 dark:text-mono-400 capitalize">
                {alert.status}
              </span>
            </span>
          </div>
          <p className="mt-1 text-sm font-medium text-mono-900 dark:text-mono-100 truncate">
            {alert.title || alert.attack_type}
          </p>
          <p className="text-xs text-mono-500 dark:text-mono-400">
            {formatTimeAgo(alert.timestamp)}
          </p>
        </div>
        <ChevronRightIcon className="h-4 w-4 text-mono-400 flex-shrink-0" />
      </div>
    </Link>
  )
}

export default function RelatedAlertsPanel({ alerts, userId }) {
  const [showAll, setShowAll] = useState(false)

  const displayAlerts = showAll ? alerts : alerts?.slice(0, 3)
  const hasMore = alerts && alerts.length > 3

  // Mock risk score history if not provided
  const mockHistory = Array.from({ length: 30 }, (_, i) => ({
    date: new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000).toISOString(),
    score: Math.floor(40 + Math.random() * 40 + (i / 30) * 20),
  }))

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-mono-900 dark:text-mono-100">
          Related Alerts & History
        </h3>
      </div>

      {/* Risk Score Chart */}
      <div className="px-4 py-3 border-b border-mono-200 dark:border-mono-800">
        <RiskScoreChart history={mockHistory} />
      </div>

      {/* Alert List */}
      <div>
        {alerts && alerts.length > 0 ? (
          <>
            <div className="divide-y divide-mono-200 dark:divide-mono-800">
              {displayAlerts.map((alert, index) => (
                <AlertItem key={alert.id || index} alert={alert} />
              ))}
            </div>
            {hasMore && (
              <div className="border-t border-mono-200 dark:border-mono-800 px-4 py-2">
                <button
                  onClick={() => setShowAll(!showAll)}
                  className="text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
                >
                  {showAll ? 'Show Less' : `Show ${alerts.length - 3} More`}
                </button>
              </div>
            )}
          </>
        ) : (
          <div className="px-4 py-6 text-center">
            <BellAlertIcon className="mx-auto h-8 w-8 text-mono-400" />
            <p className="mt-2 text-sm text-mono-500 dark:text-mono-400">
              No related alerts
            </p>
          </div>
        )}
      </div>

      {/* View All Link */}
      {alerts && alerts.length > 0 && (
        <div className="border-t border-mono-200 dark:border-mono-800 px-4 py-2 bg-mono-50 dark:bg-mono-800/50">
          <Link
            to={`/identity?user=${encodeURIComponent(userId)}`}
            className="text-xs font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 flex items-center gap-1"
          >
            View all alerts for this user
            <ChevronRightIcon className="h-3 w-3" />
          </Link>
        </div>
      )}
    </div>
  )
}
