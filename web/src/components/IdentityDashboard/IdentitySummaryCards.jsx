import {
  UserGroupIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  KeyIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'

const CARD_CONFIGS = [
  {
    id: 'highRiskUsers',
    title: 'High Risk Users',
    icon: UserGroupIcon,
    color: 'text-red-600 bg-red-100 dark:bg-red-900/30',
    getValue: (props) => props.highRiskCount,
    getTrend: (props) => props.metrics?.highRiskUsersTrend,
    description: 'Users with risk score > 65',
  },
  {
    id: 'activeIncidents',
    title: 'Active Incidents',
    icon: ExclamationTriangleIcon,
    color: 'text-orange-600 bg-orange-100 dark:bg-orange-900/30',
    getValue: (props) => props.activeIncidents,
    getTrend: (props) => props.metrics?.incidentsTrend,
    description: 'Unresolved identity incidents',
  },
  {
    id: 'authFailures',
    title: 'Auth Failures (24h)',
    icon: ShieldExclamationIcon,
    color: 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30',
    getValue: (props) => props.metrics?.authFailures24h || 0,
    getTrend: (props) => props.metrics?.authFailuresTrend,
    description: 'Failed authentication attempts',
  },
  {
    id: 'unusualLogins',
    title: 'Unusual Logins (24h)',
    icon: KeyIcon,
    color: 'text-purple-600 bg-purple-100 dark:bg-purple-900/30',
    getValue: (props) => props.metrics?.unusualLogins24h || 0,
    getTrend: (props) => props.metrics?.unusualLoginsTrend,
    description: 'Logins from new locations/devices',
  },
  {
    id: 'mfaBypass',
    title: 'MFA Bypass Attempts',
    icon: ShieldExclamationIcon,
    color: 'text-red-600 bg-red-100 dark:bg-red-900/30',
    getValue: (props) => props.metrics?.mfaBypassAttempts || 0,
    getTrend: (props) => props.metrics?.mfaBypassTrend,
    description: 'Detected MFA fatigue/bypass attempts',
  },
]

function TrendIndicator({ trend }) {
  if (!trend || trend.value === 0) return null

  const isPositive = trend.value > 0
  const TrendIcon = isPositive ? ArrowTrendingUpIcon : ArrowTrendingDownIcon
  const isGoodTrend = trend.goodDirection === 'down' ? !isPositive : isPositive

  return (
    <div
      className={clsx(
        'flex items-center gap-1 text-xs font-medium',
        isGoodTrend ? 'text-green-600' : 'text-red-600'
      )}
    >
      <TrendIcon className="h-3 w-3" />
      <span>{Math.abs(trend.value)}%</span>
    </div>
  )
}

function SummaryCard({ config, value, trend, isLoading }) {
  const Icon = config.icon

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-6 transition-all hover:shadow-md">
      <div className="flex items-start justify-between">
        <div className={clsx('rounded-lg p-2', config.color)}>
          <Icon className="h-6 w-6" />
        </div>
        <TrendIndicator trend={trend} />
      </div>

      <div className="mt-4">
        {isLoading ? (
          <div className="h-8 w-16 animate-pulse rounded bg-mono-200 dark:bg-mono-700" />
        ) : (
          <p className="text-3xl font-bold text-mono-950 dark:text-mono-50">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
        )}
        <p className="mt-1 text-sm font-medium text-mono-700 dark:text-mono-300">
          {config.title}
        </p>
        <p className="mt-0.5 text-xs text-mono-500 dark:text-mono-400">
          {config.description}
        </p>
      </div>
    </div>
  )
}

export default function IdentitySummaryCards(props) {
  const { isLoading } = props

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
      {CARD_CONFIGS.map((config) => (
        <SummaryCard
          key={config.id}
          config={config}
          value={config.getValue(props)}
          trend={config.getTrend(props)}
          isLoading={isLoading}
        />
      ))}
    </div>
  )
}
