import clsx from 'clsx'
import {
  UserCircleIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  MinusIcon,
  ShieldExclamationIcon,
  NoSymbolIcon,
  ArrowRightOnRectangleIcon,
} from '@heroicons/react/24/outline'

const RISK_LEVELS = {
  critical: {
    label: 'Critical',
    color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    gaugeColor: 'text-red-500',
  },
  high: {
    label: 'High',
    color: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
    gaugeColor: 'text-orange-500',
  },
  medium: {
    label: 'Medium',
    color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    gaugeColor: 'text-yellow-500',
  },
  low: {
    label: 'Low',
    color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
    gaugeColor: 'text-green-500',
  },
}

function RiskScoreGauge({ score, riskLevel }) {
  const level = RISK_LEVELS[riskLevel] || RISK_LEVELS.medium
  const normalizedScore = Math.min(100, Math.max(0, score))
  const rotation = (normalizedScore / 100) * 180 - 90

  return (
    <div className="relative w-32 h-16 overflow-hidden">
      {/* Background arc */}
      <svg
        viewBox="0 0 100 50"
        className="absolute inset-0 w-full h-full"
      >
        <defs>
          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#22C55E" />
            <stop offset="33%" stopColor="#EAB308" />
            <stop offset="66%" stopColor="#F97316" />
            <stop offset="100%" stopColor="#EF4444" />
          </linearGradient>
        </defs>
        <path
          d="M 5 50 A 45 45 0 0 1 95 50"
          fill="none"
          stroke="url(#gaugeGradient)"
          strokeWidth="8"
          strokeLinecap="round"
        />
      </svg>
      {/* Needle */}
      <div
        className="absolute bottom-0 left-1/2 w-1 h-10 origin-bottom -translate-x-1/2 transition-transform duration-500"
        style={{ transform: `translateX(-50%) rotate(${rotation}deg)` }}
      >
        <div className={clsx('w-1 h-8 rounded-full', level.gaugeColor.replace('text-', 'bg-'))} />
      </div>
      {/* Center dot */}
      <div className="absolute bottom-0 left-1/2 w-3 h-3 -translate-x-1/2 translate-y-1/2 rounded-full bg-mono-800 dark:bg-mono-200" />
    </div>
  )
}

function TrendIndicator({ trend }) {
  if (trend === 'rising') {
    return (
      <div className="flex items-center gap-1 text-red-600 dark:text-red-400">
        <ArrowTrendingUpIcon className="h-4 w-4" />
        <span className="text-xs font-medium">Rising</span>
      </div>
    )
  }
  if (trend === 'falling') {
    return (
      <div className="flex items-center gap-1 text-green-600 dark:text-green-400">
        <ArrowTrendingDownIcon className="h-4 w-4" />
        <span className="text-xs font-medium">Falling</span>
      </div>
    )
  }
  return (
    <div className="flex items-center gap-1 text-mono-500 dark:text-mono-400">
      <MinusIcon className="h-4 w-4" />
      <span className="text-xs font-medium">Stable</span>
    </div>
  )
}

export default function UserRiskHeader({ user }) {
  const riskLevel = user?.risk_level || 'medium'
  const riskScore = user?.risk_score || 0
  const level = RISK_LEVELS[riskLevel] || RISK_LEVELS.medium

  const handleInvestigate = () => {
    console.log('Investigating user:', user?.user_email)
  }

  const handleDisableAccount = () => {
    if (window.confirm('Are you sure you want to disable this account?')) {
      console.log('Disabling account:', user?.user_email)
    }
  }

  const handleTerminateSessions = () => {
    if (window.confirm('Are you sure you want to terminate all sessions for this user?')) {
      console.log('Terminating sessions:', user?.user_email)
    }
  }

  return (
    <div className="bg-white dark:bg-mono-900 border-b border-mono-200 dark:border-mono-800 px-6 py-6">
      <div className="flex flex-wrap items-center justify-between gap-6">
        {/* User Info */}
        <div className="flex items-center gap-4">
          <div className="h-16 w-16 rounded-full bg-mono-200 dark:bg-mono-700 flex items-center justify-center">
            {user?.avatar_url ? (
              <img
                src={user.avatar_url}
                alt={user.display_name}
                className="h-16 w-16 rounded-full object-cover"
              />
            ) : (
              <UserCircleIcon className="h-12 w-12 text-mono-400" />
            )}
          </div>
          <div>
            <h1 className="text-xl font-semibold text-mono-900 dark:text-mono-100">
              {user?.display_name || user?.user_email || 'Unknown User'}
            </h1>
            <p className="text-sm text-mono-600 dark:text-mono-400">{user?.user_email}</p>
            <div className="mt-1 flex items-center gap-3">
              {user?.department && (
                <span className="text-xs text-mono-500 dark:text-mono-500">
                  {user.department}
                </span>
              )}
              {user?.title && (
                <span className="text-xs text-mono-500 dark:text-mono-500">
                  {user.title}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Risk Score Section */}
        <div className="flex items-center gap-8">
          <div className="text-center">
            <RiskScoreGauge score={riskScore} riskLevel={riskLevel} />
            <div className="mt-2">
              <span className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {riskScore}
              </span>
              <span className="text-sm text-mono-500 dark:text-mono-400">/100</span>
            </div>
          </div>

          <div className="flex flex-col items-center gap-2">
            <span
              className={clsx(
                'inline-flex rounded-full px-3 py-1 text-sm font-semibold',
                level.color
              )}
            >
              {level.label} Risk
            </span>
            <TrendIndicator trend={user?.risk_trend} />
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleInvestigate}
            className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 transition-colors"
          >
            <ShieldExclamationIcon className="h-4 w-4" />
            Investigate
          </button>
          <button
            onClick={handleTerminateSessions}
            className="flex items-center gap-2 rounded-lg border border-orange-500 px-4 py-2 text-sm font-medium text-orange-600 hover:bg-orange-50 dark:hover:bg-orange-900/20 transition-colors"
          >
            <ArrowRightOnRectangleIcon className="h-4 w-4" />
            Terminate Sessions
          </button>
          <button
            onClick={handleDisableAccount}
            className="flex items-center gap-2 rounded-lg border border-red-500 px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
          >
            <NoSymbolIcon className="h-4 w-4" />
            Disable Account
          </button>
        </div>
      </div>
    </div>
  )
}
