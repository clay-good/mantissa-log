import clsx from 'clsx'
import {
  ExclamationTriangleIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline'

const FACTOR_TYPE_CONFIG = {
  failed_logins: { label: 'Failed Login Attempts', category: 'Authentication' },
  impossible_travel: { label: 'Impossible Travel', category: 'Location' },
  new_device: { label: 'New Device', category: 'Device' },
  new_location: { label: 'New Location', category: 'Location' },
  off_hours_activity: { label: 'Off-Hours Activity', category: 'Behavior' },
  mfa_bypass: { label: 'MFA Bypass Attempt', category: 'Authentication' },
  privilege_escalation: { label: 'Privilege Escalation', category: 'Access' },
  suspicious_ip: { label: 'Suspicious IP', category: 'Network' },
  dormant_account: { label: 'Dormant Account', category: 'Account' },
  multiple_failures: { label: 'Multiple Failures', category: 'Authentication' },
  unusual_application: { label: 'Unusual Application Access', category: 'Access' },
  session_anomaly: { label: 'Session Anomaly', category: 'Session' },
  credential_stuffing: { label: 'Credential Stuffing', category: 'Attack' },
  brute_force: { label: 'Brute Force', category: 'Attack' },
}

function RiskBar({ weight, maxWeight = 30 }) {
  const percentage = Math.min(100, (weight / maxWeight) * 100)

  return (
    <div className="w-20 h-2 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
      <div
        className={clsx(
          'h-full rounded-full transition-all duration-300',
          percentage >= 70 ? 'bg-red-500' : percentage >= 40 ? 'bg-orange-500' : 'bg-yellow-500'
        )}
        style={{ width: `${percentage}%` }}
      />
    </div>
  )
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

function RiskScoreBreakdown({ factors }) {
  const totalWeight = factors?.reduce((sum, f) => sum + (f.weight || 0), 0) || 0

  // Group by category
  const byCategory = {}
  factors?.forEach((factor) => {
    const config = FACTOR_TYPE_CONFIG[factor.type] || { label: factor.type, category: 'Other' }
    if (!byCategory[config.category]) {
      byCategory[config.category] = 0
    }
    byCategory[config.category] += factor.weight || 0
  })

  const sortedCategories = Object.entries(byCategory)
    .sort((a, b) => b[1] - a[1])

  return (
    <div className="space-y-2">
      {sortedCategories.map(([category, weight]) => {
        const percentage = totalWeight > 0 ? Math.round((weight / totalWeight) * 100) : 0
        return (
          <div key={category} className="flex items-center gap-2">
            <div className="w-24 text-xs text-mono-600 dark:text-mono-400">{category}</div>
            <div className="flex-1 h-3 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-500 rounded-full transition-all duration-300"
                style={{ width: `${percentage}%` }}
              />
            </div>
            <div className="w-10 text-xs font-medium text-mono-700 dark:text-mono-300 text-right">
              {percentage}%
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default function RiskFactorsPanel({ factors }) {
  if (!factors || factors.length === 0) {
    return (
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-4">
        <h3 className="text-sm font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Risk Factors
        </h3>
        <div className="text-center py-6">
          <ExclamationTriangleIcon className="mx-auto h-8 w-8 text-green-400" />
          <p className="mt-2 text-sm text-mono-500 dark:text-mono-400">
            No active risk factors
          </p>
        </div>
      </div>
    )
  }

  // Sort by weight descending
  const sortedFactors = [...factors].sort((a, b) => (b.weight || 0) - (a.weight || 0))

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-mono-900 dark:text-mono-100">
          Risk Factors
        </h3>
        <p className="text-xs text-mono-500 dark:text-mono-400">
          {factors.length} active factor{factors.length !== 1 ? 's' : ''}
        </p>
      </div>

      {/* Score Breakdown */}
      <div className="px-4 py-3 border-b border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-800/50">
        <h4 className="text-xs font-medium text-mono-700 dark:text-mono-300 mb-2">
          Score Composition
        </h4>
        <RiskScoreBreakdown factors={factors} />
      </div>

      {/* Factor List */}
      <div className="divide-y divide-mono-200 dark:divide-mono-800">
        {sortedFactors.map((factor, index) => {
          const config = FACTOR_TYPE_CONFIG[factor.type] || {
            label: factor.type,
            category: 'Other',
          }

          return (
            <div key={index} className="px-4 py-3 hover:bg-mono-50 dark:hover:bg-mono-800/50">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <ExclamationTriangleIcon
                      className={clsx(
                        'h-4 w-4',
                        (factor.weight || 0) >= 20
                          ? 'text-red-500'
                          : (factor.weight || 0) >= 10
                          ? 'text-orange-500'
                          : 'text-yellow-500'
                      )}
                    />
                    <span className="text-sm font-medium text-mono-900 dark:text-mono-100">
                      {config.label}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-3">
                    <span className="text-xs text-mono-500 dark:text-mono-400">
                      {config.category}
                    </span>
                    <span className="text-xs text-mono-400">•</span>
                    <span className="text-xs text-mono-500 dark:text-mono-400">
                      {formatTimeAgo(factor.detected_at)}
                    </span>
                  </div>
                  {factor.evidence && (
                    <p className="mt-1 text-xs text-mono-600 dark:text-mono-400">
                      {factor.evidence}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-xs font-medium text-mono-700 dark:text-mono-300">
                      +{factor.weight || 0}
                    </div>
                    <RiskBar weight={factor.weight || 0} />
                  </div>
                  <ChevronRightIcon className="h-4 w-4 text-mono-400" />
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
