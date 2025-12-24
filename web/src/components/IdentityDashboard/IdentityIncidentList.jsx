import { useState } from 'react'
import { useIdentityStore } from '../../stores/identityStore'
import clsx from 'clsx'
import {
  ChevronRightIcon,
  CheckCircleIcon,
  XMarkIcon,
  ArrowUpIcon,
  UserIcon,
  ClockIcon,
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

const ATTACK_TYPE_LABELS = {
  brute_force: 'Brute Force',
  credential_stuffing: 'Credential Stuffing',
  password_spray: 'Password Spray',
  mfa_fatigue: 'MFA Fatigue',
  mfa_bypass: 'MFA Bypass',
  impossible_travel: 'Impossible Travel',
  session_hijack: 'Session Hijacking',
  privilege_escalation: 'Privilege Escalation',
  account_takeover: 'Account Takeover',
  token_theft: 'Token Theft',
  dormant_account: 'Dormant Account',
}

const KILL_CHAIN_STAGES = {
  RECONNAISSANCE: { label: 'Recon', color: 'bg-slate-500' },
  INITIAL_ACCESS: { label: 'Initial Access', color: 'bg-blue-500' },
  CREDENTIAL_ACCESS: { label: 'Credential Access', color: 'bg-yellow-500' },
  PERSISTENCE: { label: 'Persistence', color: 'bg-orange-500' },
  PRIVILEGE_ESCALATION: { label: 'Priv Esc', color: 'bg-red-500' },
  LATERAL_MOVEMENT: { label: 'Lateral', color: 'bg-purple-500' },
  COLLECTION: { label: 'Collection', color: 'bg-pink-500' },
  OBJECTIVES: { label: 'Objectives', color: 'bg-red-700' },
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

function IncidentRow({ incident, isExpanded, onToggle, onSelect }) {
  const { acknowledgeIncident, dismissIncident, escalateIncident } = useIdentityStore()

  const killChainStage = KILL_CHAIN_STAGES[incident.kill_chain_stage] || null

  return (
    <>
      <tr
        className={clsx(
          'cursor-pointer hover:bg-mono-50 dark:hover:bg-mono-800/50 transition-colors',
          isExpanded && 'bg-mono-50 dark:bg-mono-800/50'
        )}
        onClick={() => onToggle(incident.id)}
      >
        {/* Severity */}
        <td className="px-4 py-3">
          <span
            className={clsx(
              'inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold',
              SEVERITY_STYLES[incident.severity] || SEVERITY_STYLES.medium
            )}
          >
            {incident.severity}
          </span>
        </td>

        {/* Type */}
        <td className="px-4 py-3">
          <div className="text-sm font-medium text-mono-900 dark:text-mono-100">
            {ATTACK_TYPE_LABELS[incident.attack_type] || incident.attack_type}
          </div>
          <div className="text-xs text-mono-500 dark:text-mono-400">
            {incident.provider}
          </div>
        </td>

        {/* Target Users */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <UserIcon className="h-4 w-4 text-mono-400" />
            <div>
              <div className="text-sm text-mono-900 dark:text-mono-100">
                {incident.target_users?.[0] || 'Unknown'}
              </div>
              {incident.target_users?.length > 1 && (
                <div className="text-xs text-mono-500">
                  +{incident.target_users.length - 1} more
                </div>
              )}
            </div>
          </div>
        </td>

        {/* Kill Chain Stage */}
        <td className="px-4 py-3">
          {killChainStage ? (
            <div className="flex items-center gap-2">
              <span
                className={clsx(
                  'h-2 w-2 rounded-full',
                  killChainStage.color
                )}
              />
              <span className="text-xs font-medium text-mono-700 dark:text-mono-300">
                {killChainStage.label}
              </span>
            </div>
          ) : (
            <span className="text-xs text-mono-400">-</span>
          )}
        </td>

        {/* Time */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-1 text-sm text-mono-600 dark:text-mono-400">
            <ClockIcon className="h-4 w-4" />
            {formatTimeAgo(incident.timestamp)}
          </div>
        </td>

        {/* Status */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <span
              className={clsx(
                'h-2 w-2 rounded-full',
                STATUS_STYLES[incident.status] || STATUS_STYLES.new
              )}
            />
            <span className="text-xs font-medium capitalize text-mono-700 dark:text-mono-300">
              {incident.status}
            </span>
          </div>
        </td>

        {/* Expand Icon */}
        <td className="px-4 py-3">
          <ChevronRightIcon
            className={clsx(
              'h-5 w-5 text-mono-400 transition-transform',
              isExpanded && 'rotate-90'
            )}
          />
        </td>
      </tr>

      {/* Expanded Details Row */}
      {isExpanded && (
        <tr className="bg-mono-50 dark:bg-mono-800/30">
          <td colSpan={7} className="px-4 py-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {/* Description */}
              <div>
                <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300">
                  Description
                </h4>
                <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
                  {incident.description || 'No description available'}
                </p>
              </div>

              {/* Affected Users */}
              <div>
                <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300">
                  Affected Users
                </h4>
                <div className="mt-1 flex flex-wrap gap-1">
                  {incident.target_users?.map((user) => (
                    <span
                      key={user}
                      className="inline-flex rounded-full bg-mono-200 dark:bg-mono-700 px-2 py-0.5 text-xs text-mono-700 dark:text-mono-300"
                    >
                      {user}
                    </span>
                  ))}
                </div>
              </div>

              {/* Risk Indicators */}
              {incident.risk_indicators && (
                <div>
                  <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300">
                    Risk Indicators
                  </h4>
                  <ul className="mt-1 list-inside list-disc text-sm text-mono-600 dark:text-mono-400">
                    {incident.risk_indicators.slice(0, 3).map((indicator, i) => (
                      <li key={i}>{indicator}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Actions */}
              <div className="flex items-end justify-end gap-2">
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    acknowledgeIncident(incident.id)
                  }}
                  className="flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
                >
                  <CheckCircleIcon className="h-4 w-4" />
                  Acknowledge
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onSelect(incident)
                  }}
                  className="flex items-center gap-1 rounded-md bg-mono-200 dark:bg-mono-700 px-3 py-1.5 text-sm font-medium text-mono-700 dark:text-mono-300 hover:bg-mono-300 dark:hover:bg-mono-600"
                >
                  Investigate
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    escalateIncident(incident.id)
                  }}
                  className="flex items-center gap-1 rounded-md border border-orange-500 px-3 py-1.5 text-sm font-medium text-orange-600 hover:bg-orange-50 dark:hover:bg-orange-900/20"
                >
                  <ArrowUpIcon className="h-4 w-4" />
                  Escalate
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    dismissIncident(incident.id)
                  }}
                  className="flex items-center gap-1 rounded-md border border-mono-300 dark:border-mono-600 px-3 py-1.5 text-sm font-medium text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800"
                >
                  <XMarkIcon className="h-4 w-4" />
                  Dismiss
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export default function IdentityIncidentList({ incidents, isLoading }) {
  const [expandedId, setExpandedId] = useState(null)
  const { setSelectedIncident } = useIdentityStore()

  const handleToggle = (id) => {
    setExpandedId(expandedId === id ? null : id)
  }

  const handleSelect = (incident) => {
    setSelectedIncident(incident.id)
  }

  if (isLoading) {
    return (
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-8">
        <div className="flex items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
        </div>
      </div>
    )
  }

  if (!incidents || incidents.length === 0) {
    return (
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-8">
        <div className="text-center text-mono-500 dark:text-mono-400">
          <ShieldExclamationIcon className="mx-auto h-12 w-12 text-mono-400" />
          <p className="mt-2">No active identity incidents</p>
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
          Active Identity Incidents
        </h3>
        <p className="text-sm text-mono-500 dark:text-mono-400">
          {incidents.length} incident{incidents.length !== 1 ? 's' : ''} requiring attention
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-mono-200 dark:divide-mono-800">
          <thead className="bg-mono-50 dark:bg-mono-800/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Severity
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Type
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Target Users
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Attack Stage
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Time
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Status
              </th>
              <th className="px-4 py-3 w-10"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-mono-200 dark:divide-mono-800">
            {incidents.map((incident) => (
              <IncidentRow
                key={incident.id}
                incident={incident}
                isExpanded={expandedId === incident.id}
                onToggle={handleToggle}
                onSelect={handleSelect}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Re-export for use
import { ShieldExclamationIcon } from '@heroicons/react/24/outline'
