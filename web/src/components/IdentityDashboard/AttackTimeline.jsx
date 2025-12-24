import { useState } from 'react'
import clsx from 'clsx'
import {
  ShieldExclamationIcon,
  UserIcon,
  ClockIcon,
  ChevronDownIcon,
} from '@heroicons/react/24/outline'

const SEVERITY_COLORS = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
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
  RECONNAISSANCE: { label: 'Reconnaissance', order: 0 },
  INITIAL_ACCESS: { label: 'Initial Access', order: 1 },
  CREDENTIAL_ACCESS: { label: 'Credential Access', order: 2 },
  PERSISTENCE: { label: 'Persistence', order: 3 },
  PRIVILEGE_ESCALATION: { label: 'Privilege Escalation', order: 4 },
  LATERAL_MOVEMENT: { label: 'Lateral Movement', order: 5 },
  COLLECTION: { label: 'Collection', order: 6 },
  OBJECTIVES: { label: 'Objectives', order: 7 },
}

function formatTime(timestamp) {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function formatDate(timestamp) {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

function groupEventsByDay(events) {
  const groups = {}
  events.forEach((event) => {
    const date = new Date(event.timestamp).toDateString()
    if (!groups[date]) {
      groups[date] = []
    }
    groups[date].push(event)
  })
  return Object.entries(groups).map(([date, events]) => ({
    date,
    events: events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
  }))
}

function TimelineEvent({ event, onSelect }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const killChainStage = KILL_CHAIN_STAGES[event.kill_chain_stage]

  return (
    <div className="relative flex gap-4">
      {/* Timeline line */}
      <div className="absolute left-[11px] top-6 bottom-0 w-0.5 bg-mono-200 dark:bg-mono-700" />

      {/* Severity dot */}
      <div
        className={clsx(
          'relative z-10 mt-1.5 h-6 w-6 rounded-full border-4 border-white dark:border-mono-900',
          SEVERITY_COLORS[event.severity] || SEVERITY_COLORS.medium
        )}
      />

      {/* Event content */}
      <div className="flex-1 pb-6">
        <div
          className={clsx(
            'rounded-lg border border-mono-200 dark:border-mono-700 bg-white dark:bg-mono-800 p-3 cursor-pointer transition-shadow hover:shadow-md',
            isExpanded && 'ring-2 ring-primary-500'
          )}
          onClick={() => setIsExpanded(!isExpanded)}
        >
          {/* Header */}
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-mono-900 dark:text-mono-100">
                  {ATTACK_TYPE_LABELS[event.attack_type] || event.attack_type}
                </span>
                <span
                  className={clsx(
                    'inline-flex rounded-full px-2 py-0.5 text-xs font-medium capitalize',
                    event.severity === 'critical' && 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
                    event.severity === 'high' && 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
                    event.severity === 'medium' && 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
                    event.severity === 'low' && 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                  )}
                >
                  {event.severity}
                </span>
              </div>

              <div className="mt-1 flex items-center gap-4 text-xs text-mono-500 dark:text-mono-400">
                <span className="flex items-center gap-1">
                  <ClockIcon className="h-3 w-3" />
                  {formatTime(event.timestamp)}
                </span>
                <span className="flex items-center gap-1">
                  <UserIcon className="h-3 w-3" />
                  {event.target_users?.[0] || 'Unknown'}
                  {event.target_users?.length > 1 && ` +${event.target_users.length - 1}`}
                </span>
                <span className="text-mono-400">{event.provider}</span>
              </div>
            </div>

            <ChevronDownIcon
              className={clsx(
                'h-5 w-5 text-mono-400 transition-transform',
                isExpanded && 'rotate-180'
              )}
            />
          </div>

          {/* Kill Chain Progress */}
          {killChainStage && (
            <div className="mt-3">
              <div className="text-xs text-mono-500 dark:text-mono-400 mb-1">
                Kill Chain Stage: {killChainStage.label}
              </div>
              <div className="flex gap-0.5">
                {Object.entries(KILL_CHAIN_STAGES).map(([key, stage]) => (
                  <div
                    key={key}
                    className={clsx(
                      'h-1.5 flex-1 rounded-full transition-colors',
                      stage.order <= killChainStage.order
                        ? stage.order === killChainStage.order
                          ? SEVERITY_COLORS[event.severity]
                          : 'bg-mono-400 dark:bg-mono-500'
                        : 'bg-mono-200 dark:bg-mono-700'
                    )}
                    title={stage.label}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Expanded details */}
          {isExpanded && (
            <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-700">
              <p className="text-sm text-mono-600 dark:text-mono-400">
                {event.description || 'No additional details available.'}
              </p>

              {event.risk_indicators && event.risk_indicators.length > 0 && (
                <div className="mt-3">
                  <h5 className="text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                    Risk Indicators
                  </h5>
                  <ul className="list-disc list-inside text-xs text-mono-600 dark:text-mono-400 space-y-0.5">
                    {event.risk_indicators.slice(0, 3).map((indicator, i) => (
                      <li key={i}>{indicator}</li>
                    ))}
                  </ul>
                </div>
              )}

              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onSelect(event)
                }}
                className="mt-3 text-xs font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
              >
                View Full Details →
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AttackTimeline({ incidents, onSelectIncident }) {
  const [visibleDays, setVisibleDays] = useState(3)

  if (!incidents || incidents.length === 0) {
    return (
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-8">
        <div className="text-center text-mono-500 dark:text-mono-400">
          <ShieldExclamationIcon className="mx-auto h-12 w-12 text-mono-400" />
          <p className="mt-2">No attack events in timeline</p>
        </div>
      </div>
    )
  }

  const groupedEvents = groupEventsByDay(incidents)
  const visibleGroups = groupedEvents.slice(0, visibleDays)
  const hasMore = groupedEvents.length > visibleDays

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
          Attack Timeline
        </h3>
        <p className="text-sm text-mono-500 dark:text-mono-400">
          Recent identity attack events
        </p>
      </div>

      <div className="p-4">
        {visibleGroups.map((group, groupIndex) => (
          <div key={group.date} className={groupIndex > 0 ? 'mt-6' : ''}>
            {/* Date header */}
            <div className="flex items-center gap-2 mb-4">
              <div className="h-px flex-1 bg-mono-200 dark:bg-mono-700" />
              <span className="text-xs font-medium text-mono-500 dark:text-mono-400 px-2">
                {formatDate(group.events[0].timestamp)}
              </span>
              <div className="h-px flex-1 bg-mono-200 dark:bg-mono-700" />
            </div>

            {/* Events */}
            <div className="relative">
              {group.events.map((event, index) => (
                <TimelineEvent
                  key={event.id || index}
                  event={event}
                  onSelect={onSelectIncident}
                />
              ))}
            </div>
          </div>
        ))}

        {hasMore && (
          <button
            onClick={() => setVisibleDays((prev) => prev + 3)}
            className="mt-4 w-full py-2 text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 border border-mono-200 dark:border-mono-700 rounded-lg hover:bg-mono-50 dark:hover:bg-mono-800"
          >
            Load More Events
          </button>
        )}
      </div>
    </div>
  )
}
