import { useState } from 'react'
import clsx from 'clsx'
import {
  CheckCircleIcon,
  XCircleIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  KeyIcon,
  ArrowRightOnRectangleIcon,
  ArrowUpCircleIcon,
  ArrowDownCircleIcon,
  DevicePhoneMobileIcon,
  ComputerDesktopIcon,
  ExclamationTriangleIcon,
  MapPinIcon,
  ChevronDownIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline'

const EVENT_TYPE_CONFIG = {
  auth_success: {
    icon: CheckCircleIcon,
    color: 'text-green-500',
    bgColor: 'bg-green-100 dark:bg-green-900/30',
    label: 'Login Success',
  },
  auth_failure: {
    icon: XCircleIcon,
    color: 'text-red-500',
    bgColor: 'bg-red-100 dark:bg-red-900/30',
    label: 'Login Failed',
  },
  mfa_success: {
    icon: ShieldCheckIcon,
    color: 'text-green-500',
    bgColor: 'bg-green-100 dark:bg-green-900/30',
    label: 'MFA Success',
  },
  mfa_failure: {
    icon: ShieldExclamationIcon,
    color: 'text-red-500',
    bgColor: 'bg-red-100 dark:bg-red-900/30',
    label: 'MFA Failed',
  },
  mfa_challenge: {
    icon: DevicePhoneMobileIcon,
    color: 'text-blue-500',
    bgColor: 'bg-blue-100 dark:bg-blue-900/30',
    label: 'MFA Challenge',
  },
  session_start: {
    icon: ArrowRightOnRectangleIcon,
    color: 'text-blue-500',
    bgColor: 'bg-blue-100 dark:bg-blue-900/30',
    label: 'Session Start',
  },
  session_end: {
    icon: ArrowRightOnRectangleIcon,
    color: 'text-mono-500',
    bgColor: 'bg-mono-100 dark:bg-mono-800',
    label: 'Session End',
  },
  privilege_grant: {
    icon: ArrowUpCircleIcon,
    color: 'text-purple-500',
    bgColor: 'bg-purple-100 dark:bg-purple-900/30',
    label: 'Privilege Granted',
  },
  privilege_revoke: {
    icon: ArrowDownCircleIcon,
    color: 'text-orange-500',
    bgColor: 'bg-orange-100 dark:bg-orange-900/30',
    label: 'Privilege Revoked',
  },
  password_change: {
    icon: KeyIcon,
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-100 dark:bg-yellow-900/30',
    label: 'Password Changed',
  },
  anomaly: {
    icon: ExclamationTriangleIcon,
    color: 'text-red-500',
    bgColor: 'bg-red-100 dark:bg-red-900/30',
    label: 'Anomaly Detected',
  },
  device_new: {
    icon: ComputerDesktopIcon,
    color: 'text-blue-500',
    bgColor: 'bg-blue-100 dark:bg-blue-900/30',
    label: 'New Device',
  },
  location_new: {
    icon: MapPinIcon,
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-100 dark:bg-yellow-900/30',
    label: 'New Location',
  },
}

const TIME_RANGE_OPTIONS = [
  { value: '1h', label: 'Last Hour' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
  { value: '90d', label: 'Last 90 Days' },
]

const RISK_LEVEL_OPTIONS = [
  { value: 'all', label: 'All Risk Levels' },
  { value: 'high', label: 'High Risk Only' },
  { value: 'medium', label: 'Medium & High' },
]

function formatTimestamp(timestamp) {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleString()
}

function TimelineEvent({ event }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const config = EVENT_TYPE_CONFIG[event.event_type] || {
    icon: ExclamationTriangleIcon,
    color: 'text-mono-500',
    bgColor: 'bg-mono-100 dark:bg-mono-800',
    label: event.event_type,
  }
  const Icon = config.icon

  const hasRisk = event.risk_indicators && event.risk_indicators.length > 0

  return (
    <div className="relative flex gap-4">
      {/* Timeline line */}
      <div className="absolute left-5 top-10 bottom-0 w-0.5 bg-mono-200 dark:bg-mono-700" />

      {/* Event icon */}
      <div
        className={clsx(
          'relative z-10 flex h-10 w-10 items-center justify-center rounded-full',
          config.bgColor
        )}
      >
        <Icon className={clsx('h-5 w-5', config.color)} />
      </div>

      {/* Event content */}
      <div className="flex-1 pb-6">
        <div
          className={clsx(
            'rounded-lg border bg-white dark:bg-mono-800 p-4 transition-shadow cursor-pointer hover:shadow-md',
            hasRisk
              ? 'border-red-200 dark:border-red-800'
              : 'border-mono-200 dark:border-mono-700'
          )}
          onClick={() => setIsExpanded(!isExpanded)}
        >
          {/* Header */}
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-mono-900 dark:text-mono-100">
                  {config.label}
                </span>
                {hasRisk && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-red-100 dark:bg-red-900/30 px-2 py-0.5 text-xs font-medium text-red-700 dark:text-red-300">
                    <ExclamationTriangleIcon className="h-3 w-3" />
                    Risk
                  </span>
                )}
              </div>
              <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
                {event.description || 'No description available'}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-mono-500 dark:text-mono-400">
                {formatTimestamp(event.timestamp)}
              </span>
              <ChevronDownIcon
                className={clsx(
                  'h-4 w-4 text-mono-400 transition-transform',
                  isExpanded && 'rotate-180'
                )}
              />
            </div>
          </div>

          {/* Context info */}
          <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-mono-500 dark:text-mono-400">
            {event.source_ip && (
              <span className="flex items-center gap-1">
                <span className="font-medium">IP:</span> {event.source_ip}
              </span>
            )}
            {event.location && (
              <span className="flex items-center gap-1">
                <MapPinIcon className="h-3 w-3" />
                {event.location}
              </span>
            )}
            {event.device && (
              <span className="flex items-center gap-1">
                <ComputerDesktopIcon className="h-3 w-3" />
                {event.device}
              </span>
            )}
            {event.application && (
              <span>{event.application}</span>
            )}
          </div>

          {/* Expanded details */}
          {isExpanded && (
            <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-700 space-y-3">
              {/* Risk Indicators */}
              {hasRisk && (
                <div>
                  <h5 className="text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                    Risk Indicators
                  </h5>
                  <ul className="list-disc list-inside text-xs text-mono-600 dark:text-mono-400 space-y-0.5">
                    {event.risk_indicators.map((indicator, i) => (
                      <li key={i}>{indicator}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Additional Details */}
              {event.details && (
                <div>
                  <h5 className="text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                    Details
                  </h5>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {Object.entries(event.details).map(([key, value]) => (
                      <div key={key}>
                        <span className="text-mono-500 dark:text-mono-400">{key}: </span>
                        <span className="text-mono-700 dark:text-mono-300">{String(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw Event */}
              {event.raw_event && (
                <div>
                  <h5 className="text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                    Raw Event
                  </h5>
                  <pre className="text-xs bg-mono-100 dark:bg-mono-900 p-2 rounded overflow-x-auto">
                    {JSON.stringify(event.raw_event, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function ActivityTimeline({ events, filters, onFilterChange }) {
  const [showFilters, setShowFilters] = useState(false)

  const eventTypes = Object.entries(EVENT_TYPE_CONFIG).map(([value, config]) => ({
    value,
    label: config.label,
  }))

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      {/* Header */}
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
              Activity Timeline
            </h3>
            <p className="text-sm text-mono-500 dark:text-mono-400">
              {events?.length || 0} events
            </p>
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={clsx(
              'flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors',
              showFilters
                ? 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
                : 'text-mono-600 hover:bg-mono-100 dark:text-mono-400 dark:hover:bg-mono-800'
            )}
          >
            <FunnelIcon className="h-4 w-4" />
            Filters
          </button>
        </div>

        {/* Filters */}
        {showFilters && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Time Range */}
            <div>
              <label className="block text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                Time Range
              </label>
              <select
                value={filters.timeRange}
                onChange={(e) => onFilterChange({ timeRange: e.target.value })}
                className="w-full rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                {TIME_RANGE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Risk Level */}
            <div>
              <label className="block text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                Risk Level
              </label>
              <select
                value={filters.riskLevel}
                onChange={(e) => onFilterChange({ riskLevel: e.target.value })}
                className="w-full rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                {RISK_LEVEL_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Event Types */}
            <div>
              <label className="block text-xs font-medium text-mono-700 dark:text-mono-300 mb-1">
                Event Types
              </label>
              <select
                value={filters.eventTypes.length === 0 ? 'all' : filters.eventTypes[0]}
                onChange={(e) =>
                  onFilterChange({
                    eventTypes: e.target.value === 'all' ? [] : [e.target.value],
                  })
                }
                className="w-full rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                <option value="all">All Event Types</option>
                {eventTypes.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Timeline */}
      <div className="p-4 max-h-[600px] overflow-y-auto">
        {events && events.length > 0 ? (
          <div className="space-y-0">
            {events.map((event, index) => (
              <TimelineEvent key={event.id || index} event={event} />
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-mono-500 dark:text-mono-400">No events found</p>
          </div>
        )}
      </div>
    </div>
  )
}
