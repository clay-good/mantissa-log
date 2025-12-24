import clsx from 'clsx'
import { FunnelIcon, XMarkIcon } from '@heroicons/react/24/outline'

const TIME_RANGE_OPTIONS = [
  { value: '1h', label: 'Last Hour' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
]

const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

const ATTACK_TYPE_OPTIONS = [
  { value: 'all', label: 'All Types' },
  { value: 'brute_force', label: 'Brute Force' },
  { value: 'credential_stuffing', label: 'Credential Stuffing' },
  { value: 'password_spray', label: 'Password Spray' },
  { value: 'mfa_fatigue', label: 'MFA Fatigue' },
  { value: 'impossible_travel', label: 'Impossible Travel' },
  { value: 'session_hijack', label: 'Session Hijack' },
  { value: 'privilege_escalation', label: 'Privilege Escalation' },
]

const PROVIDER_OPTIONS = [
  { value: 'all', label: 'All Providers' },
  { value: 'okta', label: 'Okta' },
  { value: 'azure', label: 'Azure AD' },
  { value: 'google', label: 'Google Workspace' },
  { value: 'duo', label: 'Duo' },
  { value: 'm365', label: 'Microsoft 365' },
]

export default function AttackMapFilters({ filters, onFilterChange, className }) {
  const handleChange = (key, value) => {
    onFilterChange({ ...filters, [key]: value })
  }

  const clearFilters = () => {
    onFilterChange({
      timeRange: '24h',
      severity: 'all',
      attackType: 'all',
      provider: 'all',
    })
  }

  const hasActiveFilters =
    filters.severity !== 'all' ||
    filters.attackType !== 'all' ||
    filters.provider !== 'all'

  return (
    <div className={clsx('flex flex-wrap items-center gap-3', className)}>
      <div className="flex items-center gap-2 text-mono-600 dark:text-mono-400">
        <FunnelIcon className="h-4 w-4" />
        <span className="text-sm font-medium">Filters</span>
      </div>

      {/* Time Range */}
      <select
        value={filters.timeRange}
        onChange={(e) => handleChange('timeRange', e.target.value)}
        className="rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-1.5 text-sm text-mono-900 dark:text-mono-100"
      >
        {TIME_RANGE_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      {/* Severity */}
      <select
        value={filters.severity}
        onChange={(e) => handleChange('severity', e.target.value)}
        className={clsx(
          'rounded-lg border px-3 py-1.5 text-sm',
          filters.severity !== 'all'
            ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
            : 'border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 text-mono-900 dark:text-mono-100'
        )}
      >
        {SEVERITY_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      {/* Attack Type */}
      <select
        value={filters.attackType}
        onChange={(e) => handleChange('attackType', e.target.value)}
        className={clsx(
          'rounded-lg border px-3 py-1.5 text-sm',
          filters.attackType !== 'all'
            ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
            : 'border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 text-mono-900 dark:text-mono-100'
        )}
      >
        {ATTACK_TYPE_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      {/* Provider */}
      <select
        value={filters.provider}
        onChange={(e) => handleChange('provider', e.target.value)}
        className={clsx(
          'rounded-lg border px-3 py-1.5 text-sm',
          filters.provider !== 'all'
            ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
            : 'border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 text-mono-900 dark:text-mono-100'
        )}
      >
        {PROVIDER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      {/* Clear Filters */}
      {hasActiveFilters && (
        <button
          onClick={clearFilters}
          className="flex items-center gap-1 rounded-lg px-2 py-1.5 text-sm text-mono-600 hover:bg-mono-100 dark:text-mono-400 dark:hover:bg-mono-800"
        >
          <XMarkIcon className="h-4 w-4" />
          Clear
        </button>
      )}
    </div>
  )
}
