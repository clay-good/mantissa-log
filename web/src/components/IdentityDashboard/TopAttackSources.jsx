import { useState } from 'react'
import clsx from 'clsx'
import {
  ChevronUpDownIcon,
  ChevronUpIcon,
  ChevronDownIcon,
  ShieldExclamationIcon,
  NoSymbolIcon,
  CheckCircleIcon,
} from '@heroicons/react/24/outline'

const SEVERITY_COLORS = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-600 dark:text-orange-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  low: 'text-green-600 dark:text-green-400',
}

const ATTACK_TYPE_LABELS = {
  brute_force: 'Brute Force',
  credential_stuffing: 'Credential Stuffing',
  password_spray: 'Password Spray',
  mfa_fatigue: 'MFA Fatigue',
  impossible_travel: 'Impossible Travel',
  session_hijack: 'Session Hijack',
  privilege_escalation: 'Privilege Escalation',
  account_takeover: 'Account Takeover',
}

function SortIcon({ sortKey, currentSort, currentDirection }) {
  if (currentSort !== sortKey) {
    return <ChevronUpDownIcon className="h-4 w-4 text-mono-400" />
  }
  return currentDirection === 'asc' ? (
    <ChevronUpIcon className="h-4 w-4 text-primary-600" />
  ) : (
    <ChevronDownIcon className="h-4 w-4 text-primary-600" />
  )
}

function BlockStatus({ isBlocked, onBlock }) {
  if (isBlocked) {
    return (
      <div className="flex items-center gap-1 text-red-600 dark:text-red-400">
        <NoSymbolIcon className="h-4 w-4" />
        <span className="text-xs font-medium">Blocked</span>
      </div>
    )
  }

  return (
    <button
      onClick={onBlock}
      className="flex items-center gap-1 text-xs font-medium text-mono-600 hover:text-red-600 dark:text-mono-400 dark:hover:text-red-400 transition-colors"
    >
      <NoSymbolIcon className="h-4 w-4" />
      Block
    </button>
  )
}

export default function TopAttackSources({ sources, onBlockSource, className }) {
  const [sortKey, setSortKey] = useState('count')
  const [sortDirection, setSortDirection] = useState('desc')

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDirection('desc')
    }
  }

  const sortedSources = [...(sources || [])].sort((a, b) => {
    let aVal, bVal

    switch (sortKey) {
      case 'location':
        aVal = a.name || ''
        bVal = b.name || ''
        return sortDirection === 'asc'
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal)
      case 'ips':
        aVal = a.ips?.length || 0
        bVal = b.ips?.length || 0
        break
      case 'count':
        aVal = a.count || 0
        bVal = b.count || 0
        break
      case 'severity':
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 }
        aVal = severityOrder[a.maxSeverity] || 0
        bVal = severityOrder[b.maxSeverity] || 0
        break
      default:
        aVal = a.count || 0
        bVal = b.count || 0
    }

    return sortDirection === 'asc' ? aVal - bVal : bVal - aVal
  })

  if (!sources || sources.length === 0) {
    return (
      <div
        className={clsx(
          'rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-8',
          className
        )}
      >
        <div className="text-center text-mono-500 dark:text-mono-400">
          <ShieldExclamationIcon className="mx-auto h-12 w-12 text-mono-400" />
          <p className="mt-2">No attack sources detected</p>
        </div>
      </div>
    )
  }

  return (
    <div
      className={clsx(
        'rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden',
        className
      )}
    >
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
          Top Attack Sources
        </h3>
        <p className="text-sm text-mono-500 dark:text-mono-400">
          {sources.length} location{sources.length !== 1 ? 's' : ''} with attack activity
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-mono-200 dark:divide-mono-800">
          <thead className="bg-mono-50 dark:bg-mono-800/50">
            <tr>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => handleSort('location')}
              >
                <div className="flex items-center gap-1">
                  Location
                  <SortIcon
                    sortKey="location"
                    currentSort={sortKey}
                    currentDirection={sortDirection}
                  />
                </div>
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => handleSort('ips')}
              >
                <div className="flex items-center gap-1">
                  IPs
                  <SortIcon
                    sortKey="ips"
                    currentSort={sortKey}
                    currentDirection={sortDirection}
                  />
                </div>
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => handleSort('count')}
              >
                <div className="flex items-center gap-1">
                  Attacks
                  <SortIcon
                    sortKey="count"
                    currentSort={sortKey}
                    currentDirection={sortDirection}
                  />
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Types
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => handleSort('severity')}
              >
                <div className="flex items-center gap-1">
                  Severity
                  <SortIcon
                    sortKey="severity"
                    currentSort={sortKey}
                    currentDirection={sortDirection}
                  />
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-mono-200 dark:divide-mono-800">
            {sortedSources.slice(0, 10).map((source, index) => (
              <tr
                key={index}
                className="hover:bg-mono-50 dark:hover:bg-mono-800/50 transition-colors"
              >
                <td className="px-4 py-3">
                  <div className="text-sm font-medium text-mono-900 dark:text-mono-100">
                    {source.name}
                  </div>
                  {source.lat && source.lon && (
                    <div className="text-xs text-mono-500">
                      {source.lat.toFixed(2)}, {source.lon.toFixed(2)}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
                    {source.ips?.length || 0}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm font-bold text-mono-900 dark:text-mono-100">
                    {source.count}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {source.attackTypes?.slice(0, 2).map((type) => (
                      <span
                        key={type}
                        className="inline-flex rounded bg-mono-100 dark:bg-mono-800 px-1.5 py-0.5 text-xs text-mono-600 dark:text-mono-400"
                      >
                        {ATTACK_TYPE_LABELS[type] || type}
                      </span>
                    ))}
                    {source.attackTypes?.length > 2 && (
                      <span className="text-xs text-mono-500">
                        +{source.attackTypes.length - 2}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={clsx(
                      'text-sm font-medium capitalize',
                      SEVERITY_COLORS[source.maxSeverity] || 'text-mono-500'
                    )}
                  >
                    {source.maxSeverity}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <BlockStatus
                    isBlocked={source.isBlocked}
                    onBlock={() => onBlockSource?.(source)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {sources.length > 10 && (
        <div className="border-t border-mono-200 dark:border-mono-800 px-4 py-2 bg-mono-50 dark:bg-mono-800/50">
          <span className="text-xs text-mono-500">
            Showing 10 of {sources.length} sources
          </span>
        </div>
      )}
    </div>
  )
}
