import { useState } from 'react'
import clsx from 'clsx'
import { CheckCircleIcon, ExclamationCircleIcon } from '@heroicons/react/24/outline'

const SEVERITY_COLORS = {
  critical: 'text-severity-critical bg-severity-critical/10',
  high: 'text-severity-high bg-severity-high/10',
  medium: 'text-severity-medium bg-severity-medium/10',
  low: 'text-severity-low bg-severity-low/10',
  info: 'text-severity-info bg-severity-info/10',
}

const STATUS_ICONS = {
  new: ExclamationCircleIcon,
  acknowledged: CheckCircleIcon,
  resolved: CheckCircleIcon,
}

const STATUS_COLORS = {
  new: 'text-red-600',
  acknowledged: 'text-yellow-600',
  resolved: 'text-green-600',
}

export default function AlertList({
  alerts,
  isLoading,
  onSelectAlert,
  selectedAlertId,
  onSelectForBulk,
  selectedAlerts,
}) {
  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
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

  const truncateText = (text, maxLength = 100) => {
    if (!text) return ''
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent"></div>
      </div>
    )
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="py-12 text-center text-gray-500">
        No alerts found
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="w-8 px-3 py-3">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                onChange={(e) => {
                  if (e.target.checked) {
                    onSelectForBulk(alerts.map((a) => a.id))
                  } else {
                    onSelectForBulk([])
                  }
                }}
              />
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Time
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Rule
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Title
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Severity
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Status
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 bg-white">
          {alerts.map((alert) => {
            const StatusIcon = STATUS_ICONS[alert.status] || ExclamationCircleIcon
            const isSelected = selectedAlerts?.includes(alert.id)

            return (
              <tr
                key={alert.id}
                onClick={() => onSelectAlert(alert.id)}
                className={clsx(
                  'cursor-pointer hover:bg-gray-50',
                  selectedAlertId === alert.id && 'bg-blue-50'
                )}
              >
                <td
                  className="px-3 py-4"
                  onClick={(e) => e.stopPropagation()}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={(e) => {
                      if (e.target.checked) {
                        onSelectForBulk([...(selectedAlerts || []), alert.id])
                      } else {
                        onSelectForBulk(
                          (selectedAlerts || []).filter((id) => id !== alert.id)
                        )
                      }
                    }}
                    className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                </td>
                <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                  {formatDate(alert.timestamp)}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">
                  {alert.rule_name || 'Unknown Rule'}
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm font-medium text-gray-900">
                    {truncateText(alert.title, 60)}
                  </div>
                  {alert.description && (
                    <div className="text-sm text-gray-500">
                      {truncateText(alert.description, 80)}
                    </div>
                  )}
                </td>
                <td className="px-6 py-4">
                  <span
                    className={clsx(
                      'inline-flex rounded-full px-2 py-1 text-xs font-semibold',
                      SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info
                    )}
                  >
                    {alert.severity}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <StatusIcon
                      className={clsx('h-5 w-5', STATUS_COLORS[alert.status])}
                    />
                    <span className="text-sm capitalize text-gray-900">
                      {alert.status}
                    </span>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
