import { useState } from 'react'
import {
  XMarkIcon,
  CheckCircleIcon,
  MagnifyingGlassIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'
import {
  useAlert,
  useAcknowledgeAlert,
  useResolveAlert,
  useRelatedAlerts,
} from '../../hooks/useAlerts'

const SEVERITY_COLORS = {
  critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical',
  high: 'text-severity-high bg-severity-high/10 border-severity-high',
  medium: 'text-severity-medium bg-severity-medium/10 border-severity-medium',
  low: 'text-severity-low bg-severity-low/10 border-severity-low',
  info: 'text-severity-info bg-severity-info/10 border-severity-info',
}

export default function AlertDetail({ alertId, onClose }) {
  const [resolution, setResolution] = useState('')
  const { data: alert, isLoading } = useAlert(alertId)
  const { data: relatedAlerts, isLoading: isLoadingRelated } = useRelatedAlerts(alertId)
  const { mutate: acknowledge, isPending: isAcknowledging } = useAcknowledgeAlert()
  const { mutate: resolve, isPending: isResolving } = useResolveAlert()

  if (isLoading) {
    return (
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl overflow-y-auto bg-white shadow-xl">
        <div className="flex h-full items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent"></div>
        </div>
      </div>
    )
  }

  if (!alert) {
    return null
  }

  const handleAcknowledge = () => {
    acknowledge(alertId)
  }

  const handleResolve = () => {
    resolve({ alertId, resolution })
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
  }

  const canAcknowledge = alert.status === 'new'
  const canResolve = alert.status === 'new' || alert.status === 'acknowledged'

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl overflow-y-auto bg-white shadow-xl">
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-gray-200 bg-white px-6 py-4">
        <h2 className="text-xl font-bold text-gray-900">Alert Details</h2>
        <button
          onClick={onClose}
          className="rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
        >
          <XMarkIcon className="h-6 w-6" />
        </button>
      </div>

      <div className="space-y-6 p-6">
        <div>
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className="text-lg font-bold text-gray-900">{alert.title}</h3>
              {alert.description && (
                <p className="mt-1 text-gray-600">{alert.description}</p>
              )}
            </div>
            <span
              className={clsx(
                'rounded-full border px-3 py-1 text-sm font-semibold',
                SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info
              )}
            >
              {alert.severity}
            </span>
          </div>

          <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-600">Rule</p>
              <p className="font-medium text-gray-900">{alert.rule_name}</p>
            </div>
            <div>
              <p className="text-gray-600">Status</p>
              <p className="font-medium capitalize text-gray-900">{alert.status}</p>
            </div>
            <div>
              <p className="text-gray-600">Triggered</p>
              <p className="font-medium text-gray-900">{formatDate(alert.timestamp)}</p>
            </div>
            <div>
              <p className="text-gray-600">Match Count</p>
              <p className="font-medium text-gray-900">{alert.match_count || 0}</p>
            </div>
          </div>
        </div>

        {alert.evidence && (
          <div>
            <h4 className="mb-2 font-medium text-gray-900">Evidence</h4>
            <div className="overflow-x-auto rounded-lg bg-gray-900 p-4">
              <pre className="text-sm text-green-400">
                {JSON.stringify(alert.evidence, null, 2)}
              </pre>
            </div>
          </div>
        )}

        <div>
          <h4 className="mb-2 font-medium text-gray-900">Timeline</h4>
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <ClockIcon className="mt-1 h-5 w-5 text-gray-400" />
              <div>
                <p className="text-sm font-medium text-gray-900">Alert Created</p>
                <p className="text-sm text-gray-500">{formatDate(alert.timestamp)}</p>
              </div>
            </div>
            {alert.acknowledged_at && (
              <div className="flex items-start gap-3">
                <CheckCircleIcon className="mt-1 h-5 w-5 text-yellow-600" />
                <div>
                  <p className="text-sm font-medium text-gray-900">Acknowledged</p>
                  <p className="text-sm text-gray-500">
                    {formatDate(alert.acknowledged_at)}
                  </p>
                  {alert.acknowledged_by && (
                    <p className="text-sm text-gray-500">by {alert.acknowledged_by}</p>
                  )}
                </div>
              </div>
            )}
            {alert.resolved_at && (
              <div className="flex items-start gap-3">
                <CheckCircleIcon className="mt-1 h-5 w-5 text-green-600" />
                <div>
                  <p className="text-sm font-medium text-gray-900">Resolved</p>
                  <p className="text-sm text-gray-500">{formatDate(alert.resolved_at)}</p>
                  {alert.resolved_by && (
                    <p className="text-sm text-gray-500">by {alert.resolved_by}</p>
                  )}
                  {alert.resolution && (
                    <p className="mt-1 text-sm text-gray-700">{alert.resolution}</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {relatedAlerts && relatedAlerts.alerts && relatedAlerts.alerts.length > 0 && (
          <div>
            <h4 className="mb-2 font-medium text-gray-900">Related Alerts</h4>
            <div className="space-y-2">
              {relatedAlerts.alerts.map((related) => (
                <div
                  key={related.id}
                  className="rounded-lg border border-gray-200 p-3 hover:bg-gray-50"
                >
                  <p className="text-sm font-medium text-gray-900">{related.title}</p>
                  <div className="mt-1 flex items-center gap-2 text-xs text-gray-500">
                    <span>{formatDate(related.timestamp)}</span>
                    <span>•</span>
                    <span className="capitalize">{related.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="border-t border-gray-200 pt-6">
          <h4 className="mb-3 font-medium text-gray-900">Actions</h4>
          <div className="space-y-3">
            {canAcknowledge && (
              <button
                onClick={handleAcknowledge}
                disabled={isAcknowledging}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-yellow-600 px-4 py-2 text-sm font-medium text-white hover:bg-yellow-700 disabled:opacity-50"
              >
                <CheckCircleIcon className="h-5 w-5" />
                {isAcknowledging ? 'Acknowledging...' : 'Acknowledge Alert'}
              </button>
            )}

            {canResolve && (
              <div className="space-y-2">
                <textarea
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value)}
                  placeholder="Resolution notes (optional)"
                  rows={3}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
                <button
                  onClick={handleResolve}
                  disabled={isResolving}
                  className="flex w-full items-center justify-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
                >
                  <CheckCircleIcon className="h-5 w-5" />
                  {isResolving ? 'Resolving...' : 'Resolve Alert'}
                </button>
              </div>
            )}

            <button
              onClick={() => {
                // Navigate to query page with pre-filled context
                window.location.href = `/query?context=alert:${alertId}`
              }}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              <MagnifyingGlassIcon className="h-5 w-5" />
              Investigate Further
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
