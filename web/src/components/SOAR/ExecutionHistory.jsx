import { useState } from 'react'
import clsx from 'clsx'
import {
  MagnifyingGlassIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import { useExecutions } from '../../hooks/useSOAR'

const STATUS_CONFIG = {
  pending: {
    label: 'Pending',
    icon: ClockIcon,
    color: 'bg-gray-100 text-gray-700',
  },
  running: {
    label: 'Running',
    icon: ArrowPathIcon,
    color: 'bg-blue-100 text-blue-700',
    animate: true,
  },
  completed: {
    label: 'Completed',
    icon: CheckCircleIcon,
    color: 'bg-green-100 text-green-700',
  },
  failed: {
    label: 'Failed',
    icon: XCircleIcon,
    color: 'bg-red-100 text-red-700',
  },
  cancelled: {
    label: 'Cancelled',
    icon: XCircleIcon,
    color: 'bg-gray-100 text-gray-600',
  },
  pending_approval: {
    label: 'Awaiting Approval',
    icon: ExclamationCircleIcon,
    color: 'bg-yellow-100 text-yellow-700',
  },
}

const TRIGGER_TYPE_LABELS = {
  manual: 'Manual',
  alert: 'Alert',
  scheduled: 'Scheduled',
  webhook: 'Webhook',
}

export default function ExecutionHistory({ onViewExecution }) {
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)

  const filters = {}
  if (statusFilter) filters.status = statusFilter

  const { data, isLoading, error } = useExecutions(filters, page, 20, { polling: true })

  const executions = data?.executions || []

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
  }

  const formatDuration = (ms) => {
    if (!ms) return '-'
    if (ms < 1000) return `${ms}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
        Failed to load executions. Please try again.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Statuses</option>
          {Object.entries(STATUS_CONFIG).map(([value, config]) => (
            <option key={value} value={value}>
              {config.label}
            </option>
          ))}
        </select>
      </div>

      {executions.length === 0 ? (
        <div className="py-12 text-center text-gray-500">
          No executions found.
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Execution
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Playbook
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Trigger
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Started
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Duration
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white">
                {executions.map((execution) => {
                  const statusConfig = STATUS_CONFIG[execution.status] || STATUS_CONFIG.pending
                  const StatusIcon = statusConfig.icon
                  return (
                    <tr
                      key={execution.execution_id}
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => onViewExecution(execution.execution_id)}
                    >
                      <td className="whitespace-nowrap px-6 py-4">
                        <div className="font-mono text-sm text-gray-900">
                          {execution.execution_id.slice(0, 12)}...
                        </div>
                        {execution.dry_run && (
                          <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600">
                            Dry Run
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <div className="text-sm font-medium text-gray-900">
                          {execution.playbook_name || execution.playbook_id}
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {TRIGGER_TYPE_LABELS[execution.trigger_type] || execution.trigger_type}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span
                          className={clsx(
                            'inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold',
                            statusConfig.color
                          )}
                        >
                          <StatusIcon
                            className={clsx(
                              'h-3 w-3',
                              statusConfig.animate && 'animate-spin'
                            )}
                          />
                          {statusConfig.label}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {formatDate(execution.started_at)}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {formatDuration(execution.duration_ms)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Showing {executions.length} executions
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="rounded-lg border border-gray-300 px-3 py-1 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={executions.length < 20}
                className="rounded-lg border border-gray-300 px-3 py-1 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
