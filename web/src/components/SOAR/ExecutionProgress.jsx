import { useEffect } from 'react'
import clsx from 'clsx'
import {
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import { useExecution, useExecutionLogs, useCancelExecution } from '../../hooks/useSOAR'

const STATUS_CONFIG = {
  pending: {
    icon: ClockIcon,
    color: 'text-gray-500',
    bgColor: 'bg-gray-100',
    label: 'Pending',
  },
  running: {
    icon: ArrowPathIcon,
    color: 'text-blue-500',
    bgColor: 'bg-blue-100',
    label: 'Running',
    animate: true,
  },
  completed: {
    icon: CheckCircleIcon,
    color: 'text-green-500',
    bgColor: 'bg-green-100',
    label: 'Completed',
  },
  failed: {
    icon: XCircleIcon,
    color: 'text-red-500',
    bgColor: 'bg-red-100',
    label: 'Failed',
  },
  cancelled: {
    icon: XCircleIcon,
    color: 'text-gray-500',
    bgColor: 'bg-gray-100',
    label: 'Cancelled',
  },
  pending_approval: {
    icon: ExclamationCircleIcon,
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-100',
    label: 'Awaiting Approval',
  },
}

export default function ExecutionProgress({
  executionId,
  onComplete,
  showLogs = true,
  compact = false,
}) {
  const { data, isLoading, error } = useExecution(executionId)
  const { data: logsData } = useExecutionLogs(executionId, 50, {
    enabled: showLogs && !!executionId,
    isRunning: data?.execution?.status === 'running',
  })
  const { mutate: cancelExecution, isPending: isCancelling } = useCancelExecution()

  const execution = data?.execution
  const logs = logsData?.logs || []

  useEffect(() => {
    if (execution?.is_complete && onComplete) {
      onComplete(execution)
    }
  }, [execution?.is_complete, execution, onComplete])

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-gray-500">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-gray-300 border-t-primary-600" />
        <span className="text-sm">Loading execution...</span>
      </div>
    )
  }

  if (error || !execution) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
        Failed to load execution details
      </div>
    )
  }

  const statusConfig = STATUS_CONFIG[execution.status] || STATUS_CONFIG.pending
  const StatusIcon = statusConfig.icon
  const isRunning = execution.status === 'running'
  const canCancel = isRunning || execution.status === 'pending_approval'

  if (compact) {
    return (
      <div className="flex items-center gap-2">
        <StatusIcon
          className={clsx(
            'h-5 w-5',
            statusConfig.color,
            statusConfig.animate && 'animate-spin'
          )}
        />
        <span className="text-sm font-medium">{statusConfig.label}</span>
        {execution.duration_ms && (
          <span className="text-xs text-gray-500">
            ({Math.round(execution.duration_ms / 1000)}s)
          </span>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className={clsx(
              'flex h-10 w-10 items-center justify-center rounded-full',
              statusConfig.bgColor
            )}
          >
            <StatusIcon
              className={clsx(
                'h-6 w-6',
                statusConfig.color,
                statusConfig.animate && 'animate-spin'
              )}
            />
          </div>
          <div>
            <p className="font-medium text-gray-900">{statusConfig.label}</p>
            <p className="text-sm text-gray-500">
              {execution.playbook_name || execution.playbook_id}
            </p>
          </div>
        </div>

        {canCancel && (
          <button
            onClick={() => cancelExecution({ executionId, reason: 'Cancelled by user' })}
            disabled={isCancelling}
            className="rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {isCancelling ? 'Cancelling...' : 'Cancel'}
          </button>
        )}
      </div>

      {execution.step_results && execution.step_results.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-700">Steps</p>
          <div className="space-y-1">
            {execution.step_results.map((step, index) => {
              const stepStatus = STATUS_CONFIG[step.status] || STATUS_CONFIG.pending
              const StepIcon = stepStatus.icon
              return (
                <div
                  key={step.step_id || index}
                  className="flex items-center gap-2 rounded-lg bg-gray-50 px-3 py-2"
                >
                  <StepIcon
                    className={clsx(
                      'h-4 w-4',
                      stepStatus.color,
                      stepStatus.animate && 'animate-spin'
                    )}
                  />
                  <span className="flex-1 text-sm text-gray-700">
                    {step.step_name || step.step_id}
                  </span>
                  {step.duration_ms && (
                    <span className="text-xs text-gray-500">
                      {step.duration_ms}ms
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {showLogs && logs.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-700">Action Log</p>
          <div className="max-h-48 overflow-y-auto rounded-lg bg-gray-900 p-3">
            {logs.map((log, index) => (
              <div key={log.id || index} className="text-xs">
                <span className="text-gray-500">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className="mx-2 text-gray-400">|</span>
                <span
                  className={clsx(
                    log.status === 'success' && 'text-green-400',
                    log.status === 'failed' && 'text-red-400',
                    log.status === 'pending' && 'text-yellow-400',
                    !log.status && 'text-gray-300'
                  )}
                >
                  {log.action_type}: {log.message || log.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {execution.error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3">
          <p className="text-sm font-medium text-red-800">Error</p>
          <p className="mt-1 text-sm text-red-700">{execution.error}</p>
        </div>
      )}
    </div>
  )
}
