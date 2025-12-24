import { Fragment } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import clsx from 'clsx'
import {
  XMarkIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
  ChevronDownIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline'
import { useState } from 'react'
import { useExecution, useExecutionLogs, useCancelExecution } from '../../hooks/useSOAR'
import ApprovalPrompt from './ApprovalPrompt'

const STATUS_CONFIG = {
  pending: {
    label: 'Pending',
    icon: ClockIcon,
    color: 'text-gray-500',
    bgColor: 'bg-gray-100',
  },
  running: {
    label: 'Running',
    icon: ArrowPathIcon,
    color: 'text-blue-500',
    bgColor: 'bg-blue-100',
    animate: true,
  },
  completed: {
    label: 'Completed',
    icon: CheckCircleIcon,
    color: 'text-green-500',
    bgColor: 'bg-green-100',
  },
  failed: {
    label: 'Failed',
    icon: XCircleIcon,
    color: 'text-red-500',
    bgColor: 'bg-red-100',
  },
  cancelled: {
    label: 'Cancelled',
    icon: XCircleIcon,
    color: 'text-gray-500',
    bgColor: 'bg-gray-100',
  },
  pending_approval: {
    label: 'Awaiting Approval',
    icon: ExclamationCircleIcon,
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-100',
  },
}

export default function ExecutionDetail({ executionId, onClose }) {
  const [expandedSteps, setExpandedSteps] = useState({})

  const { data, isLoading, error } = useExecution(executionId)
  const { data: logsData } = useExecutionLogs(executionId, 100, {
    isRunning: data?.execution?.status === 'running',
  })
  const { mutate: cancelExecution, isPending: isCancelling } = useCancelExecution()

  const execution = data?.execution
  const logs = logsData?.logs || []

  const toggleStep = (stepId) => {
    setExpandedSteps((prev) => ({
      ...prev,
      [stepId]: !prev[stepId],
    }))
  }

  const handleCancel = () => {
    cancelExecution({ executionId, reason: 'Cancelled by user' })
  }

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

  return (
    <Transition appear show={true} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/50" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-4xl transform overflow-hidden rounded-2xl bg-white shadow-xl transition-all">
                {isLoading ? (
                  <div className="flex h-96 items-center justify-center">
                    <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
                  </div>
                ) : error || !execution ? (
                  <div className="p-6">
                    <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
                      Failed to load execution details.
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
                      <div>
                        <Dialog.Title className="text-xl font-semibold text-gray-900">
                          Execution Details
                        </Dialog.Title>
                        <p className="mt-1 font-mono text-sm text-gray-500">
                          {execution.execution_id}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        {(execution.status === 'running' ||
                          execution.status === 'pending_approval') && (
                          <button
                            onClick={handleCancel}
                            disabled={isCancelling}
                            className="rounded-lg border border-red-300 bg-white px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-50"
                          >
                            {isCancelling ? 'Cancelling...' : 'Cancel'}
                          </button>
                        )}
                        <button
                          onClick={onClose}
                          className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                        >
                          <XMarkIcon className="h-5 w-5" />
                        </button>
                      </div>
                    </div>

                    <div className="max-h-[70vh] overflow-y-auto p-6">
                      <div className="space-y-6">
                        <div className="grid grid-cols-3 gap-6">
                          <div className="rounded-lg border border-gray-200 p-4">
                            <p className="text-sm text-gray-500">Status</p>
                            <div className="mt-2 flex items-center gap-2">
                              {(() => {
                                const config =
                                  STATUS_CONFIG[execution.status] || STATUS_CONFIG.pending
                                const Icon = config.icon
                                return (
                                  <>
                                    <div
                                      className={clsx(
                                        'flex h-8 w-8 items-center justify-center rounded-full',
                                        config.bgColor
                                      )}
                                    >
                                      <Icon
                                        className={clsx(
                                          'h-5 w-5',
                                          config.color,
                                          config.animate && 'animate-spin'
                                        )}
                                      />
                                    </div>
                                    <span className="font-medium text-gray-900">
                                      {config.label}
                                    </span>
                                  </>
                                )
                              })()}
                            </div>
                          </div>

                          <div className="rounded-lg border border-gray-200 p-4">
                            <p className="text-sm text-gray-500">Playbook</p>
                            <p className="mt-2 font-medium text-gray-900">
                              {execution.playbook_name || execution.playbook_id}
                            </p>
                            {execution.dry_run && (
                              <span className="mt-1 inline-block rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                                Dry Run
                              </span>
                            )}
                          </div>

                          <div className="rounded-lg border border-gray-200 p-4">
                            <p className="text-sm text-gray-500">Duration</p>
                            <p className="mt-2 font-medium text-gray-900">
                              {formatDuration(execution.duration_ms)}
                            </p>
                            <p className="text-xs text-gray-500">
                              Started: {formatDate(execution.started_at)}
                            </p>
                          </div>
                        </div>

                        {execution.trigger_context && (
                          <div>
                            <h3 className="mb-2 font-medium text-gray-900">
                              Trigger Context
                            </h3>
                            <div className="rounded-lg bg-gray-50 p-4">
                              <pre className="overflow-auto text-sm text-gray-700">
                                {JSON.stringify(execution.trigger_context, null, 2)}
                              </pre>
                            </div>
                          </div>
                        )}

                        {execution.pending_approval && (
                          <ApprovalPrompt
                            approval={execution.pending_approval}
                            onComplete={() => {}}
                          />
                        )}

                        {execution.step_results && execution.step_results.length > 0 && (
                          <div>
                            <h3 className="mb-3 font-medium text-gray-900">
                              Step Execution ({execution.step_results.length})
                            </h3>
                            <div className="space-y-2">
                              {execution.step_results.map((step, index) => {
                                const stepConfig =
                                  STATUS_CONFIG[step.status] || STATUS_CONFIG.pending
                                const StepIcon = stepConfig.icon
                                const isExpanded = expandedSteps[step.step_id]

                                return (
                                  <div
                                    key={step.step_id}
                                    className="rounded-lg border border-gray-200"
                                  >
                                    <div
                                      className="flex cursor-pointer items-center justify-between p-3"
                                      onClick={() => toggleStep(step.step_id)}
                                    >
                                      <div className="flex items-center gap-3">
                                        <span
                                          className={clsx(
                                            'flex h-6 w-6 items-center justify-center rounded-full',
                                            stepConfig.bgColor
                                          )}
                                        >
                                          <StepIcon
                                            className={clsx(
                                              'h-4 w-4',
                                              stepConfig.color,
                                              stepConfig.animate && 'animate-spin'
                                            )}
                                          />
                                        </span>
                                        <div>
                                          <p className="font-medium text-gray-900">
                                            {step.step_name || step.step_id}
                                          </p>
                                          <p className="text-sm text-gray-500">
                                            {step.action_type}
                                            {step.duration_ms &&
                                              ` • ${formatDuration(step.duration_ms)}`}
                                          </p>
                                        </div>
                                      </div>
                                      {isExpanded ? (
                                        <ChevronDownIcon className="h-5 w-5 text-gray-400" />
                                      ) : (
                                        <ChevronRightIcon className="h-5 w-5 text-gray-400" />
                                      )}
                                    </div>

                                    {isExpanded && (
                                      <div className="border-t border-gray-200 bg-gray-50 p-4">
                                        {step.input && (
                                          <div className="mb-3">
                                            <p className="mb-1 text-xs font-medium text-gray-500">
                                              Input
                                            </p>
                                            <pre className="rounded bg-white p-2 text-xs">
                                              {JSON.stringify(step.input, null, 2)}
                                            </pre>
                                          </div>
                                        )}
                                        {step.output && (
                                          <div className="mb-3">
                                            <p className="mb-1 text-xs font-medium text-gray-500">
                                              Output
                                            </p>
                                            <pre className="rounded bg-white p-2 text-xs">
                                              {JSON.stringify(step.output, null, 2)}
                                            </pre>
                                          </div>
                                        )}
                                        {step.error && (
                                          <div>
                                            <p className="mb-1 text-xs font-medium text-red-500">
                                              Error
                                            </p>
                                            <pre className="rounded bg-red-50 p-2 text-xs text-red-700">
                                              {step.error}
                                            </pre>
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                )
                              })}
                            </div>
                          </div>
                        )}

                        {logs.length > 0 && (
                          <div>
                            <h3 className="mb-3 font-medium text-gray-900">
                              Action Log ({logs.length})
                            </h3>
                            <div className="max-h-64 overflow-y-auto rounded-lg bg-gray-900 p-4">
                              {logs.map((log, index) => (
                                <div
                                  key={log.id || index}
                                  className="font-mono text-xs"
                                >
                                  <span className="text-gray-500">
                                    {new Date(log.timestamp).toLocaleTimeString()}
                                  </span>
                                  <span className="mx-2 text-gray-600">|</span>
                                  <span
                                    className={clsx(
                                      log.status === 'success' && 'text-green-400',
                                      log.status === 'failed' && 'text-red-400',
                                      log.status === 'skipped' && 'text-yellow-400',
                                      !['success', 'failed', 'skipped'].includes(
                                        log.status
                                      ) && 'text-gray-300'
                                    )}
                                  >
                                    [{log.action_type}] {log.message || log.status}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {execution.error && (
                          <div className="rounded-lg border border-red-200 bg-red-50 p-4">
                            <h3 className="font-medium text-red-800">Execution Error</h3>
                            <p className="mt-1 text-sm text-red-700">{execution.error}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </>
                )}
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
