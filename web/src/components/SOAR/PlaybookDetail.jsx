import { Fragment } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import clsx from 'clsx'
import {
  XMarkIcon,
  PlayIcon,
  PencilIcon,
  ClockIcon,
  UserIcon,
  TagIcon,
  ArrowRightIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  CodeBracketIcon,
} from '@heroicons/react/24/outline'
import { usePlaybook, usePlaybookVersions, useExecutePlaybook } from '../../hooks/useSOAR'

const TRIGGER_TYPE_LABELS = {
  manual: 'Manual',
  alert: 'Alert Trigger',
  scheduled: 'Scheduled',
  webhook: 'Webhook',
}

const ACTION_TYPE_ICONS = {
  isolate_host: '🖥️',
  block_ip: '🚫',
  disable_user: '👤',
  quarantine_file: '📁',
  notify: '📢',
  create_ticket: '🎫',
  query: '🔍',
  webhook: '🔗',
}

export default function PlaybookDetail({ playbookId, onClose, onEdit }) {
  const { data, isLoading, error } = usePlaybook(playbookId)
  const { data: versionsData } = usePlaybookVersions(playbookId)
  const { mutate: executePlaybook, isPending: isExecuting } = useExecutePlaybook()

  const playbook = data?.playbook
  const stats = data?.stats
  const versions = versionsData?.versions || []

  const handleExecute = (dryRun = true) => {
    executePlaybook({
      playbookId,
      dryRun,
    })
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
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
                ) : error || !playbook ? (
                  <div className="p-6">
                    <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
                      Failed to load playbook details.
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
                      <div className="flex items-center gap-4">
                        <div>
                          <Dialog.Title className="text-xl font-semibold text-gray-900">
                            {playbook.name}
                          </Dialog.Title>
                          <div className="mt-1 flex items-center gap-3 text-sm text-gray-500">
                            <span>v{playbook.version}</span>
                            <span>•</span>
                            <span
                              className={clsx(
                                'rounded-full px-2 py-0.5 text-xs font-medium',
                                playbook.enabled
                                  ? 'bg-green-100 text-green-700'
                                  : 'bg-gray-100 text-gray-600'
                              )}
                            >
                              {playbook.enabled ? 'Enabled' : 'Disabled'}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => onEdit(playbook)}
                          className="flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                        >
                          <PencilIcon className="h-4 w-4" />
                          Edit
                        </button>
                        <button
                          onClick={() => handleExecute(true)}
                          disabled={isExecuting}
                          className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
                        >
                          <PlayIcon className="h-4 w-4" />
                          {isExecuting ? 'Running...' : 'Execute'}
                        </button>
                        <button
                          onClick={onClose}
                          className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                        >
                          <XMarkIcon className="h-5 w-5" />
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-6 p-6">
                      <div className="col-span-2 space-y-6">
                        {playbook.description && (
                          <div>
                            <h3 className="mb-2 text-sm font-medium text-gray-500">
                              Description
                            </h3>
                            <p className="text-gray-900">{playbook.description}</p>
                          </div>
                        )}

                        <div>
                          <h3 className="mb-2 text-sm font-medium text-gray-500">
                            Trigger
                          </h3>
                          <div className="rounded-lg border border-gray-200 p-4">
                            <p className="font-medium text-gray-900">
                              {TRIGGER_TYPE_LABELS[playbook.trigger?.trigger_type] ||
                                playbook.trigger?.trigger_type}
                            </p>
                            {playbook.trigger?.conditions &&
                              Object.keys(playbook.trigger.conditions).length > 0 && (
                                <div className="mt-2 text-sm text-gray-600">
                                  <p className="font-medium">Conditions:</p>
                                  <pre className="mt-1 rounded bg-gray-50 p-2 text-xs">
                                    {JSON.stringify(playbook.trigger.conditions, null, 2)}
                                  </pre>
                                </div>
                              )}
                          </div>
                        </div>

                        <div>
                          <h3 className="mb-2 text-sm font-medium text-gray-500">
                            Steps ({playbook.steps?.length || 0})
                          </h3>
                          <div className="space-y-3">
                            {playbook.steps?.map((step, index) => (
                              <div
                                key={step.id}
                                className="rounded-lg border border-gray-200 p-4"
                              >
                                <div className="flex items-start justify-between">
                                  <div className="flex items-center gap-3">
                                    <span className="flex h-8 w-8 items-center justify-center rounded-full bg-gray-100 text-sm font-medium text-gray-600">
                                      {index + 1}
                                    </span>
                                    <div>
                                      <p className="font-medium text-gray-900">
                                        {step.name}
                                      </p>
                                      <div className="mt-1 flex items-center gap-2 text-sm text-gray-500">
                                        <span>
                                          {ACTION_TYPE_ICONS[step.action_type] || '⚡'}
                                        </span>
                                        <span>{step.action_type}</span>
                                        {step.provider && (
                                          <>
                                            <span>•</span>
                                            <span>{step.provider}</span>
                                          </>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                  {step.requires_approval && (
                                    <span className="flex items-center gap-1 rounded-full bg-yellow-100 px-2 py-1 text-xs font-medium text-yellow-700">
                                      <ExclamationTriangleIcon className="h-3 w-3" />
                                      Requires Approval
                                    </span>
                                  )}
                                </div>

                                {step.condition && (
                                  <div className="mt-3 rounded bg-gray-50 p-2 text-xs">
                                    <span className="text-gray-500">Condition:</span>{' '}
                                    <code>{step.condition}</code>
                                  </div>
                                )}

                                {(step.on_success || step.on_failure) && (
                                  <div className="mt-3 flex items-center gap-4 text-xs">
                                    {step.on_success && (
                                      <span className="flex items-center gap-1 text-green-600">
                                        <CheckCircleIcon className="h-4 w-4" />
                                        On success: {step.on_success}
                                      </span>
                                    )}
                                    {step.on_failure && (
                                      <span className="flex items-center gap-1 text-red-600">
                                        <ExclamationTriangleIcon className="h-4 w-4" />
                                        On failure: {step.on_failure}
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div className="space-y-6">
                        <div className="rounded-lg border border-gray-200 p-4">
                          <h3 className="mb-3 text-sm font-medium text-gray-500">
                            Metadata
                          </h3>
                          <dl className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                              <dt className="flex items-center gap-2 text-gray-500">
                                <UserIcon className="h-4 w-4" />
                                Author
                              </dt>
                              <dd className="font-medium text-gray-900">
                                {playbook.author}
                              </dd>
                            </div>
                            <div className="flex items-center justify-between">
                              <dt className="flex items-center gap-2 text-gray-500">
                                <ClockIcon className="h-4 w-4" />
                                Created
                              </dt>
                              <dd className="text-gray-900">
                                {formatDate(playbook.created)}
                              </dd>
                            </div>
                            <div className="flex items-center justify-between">
                              <dt className="flex items-center gap-2 text-gray-500">
                                <ClockIcon className="h-4 w-4" />
                                Modified
                              </dt>
                              <dd className="text-gray-900">
                                {formatDate(playbook.modified)}
                              </dd>
                            </div>
                          </dl>
                        </div>

                        {playbook.tags?.length > 0 && (
                          <div className="rounded-lg border border-gray-200 p-4">
                            <h3 className="mb-3 text-sm font-medium text-gray-500">
                              Tags
                            </h3>
                            <div className="flex flex-wrap gap-2">
                              {playbook.tags.map((tag) => (
                                <span
                                  key={tag}
                                  className="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-600"
                                >
                                  <TagIcon className="mr-1 h-3 w-3" />
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {stats && (
                          <div className="rounded-lg border border-gray-200 p-4">
                            <h3 className="mb-3 text-sm font-medium text-gray-500">
                              Execution Stats
                            </h3>
                            <dl className="space-y-2 text-sm">
                              <div className="flex items-center justify-between">
                                <dt className="text-gray-500">Total Executions</dt>
                                <dd className="font-medium text-gray-900">
                                  {stats.total_executions}
                                </dd>
                              </div>
                              <div className="flex items-center justify-between">
                                <dt className="text-gray-500">Successful</dt>
                                <dd className="font-medium text-green-600">
                                  {stats.successful_executions}
                                </dd>
                              </div>
                              <div className="flex items-center justify-between">
                                <dt className="text-gray-500">Failed</dt>
                                <dd className="font-medium text-red-600">
                                  {stats.failed_executions}
                                </dd>
                              </div>
                              <div className="flex items-center justify-between">
                                <dt className="text-gray-500">Success Rate</dt>
                                <dd className="font-medium text-gray-900">
                                  {(stats.success_rate * 100).toFixed(1)}%
                                </dd>
                              </div>
                            </dl>
                          </div>
                        )}

                        {versions.length > 0 && (
                          <div className="rounded-lg border border-gray-200 p-4">
                            <h3 className="mb-3 text-sm font-medium text-gray-500">
                              Version History
                            </h3>
                            <ul className="space-y-2 text-sm">
                              {versions.slice(0, 5).map((version) => (
                                <li
                                  key={version.version}
                                  className="flex items-center justify-between"
                                >
                                  <span className="text-gray-900">
                                    v{version.version}
                                  </span>
                                  <span className="text-gray-500">
                                    {formatDate(version.created)}
                                  </span>
                                </li>
                              ))}
                            </ul>
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
