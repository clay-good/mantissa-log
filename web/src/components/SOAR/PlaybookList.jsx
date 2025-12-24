import { useState } from 'react'
import clsx from 'clsx'
import {
  MagnifyingGlassIcon,
  EllipsisVerticalIcon,
  PlayIcon,
  PencilIcon,
  TrashIcon,
  DocumentDuplicateIcon,
  ClockIcon,
  TagIcon,
} from '@heroicons/react/24/outline'
import { Menu, Transition } from '@headlessui/react'
import { Fragment } from 'react'
import { usePlaybooks, useDeletePlaybook, useUpdatePlaybook, useExecutePlaybook } from '../../hooks/useSOAR'

const TRIGGER_TYPE_LABELS = {
  manual: 'Manual',
  alert: 'Alert',
  scheduled: 'Scheduled',
  webhook: 'Webhook',
}

const TRIGGER_TYPE_COLORS = {
  manual: 'bg-gray-100 text-gray-700',
  alert: 'bg-blue-100 text-blue-700',
  scheduled: 'bg-purple-100 text-purple-700',
  webhook: 'bg-green-100 text-green-700',
}

export default function PlaybookList({ onView, onEdit }) {
  const [search, setSearch] = useState('')
  const [triggerFilter, setTriggerFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')
  const [page, setPage] = useState(1)

  const filters = {}
  if (enabledFilter === 'true') filters.enabled = true
  if (enabledFilter === 'false') filters.enabled = false
  if (triggerFilter) filters.trigger_type = triggerFilter
  if (search) filters.search = search

  const { data, isLoading, error } = usePlaybooks(filters, page, 20)
  const { mutate: deletePlaybook, isPending: isDeleting } = useDeletePlaybook()
  const { mutate: updatePlaybook } = useUpdatePlaybook()
  const { mutate: executePlaybook } = useExecutePlaybook()

  const playbooks = data?.playbooks || []
  const totalPages = data?.total_pages || 1

  const handleToggleEnabled = (playbook) => {
    updatePlaybook({
      playbookId: playbook.id,
      updates: { enabled: !playbook.enabled },
    })
  }

  const handleDelete = (playbook) => {
    if (window.confirm(`Are you sure you want to delete "${playbook.name}"?`)) {
      deletePlaybook(playbook.id)
    }
  }

  const handleExecute = (playbook) => {
    executePlaybook({
      playbookId: playbook.id,
      dryRun: true,
    })
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
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
        Failed to load playbooks. Please try again.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search playbooks..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-gray-300 py-2 pl-10 pr-4 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
        </div>

        <select
          value={triggerFilter}
          onChange={(e) => setTriggerFilter(e.target.value)}
          className="rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Triggers</option>
          {Object.entries(TRIGGER_TYPE_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>

        <select
          value={enabledFilter}
          onChange={(e) => setEnabledFilter(e.target.value)}
          className="rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Status</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </select>
      </div>

      {playbooks.length === 0 ? (
        <div className="py-12 text-center text-gray-500">
          No playbooks found. Create your first playbook to get started.
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Version
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Trigger
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Modified
                  </th>
                  <th className="relative px-6 py-3">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white">
                {playbooks.map((playbook) => (
                  <tr
                    key={playbook.id}
                    className="cursor-pointer hover:bg-gray-50"
                    onClick={() => onView(playbook.id)}
                  >
                    <td className="whitespace-nowrap px-6 py-4">
                      <div>
                        <div className="font-medium text-gray-900">
                          {playbook.name}
                        </div>
                        {playbook.description && (
                          <div className="max-w-xs truncate text-sm text-gray-500">
                            {playbook.description}
                          </div>
                        )}
                        {playbook.tags?.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {playbook.tags.slice(0, 3).map((tag) => (
                              <span
                                key={tag}
                                className="inline-flex items-center rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600"
                              >
                                <TagIcon className="mr-0.5 h-3 w-3" />
                                {tag}
                              </span>
                            ))}
                            {playbook.tags.length > 3 && (
                              <span className="text-xs text-gray-500">
                                +{playbook.tags.length - 3}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      v{playbook.version}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <span
                        className={clsx(
                          'inline-flex rounded-full px-2 py-1 text-xs font-semibold',
                          TRIGGER_TYPE_COLORS[playbook.trigger?.trigger_type] ||
                            'bg-gray-100 text-gray-700'
                        )}
                      >
                        {TRIGGER_TYPE_LABELS[playbook.trigger?.trigger_type] ||
                          playbook.trigger?.trigger_type}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <span
                        className={clsx(
                          'inline-flex rounded-full px-2 py-1 text-xs font-semibold',
                          playbook.enabled
                            ? 'bg-green-100 text-green-700'
                            : 'bg-gray-100 text-gray-600'
                        )}
                      >
                        {playbook.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      <div className="flex items-center gap-1">
                        <ClockIcon className="h-4 w-4" />
                        {formatDate(playbook.modified)}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-right text-sm font-medium">
                      <Menu as="div" className="relative inline-block text-left">
                        <Menu.Button
                          onClick={(e) => e.stopPropagation()}
                          className="rounded p-1 hover:bg-gray-100"
                        >
                          <EllipsisVerticalIcon className="h-5 w-5 text-gray-500" />
                        </Menu.Button>
                        <Transition
                          as={Fragment}
                          enter="transition ease-out duration-100"
                          enterFrom="transform opacity-0 scale-95"
                          enterTo="transform opacity-100 scale-100"
                          leave="transition ease-in duration-75"
                          leaveFrom="transform opacity-100 scale-100"
                          leaveTo="transform opacity-0 scale-95"
                        >
                          <Menu.Items className="absolute right-0 z-10 mt-2 w-48 origin-top-right rounded-lg bg-white shadow-lg ring-1 ring-black/5 focus:outline-none">
                            <div className="py-1">
                              <Menu.Item>
                                {({ active }) => (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      onEdit(playbook)
                                    }}
                                    className={clsx(
                                      'flex w-full items-center gap-2 px-4 py-2 text-sm',
                                      active ? 'bg-gray-100' : ''
                                    )}
                                  >
                                    <PencilIcon className="h-4 w-4" />
                                    Edit
                                  </button>
                                )}
                              </Menu.Item>
                              <Menu.Item>
                                {({ active }) => (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      handleExecute(playbook)
                                    }}
                                    className={clsx(
                                      'flex w-full items-center gap-2 px-4 py-2 text-sm',
                                      active ? 'bg-gray-100' : ''
                                    )}
                                  >
                                    <PlayIcon className="h-4 w-4" />
                                    Execute (Dry Run)
                                  </button>
                                )}
                              </Menu.Item>
                              <Menu.Item>
                                {({ active }) => (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      handleToggleEnabled(playbook)
                                    }}
                                    className={clsx(
                                      'flex w-full items-center gap-2 px-4 py-2 text-sm',
                                      active ? 'bg-gray-100' : ''
                                    )}
                                  >
                                    <DocumentDuplicateIcon className="h-4 w-4" />
                                    {playbook.enabled ? 'Disable' : 'Enable'}
                                  </button>
                                )}
                              </Menu.Item>
                              <Menu.Item>
                                {({ active }) => (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      handleDelete(playbook)
                                    }}
                                    disabled={isDeleting}
                                    className={clsx(
                                      'flex w-full items-center gap-2 px-4 py-2 text-sm text-red-600',
                                      active ? 'bg-red-50' : ''
                                    )}
                                  >
                                    <TrashIcon className="h-4 w-4" />
                                    Delete
                                  </button>
                                )}
                              </Menu.Item>
                            </div>
                          </Menu.Items>
                        </Transition>
                      </Menu>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-500">
                Page {page} of {totalPages}
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
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="rounded-lg border border-gray-300 px-3 py-1 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
