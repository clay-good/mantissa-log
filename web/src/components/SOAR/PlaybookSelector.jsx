import { Fragment, useState } from 'react'
import { Dialog, Transition, Listbox } from '@headlessui/react'
import {
  PlayIcon,
  XMarkIcon,
  ChevronUpDownIcon,
  CheckIcon,
  DocumentTextIcon,
  TagIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'
import { useMatchingPlaybooks, usePlaybooks } from '../../hooks/useSOAR'

export default function PlaybookSelector({
  isOpen,
  onClose,
  onSelect,
  alertId,
  showAllPlaybooks = true,
}) {
  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [showMatchingOnly, setShowMatchingOnly] = useState(true)
  const [dryRun, setDryRun] = useState(true)

  const { data: matchingData, isLoading: matchingLoading } = useMatchingPlaybooks(alertId, {
    enabled: !!alertId && showMatchingOnly,
  })

  const { data: allData, isLoading: allLoading } = usePlaybooks(
    { enabled: true },
    1,
    100,
    { enabled: !showMatchingOnly || showAllPlaybooks }
  )

  const playbooks = showMatchingOnly
    ? matchingData?.playbooks || []
    : allData?.playbooks || []

  const isLoading = showMatchingOnly ? matchingLoading : allLoading

  const handleExecute = () => {
    if (selectedPlaybook) {
      onSelect({
        playbookId: selectedPlaybook.id,
        playbookName: selectedPlaybook.name,
        dryRun,
      })
    }
  }

  return (
    <Transition appear show={isOpen} as={Fragment}>
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
              <Dialog.Panel className="w-full max-w-lg transform overflow-hidden rounded-2xl bg-white shadow-xl transition-all">
                <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
                  <Dialog.Title className="text-lg font-semibold text-gray-900">
                    Select Playbook
                  </Dialog.Title>
                  <button
                    onClick={onClose}
                    className="rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>

                <div className="p-6">
                  {showAllPlaybooks && alertId && (
                    <div className="mb-4 flex items-center gap-2">
                      <button
                        onClick={() => setShowMatchingOnly(true)}
                        className={clsx(
                          'rounded-lg px-3 py-1.5 text-sm font-medium',
                          showMatchingOnly
                            ? 'bg-primary-100 text-primary-700'
                            : 'text-gray-600 hover:bg-gray-100'
                        )}
                      >
                        Matching
                      </button>
                      <button
                        onClick={() => setShowMatchingOnly(false)}
                        className={clsx(
                          'rounded-lg px-3 py-1.5 text-sm font-medium',
                          !showMatchingOnly
                            ? 'bg-primary-100 text-primary-700'
                            : 'text-gray-600 hover:bg-gray-100'
                        )}
                      >
                        All Playbooks
                      </button>
                    </div>
                  )}

                  {isLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
                    </div>
                  ) : playbooks.length === 0 ? (
                    <div className="py-8 text-center text-gray-500">
                      {showMatchingOnly
                        ? 'No playbooks match this alert'
                        : 'No playbooks available'}
                    </div>
                  ) : (
                    <Listbox value={selectedPlaybook} onChange={setSelectedPlaybook}>
                      <div className="relative">
                        <Listbox.Button className="relative w-full cursor-pointer rounded-lg border border-gray-300 bg-white py-3 pl-4 pr-10 text-left focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500">
                          {selectedPlaybook ? (
                            <div className="flex items-center gap-2">
                              <PlayIcon className="h-5 w-5 text-primary-600" />
                              <span className="block truncate">
                                {selectedPlaybook.name}
                              </span>
                            </div>
                          ) : (
                            <span className="block text-gray-500">
                              Choose a playbook...
                            </span>
                          )}
                          <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
                            <ChevronUpDownIcon className="h-5 w-5 text-gray-400" />
                          </span>
                        </Listbox.Button>

                        <Transition
                          as={Fragment}
                          leave="transition ease-in duration-100"
                          leaveFrom="opacity-100"
                          leaveTo="opacity-0"
                        >
                          <Listbox.Options className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-lg bg-white py-1 shadow-lg ring-1 ring-black/5 focus:outline-none">
                            {playbooks.map((playbook) => (
                              <Listbox.Option
                                key={playbook.id}
                                value={playbook}
                                className={({ active }) =>
                                  clsx(
                                    'relative cursor-pointer select-none py-3 pl-10 pr-4',
                                    active
                                      ? 'bg-primary-50 text-primary-900'
                                      : 'text-gray-900'
                                  )
                                }
                              >
                                {({ selected, active }) => (
                                  <>
                                    <div className="flex flex-col">
                                      <span
                                        className={clsx(
                                          'block truncate',
                                          selected ? 'font-medium' : 'font-normal'
                                        )}
                                      >
                                        {playbook.name}
                                      </span>
                                      {playbook.description && (
                                        <span
                                          className={clsx(
                                            'block truncate text-sm',
                                            active
                                              ? 'text-primary-700'
                                              : 'text-gray-500'
                                          )}
                                        >
                                          {playbook.description}
                                        </span>
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
                                        </div>
                                      )}
                                    </div>
                                    {selected && (
                                      <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-primary-600">
                                        <CheckIcon className="h-5 w-5" />
                                      </span>
                                    )}
                                  </>
                                )}
                              </Listbox.Option>
                            ))}
                          </Listbox.Options>
                        </Transition>
                      </div>
                    </Listbox>
                  )}

                  {selectedPlaybook && (
                    <div className="mt-4 rounded-lg bg-gray-50 p-4">
                      <div className="flex items-start gap-3">
                        <DocumentTextIcon className="mt-0.5 h-5 w-5 text-gray-400" />
                        <div className="flex-1">
                          <p className="font-medium text-gray-900">
                            {selectedPlaybook.name}
                          </p>
                          {selectedPlaybook.description && (
                            <p className="mt-1 text-sm text-gray-600">
                              {selectedPlaybook.description}
                            </p>
                          )}
                          <div className="mt-2 text-xs text-gray-500">
                            Version {selectedPlaybook.version} •{' '}
                            {selectedPlaybook.steps?.length || 0} steps
                          </div>
                        </div>
                      </div>

                      <div className="mt-4 flex items-center gap-2">
                        <input
                          type="checkbox"
                          id="dryRun"
                          checked={dryRun}
                          onChange={(e) => setDryRun(e.target.checked)}
                          className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                        />
                        <label
                          htmlFor="dryRun"
                          className="text-sm text-gray-700"
                        >
                          Dry run (simulate without executing actions)
                        </label>
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-200 px-6 py-4">
                  <button
                    onClick={onClose}
                    className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleExecute}
                    disabled={!selectedPlaybook}
                    className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <PlayIcon className="h-4 w-4" />
                    {dryRun ? 'Run Dry Run' : 'Execute Playbook'}
                  </button>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
