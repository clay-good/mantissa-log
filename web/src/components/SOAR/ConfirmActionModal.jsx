import { Fragment } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'

const SEVERITY_CONFIG = {
  low: {
    icon: ShieldExclamationIcon,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-100',
    buttonColor: 'bg-blue-600 hover:bg-blue-700',
  },
  medium: {
    icon: ShieldExclamationIcon,
    iconColor: 'text-yellow-600',
    iconBg: 'bg-yellow-100',
    buttonColor: 'bg-yellow-600 hover:bg-yellow-700',
  },
  high: {
    icon: ExclamationTriangleIcon,
    iconColor: 'text-orange-600',
    iconBg: 'bg-orange-100',
    buttonColor: 'bg-orange-600 hover:bg-orange-700',
  },
  critical: {
    icon: ExclamationTriangleIcon,
    iconColor: 'text-red-600',
    iconBg: 'bg-red-100',
    buttonColor: 'bg-red-600 hover:bg-red-700',
  },
}

export default function ConfirmActionModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  actionLabel = 'Confirm',
  cancelLabel = 'Cancel',
  severity = 'high',
  details,
  isLoading = false,
}) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.high
  const Icon = config.icon

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
          <div className="flex min-h-full items-center justify-center p-4 text-center">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">
                <div className="flex items-start gap-4">
                  <div
                    className={clsx(
                      'flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full',
                      config.iconBg
                    )}
                  >
                    <Icon className={clsx('h-6 w-6', config.iconColor)} />
                  </div>

                  <div className="flex-1">
                    <Dialog.Title
                      as="h3"
                      className="text-lg font-semibold text-gray-900"
                    >
                      {title}
                    </Dialog.Title>

                    <p className="mt-2 text-sm text-gray-600">{message}</p>

                    {details && (
                      <div className="mt-3 rounded-lg bg-gray-50 p-3">
                        <dl className="space-y-1 text-sm">
                          {Object.entries(details).map(([key, value]) => (
                            <div key={key} className="flex justify-between">
                              <dt className="text-gray-500">{key}:</dt>
                              <dd className="font-medium text-gray-900">
                                {value}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={onClose}
                    disabled={isLoading}
                    className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50"
                  >
                    {cancelLabel}
                  </button>
                  <button
                    type="button"
                    onClick={onConfirm}
                    disabled={isLoading}
                    className={clsx(
                      'inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium text-white focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50',
                      config.buttonColor
                    )}
                  >
                    {isLoading && (
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                    )}
                    {actionLabel}
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
