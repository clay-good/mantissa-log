import { useState } from 'react'
import { CheckCircleIcon, XCircleIcon, PlusIcon } from '@heroicons/react/24/outline'
import { useIntegrationStatus } from '../../hooks/useIntegrations'
import clsx from 'clsx'

export default function AlertDestinationSelector({ selected = [], onChange }) {
  const { data: integrationStatus, isLoading } = useIntegrationStatus()
  const [selectedDestinations, setSelectedDestinations] = useState(selected)

  const handleToggle = (integrationId) => {
    const newSelected = selectedDestinations.includes(integrationId)
      ? selectedDestinations.filter(id => id !== integrationId)
      : [...selectedDestinations, integrationId]

    setSelectedDestinations(newSelected)
    if (onChange) {
      onChange(newSelected)
    }
  }

  const getIntegrationIcon = (status) => {
    if (status === 'configured') {
      return <CheckCircleIcon className="h-4 w-4 text-green-600 dark:text-green-400" />
    }
    return <XCircleIcon className="h-4 w-4 text-mono-400 dark:text-mono-600" />
  }

  if (isLoading) {
    return (
      <div className="rounded-lg border border-gray-200 p-4">
        <h4 className="text-sm font-medium text-gray-900">Alert Destinations</h4>
        <p className="mt-2 text-sm text-gray-600">Loading integrations...</p>
      </div>
    )
  }

  const integrations = integrationStatus?.integrations || []

  return (
    <div className="rounded-lg border border-gray-200 p-4">
      <h4 className="text-sm font-medium text-gray-900">
        Alert Destinations
      </h4>
      <p className="mt-1 text-sm text-gray-600">
        Select where alerts should be sent when this rule triggers
      </p>

      {integrations.length === 0 ? (
        <div className="mt-4 rounded-lg bg-gray-50 border border-gray-200 p-4 text-center">
          <p className="text-sm text-gray-600">No integrations configured</p>
          <a
            href="/settings/integrations"
            className="mt-2 inline-flex items-center gap-1 text-sm text-primary-600 hover:text-primary-700"
          >
            <PlusIcon className="h-4 w-4" />
            Set up integrations
          </a>
        </div>
      ) : (
        <div className="mt-4 space-y-2">
          {integrations.map((integration) => {
            const isSelected = selectedDestinations.includes(integration.id)
            const isConfigured = integration.status === 'configured'

            return (
              <button
                key={integration.id}
                type="button"
                onClick={() => isConfigured && handleToggle(integration.id)}
                disabled={!isConfigured}
                className={clsx(
                  'w-full rounded-lg border p-3 text-left transition-all',
                  isSelected && isConfigured && 'border-primary-500 bg-primary-50 dark:bg-primary-900/20',
                  !isSelected && isConfigured && 'border-gray-200 hover:border-gray-300 hover:bg-gray-50',
                  !isConfigured && 'border-gray-200 bg-gray-50 opacity-60 cursor-not-allowed'
                )}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    {getIntegrationIcon(integration.status)}
                    <div>
                      <h5 className="text-sm font-medium text-gray-900">
                        {integration.name}
                      </h5>
                      <p className="text-xs text-gray-600 mt-0.5">
                        {isConfigured ? (
                          integration.description || 'Configured and ready'
                        ) : (
                          <>
                            Not configured.{' '}
                            <a
                              href="/settings/integrations"
                              className="text-primary-600 hover:text-primary-700"
                              onClick={(e) => e.stopPropagation()}
                            >
                              Set up now
                            </a>
                          </>
                        )}
                      </p>
                      {isConfigured && integration.lastTested && (
                        <p className="text-xs text-gray-500 mt-1">
                          Last tested: {new Date(integration.lastTested).toLocaleString()}
                        </p>
                      )}
                    </div>
                  </div>
                  {isSelected && isConfigured && (
                    <div className="flex h-5 w-5 items-center justify-center rounded-full bg-primary-600 text-white">
                      <CheckCircleIcon className="h-4 w-4" />
                    </div>
                  )}
                </div>
              </button>
            )
          })}
        </div>
      )}

      {selectedDestinations.length > 0 && (
        <div className="mt-4 rounded-lg bg-blue-50 p-3">
          <p className="text-sm text-blue-800">
            <span className="font-medium">Selected:</span>{' '}
            {selectedDestinations.length} destination{selectedDestinations.length !== 1 ? 's' : ''}
          </p>
        </div>
      )}
    </div>
  )
}
