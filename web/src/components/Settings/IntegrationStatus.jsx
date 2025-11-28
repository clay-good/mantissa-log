import { CheckCircleIcon, XCircleIcon, ClockIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

export default function IntegrationStatus({ integrations }) {
  const getStatusIcon = (status) => {
    switch (status) {
      case 'configured':
        return <CheckCircleIcon className="h-5 w-5 text-green-600 dark:text-green-400" />
      case 'error':
        return <XCircleIcon className="h-5 w-5 text-red-600 dark:text-red-400" />
      case 'pending':
        return <ClockIcon className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
      default:
        return <XCircleIcon className="h-5 w-5 text-mono-400 dark:text-mono-600" />
    }
  }

  const getStatusText = (status) => {
    switch (status) {
      case 'configured':
        return 'Configured'
      case 'error':
        return 'Error'
      case 'pending':
        return 'Pending'
      default:
        return 'Not Configured'
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'configured':
        return 'text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
      case 'error':
        return 'text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
      case 'pending':
        return 'text-yellow-700 dark:text-yellow-300 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
      default:
        return 'text-mono-600 dark:text-mono-400 bg-mono-50 dark:bg-mono-900 border-mono-200 dark:border-mono-800'
    }
  }

  if (!integrations || integrations.length === 0) {
    return null
  }

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-900 p-4">
      <h4 className="text-sm font-medium text-mono-950 dark:text-mono-50 mb-3">
        Integration Status
      </h4>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {integrations.map((integration) => (
          <div
            key={integration.id}
            className={clsx(
              'rounded-lg border p-3 transition-all',
              getStatusColor(integration.status)
            )}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  {getStatusIcon(integration.status)}
                  <h5 className="text-sm font-medium">{integration.name}</h5>
                </div>
                <p className="mt-1 text-xs opacity-80">
                  {getStatusText(integration.status)}
                </p>
                {integration.lastTested && integration.status === 'configured' && (
                  <p className="mt-1 text-xs opacity-60">
                    Tested {new Date(integration.lastTested).toLocaleDateString()}
                  </p>
                )}
                {integration.error && integration.status === 'error' && (
                  <p className="mt-1 text-xs opacity-80">
                    {integration.error}
                  </p>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
