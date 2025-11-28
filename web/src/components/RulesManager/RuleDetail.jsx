import { useState } from 'react'
import {
  PencilIcon,
  PlayIcon,
  ClockIcon,
  BellAlertIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'
import { useRule, useTestRule, useRuleHistory, useRuleAlerts } from '../../hooks/useRules'

const SEVERITY_COLORS = {
  critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical',
  high: 'text-severity-high bg-severity-high/10 border-severity-high',
  medium: 'text-severity-medium bg-severity-medium/10 border-severity-medium',
  low: 'text-severity-low bg-severity-low/10 border-severity-low',
  info: 'text-severity-info bg-severity-info/10 border-severity-info',
}

export default function RuleDetail({ ruleId, onEdit, onClose }) {
  const [activeTab, setActiveTab] = useState('details')
  const { data: rule, isLoading } = useRule(ruleId)
  const { data: history, isLoading: isLoadingHistory } = useRuleHistory(ruleId, 1, 10, {
    enabled: activeTab === 'history',
  })
  const { data: alerts, isLoading: isLoadingAlerts } = useRuleAlerts(ruleId, 1, 10, {
    enabled: activeTab === 'alerts',
  })
  const { mutate: testRule, isPending: isTesting, data: testResults } = useTestRule()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent"></div>
      </div>
    )
  }

  if (!rule) {
    return (
      <div className="py-12 text-center text-gray-500">
        Rule not found
      </div>
    )
  }

  const handleTest = () => {
    testRule(ruleId)
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'Never'
    return new Date(timestamp).toLocaleString()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h2 className="text-2xl font-bold text-gray-900">{rule.name}</h2>
          {rule.description && (
            <p className="mt-1 text-gray-600">{rule.description}</p>
          )}
          <div className="mt-3 flex items-center gap-3">
            <span
              className={clsx(
                'inline-flex rounded-full border px-3 py-1 text-sm font-semibold',
                SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.info
              )}
            >
              {rule.severity}
            </span>
            <span className="text-sm text-gray-500">
              Category: {rule.category}
            </span>
            <span
              className={clsx(
                'text-sm font-medium',
                rule.enabled ? 'text-green-600' : 'text-gray-400'
              )}
            >
              {rule.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleTest}
            disabled={isTesting}
            className="flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
          >
            <PlayIcon className="h-4 w-4" />
            {isTesting ? 'Testing...' : 'Test Rule'}
          </button>
          <button
            onClick={onEdit}
            className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700"
          >
            <PencilIcon className="h-4 w-4" />
            Edit
          </button>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
      </div>

      {testResults && (
        <div
          className={clsx(
            'rounded-lg border p-4',
            testResults.match_count > 0
              ? 'border-green-200 bg-green-50'
              : 'border-blue-200 bg-blue-50'
          )}
        >
          <h4 className="font-medium text-gray-900">Test Results</h4>
          <p className="mt-1 text-sm text-gray-700">
            {testResults.match_count > 0
              ? `Rule matched ${testResults.match_count} events`
              : 'Rule did not match any events'}
          </p>
          {testResults.execution_time && (
            <p className="mt-1 text-xs text-gray-500">
              Execution time: {testResults.execution_time}ms
            </p>
          )}
        </div>
      )}

      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          <button
            onClick={() => setActiveTab('details')}
            className={clsx(
              'border-b-2 px-1 py-3 text-sm font-medium',
              activeTab === 'details'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
            )}
          >
            Details
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={clsx(
              'flex items-center gap-2 border-b-2 px-1 py-3 text-sm font-medium',
              activeTab === 'history'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
            )}
          >
            <ClockIcon className="h-4 w-4" />
            Execution History
          </button>
          <button
            onClick={() => setActiveTab('alerts')}
            className={clsx(
              'flex items-center gap-2 border-b-2 px-1 py-3 text-sm font-medium',
              activeTab === 'alerts'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
            )}
          >
            <BellAlertIcon className="h-4 w-4" />
            Triggered Alerts
          </button>
        </nav>
      </div>

      {activeTab === 'details' && (
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-medium text-gray-700">Query</h3>
            <pre className="mt-2 overflow-x-auto rounded-lg bg-gray-900 p-4 text-sm text-green-400">
              {rule.query}
            </pre>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-medium text-gray-700">Schedule</h3>
              <p className="mt-1 text-sm text-gray-900">
                {rule.schedule || 'Every 5 minutes'}
              </p>
            </div>

            {rule.threshold && (
              <div>
                <h3 className="text-sm font-medium text-gray-700">Threshold</h3>
                <p className="mt-1 text-sm text-gray-900">
                  {rule.threshold.count} matches in {rule.threshold.window}
                </p>
              </div>
            )}

            <div>
              <h3 className="text-sm font-medium text-gray-700">Last Run</h3>
              <p className="mt-1 text-sm text-gray-900">
                {formatDate(rule.last_run)}
              </p>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-700">Last Triggered</h3>
              <p className="mt-1 text-sm text-gray-900">
                {formatDate(rule.last_triggered)}
              </p>
            </div>
          </div>

          {rule.metadata?.tags && rule.metadata.tags.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-700">Tags</h3>
              <div className="mt-2 flex flex-wrap gap-2">
                {rule.metadata.tags.map((tag) => (
                  <span
                    key={tag}
                    className="rounded-full bg-gray-100 px-3 py-1 text-sm text-gray-700"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {rule.metadata?.mitre_attack && rule.metadata.mitre_attack.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-700">MITRE ATT&CK</h3>
              <div className="mt-2 flex flex-wrap gap-2">
                {rule.metadata.mitre_attack.map((technique) => (
                  <span
                    key={technique}
                    className="rounded-full bg-red-100 px-3 py-1 text-sm text-red-700"
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </div>
          )}

          {rule.destinations && rule.destinations.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-700">Alert Destinations</h3>
              <ul className="mt-2 space-y-1">
                {rule.destinations.map((dest, idx) => (
                  <li key={idx} className="text-sm text-gray-900">
                    {dest.type}: {dest.target}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {activeTab === 'history' && (
        <div>
          {isLoadingHistory ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary-600 border-t-transparent"></div>
            </div>
          ) : history && history.executions && history.executions.length > 0 ? (
            <div className="space-y-2">
              {history.executions.map((execution) => (
                <div
                  key={execution.id}
                  className="flex items-center justify-between rounded-lg border border-gray-200 p-4"
                >
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      {formatDate(execution.timestamp)}
                    </p>
                    <p className="text-sm text-gray-500">
                      {execution.match_count > 0
                        ? `${execution.match_count} matches`
                        : 'No matches'}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-gray-500">
                      {execution.execution_time}ms
                    </p>
                    <span
                      className={clsx(
                        'text-xs font-medium',
                        execution.status === 'success'
                          ? 'text-green-600'
                          : 'text-red-600'
                      )}
                    >
                      {execution.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="py-8 text-center text-gray-500">No execution history</p>
          )}
        </div>
      )}

      {activeTab === 'alerts' && (
        <div>
          {isLoadingAlerts ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary-600 border-t-transparent"></div>
            </div>
          ) : alerts && alerts.alerts && alerts.alerts.length > 0 ? (
            <div className="space-y-2">
              {alerts.alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <p className="font-medium text-gray-900">{alert.title}</p>
                      <p className="mt-1 text-sm text-gray-600">
                        {alert.description}
                      </p>
                      <p className="mt-1 text-xs text-gray-500">
                        {formatDate(alert.timestamp)}
                      </p>
                    </div>
                    <span
                      className={clsx(
                        'rounded-full px-2 py-1 text-xs font-semibold',
                        SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info
                      )}
                    >
                      {alert.severity}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="py-8 text-center text-gray-500">No alerts triggered</p>
          )}
        </div>
      )}
    </div>
  )
}
