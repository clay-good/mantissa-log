import { useState } from 'react'
import { ChevronDownIcon, ChevronUpIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'
import { useToggleRule } from '../../hooks/useRules'

const SEVERITY_COLORS = {
  critical: 'text-severity-critical bg-severity-critical/10',
  high: 'text-severity-high bg-severity-high/10',
  medium: 'text-severity-medium bg-severity-medium/10',
  low: 'text-severity-low bg-severity-low/10',
  info: 'text-severity-info bg-severity-info/10',
}

export default function RulesList({ rules, onSelectRule, selectedRuleId }) {
  const [expandedRuleId, setExpandedRuleId] = useState(null)
  const { mutate: toggleRule } = useToggleRule()

  const handleToggleExpand = (ruleId) => {
    setExpandedRuleId(expandedRuleId === ruleId ? null : ruleId)
  }

  const handleToggleEnabled = (e, rule) => {
    e.stopPropagation()
    toggleRule({ ruleId: rule.id, enabled: !rule.enabled })
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'Never'
    return new Date(timestamp).toLocaleString()
  }

  if (!rules || rules.length === 0) {
    return (
      <div className="py-12 text-center text-gray-500">
        No detection rules found
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="w-8"></th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Name
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Severity
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Category
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Schedule
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Last Run
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Last Triggered
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              Enabled
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 bg-white">
          {rules.map((rule) => (
            <>
              <tr
                key={rule.id}
                onClick={() => onSelectRule(rule.id)}
                className={clsx(
                  'cursor-pointer hover:bg-gray-50',
                  selectedRuleId === rule.id && 'bg-blue-50'
                )}
              >
                <td className="px-2 py-4">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      handleToggleExpand(rule.id)
                    }}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    {expandedRuleId === rule.id ? (
                      <ChevronUpIcon className="h-4 w-4" />
                    ) : (
                      <ChevronDownIcon className="h-4 w-4" />
                    )}
                  </button>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm font-medium text-gray-900">{rule.name}</div>
                  {rule.description && (
                    <div className="text-sm text-gray-500">{rule.description}</div>
                  )}
                </td>
                <td className="px-6 py-4">
                  <span
                    className={clsx(
                      'inline-flex rounded-full px-2 py-1 text-xs font-semibold',
                      SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.info
                    )}
                  >
                    {rule.severity}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">{rule.category}</td>
                <td className="px-6 py-4 text-sm text-gray-900">
                  {rule.schedule || 'Every 5 minutes'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  {formatDate(rule.last_run)}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  {formatDate(rule.last_triggered)}
                </td>
                <td className="px-6 py-4">
                  <button
                    onClick={(e) => handleToggleEnabled(e, rule)}
                    className={clsx(
                      'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
                      rule.enabled ? 'bg-primary-600' : 'bg-gray-200'
                    )}
                  >
                    <span
                      className={clsx(
                        'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                        rule.enabled ? 'translate-x-6' : 'translate-x-1'
                      )}
                    />
                  </button>
                </td>
              </tr>
              {expandedRuleId === rule.id && (
                <tr>
                  <td colSpan={8} className="bg-gray-50 px-6 py-4">
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium text-gray-700">Query:</span>
                        <pre className="mt-1 overflow-x-auto rounded bg-gray-900 p-2 text-green-400">
                          {rule.query}
                        </pre>
                      </div>
                      {rule.threshold && (
                        <div>
                          <span className="font-medium text-gray-700">Threshold:</span>
                          <span className="ml-2 text-gray-900">
                            {rule.threshold.count} matches in {rule.threshold.window}
                          </span>
                        </div>
                      )}
                      {rule.metadata?.tags && rule.metadata.tags.length > 0 && (
                        <div>
                          <span className="font-medium text-gray-700">Tags:</span>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {rule.metadata.tags.map((tag) => (
                              <span
                                key={tag}
                                className="rounded bg-gray-200 px-2 py-1 text-xs text-gray-700"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  )
}
