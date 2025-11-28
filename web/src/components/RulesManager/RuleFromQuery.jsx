import { useState } from 'react'
import { XMarkIcon } from '@heroicons/react/24/outline'
import { useCreateRule } from '../../hooks/useRules'

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const CATEGORY_OPTIONS = ['access', 'network', 'data', 'compliance', 'threat']

export default function RuleFromQuery({ query, explanation, onClose, onSuccess }) {
  const { mutate: createRule, isPending } = useCreateRule()

  const [formData, setFormData] = useState({
    name: '',
    description: explanation || '',
    severity: 'medium',
    category: 'access',
    schedule: 'rate(5 minutes)',
    threshold: {
      count: 1,
      window: '5m',
    },
  })

  const handleChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }))
  }

  const handleThresholdChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      threshold: {
        ...prev.threshold,
        [field]: value,
      },
    }))
  }

  const handleSubmit = (e) => {
    e.preventDefault()

    const ruleData = {
      name: formData.name,
      description: formData.description,
      query: query,
      severity: formData.severity,
      category: formData.category,
      schedule: formData.schedule,
      enabled: true,
      threshold: {
        count: parseInt(formData.threshold.count, 10),
        window: formData.threshold.window,
      },
      metadata: {
        tags: ['generated-from-query'],
        created_from: 'natural-language-query',
      },
    }

    createRule(ruleData, {
      onSuccess: () => {
        onSuccess?.()
        onClose()
      },
    })
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black bg-opacity-50">
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="w-full max-w-2xl rounded-lg bg-white shadow-xl">
          <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
            <h2 className="text-xl font-bold text-gray-900">
              Save as Detection Rule
            </h2>
            <button
              onClick={onClose}
              className="rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6 p-6">
            <div className="rounded-lg bg-blue-50 p-4">
              <h4 className="text-sm font-medium text-blue-900">
                Converting Query to Detection Rule
              </h4>
              <p className="mt-1 text-sm text-blue-800">
                This will create a detection rule that runs on a schedule and generates
                alerts when matches are found.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Query (from natural language)
              </label>
              <pre className="mt-1 overflow-x-auto rounded-lg bg-gray-900 p-3 text-sm text-green-400">
                {query}
              </pre>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Rule Name *
              </label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => handleChange('name', e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                placeholder="e.g., Monitor Failed Logins"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Description
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => handleChange('description', e.target.value)}
                rows={3}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                placeholder="Describe what this rule detects and when it should alert"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Severity *
                </label>
                <select
                  required
                  value={formData.severity}
                  onChange={(e) => handleChange('severity', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                >
                  {SEVERITY_OPTIONS.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity.charAt(0).toUpperCase() + severity.slice(1)}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Category *
                </label>
                <select
                  required
                  value={formData.category}
                  onChange={(e) => handleChange('category', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                >
                  {CATEGORY_OPTIONS.map((category) => (
                    <option key={category} value={category}>
                      {category.charAt(0).toUpperCase() + category.slice(1)}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Schedule
              </label>
              <select
                value={formData.schedule}
                onChange={(e) => handleChange('schedule', e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
              >
                <option value="rate(5 minutes)">Every 5 minutes</option>
                <option value="rate(15 minutes)">Every 15 minutes</option>
                <option value="rate(30 minutes)">Every 30 minutes</option>
                <option value="rate(1 hour)">Every hour</option>
                <option value="rate(6 hours)">Every 6 hours</option>
                <option value="rate(12 hours)">Every 12 hours</option>
                <option value="rate(1 day)">Daily</option>
              </select>
              <p className="mt-1 text-xs text-gray-500">
                How often should this rule run?
              </p>
            </div>

            <div className="rounded-lg border border-gray-200 p-4">
              <h4 className="text-sm font-medium text-gray-900">
                Alert Threshold Configuration
              </h4>
              <p className="mt-1 text-sm text-gray-600">
                Configure when this rule should generate an alert
              </p>

              <div className="mt-4 grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Match Count *
                  </label>
                  <input
                    type="number"
                    required
                    min="1"
                    value={formData.threshold.count}
                    onChange={(e) => handleThresholdChange('count', e.target.value)}
                    className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Alert when at least this many events match
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Time Window *
                  </label>
                  <select
                    required
                    value={formData.threshold.window}
                    onChange={(e) => handleThresholdChange('window', e.target.value)}
                    className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  >
                    <option value="5m">5 minutes</option>
                    <option value="15m">15 minutes</option>
                    <option value="30m">30 minutes</option>
                    <option value="1h">1 hour</option>
                    <option value="6h">6 hours</option>
                    <option value="12h">12 hours</option>
                    <option value="1d">1 day</option>
                    <option value="7d">7 days</option>
                  </select>
                  <p className="mt-1 text-xs text-gray-500">
                    Within this time period
                  </p>
                </div>
              </div>

              <div className="mt-3 rounded-lg bg-gray-50 p-3">
                <p className="text-sm text-gray-700">
                  <span className="font-medium">Alert condition:</span> Trigger an alert if{' '}
                  <span className="font-semibold text-primary-600">
                    {formData.threshold.count} or more
                  </span>{' '}
                  events match within a{' '}
                  <span className="font-semibold text-primary-600">
                    {formData.threshold.window}
                  </span>{' '}
                  window
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-3 border-t border-gray-200 pt-6">
              <button
                type="button"
                onClick={onClose}
                disabled={isPending}
                className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isPending}
                className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
              >
                {isPending ? 'Creating Rule...' : 'Create Detection Rule'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
