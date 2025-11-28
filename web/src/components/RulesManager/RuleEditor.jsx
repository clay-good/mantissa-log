import { useState, useEffect } from 'react'
import { XMarkIcon } from '@heroicons/react/24/outline'
import { useCreateRule, useUpdateRule, useValidateQuery } from '../../hooks/useRules'

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const CATEGORY_OPTIONS = ['access', 'network', 'data', 'compliance', 'threat']

export default function RuleEditor({ rule, onClose, onSuccess }) {
  const isEditing = !!rule
  const { mutate: createRule, isPending: isCreating } = useCreateRule()
  const { mutate: updateRule, isPending: isUpdating } = useUpdateRule()
  const { mutate: validateQuery, isPending: isValidating } = useValidateQuery()

  const [formData, setFormData] = useState({
    name: rule?.name || '',
    description: rule?.description || '',
    query: rule?.query || '',
    severity: rule?.severity || 'medium',
    category: rule?.category || 'access',
    schedule: rule?.schedule || 'rate(5 minutes)',
    enabled: rule?.enabled !== undefined ? rule.enabled : true,
    threshold: {
      count: rule?.threshold?.count || 1,
      window: rule?.threshold?.window || '5m',
    },
    tags: rule?.metadata?.tags?.join(', ') || '',
    mitre_attack: rule?.metadata?.mitre_attack?.join(', ') || '',
  })

  const [validationResult, setValidationResult] = useState(null)

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

  const handleValidate = () => {
    validateQuery(formData.query, {
      onSuccess: (data) => {
        setValidationResult(data)
      },
    })
  }

  const handleSubmit = (e) => {
    e.preventDefault()

    const ruleData = {
      name: formData.name,
      description: formData.description,
      query: formData.query,
      severity: formData.severity,
      category: formData.category,
      schedule: formData.schedule,
      enabled: formData.enabled,
      threshold: {
        count: parseInt(formData.threshold.count, 10),
        window: formData.threshold.window,
      },
      metadata: {
        tags: formData.tags
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean),
        mitre_attack: formData.mitre_attack
          .split(',')
          .map((id) => id.trim())
          .filter(Boolean),
      },
    }

    if (isEditing) {
      updateRule(
        { ruleId: rule.id, updates: ruleData },
        {
          onSuccess: () => {
            onSuccess?.()
            onClose()
          },
        }
      )
    } else {
      createRule(ruleData, {
        onSuccess: () => {
          onSuccess?.()
          onClose()
        },
      })
    }
  }

  const isPending = isCreating || isUpdating

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black bg-opacity-50">
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="w-full max-w-4xl rounded-lg bg-white shadow-xl">
          <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
            <h2 className="text-xl font-bold text-gray-900">
              {isEditing ? 'Edit Detection Rule' : 'Create Detection Rule'}
            </h2>
            <button
              onClick={onClose}
              className="rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6 p-6">
            <div className="grid grid-cols-2 gap-6">
              <div className="col-span-2">
                <label className="block text-sm font-medium text-gray-700">
                  Rule Name *
                </label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => handleChange('name', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="e.g., Suspicious Login Pattern"
                />
              </div>

              <div className="col-span-2">
                <label className="block text-sm font-medium text-gray-700">
                  Description
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => handleChange('description', e.target.value)}
                  rows={2}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="Describe what this rule detects"
                />
              </div>

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

              <div className="col-span-2">
                <div className="flex items-center justify-between">
                  <label className="block text-sm font-medium text-gray-700">
                    SQL Query *
                  </label>
                  <button
                    type="button"
                    onClick={handleValidate}
                    disabled={isValidating || !formData.query}
                    className="text-sm text-primary-600 hover:text-primary-700 disabled:text-gray-400"
                  >
                    {isValidating ? 'Validating...' : 'Validate Query'}
                  </button>
                </div>
                <textarea
                  required
                  value={formData.query}
                  onChange={(e) => handleChange('query', e.target.value)}
                  rows={10}
                  className="mt-1 block w-full rounded-lg border border-gray-300 bg-gray-900 px-3 py-2 font-mono text-sm text-green-400 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="SELECT * FROM cloudtrail WHERE ..."
                />
                {validationResult && (
                  <div
                    className={`mt-2 rounded-lg p-3 text-sm ${
                      validationResult.valid
                        ? 'bg-green-50 text-green-800'
                        : 'bg-red-50 text-red-800'
                    }`}
                  >
                    {validationResult.valid
                      ? 'Query is valid'
                      : `Invalid query: ${validationResult.error}`}
                  </div>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Schedule
                </label>
                <input
                  type="text"
                  value={formData.schedule}
                  onChange={(e) => handleChange('schedule', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="rate(5 minutes)"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Examples: rate(5 minutes), rate(1 hour), cron(0 12 * * ? *)
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Enabled
                </label>
                <div className="mt-1">
                  <button
                    type="button"
                    onClick={() => handleChange('enabled', !formData.enabled)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      formData.enabled ? 'bg-primary-600' : 'bg-gray-200'
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                        formData.enabled ? 'translate-x-6' : 'translate-x-1'
                      }`}
                    />
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Threshold Count *
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
                  Number of matches to trigger alert
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Threshold Window *
                </label>
                <input
                  type="text"
                  required
                  value={formData.threshold.window}
                  onChange={(e) => handleThresholdChange('window', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="e.g., 5m, 1h, 1d"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Time window: 5m, 1h, 1d
                </p>
              </div>

              <div className="col-span-2">
                <label className="block text-sm font-medium text-gray-700">
                  Tags
                </label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => handleChange('tags', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="authentication, brute-force, cloudtrail"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Comma-separated tags
                </p>
              </div>

              <div className="col-span-2">
                <label className="block text-sm font-medium text-gray-700">
                  MITRE ATT&CK Techniques
                </label>
                <input
                  type="text"
                  value={formData.mitre_attack}
                  onChange={(e) => handleChange('mitre_attack', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                  placeholder="T1110, T1078"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Comma-separated MITRE ATT&CK technique IDs
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
                {isPending
                  ? isEditing
                    ? 'Updating...'
                    : 'Creating...'
                  : isEditing
                    ? 'Update Rule'
                    : 'Create Rule'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
