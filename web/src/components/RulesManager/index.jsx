import { useState } from 'react'
import {
  PlusIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline'
import { useRules, useBulkToggleRules } from '../../hooks/useRules'
import RulesList from './RulesList'
import RuleDetail from './RuleDetail'
import RuleEditor from './RuleEditor'

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const CATEGORY_OPTIONS = ['access', 'network', 'data', 'compliance', 'threat']

export default function RulesManager() {
  const [selectedRuleId, setSelectedRuleId] = useState(null)
  const [showEditor, setShowEditor] = useState(false)
  const [editingRule, setEditingRule] = useState(null)
  const [showFilters, setShowFilters] = useState(false)
  const [selectedRules, setSelectedRules] = useState([])

  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    category: '',
    enabled: undefined,
  })

  const { data: rulesData, isLoading, refetch } = useRules(filters, 1, 50)
  const { mutate: bulkToggle } = useBulkToggleRules()

  const handleFilterChange = (field, value) => {
    setFilters((prev) => ({
      ...prev,
      [field]: value,
    }))
  }

  const handleCreateNew = () => {
    setEditingRule(null)
    setShowEditor(true)
  }

  const handleEdit = (ruleId) => {
    const rule = rulesData?.rules?.find((r) => r.id === ruleId)
    if (rule) {
      setEditingRule(rule)
      setShowEditor(true)
    }
  }

  const handleCloseEditor = () => {
    setShowEditor(false)
    setEditingRule(null)
  }

  const handleEditorSuccess = () => {
    refetch()
  }

  const handleSelectRule = (ruleId) => {
    setSelectedRuleId(ruleId)
  }

  const handleCloseDetail = () => {
    setSelectedRuleId(null)
  }

  const handleToggleSelection = (ruleId) => {
    setSelectedRules((prev) =>
      prev.includes(ruleId)
        ? prev.filter((id) => id !== ruleId)
        : [...prev, ruleId]
    )
  }

  const handleBulkEnable = () => {
    if (selectedRules.length > 0) {
      bulkToggle({ ruleIds: selectedRules, enabled: true })
      setSelectedRules([])
    }
  }

  const handleBulkDisable = () => {
    if (selectedRules.length > 0) {
      bulkToggle({ ruleIds: selectedRules, enabled: false })
      setSelectedRules([])
    }
  }

  const stats = rulesData?.rules
    ? {
        total: rulesData.rules.length,
        enabled: rulesData.rules.filter((r) => r.enabled).length,
        disabled: rulesData.rules.filter((r) => !r.enabled).length,
        critical: rulesData.rules.filter((r) => r.severity === 'critical').length,
      }
    : { total: 0, enabled: 0, disabled: 0, critical: 0 }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mb-2">Detection Rules</h1>
        <p className="text-gray-600">
          Manage automated detection rules that continuously monitor your logs
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <div className="card">
          <p className="text-sm text-gray-600">Total Rules</p>
          <p className="mt-1 text-3xl font-bold text-gray-900">{stats.total}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-600">Enabled</p>
          <p className="mt-1 text-3xl font-bold text-green-600">{stats.enabled}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-600">Disabled</p>
          <p className="mt-1 text-3xl font-bold text-gray-400">{stats.disabled}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-600">Critical Severity</p>
          <p className="mt-1 text-3xl font-bold text-red-600">{stats.critical}</p>
        </div>
      </div>

      <div className="card">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex flex-1 items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search rules..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  className="w-full rounded-lg border border-gray-300 py-2 pl-10 pr-4 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center gap-2 rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                <FunnelIcon className="h-4 w-4" />
                Filters
              </button>
            </div>
            <button
              onClick={handleCreateNew}
              className="btn btn-primary flex items-center gap-2"
            >
              <PlusIcon className="h-5 w-5" />
              Create Rule
            </button>
          </div>

          {showFilters && (
            <div className="grid grid-cols-3 gap-4 rounded-lg border border-gray-200 p-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Severity
                </label>
                <select
                  value={filters.severity}
                  onChange={(e) => handleFilterChange('severity', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                >
                  <option value="">All Severities</option>
                  {SEVERITY_OPTIONS.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity.charAt(0).toUpperCase() + severity.slice(1)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Category
                </label>
                <select
                  value={filters.category}
                  onChange={(e) => handleFilterChange('category', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                >
                  <option value="">All Categories</option>
                  {CATEGORY_OPTIONS.map((category) => (
                    <option key={category} value={category}>
                      {category.charAt(0).toUpperCase() + category.slice(1)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Status
                </label>
                <select
                  value={
                    filters.enabled === undefined
                      ? ''
                      : filters.enabled
                        ? 'enabled'
                        : 'disabled'
                  }
                  onChange={(e) =>
                    handleFilterChange(
                      'enabled',
                      e.target.value === ''
                        ? undefined
                        : e.target.value === 'enabled'
                    )
                  }
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                >
                  <option value="">All Statuses</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
            </div>
          )}

          {selectedRules.length > 0 && (
            <div className="flex items-center justify-between rounded-lg bg-blue-50 p-4">
              <p className="text-sm text-blue-900">
                {selectedRules.length} rule{selectedRules.length > 1 ? 's' : ''} selected
              </p>
              <div className="flex gap-2">
                <button
                  onClick={handleBulkEnable}
                  className="rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700"
                >
                  Enable Selected
                </button>
                <button
                  onClick={handleBulkDisable}
                  className="rounded-lg bg-gray-600 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700"
                >
                  Disable Selected
                </button>
              </div>
            </div>
          )}

          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent"></div>
            </div>
          ) : (
            <RulesList
              rules={rulesData?.rules || []}
              onSelectRule={handleSelectRule}
              selectedRuleId={selectedRuleId}
            />
          )}
        </div>
      </div>

      {selectedRuleId && (
        <div className="card">
          <RuleDetail
            ruleId={selectedRuleId}
            onEdit={() => handleEdit(selectedRuleId)}
            onClose={handleCloseDetail}
          />
        </div>
      )}

      {showEditor && (
        <RuleEditor
          rule={editingRule}
          onClose={handleCloseEditor}
          onSuccess={handleEditorSuccess}
        />
      )}
    </div>
  )
}
