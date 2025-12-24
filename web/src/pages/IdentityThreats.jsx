import { useState } from 'react'
import { useIdentityDashboard } from '../hooks/useIdentityDashboard'
import IdentitySummaryCards from '../components/IdentityDashboard/IdentitySummaryCards'
import IdentityIncidentList from '../components/IdentityDashboard/IdentityIncidentList'
import AttackTimeline from '../components/IdentityDashboard/AttackTimeline'
import IdentityMetrics from '../components/IdentityDashboard/IdentityMetrics'
import IncidentDetailPanel from '../components/IdentityDashboard/IncidentDetailPanel'
import { ArrowPathIcon, FunnelIcon } from '@heroicons/react/24/outline'

const TIME_RANGE_OPTIONS = [
  { value: '1h', label: 'Last Hour' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
]

const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

export default function IdentityThreats() {
  const [showFilters, setShowFilters] = useState(false)

  const {
    highRiskUsers,
    activeIncidents,
    metrics,
    selectedIncident,
    filters,
    isLoading,
    lastUpdated,
    setFilters,
    refresh,
    highRiskCount,
    totalActiveIncidents,
    criticalIncidentsCount,
  } = useIdentityDashboard({
    autoRefresh: true,
    refreshInterval: 30000,
  })

  const handleFilterChange = (key, value) => {
    setFilters({ [key]: value })
  }

  const formatLastUpdated = () => {
    if (!lastUpdated) return 'Never'
    const now = new Date()
    const diff = Math.floor((now - lastUpdated) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return lastUpdated.toLocaleTimeString()
  }

  return (
    <div className="min-h-screen bg-mono-50 dark:bg-mono-950 p-6">
      {/* Header */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
            Identity Threats
          </h1>
          <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
            Monitor and respond to identity-based security threats
          </p>
        </div>

        <div className="flex items-center gap-4">
          {/* Last Updated */}
          <span className="text-sm text-mono-500 dark:text-mono-400">
            Updated: {formatLastUpdated()}
          </span>

          {/* Refresh Button */}
          <button
            onClick={refresh}
            disabled={isLoading}
            className="flex items-center gap-2 rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-900 px-3 py-2 text-sm font-medium text-mono-700 dark:text-mono-300 hover:bg-mono-50 dark:hover:bg-mono-800 disabled:opacity-50"
          >
            <ArrowPathIcon className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          {/* Filter Toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2 rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-900 px-3 py-2 text-sm font-medium text-mono-700 dark:text-mono-300 hover:bg-mono-50 dark:hover:bg-mono-800"
          >
            <FunnelIcon className="h-4 w-4" />
            Filters
          </button>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="mb-6 rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            {/* Time Range */}
            <div>
              <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-1">
                Time Range
              </label>
              <select
                value={filters.timeRange}
                onChange={(e) => handleFilterChange('timeRange', e.target.value)}
                className="w-full rounded-md border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                {TIME_RANGE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Severity */}
            <div>
              <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-1">
                Severity
              </label>
              <select
                value={filters.severity}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                className="w-full rounded-md border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                {SEVERITY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Provider */}
            <div>
              <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-1">
                Provider
              </label>
              <select
                value={filters.provider}
                onChange={(e) => handleFilterChange('provider', e.target.value)}
                className="w-full rounded-md border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                <option value="all">All Providers</option>
                <option value="okta">Okta</option>
                <option value="azure">Azure AD / Entra ID</option>
                <option value="google">Google Workspace</option>
                <option value="duo">Duo</option>
              </select>
            </div>

            {/* Attack Type */}
            <div>
              <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-1">
                Attack Type
              </label>
              <select
                value={filters.attackType}
                onChange={(e) => handleFilterChange('attackType', e.target.value)}
                className="w-full rounded-md border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                <option value="all">All Types</option>
                <option value="brute_force">Brute Force</option>
                <option value="credential_stuffing">Credential Stuffing</option>
                <option value="password_spray">Password Spray</option>
                <option value="mfa_fatigue">MFA Fatigue</option>
                <option value="impossible_travel">Impossible Travel</option>
                <option value="session_hijack">Session Hijacking</option>
                <option value="privilege_escalation">Privilege Escalation</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="mb-6">
        <IdentitySummaryCards
          highRiskCount={highRiskCount}
          activeIncidents={totalActiveIncidents}
          criticalIncidents={criticalIncidentsCount}
          metrics={metrics}
          isLoading={isLoading}
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Incidents List - Takes 2 columns */}
        <div className="lg:col-span-2">
          <IdentityIncidentList
            incidents={activeIncidents}
            isLoading={isLoading}
          />
        </div>

        {/* Attack Timeline - Takes 1 column */}
        <div className="lg:col-span-1">
          <AttackTimeline
            incidents={activeIncidents}
            timeRange={filters.timeRange}
          />
        </div>
      </div>

      {/* Metrics Charts */}
      <div className="mt-6">
        <IdentityMetrics metrics={metrics} isLoading={isLoading} />
      </div>

      {/* Incident Detail Panel (Slide-over) */}
      {selectedIncident && (
        <IncidentDetailPanel
          incident={selectedIncident}
          onClose={() => useIdentityStore.getState().clearSelectedIncident()}
        />
      )}
    </div>
  )
}
