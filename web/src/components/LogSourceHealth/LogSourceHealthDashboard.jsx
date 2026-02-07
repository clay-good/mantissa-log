import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import {
  MagnifyingGlassIcon,
  ArrowPathIcon,
  ChevronUpIcon,
  ChevronDownIcon,
  Cog6ToothIcon,
  ShieldCheckIcon,
  EnvelopeIcon,
  ComputerDesktopIcon,
  DevicePhoneMobileIcon,
  CloudIcon,
  ArrowsRightLeftIcon,
  ShieldExclamationIcon,
  BugAntIcon,
  CircleStackIcon,
  BuildingOfficeIcon,
  ChatBubbleLeftRightIcon,
  KeyIcon,
  CodeBracketIcon,
  CubeIcon,
  CubeTransparentIcon,
  CommandLineIcon,
  DocumentTextIcon,
  SignalIcon,
} from '@heroicons/react/24/outline'
import LogSourceStatusBadge from './LogSourceStatusBadge'
import LogSourceHealthConfig from './LogSourceHealthConfig'
import {
  useSourceHealthList,
  useHealthSummary,
  useTriggerHealthCheck,
  useUpdateHealthConfig,
} from '../../hooks/useLogSourceHealth'

const SOURCE_DISPLAY_NAMES = {
  okta: 'Okta',
  google_workspace: 'Google Workspace',
  microsoft365: 'Microsoft 365',
  duo: 'Duo Security',
  cloudtrail: 'AWS CloudTrail',
  vpc_flow_logs: 'VPC Flow Logs',
  guardduty: 'AWS GuardDuty',
  gcp_logging: 'GCP Cloud Logging',
  azure_monitor: 'Azure Monitor',
  crowdstrike: 'CrowdStrike',
  jamf: 'Jamf',
  snowflake: 'Snowflake',
  salesforce: 'Salesforce',
  slack: 'Slack',
  onepassword: '1Password',
  github: 'GitHub',
  kubernetes: 'Kubernetes',
  docker: 'Docker',
  syslog: 'Syslog',
  json_generic: 'Generic JSON',
  otlp: 'OTLP',
}

const SOURCE_ICONS = {
  okta: ShieldCheckIcon,
  google_workspace: EnvelopeIcon,
  microsoft365: ComputerDesktopIcon,
  duo: DevicePhoneMobileIcon,
  cloudtrail: CloudIcon,
  vpc_flow_logs: ArrowsRightLeftIcon,
  guardduty: ShieldExclamationIcon,
  gcp_logging: CloudIcon,
  azure_monitor: CloudIcon,
  crowdstrike: BugAntIcon,
  jamf: DevicePhoneMobileIcon,
  snowflake: CircleStackIcon,
  salesforce: BuildingOfficeIcon,
  slack: ChatBubbleLeftRightIcon,
  onepassword: KeyIcon,
  github: CodeBracketIcon,
  kubernetes: CubeIcon,
  docker: CubeTransparentIcon,
  syslog: CommandLineIcon,
  json_generic: DocumentTextIcon,
  otlp: SignalIcon,
}

const STATUS_LABELS = {
  HEALTHY: 'Healthy',
  DELAYED: 'Delayed',
  SILENT: 'Silent',
  VOLUME_ANOMALY: 'Volume Anomaly',
  UNKNOWN: 'Unknown',
}

const STATUS_CARD_COLORS = {
  HEALTHY: 'text-green-700 dark:text-green-400',
  DELAYED: 'text-yellow-700 dark:text-yellow-400',
  SILENT: 'text-red-700 dark:text-red-400',
  VOLUME_ANOMALY: 'text-orange-700 dark:text-orange-400',
  UNKNOWN: 'text-mono-600 dark:text-mono-400',
}

const STATUS_OPTIONS = ['HEALTHY', 'DELAYED', 'SILENT', 'VOLUME_ANOMALY', 'UNKNOWN']

const TABLE_COLUMNS = [
  { key: 'source_type', label: 'Source' },
  { key: 'status', label: 'Status' },
  { key: 'last_event_timestamp', label: 'Last Event' },
  { key: 'event_count_current_window', label: 'Current Count' },
  { key: 'baseline_hourly_volume', label: 'Baseline' },
  { key: 'deviation', label: 'Deviation' },
  { key: 'consecutive_failures', label: 'Failures' },
]

function computeDeviation(source) {
  if (!source.baseline_hourly_volume || source.baseline_hourly_volume === 0) return null
  return ((source.event_count_current_window - source.baseline_hourly_volume) / source.baseline_hourly_volume) * 100
}

function formatRelativeTime(timestamp) {
  if (!timestamp) return 'Never'
  const diff = Date.now() - new Date(timestamp).getTime()
  if (diff < 0) return 'Just now'
  const mins = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  if (hours < 24) return `${hours}h ago`
  if (days < 7) return `${days}d ago`
  return new Date(timestamp).toLocaleDateString()
}

export default function LogSourceHealthDashboard() {
  const navigate = useNavigate()
  const [statusFilter, setStatusFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [sortField, setSortField] = useState('source_type')
  const [sortDirection, setSortDirection] = useState('asc')
  const [configModalSource, setConfigModalSource] = useState(null)

  const { data: sourcesData, isLoading: isLoadingSources } = useSourceHealthList(statusFilter, {
    polling: true,
  })
  const { data: summaryData, isLoading: isLoadingSummary } = useHealthSummary({ polling: true })
  const { mutate: triggerCheck, isPending: isChecking } = useTriggerHealthCheck()
  const { mutate: updateConfig, isPending: isSavingConfig } = useUpdateHealthConfig()

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDirection('asc')
    }
  }

  const sortedSources = useMemo(() => {
    let sources = sourcesData?.sources || []

    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      sources = sources.filter(
        (s) =>
          s.source_type.toLowerCase().includes(q) ||
          (SOURCE_DISPLAY_NAMES[s.source_type] || '').toLowerCase().includes(q),
      )
    }

    return [...sources].sort((a, b) => {
      let aVal, bVal
      switch (sortField) {
        case 'source_type':
          aVal = SOURCE_DISPLAY_NAMES[a.source_type] || a.source_type
          bVal = SOURCE_DISPLAY_NAMES[b.source_type] || b.source_type
          return sortDirection === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        case 'status':
          aVal = a.status
          bVal = b.status
          return sortDirection === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        case 'last_event_timestamp':
          aVal = a.last_event_timestamp ? new Date(a.last_event_timestamp).getTime() : 0
          bVal = b.last_event_timestamp ? new Date(b.last_event_timestamp).getTime() : 0
          return sortDirection === 'asc' ? aVal - bVal : bVal - aVal
        case 'deviation':
          aVal = computeDeviation(a) ?? -Infinity
          bVal = computeDeviation(b) ?? -Infinity
          return sortDirection === 'asc' ? aVal - bVal : bVal - aVal
        case 'event_count_current_window':
        case 'baseline_hourly_volume':
        case 'consecutive_failures':
          aVal = a[sortField] || 0
          bVal = b[sortField] || 0
          return sortDirection === 'asc' ? aVal - bVal : bVal - aVal
        default:
          return 0
      }
    })
  }, [sourcesData, searchQuery, sortField, sortDirection])

  return (
    <div className="space-y-6 p-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">Log Source Health</h1>
        <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
          Monitor the health and volume of all ingested log sources
        </p>
      </div>

      {/* Summary bar */}
      {isLoadingSummary ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="skeleton-card h-20" />
          ))}
        </div>
      ) : summaryData ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <div className="card flex flex-col items-center justify-center py-4">
            <p className="text-xs font-medium text-mono-600 dark:text-mono-400">Total Sources</p>
            <p className="mt-1 text-2xl font-bold text-mono-950 dark:text-mono-50">
              {summaryData.total_sources_monitored}
            </p>
          </div>
          {STATUS_OPTIONS.map((status) => (
            <div
              key={status}
              onClick={() => setStatusFilter(statusFilter === status ? '' : status)}
              className={clsx(
                'card flex flex-col items-center justify-center py-4 cursor-pointer transition-all',
                statusFilter === status && 'ring-2 ring-mono-500',
              )}
            >
              <p className={clsx('text-xs font-medium', STATUS_CARD_COLORS[status])}>
                {STATUS_LABELS[status]}
              </p>
              <p className={clsx('mt-1 text-2xl font-bold', STATUS_CARD_COLORS[status])}>
                {summaryData.status_counts?.[status] ?? 0}
              </p>
            </div>
          ))}
        </div>
      ) : null}

      {/* Table section */}
      <div className="card">
        {/* Search and filter bar */}
        <div className="flex items-center justify-between mb-4 gap-4">
          <div className="relative flex-1 max-w-md">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-mono-400" />
            <input
              type="text"
              placeholder="Search sources..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-10"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input w-auto"
          >
            <option value="">All Statuses</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABELS[s]}
              </option>
            ))}
          </select>
        </div>

        {isLoadingSources ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-mono-600 border-t-transparent" />
          </div>
        ) : sortedSources.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-title">No sources found</p>
            <p className="empty-state-description">
              {statusFilter
                ? 'No sources match the selected filter.'
                : 'No log sources are currently monitored.'}
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  {TABLE_COLUMNS.map((col) => (
                    <th
                      key={col.key}
                      onClick={() => handleSort(col.key)}
                      className="cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-1">
                        {col.label}
                        {sortField === col.key &&
                          (sortDirection === 'asc' ? (
                            <ChevronUpIcon className="h-3 w-3" />
                          ) : (
                            <ChevronDownIcon className="h-3 w-3" />
                          ))}
                      </div>
                    </th>
                  ))}
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedSources.map((source) => {
                  const SourceIcon = SOURCE_ICONS[source.source_type] || DocumentTextIcon
                  const deviation = computeDeviation(source)
                  return (
                    <tr
                      key={source.source_type}
                      onClick={() => navigate(`/health/${source.source_type}`)}
                      className="cursor-pointer"
                    >
                      <td>
                        <div className="flex items-center gap-2">
                          <SourceIcon className="h-5 w-5 text-mono-500 dark:text-mono-400 flex-shrink-0" />
                          <span className="font-medium text-mono-900 dark:text-mono-100">
                            {SOURCE_DISPLAY_NAMES[source.source_type] || source.source_type}
                          </span>
                        </div>
                      </td>
                      <td>
                        <LogSourceStatusBadge status={source.status} size="sm" />
                      </td>
                      <td className="text-mono-600 dark:text-mono-400 whitespace-nowrap">
                        {formatRelativeTime(source.last_event_timestamp)}
                      </td>
                      <td className="font-mono text-mono-900 dark:text-mono-100">
                        {(source.event_count_current_window || 0).toLocaleString()}
                      </td>
                      <td className="font-mono text-mono-600 dark:text-mono-400">
                        {source.baseline_hourly_volume != null
                          ? source.baseline_hourly_volume.toFixed(0)
                          : 'N/A'}
                      </td>
                      <td>
                        {deviation != null ? (
                          <span
                            className={clsx(
                              'font-mono text-sm',
                              Math.abs(deviation) > 50
                                ? 'text-red-600 dark:text-red-400'
                                : Math.abs(deviation) > 20
                                  ? 'text-orange-600 dark:text-orange-400'
                                  : 'text-mono-600 dark:text-mono-400',
                            )}
                          >
                            {deviation > 0 ? '+' : ''}
                            {deviation.toFixed(1)}%
                          </span>
                        ) : (
                          <span className="text-mono-400 dark:text-mono-600">N/A</span>
                        )}
                      </td>
                      <td className="font-mono text-mono-900 dark:text-mono-100">
                        {source.consecutive_failures}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => triggerCheck(source.source_type)}
                            className="btn-ghost btn-sm p-1.5"
                            title="Check Now"
                            disabled={isChecking}
                          >
                            <ArrowPathIcon
                              className={clsx('h-4 w-4', isChecking && 'animate-spin')}
                            />
                          </button>
                          <button
                            onClick={() => setConfigModalSource(source.source_type)}
                            className="btn-ghost btn-sm p-1.5"
                            title="Configure"
                          >
                            <Cog6ToothIcon className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Config modal */}
      <LogSourceHealthConfig
        isOpen={!!configModalSource}
        onClose={() => setConfigModalSource(null)}
        sourceType={configModalSource}
        currentConfig={
          sourcesData?.sources?.find((s) => s.source_type === configModalSource)?.config
        }
        onSave={(sourceType, config) => {
          updateConfig(
            { sourceType, config },
            { onSuccess: () => setConfigModalSource(null) },
          )
        }}
        isSaving={isSavingConfig}
      />
    </div>
  )
}
