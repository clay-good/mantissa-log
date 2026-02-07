import { useState, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import {
  ArrowLeftIcon,
  ArrowPathIcon,
  Cog6ToothIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  HandRaisedIcon,
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
import LogSourceVolumeChart from './LogSourceVolumeChart'
import GapTimeline from './GapTimeline'
import LogSourceHealthConfig from './LogSourceHealthConfig'
import {
  useSourceHealthDetail,
  useSourceHealthHistory,
  useTriggerHealthCheck,
  useUpdateHealthConfig,
  useAcknowledgeHealthAlert,
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

const TIME_RANGE_OPTIONS = [
  { value: '24h', label: 'Last 24 Hours', hours: 24, granularity: 'hour' },
  { value: '7d', label: 'Last 7 Days', hours: 168, granularity: 'hour' },
  { value: '30d', label: 'Last 30 Days', hours: 720, granularity: 'day' },
]

const CONFIG_DISPLAY_FIELDS = [
  { key: 'expected_max_latency_seconds', label: 'Max Latency', suffix: 's' },
  { key: 'silence_threshold_seconds', label: 'Silence Threshold', suffix: 's' },
  { key: 'volume_anomaly_stddev_threshold', label: 'Anomaly Threshold', suffix: ' stddev' },
  { key: 'volume_drop_percentage_threshold', label: 'Drop Threshold', format: (v) => `${(v * 100).toFixed(0)}%` },
  { key: 'volume_spike_percentage_threshold', label: 'Spike Threshold', suffix: 'x' },
  { key: 'check_interval_seconds', label: 'Check Interval', suffix: 's' },
  { key: 'alert_suppression_seconds', label: 'Alert Suppression', suffix: 's' },
  { key: 'gap_minimum_duration_seconds', label: 'Min Gap Duration', suffix: 's' },
]

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

function formatFullDate(timestamp) {
  if (!timestamp) return 'N/A'
  return new Date(timestamp).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

export default function LogSourceHealthDetail() {
  const { sourceType } = useParams()
  const navigate = useNavigate()
  const [timeRange, setTimeRange] = useState('24h')
  const [showConfig, setShowConfig] = useState(false)
  const [showAckForm, setShowAckForm] = useState(false)
  const [ackNotes, setAckNotes] = useState('')
  const [ackDuration, setAckDuration] = useState(3600)

  const selectedRange = TIME_RANGE_OPTIONS.find((r) => r.value === timeRange)

  const { startTime, endTime } = useMemo(() => {
    const end = new Date()
    const start = new Date()
    start.setHours(start.getHours() - selectedRange.hours)
    return { startTime: start.toISOString(), endTime: end.toISOString() }
  }, [timeRange, selectedRange.hours])

  const { data: detail, isLoading: isLoadingDetail } = useSourceHealthDetail(sourceType)
  const { data: historyData, isLoading: isLoadingHistory } = useSourceHealthHistory(
    sourceType,
    startTime,
    endTime,
    selectedRange.granularity,
  )
  const { mutate: triggerCheck, isPending: isChecking } = useTriggerHealthCheck()
  const { mutate: updateConfig, isPending: isSavingConfig } = useUpdateHealthConfig()
  const { mutate: acknowledge, isPending: isAcknowledging } = useAcknowledgeHealthAlert()

  const SourceIcon = SOURCE_ICONS[sourceType] || DocumentTextIcon

  const gapData = useMemo(() => {
    if (historyData?.gap_windows?.length) return historyData.gap_windows
    if (detail?.state?.gap_windows?.length) {
      return detail.state.gap_windows.map(([start, end]) => ({
        start,
        end,
        duration_seconds: (new Date(end) - new Date(start)) / 1000,
      }))
    }
    return []
  }, [historyData, detail])

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/health')}
            className="btn-ghost p-2 rounded-lg"
            aria-label="Back to dashboard"
          >
            <ArrowLeftIcon className="h-5 w-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <SourceIcon className="h-6 w-6 text-mono-500 dark:text-mono-400" />
              <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                {SOURCE_DISPLAY_NAMES[sourceType] || sourceType}
              </h1>
              {detail && <LogSourceStatusBadge status={detail.state.status} />}
            </div>
            <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
              Source type:{' '}
              <code className="font-mono text-xs bg-mono-100 dark:bg-mono-800 px-1.5 py-0.5 rounded">
                {sourceType}
              </code>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => triggerCheck(sourceType)}
            className="btn-secondary"
            disabled={isChecking}
          >
            <ArrowPathIcon className={clsx('h-4 w-4 mr-2', isChecking && 'animate-spin')} />
            Check Now
          </button>
          <button onClick={() => setShowConfig(true)} className="btn-secondary">
            <Cog6ToothIcon className="h-4 w-4 mr-2" />
            Configure
          </button>
        </div>
      </div>

      {isLoadingDetail ? (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="skeleton-card h-32" />
          ))}
        </div>
      ) : detail ? (
        <>
          {/* Stats cards */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="card py-4">
              <p className="label">Last Event</p>
              <p className="text-lg font-semibold text-mono-950 dark:text-mono-50">
                {formatRelativeTime(detail.state.last_event_timestamp)}
              </p>
            </div>
            <div className="card py-4">
              <p className="label">Current Window Count</p>
              <p className="text-lg font-semibold font-mono text-mono-950 dark:text-mono-50">
                {(detail.state.event_count_current_window || 0).toLocaleString()}
              </p>
            </div>
            <div className="card py-4">
              <p className="label">Previous Window Count</p>
              <p className="text-lg font-semibold font-mono text-mono-950 dark:text-mono-50">
                {(detail.state.event_count_previous_window || 0).toLocaleString()}
              </p>
            </div>
            <div className="card py-4">
              <p className="label">Baseline Hourly Volume</p>
              <p className="text-lg font-semibold font-mono text-mono-950 dark:text-mono-50">
                {detail.baseline
                  ? `${detail.baseline.hourly_volume.toFixed(0)} \u00b1 ${detail.baseline.hourly_stddev.toFixed(0)}`
                  : 'Not established'}
              </p>
            </div>
          </div>

          {/* Volume chart with time range selector */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
                Event Volume
              </h2>
              <div className="flex items-center gap-1">
                {TIME_RANGE_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setTimeRange(opt.value)}
                    className={clsx(
                      'px-3 py-1.5 text-xs rounded-lg transition-colors',
                      timeRange === opt.value
                        ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-900'
                        : 'bg-mono-100 dark:bg-mono-800 text-mono-600 dark:text-mono-400 hover:bg-mono-200 dark:hover:bg-mono-700',
                    )}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
            <LogSourceVolumeChart
              data={historyData?.history || []}
              baseline={historyData?.baseline || detail.baseline}
              gapWindows={historyData?.gap_windows || []}
              timeRange={timeRange}
              isLoading={isLoadingHistory}
            />
          </div>

          {/* Gap timeline */}
          <GapTimeline gaps={gapData} startTime={startTime} endTime={endTime} />

          {/* Status information */}
          <div className="card">
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-100 mb-4">
              Status Information
            </h3>
            <div className="space-y-3">
              <div className="flex items-start gap-3">
                <ClockIcon className="mt-0.5 h-5 w-5 text-mono-400 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-mono-900 dark:text-mono-100">
                    Last Health Check
                  </p>
                  <p className="text-sm text-mono-500 dark:text-mono-400">
                    {formatFullDate(detail.state.last_check_timestamp)}
                  </p>
                </div>
              </div>

              {detail.state.consecutive_failures > 0 && (
                <div className="flex items-start gap-3">
                  <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 text-orange-500 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-mono-900 dark:text-mono-100">
                      Consecutive Failures
                    </p>
                    <p className="text-sm text-mono-500 dark:text-mono-400">
                      {detail.state.consecutive_failures} consecutive check
                      {detail.state.consecutive_failures !== 1 ? 's' : ''} with issues
                    </p>
                  </div>
                </div>
              )}

              {detail.state.last_alert_timestamp && (
                <div className="flex items-start gap-3">
                  <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 text-red-500 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-mono-900 dark:text-mono-100">
                      Last Alert
                    </p>
                    <p className="text-sm text-mono-500 dark:text-mono-400">
                      {formatFullDate(detail.state.last_alert_timestamp)}
                    </p>
                  </div>
                </div>
              )}

              {detail.state.metadata?.acknowledged_by && (
                <div className="flex items-start gap-3">
                  <CheckCircleIcon className="mt-0.5 h-5 w-5 text-green-500 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-mono-900 dark:text-mono-100">
                      Acknowledged
                    </p>
                    <p className="text-sm text-mono-500 dark:text-mono-400">
                      By {detail.state.metadata.acknowledged_by} at{' '}
                      {formatFullDate(detail.state.metadata.acknowledged_at)}
                    </p>
                    {detail.state.metadata.acknowledgment_notes && (
                      <p className="mt-1 text-sm text-mono-600 dark:text-mono-400 italic">
                        &ldquo;{detail.state.metadata.acknowledgment_notes}&rdquo;
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Acknowledge / Actions */}
          {detail.state.status !== 'HEALTHY' && detail.state.status !== 'UNKNOWN' && (
            <div className="card">
              <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-100 mb-4">
                Actions
              </h3>
              {!showAckForm ? (
                <button onClick={() => setShowAckForm(true)} className="btn-warning">
                  <HandRaisedIcon className="h-4 w-4 mr-2" />
                  Acknowledge &amp; Suppress Alerts
                </button>
              ) : (
                <div className="space-y-4">
                  <div>
                    <label className="label">Suppression Duration</label>
                    <select
                      value={ackDuration}
                      onChange={(e) => setAckDuration(Number(e.target.value))}
                      className="input w-auto"
                    >
                      <option value={1800}>30 minutes</option>
                      <option value={3600}>1 hour</option>
                      <option value={14400}>4 hours</option>
                      <option value={86400}>24 hours</option>
                    </select>
                  </div>
                  <div>
                    <label className="label">Notes</label>
                    <textarea
                      value={ackNotes}
                      onChange={(e) => setAckNotes(e.target.value)}
                      placeholder="Reason for acknowledgment..."
                      rows={3}
                      className="input"
                    />
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        acknowledge({
                          sourceType,
                          suppression_duration_seconds: ackDuration,
                          notes: ackNotes,
                        })
                        setShowAckForm(false)
                        setAckNotes('')
                      }}
                      disabled={isAcknowledging}
                      className="btn-warning"
                    >
                      {isAcknowledging ? 'Acknowledging...' : 'Acknowledge'}
                    </button>
                    <button
                      onClick={() => {
                        setShowAckForm(false)
                        setAckNotes('')
                      }}
                      className="btn-secondary"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Current config summary */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-100">
                Health Configuration
              </h3>
              <button onClick={() => setShowConfig(true)} className="btn-ghost btn-sm">
                <Cog6ToothIcon className="h-4 w-4 mr-1" />
                Edit
              </button>
            </div>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
              <div>
                <p className="text-xs text-mono-500 dark:text-mono-400">Monitoring</p>
                <p className="font-medium text-mono-900 dark:text-mono-100">
                  {detail.config.enabled ? 'Enabled' : 'Disabled'}
                </p>
              </div>
              <div>
                <p className="text-xs text-mono-500 dark:text-mono-400">Gap Detection</p>
                <p className="font-medium text-mono-900 dark:text-mono-100">
                  {detail.config.gap_detection_enabled ? 'Enabled' : 'Disabled'}
                </p>
              </div>
              {CONFIG_DISPLAY_FIELDS.map((field) => (
                <div key={field.key}>
                  <p className="text-xs text-mono-500 dark:text-mono-400">{field.label}</p>
                  <p className="font-mono text-sm text-mono-900 dark:text-mono-100">
                    {field.format
                      ? field.format(detail.config[field.key])
                      : `${detail.config[field.key]}${field.suffix || ''}`}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </>
      ) : (
        <div className="empty-state">
          <p className="empty-state-title">Source Not Found</p>
          <p className="empty-state-description">
            The source type &ldquo;{sourceType}&rdquo; was not found.
          </p>
        </div>
      )}

      {/* Config modal */}
      <LogSourceHealthConfig
        isOpen={showConfig}
        onClose={() => setShowConfig(false)}
        sourceType={sourceType}
        currentConfig={detail?.config}
        onSave={(st, config) =>
          updateConfig({ sourceType: st, config }, { onSuccess: () => setShowConfig(false) })
        }
        isSaving={isSavingConfig}
      />
    </div>
  )
}
