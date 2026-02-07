import { Link } from 'react-router-dom'
import { useHealthSummary, useSourceHealthList } from '../hooks/useLogSourceHealth'
import LogSourceStatusBadge from '../components/LogSourceHealth/LogSourceStatusBadge'
import {
  HeartIcon,
  ArrowRightIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline'

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

const STATUS_LABELS = {
  HEALTHY: 'Healthy',
  DELAYED: 'Delayed',
  SILENT: 'Silent',
  VOLUME_ANOMALY: 'Anomaly',
  UNKNOWN: 'Unknown',
}

const STATUS_DOT_COLORS = {
  HEALTHY: 'bg-green-500',
  DELAYED: 'bg-yellow-500',
  SILENT: 'bg-red-500',
  VOLUME_ANOMALY: 'bg-orange-500',
  UNKNOWN: 'bg-mono-400',
}

export default function Dashboard() {
  const { data: summary, isLoading: summaryLoading } = useHealthSummary({ polling: true })
  const { data: sourcesData } = useSourceHealthList('', { polling: true })

  const unhealthySources = (sourcesData?.sources || []).filter(
    (s) => s.status === 'SILENT' || s.status === 'DELAYED' || s.status === 'VOLUME_ANOMALY'
  )

  const statusCounts = summary?.status_counts || {}
  const totalSources = summary?.total_sources_monitored || 0

  return (
    <div className="p-6">
      <h1 className="mb-6 text-2xl font-bold text-mono-950 dark:text-mono-50">Dashboard</h1>
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Active Alerts</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">12</p>
        </div>
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Detection Rules</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">45</p>
        </div>
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Events Today</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">1.2M</p>
        </div>
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Queries Run</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">89</p>
        </div>
      </div>

      {/* Log Source Health Summary */}
      <div className="mt-6 bg-white dark:bg-mono-900 rounded-lg border border-mono-200 dark:border-mono-800">
        <div className="flex items-center justify-between px-6 py-4 border-b border-mono-200 dark:border-mono-800">
          <div className="flex items-center gap-2">
            <HeartIcon className="h-5 w-5 text-mono-600 dark:text-mono-400" />
            <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
              Log Source Health
            </h2>
          </div>
          <Link
            to="/health"
            className="flex items-center gap-1 text-sm font-medium text-mono-600 hover:text-mono-900 dark:text-mono-400 dark:hover:text-mono-100 transition-colors"
          >
            View all
            <ArrowRightIcon className="h-4 w-4" />
          </Link>
        </div>

        {summaryLoading ? (
          <div className="p-6">
            <div className="animate-pulse space-y-3">
              <div className="h-4 bg-mono-200 dark:bg-mono-700 rounded w-1/3" />
              <div className="h-4 bg-mono-200 dark:bg-mono-700 rounded w-1/2" />
              <div className="h-4 bg-mono-200 dark:bg-mono-700 rounded w-2/5" />
            </div>
          </div>
        ) : (
          <div className="p-6">
            {/* Status counts row */}
            <div className="flex flex-wrap items-center gap-4 mb-4">
              <span className="text-sm text-mono-600 dark:text-mono-400">
                {totalSources} sources monitored
              </span>
              <span className="text-mono-300 dark:text-mono-700">|</span>
              {Object.entries(STATUS_LABELS).map(([key, label]) => {
                const count = statusCounts[key] || 0
                if (count === 0) return null
                return (
                  <div key={key} className="flex items-center gap-1.5">
                    <span className={`inline-block h-2 w-2 rounded-full ${STATUS_DOT_COLORS[key]}`} />
                    <span className="text-sm text-mono-700 dark:text-mono-300">
                      {count} {label}
                    </span>
                  </div>
                )
              })}
            </div>

            {/* Unhealthy sources list */}
            {unhealthySources.length > 0 ? (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 mb-2">
                  <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
                    Unhealthy Sources
                  </span>
                </div>
                {unhealthySources.slice(0, 5).map((source) => (
                  <Link
                    key={source.source_type}
                    to={`/health/${source.source_type}`}
                    className="flex items-center justify-between p-3 rounded-md bg-mono-50 dark:bg-mono-800/50 hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-medium text-mono-900 dark:text-mono-100">
                        {SOURCE_DISPLAY_NAMES[source.source_type] || source.source_type}
                      </span>
                      <LogSourceStatusBadge status={source.status} size="sm" />
                    </div>
                    <span className="text-xs text-mono-500 dark:text-mono-400">
                      {source.consecutive_failures > 0 &&
                        `${source.consecutive_failures} failure${source.consecutive_failures !== 1 ? 's' : ''}`}
                    </span>
                  </Link>
                ))}
                {unhealthySources.length > 5 && (
                  <Link
                    to="/health"
                    className="block text-center text-sm text-mono-500 hover:text-mono-700 dark:text-mono-400 dark:hover:text-mono-200 pt-1 transition-colors"
                  >
                    +{unhealthySources.length - 5} more unhealthy source{unhealthySources.length - 5 !== 1 ? 's' : ''}
                  </Link>
                )}
              </div>
            ) : (
              <p className="text-sm text-mono-500 dark:text-mono-400">
                All monitored sources are healthy.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
