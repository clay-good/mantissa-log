import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  XMarkIcon,
  ArrowTopRightOnSquareIcon,
  ExclamationTriangleIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
} from '@heroicons/react/24/outline'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

import { getServiceDetail } from '../../services/apmApi'

/**
 * Service Detail Panel
 *
 * Slide-out panel showing detailed information about a selected service.
 */

function formatLatency(ms) {
  if (ms === null || ms === undefined) return '-'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${Math.round(ms)}ms`
}

function formatNumber(num) {
  if (num === null || num === undefined) return '-'
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

function formatErrorRate(rate) {
  if (rate === null || rate === undefined) return '-'
  return `${(rate * 100).toFixed(2)}%`
}

function getHealthStatus(errorRate) {
  if (errorRate === null || errorRate === undefined) {
    return { label: 'Unknown', color: 'mono' }
  }
  if (errorRate >= 0.1) {
    return { label: 'Critical', color: 'red' }
  }
  if (errorRate >= 0.05) {
    return { label: 'Degraded', color: 'yellow' }
  }
  return { label: 'Healthy', color: 'green' }
}

export default function ServiceDetail({ serviceName, start, end, onClose }) {
  const {
    data,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['serviceDetail', serviceName, start, end],
    queryFn: () => getServiceDetail(serviceName, { start, end }),
    enabled: !!serviceName,
  })

  const health = getHealthStatus(data?.stats?.error_rate)

  // Prepare latency chart data
  const latencyChartData = data?.stats
    ? [
        { name: 'Avg', value: data.stats.avg_latency_ms || 0 },
        { name: 'P50', value: data.stats.p50_latency_ms || 0 },
        { name: 'P95', value: data.stats.p95_latency_ms || 0 },
        { name: 'P99', value: data.stats.p99_latency_ms || 0 },
      ]
    : []

  return (
    <div className="absolute inset-y-0 right-0 w-[480px] bg-white dark:bg-mono-950 border-l border-mono-200 dark:border-mono-800 shadow-xl flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-mono-200 dark:border-mono-800">
        <div className="flex items-center gap-3">
          <div
            className={clsx('w-3 h-3 rounded-full', {
              'bg-green-500': health.color === 'green',
              'bg-yellow-500': health.color === 'yellow',
              'bg-red-500': health.color === 'red',
              'bg-mono-400': health.color === 'mono',
            })}
          />
          <div>
            <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
              {serviceName}
            </h2>
            <span
              className={clsx('text-xs font-medium', {
                'text-green-600 dark:text-green-400': health.color === 'green',
                'text-yellow-600 dark:text-yellow-400': health.color === 'yellow',
                'text-red-600 dark:text-red-400': health.color === 'red',
                'text-mono-500': health.color === 'mono',
              })}
            >
              {health.label}
            </span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-lg hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
        >
          <XMarkIcon className="h-5 w-5 text-mono-500" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin h-8 w-8 border-2 border-mono-300 border-t-mono-900 dark:border-mono-600 dark:border-t-mono-100 rounded-full"></div>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-full text-red-500">
            <div className="text-center">
              <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4" />
              <p>Failed to load service details</p>
            </div>
          </div>
        ) : (
          <div className="p-6 space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-2 gap-4">
              <StatCard
                label="Requests"
                value={formatNumber(data?.stats?.request_count)}
                icon={ArrowTrendingUpIcon}
              />
              <StatCard
                label="Error Rate"
                value={formatErrorRate(data?.stats?.error_rate)}
                valueColor={
                  data?.stats?.error_rate >= 0.1
                    ? 'text-red-600 dark:text-red-400'
                    : data?.stats?.error_rate >= 0.05
                      ? 'text-yellow-600 dark:text-yellow-400'
                      : ''
                }
                icon={ExclamationTriangleIcon}
              />
              <StatCard
                label="Avg Latency"
                value={formatLatency(data?.stats?.avg_latency_ms)}
                icon={ArrowTrendingDownIcon}
              />
              <StatCard
                label="P95 Latency"
                value={formatLatency(data?.stats?.p95_latency_ms)}
                icon={ArrowTrendingDownIcon}
              />
            </div>

            {/* Latency Chart */}
            {latencyChartData.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-mono-700 dark:text-mono-300 mb-3">
                  Latency Distribution
                </h3>
                <div className="h-32 bg-mono-50 dark:bg-mono-900 rounded-lg p-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={latencyChartData}>
                      <XAxis
                        dataKey="name"
                        axisLine={false}
                        tickLine={false}
                        tick={{ fontSize: 11, fill: '#737373' }}
                      />
                      <YAxis
                        axisLine={false}
                        tickLine={false}
                        tick={{ fontSize: 11, fill: '#737373' }}
                        tickFormatter={(v) => `${v}ms`}
                      />
                      <Tooltip
                        formatter={(value) => [`${Math.round(value)}ms`, 'Latency']}
                        contentStyle={{
                          backgroundColor: 'var(--color-mono-900)',
                          border: 'none',
                          borderRadius: '8px',
                          color: '#fff',
                        }}
                      />
                      <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Dependencies */}
            {data?.dependencies && (
              <div>
                <h3 className="text-sm font-medium text-mono-700 dark:text-mono-300 mb-3">
                  Dependencies
                </h3>
                <div className="space-y-3">
                  {/* Upstream */}
                  {data.dependencies.upstream_services?.length > 0 && (
                    <div>
                      <p className="text-xs text-mono-500 mb-2">Upstream (calls this service)</p>
                      <div className="flex flex-wrap gap-2">
                        {data.dependencies.upstream_services.map((svc) => (
                          <span
                            key={svc}
                            className="px-2 py-1 text-xs bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300 rounded-md"
                          >
                            {svc}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Downstream */}
                  {data.dependencies.downstream_services?.length > 0 && (
                    <div>
                      <p className="text-xs text-mono-500 mb-2">Downstream (called by this service)</p>
                      <div className="flex flex-wrap gap-2">
                        {data.dependencies.downstream_services.map((svc) => (
                          <span
                            key={svc}
                            className="px-2 py-1 text-xs bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300 rounded-md"
                          >
                            {svc}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {!data.dependencies.upstream_services?.length &&
                    !data.dependencies.downstream_services?.length && (
                      <p className="text-sm text-mono-500">No dependencies found</p>
                    )}
                </div>
              </div>
            )}

            {/* Operations */}
            {data?.operations?.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-mono-700 dark:text-mono-300 mb-3">
                  Operations ({data.operations.length})
                </h3>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {data.operations.slice(0, 10).map((op) => (
                    <div
                      key={op.operation_name}
                      className="p-3 bg-mono-50 dark:bg-mono-900 rounded-lg"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-mono-900 dark:text-mono-100 truncate max-w-[250px]">
                          {op.operation_name}
                        </span>
                        <span className="text-xs text-mono-500">
                          {formatNumber(op.request_count)} req
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-mono-500">
                        <span>Avg: {formatLatency(op.avg_latency_ms)}</span>
                        <span>P95: {formatLatency(op.p95_latency_ms)}</span>
                        <span
                          className={
                            op.error_rate >= 0.05
                              ? 'text-red-500'
                              : ''
                          }
                        >
                          Err: {formatErrorRate(op.error_rate)}
                        </span>
                      </div>
                    </div>
                  ))}
                  {data.operations.length > 10 && (
                    <p className="text-xs text-mono-500 text-center">
                      +{data.operations.length - 10} more operations
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-6 py-4 border-t border-mono-200 dark:border-mono-800">
        <button
          className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-mono-950 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded-lg text-sm font-medium hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors"
        >
          <ArrowTopRightOnSquareIcon className="h-4 w-4" />
          View Traces
        </button>
      </div>
    </div>
  )
}

function StatCard({ label, value, valueColor = '', icon: Icon }) {
  return (
    <div className="p-4 bg-mono-50 dark:bg-mono-900 rounded-lg">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-mono-500 uppercase tracking-wide">{label}</span>
        {Icon && <Icon className="h-4 w-4 text-mono-400" />}
      </div>
      <span className={clsx('text-xl font-semibold text-mono-900 dark:text-mono-100', valueColor)}>
        {value}
      </span>
    </div>
  )
}
