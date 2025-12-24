import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  MagnifyingGlassIcon,
  ExclamationTriangleIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  FunnelIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

import { searchTraces, getTimeRangeTimestamps, TIME_RANGES } from '../../services/apmApi'

/**
 * Trace List Component
 *
 * Displays a searchable, filterable list of traces with the ability
 * to click through to the trace viewer.
 */

function formatDuration(ms) {
  if (ms === null || ms === undefined) return '-'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${Math.round(ms)}ms`
}

function formatTimestamp(isoString) {
  if (!isoString) return '-'
  const date = new Date(isoString)
  return date.toLocaleString()
}

function truncateId(id, length = 8) {
  if (!id) return '-'
  if (id.length <= length) return id
  return `${id.substring(0, length)}...`
}

export default function TraceList({ onTraceSelect, timeRange = '1h' }) {
  const [filters, setFilters] = useState({
    serviceName: '',
    operationName: '',
    traceId: '',
    status: 'all',
    minDuration: '',
    maxDuration: '',
  })
  const [showFilters, setShowFilters] = useState(false)
  const [copiedId, setCopiedId] = useState(null)

  // Get time range
  const { start, end } = getTimeRangeTimestamps(timeRange)

  // Build search filters
  const searchFilters = useMemo(
    () => ({
      ...filters,
      minDuration: filters.minDuration ? parseInt(filters.minDuration, 10) : undefined,
      maxDuration: filters.maxDuration ? parseInt(filters.maxDuration, 10) : undefined,
      start,
      end,
      limit: 100,
    }),
    [filters, start, end]
  )

  // Search traces
  const {
    data,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['traceSearch', searchFilters],
    queryFn: () => searchTraces(searchFilters),
    staleTime: 30000,
  })

  const handleFilterChange = (field, value) => {
    setFilters((prev) => ({ ...prev, [field]: value }))
  }

  const handleClearFilters = () => {
    setFilters({
      serviceName: '',
      operationName: '',
      traceId: '',
      status: 'all',
      minDuration: '',
      maxDuration: '',
    })
  }

  const handleCopyTraceId = async (traceId, e) => {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(traceId)
      setCopiedId(traceId)
      setTimeout(() => setCopiedId(null), 2000)
      toast.success('Trace ID copied')
    } catch {
      toast.error('Failed to copy')
    }
  }

  const hasActiveFilters =
    filters.serviceName ||
    filters.operationName ||
    filters.traceId ||
    filters.status !== 'all' ||
    filters.minDuration ||
    filters.maxDuration

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="animate-spin h-8 w-8 border-2 border-mono-300 border-t-mono-900 dark:border-mono-600 dark:border-t-mono-100 rounded-full mx-auto"></div>
          <p className="mt-4 text-mono-600 dark:text-mono-400">Searching traces...</p>
        </div>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center text-red-500">
          <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4" />
          <p className="font-medium">Failed to search traces</p>
          <p className="text-sm mt-1">{error.message}</p>
        </div>
      </div>
    )
  }

  const traces = data?.traces || []

  return (
    <div className="h-full flex flex-col p-6">
      {/* Search Header */}
      <div className="mb-4 space-y-3">
        {/* Quick Search */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-mono-400" />
            <input
              type="text"
              placeholder="Search by trace ID..."
              value={filters.traceId}
              onChange={(e) => handleFilterChange('traceId', e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-900 text-sm text-mono-950 dark:text-mono-50 placeholder-mono-500 focus:outline-none focus:ring-2 focus:ring-mono-500"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={clsx(
              'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
              showFilters || hasActiveFilters
                ? 'bg-mono-950 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                : 'bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300 hover:bg-mono-200 dark:hover:bg-mono-700'
            )}
          >
            <FunnelIcon className="h-4 w-4" />
            Filters
            {hasActiveFilters && (
              <span className="ml-1 px-1.5 py-0.5 bg-mono-100 dark:bg-mono-800 text-mono-900 dark:text-mono-100 rounded text-xs">
                {Object.values(filters).filter((v) => v && v !== 'all').length}
              </span>
            )}
          </button>
          <button
            onClick={() => refetch()}
            className="px-3 py-2 rounded-lg bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300 hover:bg-mono-200 dark:hover:bg-mono-700 text-sm font-medium transition-colors"
          >
            Search
          </button>
        </div>

        {/* Advanced Filters */}
        {showFilters && (
          <div className="p-4 bg-mono-50 dark:bg-mono-900 rounded-lg border border-mono-200 dark:border-mono-800">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div>
                <label className="block text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                  Service
                </label>
                <input
                  type="text"
                  placeholder="Any service"
                  value={filters.serviceName}
                  onChange={(e) => handleFilterChange('serviceName', e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-950 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                  Operation
                </label>
                <input
                  type="text"
                  placeholder="Any operation"
                  value={filters.operationName}
                  onChange={(e) => handleFilterChange('operationName', e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-950 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                  Status
                </label>
                <select
                  value={filters.status}
                  onChange={(e) => handleFilterChange('status', e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-950 text-sm"
                >
                  <option value="all">All</option>
                  <option value="ok">OK</option>
                  <option value="error">Error</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                  Min Duration (ms)
                </label>
                <input
                  type="number"
                  placeholder="0"
                  value={filters.minDuration}
                  onChange={(e) => handleFilterChange('minDuration', e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-950 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                  Max Duration (ms)
                </label>
                <input
                  type="number"
                  placeholder="No limit"
                  value={filters.maxDuration}
                  onChange={(e) => handleFilterChange('maxDuration', e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-950 text-sm"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={handleClearFilters}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
                >
                  <XMarkIcon className="h-4 w-4" />
                  Clear
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Results */}
      {traces.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-mono-500">
          <div className="text-center">
            <MagnifyingGlassIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p className="text-lg font-medium">No traces found</p>
            <p className="text-sm mt-1">Try adjusting your filters or time range</p>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-auto rounded-lg border border-mono-200 dark:border-mono-800">
          <table className="min-w-full divide-y divide-mono-200 dark:divide-mono-800">
            <thead className="bg-mono-50 dark:bg-mono-900 sticky top-0">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Trace ID
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Root Service
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Root Operation
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Duration
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Spans
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400">
                  Timestamp
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-mono-950 divide-y divide-mono-200 dark:divide-mono-800">
              {traces.map((trace) => {
                const hasErrors = trace.error_count > 0 || trace.status === 'error'
                return (
                  <tr
                    key={trace.trace_id}
                    onClick={() => onTraceSelect?.(trace.trace_id)}
                    className="hover:bg-mono-50 dark:hover:bg-mono-900 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <code className="text-sm font-mono text-mono-700 dark:text-mono-300">
                          {truncateId(trace.trace_id, 12)}
                        </code>
                        <button
                          onClick={(e) => handleCopyTraceId(trace.trace_id, e)}
                          className="p-1 rounded hover:bg-mono-200 dark:hover:bg-mono-700 transition-colors"
                          title="Copy trace ID"
                        >
                          {copiedId === trace.trace_id ? (
                            <CheckIcon className="h-3.5 w-3.5 text-green-500" />
                          ) : (
                            <ClipboardDocumentIcon className="h-3.5 w-3.5 text-mono-400" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-900 dark:text-mono-100">
                      {trace.root_service || trace.service_name || '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400 max-w-[200px] truncate">
                      {trace.root_operation || trace.operation_name || '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                      {formatDuration(trace.duration_ms || trace.total_duration_ms)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                      {trace.span_count || '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {hasErrors ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                          Error
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                          OK
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                      {formatTimestamp(trace.start_time || trace.trace_start)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Summary */}
      <div className="mt-4 flex items-center justify-between text-sm text-mono-500">
        <span>
          {traces.length} trace{traces.length !== 1 ? 's' : ''} found
        </span>
        <span>Time range: {TIME_RANGES[timeRange]?.label || timeRange}</span>
      </div>
    </div>
  )
}
