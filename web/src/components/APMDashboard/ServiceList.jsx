import { useState, useMemo } from 'react'
import clsx from 'clsx'
import {
  ChevronUpIcon,
  ChevronDownIcon,
  ExclamationTriangleIcon,
  ListBulletIcon,
} from '@heroicons/react/24/outline'

/**
 * Service List Component
 *
 * Displays a sortable table of all services with their metrics.
 */

const COLUMNS = [
  { id: 'service_name', label: 'Service', sortable: true },
  { id: 'request_count', label: 'Requests', sortable: true },
  { id: 'error_rate', label: 'Error Rate', sortable: true },
  { id: 'avg_latency_ms', label: 'Avg Latency', sortable: true },
  { id: 'p95_latency_ms', label: 'P95 Latency', sortable: true },
  { id: 'operation_count', label: 'Operations', sortable: true },
]

function formatNumber(num) {
  if (num === null || num === undefined) return '-'
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

function formatLatency(ms) {
  if (ms === null || ms === undefined) return '-'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${Math.round(ms)}ms`
}

function formatErrorRate(rate) {
  if (rate === null || rate === undefined) return '-'
  return `${(rate * 100).toFixed(2)}%`
}

function getHealthIndicator(errorRate) {
  if (errorRate === null || errorRate === undefined) {
    return { color: 'bg-mono-300 dark:bg-mono-600', label: 'Unknown' }
  }
  if (errorRate >= 0.1) {
    return { color: 'bg-red-500', label: 'Error' }
  }
  if (errorRate >= 0.05) {
    return { color: 'bg-yellow-500', label: 'Degraded' }
  }
  return { color: 'bg-green-500', label: 'Healthy' }
}

export default function ServiceList({ data, isLoading, error, onServiceSelect }) {
  const [sortColumn, setSortColumn] = useState('request_count')
  const [sortDirection, setSortDirection] = useState('desc')
  const [searchQuery, setSearchQuery] = useState('')

  // Sort and filter services
  const sortedServices = useMemo(() => {
    if (!data?.services) return []

    let filtered = data.services
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter((s) => s.service_name?.toLowerCase().includes(query))
    }

    return [...filtered].sort((a, b) => {
      let aVal = a[sortColumn]
      let bVal = b[sortColumn]

      // Handle null/undefined
      if (aVal === null || aVal === undefined) aVal = sortDirection === 'asc' ? Infinity : -Infinity
      if (bVal === null || bVal === undefined) bVal = sortDirection === 'asc' ? Infinity : -Infinity

      // String comparison for service name
      if (sortColumn === 'service_name') {
        return sortDirection === 'asc'
          ? String(aVal).localeCompare(String(bVal))
          : String(bVal).localeCompare(String(aVal))
      }

      // Numeric comparison
      return sortDirection === 'asc' ? aVal - bVal : bVal - aVal
    })
  }, [data?.services, sortColumn, sortDirection, searchQuery])

  const handleSort = (columnId) => {
    if (sortColumn === columnId) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortColumn(columnId)
      setSortDirection('desc')
    }
  }

  const handleRowClick = (serviceName) => {
    if (onServiceSelect) {
      onServiceSelect(serviceName)
    }
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="animate-spin h-8 w-8 border-2 border-mono-300 border-t-mono-900 dark:border-mono-600 dark:border-t-mono-100 rounded-full mx-auto"></div>
          <p className="mt-4 text-mono-600 dark:text-mono-400">Loading services...</p>
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
          <p className="font-medium">Failed to load services</p>
          <p className="text-sm mt-1">{error.message}</p>
        </div>
      </div>
    )
  }

  // Empty state
  if (!data?.services || data.services.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-mono-500">
        <div className="text-center">
          <ListBulletIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p className="text-lg font-medium">No services found</p>
          <p className="text-sm mt-1">No trace data in the selected time range</p>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col p-6">
      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search services..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full max-w-md rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-900 px-4 py-2 text-sm text-mono-950 dark:text-mono-50 placeholder-mono-500 focus:outline-none focus:ring-2 focus:ring-mono-500"
        />
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto rounded-lg border border-mono-200 dark:border-mono-800">
        <table className="min-w-full divide-y divide-mono-200 dark:divide-mono-800">
          <thead className="bg-mono-50 dark:bg-mono-900 sticky top-0">
            <tr>
              {COLUMNS.map((column) => (
                <th
                  key={column.id}
                  className={clsx(
                    'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-mono-600 dark:text-mono-400',
                    column.sortable && 'cursor-pointer hover:text-mono-900 dark:hover:text-mono-200'
                  )}
                  onClick={() => column.sortable && handleSort(column.id)}
                >
                  <div className="flex items-center gap-1">
                    {column.label}
                    {column.sortable && sortColumn === column.id && (
                      sortDirection === 'asc' ? (
                        <ChevronUpIcon className="h-4 w-4" />
                      ) : (
                        <ChevronDownIcon className="h-4 w-4" />
                      )
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-mono-950 divide-y divide-mono-200 dark:divide-mono-800">
            {sortedServices.map((service) => {
              const health = getHealthIndicator(service.error_rate)
              return (
                <tr
                  key={service.service_name}
                  onClick={() => handleRowClick(service.service_name)}
                  className="hover:bg-mono-50 dark:hover:bg-mono-900 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <div className={clsx('w-2 h-2 rounded-full', health.color)} title={health.label} />
                      <span className="text-sm font-medium text-mono-900 dark:text-mono-100">
                        {service.service_name}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                    {formatNumber(service.request_count)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={clsx(
                        'text-sm',
                        service.error_rate >= 0.1
                          ? 'text-red-600 dark:text-red-400'
                          : service.error_rate >= 0.05
                            ? 'text-yellow-600 dark:text-yellow-400'
                            : 'text-mono-600 dark:text-mono-400'
                      )}
                    >
                      {formatErrorRate(service.error_rate)}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                    {formatLatency(service.avg_latency_ms)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                    {formatLatency(service.p95_latency_ms)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-mono-600 dark:text-mono-400">
                    {service.operation_count || '-'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Summary */}
      <div className="mt-4 flex items-center justify-between text-sm text-mono-500">
        <span>
          {sortedServices.length} of {data.services.length} services
        </span>
        {data.time_range && (
          <span>
            Data from {new Date(data.time_range.start).toLocaleString()} to{' '}
            {new Date(data.time_range.end).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  )
}
