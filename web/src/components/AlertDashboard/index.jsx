import { useState, useMemo } from 'react'
import { MagnifyingGlassIcon, FunnelIcon } from '@heroicons/react/24/outline'
import {
  useAlerts,
  useAlertStats,
  useAlertTimeline,
  useBulkAcknowledge,
  useBulkResolve,
} from '../../hooks/useAlerts'
import AlertStats from './AlertStats'
import AlertTimeline from './AlertTimeline'
import AlertList from './AlertList'
import AlertDetail from './AlertDetail'

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const STATUS_OPTIONS = ['new', 'acknowledged', 'resolved']

export default function AlertDashboard() {
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [selectedAlerts, setSelectedAlerts] = useState([])
  const [showFilters, setShowFilters] = useState(false)

  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    status: '',
    ruleId: '',
    startTime: '',
    endTime: '',
  })

  // Calculate default time range (last 24 hours)
  const defaultEndTime = useMemo(() => new Date().toISOString(), [])
  const defaultStartTime = useMemo(() => {
    const date = new Date()
    date.setHours(date.getHours() - 24)
    return date.toISOString()
  }, [])

  const { data: alertsData, isLoading: isLoadingAlerts } = useAlerts(filters, 1, 50, {
    polling: true,
  })

  const { data: statsData, isLoading: isLoadingStats } = useAlertStats(
    filters.startTime || defaultStartTime,
    filters.endTime || defaultEndTime,
    { polling: true }
  )

  const { data: timelineData, isLoading: isLoadingTimeline } = useAlertTimeline(
    filters.startTime || defaultStartTime,
    filters.endTime || defaultEndTime,
    '1h'
  )

  const { mutate: bulkAcknowledge } = useBulkAcknowledge()
  const { mutate: bulkResolve } = useBulkResolve()

  const handleFilterChange = (field, value) => {
    setFilters((prev) => ({
      ...prev,
      [field]: value,
    }))
  }

  const handleSelectAlert = (alertId) => {
    setSelectedAlertId(alertId)
  }

  const handleCloseDetail = () => {
    setSelectedAlertId(null)
  }

  const handleBulkAcknowledge = () => {
    if (selectedAlerts.length > 0) {
      bulkAcknowledge(selectedAlerts)
      setSelectedAlerts([])
    }
  }

  const handleBulkResolve = () => {
    if (selectedAlerts.length > 0) {
      bulkResolve({ alertIds: selectedAlerts, resolution: 'Bulk resolved' })
      setSelectedAlerts([])
    }
  }

  const handleQuickFilter = (field, value) => {
    setFilters((prev) => ({
      ...prev,
      [field]: value,
    }))
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mb-2">Alert Dashboard</h1>
        <p className="text-gray-600">
          Monitor and manage security alerts from detection rules
        </p>
      </div>

      <AlertStats stats={statsData} isLoading={isLoadingStats} />

      <AlertTimeline data={timelineData} isLoading={isLoadingTimeline} />

      <div className="card">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex flex-1 items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search alerts..."
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
          </div>

          {showFilters && (
            <div className="grid grid-cols-4 gap-4 rounded-lg border border-gray-200 p-4">
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
                  Status
                </label>
                <select
                  value={filters.status}
                  onChange={(e) => handleFilterChange('status', e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                >
                  <option value="">All Statuses</option>
                  {STATUS_OPTIONS.map((status) => (
                    <option key={status} value={status}>
                      {status.charAt(0).toUpperCase() + status.slice(1)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Start Time
                </label>
                <input
                  type="datetime-local"
                  value={
                    filters.startTime
                      ? new Date(filters.startTime).toISOString().slice(0, 16)
                      : ''
                  }
                  onChange={(e) =>
                    handleFilterChange(
                      'startTime',
                      e.target.value ? new Date(e.target.value).toISOString() : ''
                    )
                  }
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  End Time
                </label>
                <input
                  type="datetime-local"
                  value={
                    filters.endTime
                      ? new Date(filters.endTime).toISOString().slice(0, 16)
                      : ''
                  }
                  onChange={(e) =>
                    handleFilterChange(
                      'endTime',
                      e.target.value ? new Date(e.target.value).toISOString() : ''
                    )
                  }
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>
            </div>
          )}

          {selectedAlerts.length > 0 && (
            <div className="flex items-center justify-between rounded-lg bg-blue-50 p-4">
              <p className="text-sm text-blue-900">
                {selectedAlerts.length} alert{selectedAlerts.length > 1 ? 's' : ''}{' '}
                selected
              </p>
              <div className="flex gap-2">
                <button
                  onClick={handleBulkAcknowledge}
                  className="rounded-lg bg-yellow-600 px-4 py-2 text-sm font-medium text-white hover:bg-yellow-700"
                >
                  Acknowledge Selected
                </button>
                <button
                  onClick={handleBulkResolve}
                  className="rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700"
                >
                  Resolve Selected
                </button>
              </div>
            </div>
          )}

          <AlertList
            alerts={alertsData?.alerts || []}
            isLoading={isLoadingAlerts}
            onSelectAlert={handleSelectAlert}
            selectedAlertId={selectedAlertId}
            onSelectForBulk={setSelectedAlerts}
            selectedAlerts={selectedAlerts}
          />
        </div>
      </div>

      {selectedAlertId && (
        <AlertDetail alertId={selectedAlertId} onClose={handleCloseDetail} />
      )}
    </div>
  )
}
