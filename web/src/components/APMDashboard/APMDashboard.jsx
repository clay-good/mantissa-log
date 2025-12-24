import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowPathIcon,
  MapIcon,
  ListBulletIcon,
  ChartBarIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline'

import ServiceMap from './ServiceMap'
import ServiceList from './ServiceList'
import ServiceDetail from './ServiceDetail'
import TraceList from './TraceList'
import TraceViewer from './TraceViewer'
import { getServiceMap, getServices, TIME_RANGES, getTimeRangeTimestamps } from '../../services/apmApi'

const TABS = [
  { id: 'map', name: 'Service Map', icon: MapIcon },
  { id: 'services', name: 'Services', icon: ListBulletIcon },
  { id: 'traces', name: 'Traces', icon: MagnifyingGlassIcon },
  { id: 'metrics', name: 'Metrics', icon: ChartBarIcon },
]

const REFRESH_INTERVALS = [
  { value: 0, label: 'Off' },
  { value: 30000, label: '30s' },
  { value: 60000, label: '1m' },
  { value: 300000, label: '5m' },
]

export default function APMDashboard() {
  const [activeTab, setActiveTab] = useState('map')
  const [timeRange, setTimeRange] = useState('1h')
  const [refreshInterval, setRefreshInterval] = useState(0)
  const [selectedService, setSelectedService] = useState(null)
  const [selectedTraceId, setSelectedTraceId] = useState(null)

  // Calculate time range timestamps
  const { start, end } = getTimeRangeTimestamps(timeRange)

  // Fetch service map data
  const {
    data: serviceMapData,
    isLoading: isLoadingMap,
    error: mapError,
    refetch: refetchMap,
  } = useQuery({
    queryKey: ['serviceMap', start, end],
    queryFn: () => getServiceMap({ start, end, format: 'cytoscape' }),
    refetchInterval: refreshInterval || false,
    staleTime: 30000,
  })

  // Fetch services list
  const {
    data: servicesData,
    isLoading: isLoadingServices,
    error: servicesError,
    refetch: refetchServices,
  } = useQuery({
    queryKey: ['services', start, end],
    queryFn: () => getServices({ start, end, limit: 100, sortBy: 'request_count', order: 'desc' }),
    refetchInterval: refreshInterval || false,
    staleTime: 30000,
    enabled: activeTab === 'services' || activeTab === 'map',
  })

  const handleRefresh = useCallback(() => {
    refetchMap()
    refetchServices()
  }, [refetchMap, refetchServices])

  const handleServiceSelect = useCallback((serviceName) => {
    setSelectedService(serviceName)
  }, [])

  const handleCloseDetail = useCallback(() => {
    setSelectedService(null)
  }, [])

  const handleTraceSelect = useCallback((traceId) => {
    setSelectedTraceId(traceId)
  }, [])

  const handleCloseTraceViewer = useCallback(() => {
    setSelectedTraceId(null)
  }, [])

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-mono-200 dark:border-mono-800 px-6 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-mono-950 dark:text-mono-50">
            APM Dashboard
          </h1>
          <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
            Application Performance Monitoring
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-4">
          {/* Time Range Selector */}
          <div className="flex items-center gap-2">
            <span className="text-sm text-mono-600 dark:text-mono-400">Time Range:</span>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-900 px-3 py-1.5 text-sm text-mono-950 dark:text-mono-50 focus:outline-none focus:ring-2 focus:ring-mono-500"
            >
              {Object.entries(TIME_RANGES).map(([key, { label }]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select>
          </div>

          {/* Auto Refresh */}
          <div className="flex items-center gap-2">
            <span className="text-sm text-mono-600 dark:text-mono-400">Refresh:</span>
            <select
              value={refreshInterval}
              onChange={(e) => setRefreshInterval(Number(e.target.value))}
              className="rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-900 px-3 py-1.5 text-sm text-mono-950 dark:text-mono-50 focus:outline-none focus:ring-2 focus:ring-mono-500"
            >
              {REFRESH_INTERVALS.map(({ value, label }) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>

          {/* Manual Refresh Button */}
          <button
            onClick={handleRefresh}
            className="flex items-center gap-2 rounded-lg bg-mono-100 dark:bg-mono-800 px-3 py-1.5 text-sm font-medium text-mono-700 dark:text-mono-300 hover:bg-mono-200 dark:hover:bg-mono-700 transition-colors"
          >
            <ArrowPathIcon className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-mono-200 dark:border-mono-800 px-6">
        <nav className="flex space-x-1">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                activeTab === tab.id
                  ? 'border-mono-950 dark:border-mono-50 text-mono-950 dark:text-mono-50'
                  : 'border-transparent text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50'
              )}
            >
              <tab.icon className="h-5 w-5" />
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden relative">
        {/* Service Map Tab */}
        {activeTab === 'map' && (
          <ServiceMap
            data={serviceMapData}
            isLoading={isLoadingMap}
            error={mapError}
            onServiceSelect={handleServiceSelect}
          />
        )}

        {/* Services List Tab */}
        {activeTab === 'services' && (
          <ServiceList
            data={servicesData}
            isLoading={isLoadingServices}
            error={servicesError}
            onServiceSelect={handleServiceSelect}
          />
        )}

        {/* Traces Tab */}
        {activeTab === 'traces' && (
          <TraceList
            start={start}
            end={end}
            onTraceSelect={handleTraceSelect}
          />
        )}

        {/* Metrics Tab - Placeholder */}
        {activeTab === 'metrics' && (
          <div className="flex items-center justify-center h-full text-mono-500">
            <div className="text-center">
              <ChartBarIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium">Metrics Explorer</p>
              <p className="text-sm mt-1">Coming soon - explore application metrics</p>
            </div>
          </div>
        )}

        {/* Service Detail Slide-out */}
        {selectedService && (
          <ServiceDetail
            serviceName={selectedService}
            start={start}
            end={end}
            onClose={handleCloseDetail}
          />
        )}

        {/* Trace Viewer Modal */}
        {selectedTraceId && (
          <TraceViewer
            traceId={selectedTraceId}
            onClose={handleCloseTraceViewer}
          />
        )}
      </div>
    </div>
  )
}
