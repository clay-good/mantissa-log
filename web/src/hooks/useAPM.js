import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as apmApi from '../services/apmApi'

// ============================================
// Service Map
// ============================================

/**
 * Hook to fetch the service dependency map
 * @param {Object} options
 * @param {string} options.timeRange - Time range preset (1h, 6h, 24h, 7d)
 * @param {string} options.start - Custom start time (ISO 8601)
 * @param {string} options.end - Custom end time (ISO 8601)
 * @param {string} options.format - Response format ('cytoscape' or 'raw')
 */
export function useServiceMap({ timeRange = '1h', start, end, format = 'cytoscape' } = {}, options = {}) {
  // Use custom times or derive from preset
  const times = start && end
    ? { start, end }
    : apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['serviceMap', times.start, times.end, format],
    queryFn: () => apmApi.getServiceMap({ ...times, format }),
    staleTime: 30000, // Service map is relatively stable
    refetchInterval: options.autoRefresh ? 60000 : false,
    ...options,
  })
}

// ============================================
// Services List
// ============================================

/**
 * Hook to fetch list of services with metrics
 * @param {Object} options
 * @param {string} options.timeRange - Time range preset
 * @param {string} options.start - Custom start time
 * @param {string} options.end - Custom end time
 * @param {number} options.limit - Maximum services to return
 * @param {string} options.sortBy - Sort field
 * @param {string} options.order - Sort order (asc/desc)
 */
export function useServices({ timeRange = '1h', start, end, limit, sortBy, order } = {}, options = {}) {
  const times = start && end
    ? { start, end }
    : apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['services', times.start, times.end, limit, sortBy, order],
    queryFn: () => apmApi.getServices({ ...times, limit, sortBy, order }),
    staleTime: 30000,
    ...options,
  })
}

/**
 * Hook to fetch list of service names for autocomplete
 * @param {Object} options
 * @param {string} options.timeRange - Time range preset
 */
export function useServiceNames({ timeRange = '24h' } = {}, options = {}) {
  const times = apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['serviceNames', times.start, times.end],
    queryFn: () => apmApi.getServiceNames(times),
    staleTime: 300000, // Service names don't change frequently
    ...options,
  })
}

// ============================================
// Service Detail
// ============================================

/**
 * Hook to fetch details for a specific service
 * @param {string} serviceName - Name of the service
 * @param {Object} options
 * @param {string} options.timeRange - Time range preset
 * @param {string} options.start - Custom start time
 * @param {string} options.end - Custom end time
 */
export function useServiceDetail(serviceName, { timeRange = '1h', start, end } = {}, options = {}) {
  const times = start && end
    ? { start, end }
    : apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['serviceDetail', serviceName, times.start, times.end],
    queryFn: () => apmApi.getServiceDetail(serviceName, times),
    enabled: !!serviceName && options.enabled !== false,
    staleTime: 30000,
    ...options,
  })
}

/**
 * Hook to fetch operations for a service (autocomplete)
 * @param {string} serviceName - Name of the service
 * @param {Object} options
 * @param {string} options.timeRange - Time range preset
 */
export function useServiceOperations(serviceName, { timeRange = '24h' } = {}, options = {}) {
  const times = apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['serviceOperations', serviceName, times.start, times.end],
    queryFn: () => apmApi.getOperationNames(serviceName, times),
    enabled: !!serviceName && options.enabled !== false,
    staleTime: 300000,
    ...options,
  })
}

// ============================================
// Traces
// ============================================

/**
 * Hook to search for traces with filters
 * @param {Object} filters
 * @param {string} filters.serviceName - Filter by service name
 * @param {string} filters.operationName - Filter by operation
 * @param {string} filters.traceId - Direct trace lookup
 * @param {string} filters.status - Filter by status (all/ok/error)
 * @param {number} filters.minDuration - Minimum duration in ms
 * @param {number} filters.maxDuration - Maximum duration in ms
 * @param {string} filters.timeRange - Time range preset
 * @param {number} filters.limit - Max results
 * @param {number} filters.offset - Pagination offset
 * @param {Object} filters.attributes - Attribute filters
 */
export function useTraceSearch(filters = {}, options = {}) {
  const {
    serviceName,
    operationName,
    traceId,
    status,
    minDuration,
    maxDuration,
    timeRange = '1h',
    start,
    end,
    limit = 50,
    offset = 0,
    attributes,
  } = filters

  const times = start && end
    ? { start, end }
    : apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: [
      'traceSearch',
      serviceName,
      operationName,
      traceId,
      status,
      minDuration,
      maxDuration,
      times.start,
      times.end,
      limit,
      offset,
      JSON.stringify(attributes),
    ],
    queryFn: () => apmApi.searchTraces({
      serviceName,
      operationName,
      traceId,
      status,
      minDuration,
      maxDuration,
      ...times,
      limit,
      offset,
      attributes,
    }),
    staleTime: 15000,
    ...options,
  })
}

/**
 * Hook to fetch traces (simple version without advanced filters)
 * @param {Object} filters - Basic trace filters
 * @param {Object} options - Query options
 */
export function useTraces(filters = {}, options = {}) {
  const { timeRange = '1h', ...restFilters } = filters
  const times = apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['traces', times.start, times.end, restFilters],
    queryFn: () => apmApi.getTraces({ ...times, ...restFilters }),
    staleTime: 15000,
    ...options,
  })
}

/**
 * Hook to fetch a single trace by ID
 * @param {string} traceId - The trace ID
 */
export function useTrace(traceId, options = {}) {
  return useQuery({
    queryKey: ['trace', traceId],
    queryFn: () => apmApi.getTrace(traceId),
    enabled: !!traceId && options.enabled !== false,
    staleTime: 60000, // Traces are immutable
    ...options,
  })
}

/**
 * Hook to get trace tree structure from a trace
 * Combines trace fetching with tree building
 * @param {string} traceId - The trace ID
 */
export function useTraceTree(traceId, options = {}) {
  const traceQuery = useTrace(traceId, options)

  // Build tree when data is available
  const tree = traceQuery.data?.spans
    ? apmApi.buildTraceTree(traceQuery.data.spans)
    : null

  const flatSpans = tree
    ? apmApi.flattenTraceTree(tree)
    : []

  return {
    ...traceQuery,
    tree,
    flatSpans,
  }
}

// ============================================
// Metrics
// ============================================

/**
 * Hook to fetch APM metrics
 * @param {Object} filters
 * @param {string} filters.serviceName - Filter by service
 * @param {string} filters.metricName - Filter by metric name
 * @param {string} filters.timeRange - Time range preset
 */
export function useMetrics(filters = {}, options = {}) {
  const { serviceName, metricName, timeRange = '1h', start, end } = filters

  const times = start && end
    ? { start, end }
    : apmApi.getTimeRangeTimestamps(timeRange)

  return useQuery({
    queryKey: ['apmMetrics', serviceName, metricName, times.start, times.end],
    queryFn: () => apmApi.getMetrics({ serviceName, metricName, ...times }),
    staleTime: 30000,
    ...options,
  })
}

// ============================================
// Health Overview
// ============================================

/**
 * Hook to fetch APM health overview
 * @param {string} timeRange - Time range preset
 */
export function useAPMHealth(timeRange = '1h', options = {}) {
  return useQuery({
    queryKey: ['apmHealth', timeRange],
    queryFn: () => apmApi.getAPMHealth(timeRange),
    staleTime: 30000,
    refetchInterval: options.autoRefresh ? 30000 : false,
    ...options,
  })
}

// ============================================
// Combined/Workflow Hooks
// ============================================

/**
 * Hook for the complete APM dashboard state
 * Combines service map, services list, and health
 * @param {Object} options
 * @param {string} options.timeRange - Time range for all queries
 * @param {boolean} options.autoRefresh - Enable auto-refresh
 */
export function useAPMDashboard({ timeRange = '1h', autoRefresh = false } = {}) {
  const serviceMapQuery = useServiceMap({ timeRange }, { autoRefresh })
  const servicesQuery = useServices({ timeRange }, { autoRefresh })
  const healthQuery = useAPMHealth(timeRange, { autoRefresh })

  return {
    serviceMap: serviceMapQuery.data,
    serviceMapLoading: serviceMapQuery.isLoading,
    serviceMapError: serviceMapQuery.error,

    services: servicesQuery.data?.services || [],
    servicesLoading: servicesQuery.isLoading,
    servicesError: servicesQuery.error,

    health: healthQuery.data,
    healthLoading: healthQuery.isLoading,
    healthError: healthQuery.error,

    isLoading: serviceMapQuery.isLoading || servicesQuery.isLoading || healthQuery.isLoading,
    isError: serviceMapQuery.isError || servicesQuery.isError || healthQuery.isError,

    refetch: () => {
      serviceMapQuery.refetch()
      servicesQuery.refetch()
      healthQuery.refetch()
    },
  }
}

/**
 * Hook for service investigation workflow
 * Fetches service detail, operations, and recent traces
 * @param {string} serviceName - Service to investigate
 * @param {Object} options
 * @param {string} options.timeRange - Time range
 */
export function useServiceInvestigation(serviceName, { timeRange = '1h' } = {}) {
  const detailQuery = useServiceDetail(serviceName, { timeRange })
  const operationsQuery = useServiceOperations(serviceName, { timeRange })
  const tracesQuery = useTraceSearch({
    serviceName,
    timeRange,
    limit: 20,
    status: 'error',
  }, {
    enabled: !!serviceName,
  })

  return {
    service: detailQuery.data,
    serviceLoading: detailQuery.isLoading,
    serviceError: detailQuery.error,

    operations: operationsQuery.data?.operations || [],
    operationsLoading: operationsQuery.isLoading,

    errorTraces: tracesQuery.data?.traces || [],
    errorTracesLoading: tracesQuery.isLoading,

    isLoading: detailQuery.isLoading,
    refetch: () => {
      detailQuery.refetch()
      operationsQuery.refetch()
      tracesQuery.refetch()
    },
  }
}

/**
 * Hook for trace investigation workflow
 * Fetches trace with tree structure and related data
 * @param {string} traceId - Trace to investigate
 */
export function useTraceInvestigation(traceId) {
  const traceTreeQuery = useTraceTree(traceId)

  // Get the root service from the trace
  const rootService = traceTreeQuery.tree?.roots?.[0]?.service_name

  // Fetch service detail if we have a root service
  const serviceQuery = useServiceDetail(rootService, {}, {
    enabled: !!rootService,
  })

  return {
    trace: traceTreeQuery.data,
    tree: traceTreeQuery.tree,
    flatSpans: traceTreeQuery.flatSpans,
    traceLoading: traceTreeQuery.isLoading,
    traceError: traceTreeQuery.error,

    rootService,
    serviceDetail: serviceQuery.data,
    serviceLoading: serviceQuery.isLoading,

    isLoading: traceTreeQuery.isLoading,
    refetch: traceTreeQuery.refetch,
  }
}

// ============================================
// Utility Exports
// ============================================

export { TIME_RANGES, getTimeRangeTimestamps, buildTraceTree, flattenTraceTree } from '../services/apmApi'
