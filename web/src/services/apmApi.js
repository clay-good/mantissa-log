/**
 * API client for APM (Application Performance Monitoring) endpoints
 */

const API_BASE = import.meta.env.VITE_API_URL || '/api'

async function fetchWithAuth(url, options = {}) {
  const response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }))
    throw new Error(error.message || `HTTP error ${response.status}`)
  }

  return response.json()
}

/**
 * Build query string from parameters
 */
function buildQueryString(params) {
  const searchParams = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      searchParams.append(key, value)
    }
  })
  const query = searchParams.toString()
  return query ? `?${query}` : ''
}

/**
 * Get service dependency map
 * @param {Object} options
 * @param {string} options.start - ISO 8601 start time
 * @param {string} options.end - ISO 8601 end time
 * @param {string} options.format - Response format ('cytoscape' or 'raw')
 */
export async function getServiceMap({ start, end, format = 'cytoscape' } = {}) {
  const query = buildQueryString({ start, end, format })
  return fetchWithAuth(`/apm/service-map${query}`)
}

/**
 * Get list of all services with metrics
 * @param {Object} options
 * @param {string} options.start - ISO 8601 start time
 * @param {string} options.end - ISO 8601 end time
 * @param {number} options.limit - Maximum number of services
 * @param {string} options.sortBy - Sort field
 * @param {string} options.order - Sort order (asc/desc)
 */
export async function getServices({ start, end, limit, sortBy, order } = {}) {
  const query = buildQueryString({
    start,
    end,
    limit,
    sort_by: sortBy,
    order,
  })
  return fetchWithAuth(`/apm/services${query}`)
}

/**
 * Get detailed information for a specific service
 * @param {string} serviceName - Name of the service
 * @param {Object} options
 * @param {string} options.start - ISO 8601 start time
 * @param {string} options.end - ISO 8601 end time
 */
export async function getServiceDetail(serviceName, { start, end } = {}) {
  const encodedName = encodeURIComponent(serviceName)
  const query = buildQueryString({ start, end })
  return fetchWithAuth(`/apm/services/${encodedName}${query}`)
}

/**
 * Get traces matching filters
 * @param {Object} filters
 * @param {string} filters.serviceName - Filter by service name
 * @param {string} filters.operationName - Filter by operation name
 * @param {string} filters.traceId - Filter by trace ID
 * @param {string} filters.status - Filter by status (ok/error)
 * @param {number} filters.minDuration - Minimum duration in ms
 * @param {string} filters.start - ISO 8601 start time
 * @param {string} filters.end - ISO 8601 end time
 * @param {number} filters.limit - Maximum number of traces
 */
export async function getTraces({
  serviceName,
  operationName,
  traceId,
  status,
  minDuration,
  start,
  end,
  limit,
} = {}) {
  const query = buildQueryString({
    service_name: serviceName,
    operation_name: operationName,
    trace_id: traceId,
    status,
    min_duration: minDuration,
    start,
    end,
    limit,
  })
  return fetchWithAuth(`/apm/traces${query}`)
}

/**
 * Get a specific trace by ID
 * @param {string} traceId - The trace ID
 */
export async function getTrace(traceId) {
  return fetchWithAuth(`/apm/traces/${traceId}`)
}

/**
 * Get APM metrics
 * @param {Object} options
 * @param {string} options.serviceName - Filter by service name
 * @param {string} options.metricName - Filter by metric name
 * @param {string} options.start - ISO 8601 start time
 * @param {string} options.end - ISO 8601 end time
 */
export async function getMetrics({ serviceName, metricName, start, end } = {}) {
  const query = buildQueryString({
    service_name: serviceName,
    metric_name: metricName,
    start,
    end,
  })
  return fetchWithAuth(`/apm/metrics${query}`)
}

/**
 * Get APM health overview
 * @param {string} timeRange - Time range (1h, 6h, 24h, 7d)
 */
export async function getAPMHealth(timeRange = '1h') {
  return fetchWithAuth(`/apm/health?time_range=${timeRange}`)
}

/**
 * Time range presets for APM queries
 */
export const TIME_RANGES = {
  '15m': { label: '15 minutes', minutes: 15 },
  '1h': { label: '1 hour', minutes: 60 },
  '6h': { label: '6 hours', minutes: 360 },
  '24h': { label: '24 hours', minutes: 1440 },
  '7d': { label: '7 days', minutes: 10080 },
}

/**
 * Convert time range preset to start/end timestamps
 * @param {string} preset - Time range preset key
 * @returns {Object} - { start, end } ISO timestamps
 */
export function getTimeRangeTimestamps(preset) {
  const config = TIME_RANGES[preset]
  if (!config) {
    throw new Error(`Invalid time range preset: ${preset}`)
  }

  const end = new Date()
  const start = new Date(end.getTime() - config.minutes * 60 * 1000)

  return {
    start: start.toISOString(),
    end: end.toISOString(),
  }
}

/**
 * Search for traces with advanced filters
 * @param {Object} filters
 * @param {string} filters.serviceName - Filter by service name
 * @param {string} filters.operationName - Filter by operation name
 * @param {string} filters.traceId - Direct trace ID lookup
 * @param {string} filters.status - Filter by status (all/ok/error)
 * @param {number} filters.minDuration - Minimum duration in ms
 * @param {number} filters.maxDuration - Maximum duration in ms
 * @param {string} filters.start - ISO 8601 start time
 * @param {string} filters.end - ISO 8601 end time
 * @param {number} filters.limit - Maximum number of results
 * @param {number} filters.offset - Pagination offset
 * @param {Object} filters.attributes - Key-value attribute filters
 */
export async function searchTraces({
  serviceName,
  operationName,
  traceId,
  status,
  minDuration,
  maxDuration,
  start,
  end,
  limit = 50,
  offset = 0,
  attributes,
} = {}) {
  // If traceId is provided, do direct lookup
  if (traceId) {
    return getTrace(traceId).then((trace) => ({
      traces: trace ? [trace] : [],
      total: trace ? 1 : 0,
    }))
  }

  const query = buildQueryString({
    service_name: serviceName,
    operation_name: operationName,
    status: status === 'all' ? undefined : status,
    min_duration: minDuration,
    max_duration: maxDuration,
    start,
    end,
    limit,
    offset,
  })

  // Add attribute filters as additional query params
  let url = `/apm/traces/search${query}`
  if (attributes && Object.keys(attributes).length > 0) {
    const attrParams = Object.entries(attributes)
      .map(([k, v]) => `attr.${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&')
    url += query ? `&${attrParams}` : `?${attrParams}`
  }

  return fetchWithAuth(url)
}

/**
 * Get list of available service names for autocomplete
 * @param {Object} options
 * @param {string} options.start - ISO 8601 start time
 * @param {string} options.end - ISO 8601 end time
 */
export async function getServiceNames({ start, end } = {}) {
  const query = buildQueryString({ start, end })
  return fetchWithAuth(`/apm/services/names${query}`)
}

/**
 * Get list of operations for a service (for autocomplete)
 * @param {string} serviceName - Service name
 * @param {Object} options
 * @param {string} options.start - ISO 8601 start time
 * @param {string} options.end - ISO 8601 end time
 */
export async function getOperationNames(serviceName, { start, end } = {}) {
  const query = buildQueryString({ start, end })
  return fetchWithAuth(`/apm/services/${encodeURIComponent(serviceName)}/operations${query}`)
}

/**
 * Build a trace tree from flat span list
 * @param {Array} spans - Array of span objects
 * @returns {Object} - Tree structure with root nodes and children
 */
export function buildTraceTree(spans) {
  if (!spans || spans.length === 0) {
    return { roots: [], orphans: [], spanMap: {} }
  }

  // Create a map of span_id -> span
  const spanMap = {}
  spans.forEach((span) => {
    spanMap[span.span_id] = {
      ...span,
      children: [],
    }
  })

  const roots = []
  const orphans = []

  // Build tree relationships
  spans.forEach((span) => {
    const node = spanMap[span.span_id]
    if (!span.parent_span_id) {
      // Root span (no parent)
      roots.push(node)
    } else if (spanMap[span.parent_span_id]) {
      // Has parent in this trace
      spanMap[span.parent_span_id].children.push(node)
    } else {
      // Parent not found (orphan span)
      orphans.push(node)
    }
  })

  // Sort children by start_time
  const sortChildren = (node) => {
    node.children.sort((a, b) => {
      const aTime = new Date(a.start_time).getTime()
      const bTime = new Date(b.start_time).getTime()
      return aTime - bTime
    })
    node.children.forEach(sortChildren)
  }

  roots.forEach(sortChildren)

  // Sort roots by start_time
  roots.sort((a, b) => {
    const aTime = new Date(a.start_time).getTime()
    const bTime = new Date(b.start_time).getTime()
    return aTime - bTime
  })

  return { roots, orphans, spanMap }
}

/**
 * Flatten trace tree for rendering (with depth info)
 * @param {Object} tree - Tree from buildTraceTree
 * @returns {Array} - Flat array with depth property
 */
export function flattenTraceTree(tree) {
  const result = []

  const traverse = (node, depth) => {
    result.push({ ...node, depth, hasChildren: node.children.length > 0 })
    node.children.forEach((child) => traverse(child, depth + 1))
  }

  tree.roots.forEach((root) => traverse(root, 0))
  tree.orphans.forEach((orphan) => {
    result.push({ ...orphan, depth: 0, hasChildren: orphan.children.length > 0, isOrphan: true })
  })

  return result
}
