/**
 * API client for identity threat detection endpoints
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
 * Get list of high-risk users (risk score > 65)
 */
export async function getHighRiskUsers(threshold = 65) {
  return fetchWithAuth(`/identity/users/high-risk?threshold=${threshold}`)
}

/**
 * Get active identity incidents
 */
export async function getActiveIncidents(filters = {}) {
  const params = new URLSearchParams()

  if (filters.severity && filters.severity !== 'all') {
    params.append('severity', filters.severity)
  }
  if (filters.provider && filters.provider !== 'all') {
    params.append('provider', filters.provider)
  }
  if (filters.attackType && filters.attackType !== 'all') {
    params.append('attack_type', filters.attackType)
  }
  if (filters.timeRange) {
    params.append('time_range', filters.timeRange)
  }

  const query = params.toString()
  return fetchWithAuth(`/identity/incidents/active${query ? `?${query}` : ''}`)
}

/**
 * Get identity metrics for dashboard
 */
export async function getIdentityMetrics(timeRange = '24h') {
  return fetchWithAuth(`/identity/metrics?time_range=${timeRange}`)
}

/**
 * Get detailed information about a specific incident
 */
export async function getIncidentDetails(incidentId) {
  return fetchWithAuth(`/identity/incidents/${incidentId}`)
}

/**
 * Acknowledge an identity incident
 */
export async function acknowledgeIncident(incidentId) {
  return fetchWithAuth(`/identity/incidents/${incidentId}/acknowledge`, {
    method: 'POST',
  })
}

/**
 * Dismiss an identity incident
 */
export async function dismissIncident(incidentId, reason = '') {
  return fetchWithAuth(`/identity/incidents/${incidentId}/dismiss`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })
}

/**
 * Escalate an identity incident
 */
export async function escalateIncident(incidentId, notes = '') {
  return fetchWithAuth(`/identity/incidents/${incidentId}/escalate`, {
    method: 'POST',
    body: JSON.stringify({ notes }),
  })
}

/**
 * Get user risk profile
 */
export async function getUserRiskProfile(userEmail) {
  return fetchWithAuth(`/identity/users/${encodeURIComponent(userEmail)}/risk-profile`)
}

/**
 * Get user activity timeline
 */
export async function getUserTimeline(userEmail, timeRange = '7d') {
  return fetchWithAuth(
    `/identity/users/${encodeURIComponent(userEmail)}/timeline?time_range=${timeRange}`
  )
}

/**
 * Get user baseline comparison
 */
export async function getUserBaselineComparison(userEmail) {
  return fetchWithAuth(`/identity/users/${encodeURIComponent(userEmail)}/baseline-comparison`)
}

/**
 * Get user's related alerts
 */
export async function getUserAlerts(userEmail, limit = 20) {
  return fetchWithAuth(
    `/identity/users/${encodeURIComponent(userEmail)}/alerts?limit=${limit}`
  )
}

/**
 * Execute response action on a user
 */
export async function executeResponseAction(userEmail, action, options = {}) {
  return fetchWithAuth(`/identity/users/${encodeURIComponent(userEmail)}/actions/${action}`, {
    method: 'POST',
    body: JSON.stringify(options),
  })
}

/**
 * Get attack map data (geographic distribution of attacks)
 */
export async function getAttackMapData(timeRange = '24h') {
  return fetchWithAuth(`/identity/attacks/map?time_range=${timeRange}`)
}

/**
 * Get attack timeline for visualization
 */
export async function getAttackTimeline(timeRange = '24h') {
  return fetchWithAuth(`/identity/attacks/timeline?time_range=${timeRange}`)
}

/**
 * Get provider-specific metrics
 */
export async function getProviderMetrics(provider) {
  return fetchWithAuth(`/identity/providers/${provider}/metrics`)
}

/**
 * Get kill chain analysis for an incident
 */
export async function getKillChainAnalysis(incidentId) {
  return fetchWithAuth(`/identity/incidents/${incidentId}/kill-chain`)
}

/**
 * Get peer comparison for a user
 */
export async function getUserPeerComparison(userEmail) {
  return fetchWithAuth(`/identity/users/${encodeURIComponent(userEmail)}/peer-comparison`)
}
