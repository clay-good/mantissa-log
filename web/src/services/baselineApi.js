/**
 * API client for behavioral baseline endpoints.
 */

const API_BASE = '/api/v1/identity/baselines'

/**
 * Get paginated list of user baselines.
 * @param {Object} filters - Filter options
 * @param {Object} pagination - Pagination options
 * @returns {Promise<Object>} - { baselines, total, page, pageSize }
 */
export async function getBaselines(filters = {}, pagination = {}) {
  const params = new URLSearchParams()

  // Add filters
  if (filters.search) {
    params.append('search', filters.search)
  }
  if (filters.status && filters.status !== 'all') {
    params.append('status', filters.status)
  }
  if (filters.provider && filters.provider !== 'all') {
    params.append('provider', filters.provider)
  }
  if (filters.minMaturity) {
    params.append('min_maturity', filters.minMaturity)
  }
  if (filters.maxMaturity) {
    params.append('max_maturity', filters.maxMaturity)
  }

  // Add pagination
  params.append('page', pagination.page || 1)
  params.append('page_size', pagination.pageSize || 25)

  // Add sorting
  if (pagination.sortBy) {
    params.append('sort_by', pagination.sortBy)
    params.append('sort_order', pagination.sortOrder || 'desc')
  }

  const response = await fetch(`${API_BASE}?${params.toString()}`)

  if (!response.ok) {
    throw new Error(`Failed to fetch baselines: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Get detailed baseline for a specific user.
 * @param {string} userEmail - User email address
 * @returns {Promise<Object>} - Baseline detail object
 */
export async function getBaselineDetail(userEmail) {
  const encodedEmail = encodeURIComponent(userEmail)
  const response = await fetch(`${API_BASE}/${encodedEmail}`)

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Baseline not found for user: ${userEmail}`)
    }
    throw new Error(`Failed to fetch baseline: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Reset a user's baseline (start learning fresh).
 * @param {string} userEmail - User email address
 * @returns {Promise<Object>} - Updated baseline status
 */
export async function resetBaseline(userEmail) {
  const encodedEmail = encodeURIComponent(userEmail)
  const response = await fetch(`${API_BASE}/${encodedEmail}/reset`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    throw new Error(`Failed to reset baseline: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Update baseline settings for a user.
 * @param {string} userEmail - User email address
 * @param {Object} settings - Settings to update
 * @returns {Promise<Object>} - Updated baseline
 */
export async function updateBaselineSettings(userEmail, settings) {
  const encodedEmail = encodeURIComponent(userEmail)
  const response = await fetch(`${API_BASE}/${encodedEmail}/settings`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(settings),
  })

  if (!response.ok) {
    throw new Error(`Failed to update baseline settings: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Mark a user as a service account.
 * @param {string} userEmail - User email address
 * @param {boolean} isServiceAccount - Whether this is a service account
 * @returns {Promise<Object>} - Updated baseline
 */
export async function markAsServiceAccount(userEmail, isServiceAccount = true) {
  return updateBaselineSettings(userEmail, {
    is_service_account: isServiceAccount,
  })
}

/**
 * Exclude user from anomaly detection.
 * @param {string} userEmail - User email address
 * @param {boolean} exclude - Whether to exclude
 * @param {string} reason - Reason for exclusion
 * @returns {Promise<Object>} - Updated baseline
 */
export async function excludeFromAnomalyDetection(userEmail, exclude = true, reason = '') {
  return updateBaselineSettings(userEmail, {
    excluded_from_detection: exclude,
    exclusion_reason: reason,
  })
}

/**
 * Force rebuild baseline from historical data.
 * @param {string} userEmail - User email address
 * @param {number} daysBack - Number of days of history to use
 * @returns {Promise<Object>} - Rebuild job status
 */
export async function forceRebuildBaseline(userEmail, daysBack = 30) {
  const encodedEmail = encodeURIComponent(userEmail)
  const response = await fetch(`${API_BASE}/${encodedEmail}/rebuild`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ days_back: daysBack }),
  })

  if (!response.ok) {
    throw new Error(`Failed to rebuild baseline: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Get baseline statistics summary.
 * @returns {Promise<Object>} - Summary statistics
 */
export async function getBaselineStats() {
  const response = await fetch(`${API_BASE}/stats`)

  if (!response.ok) {
    throw new Error(`Failed to fetch baseline stats: ${response.statusText}`)
  }

  return response.json()
}
