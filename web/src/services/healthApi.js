import { apiClient } from './api'

export const healthApi = {
  /**
   * List all log source health statuses
   * @param {string} [statusFilter] - Optional comma-separated status filter (e.g., "SILENT,DELAYED")
   * @returns {Promise<Object>} { sources: Array, total: number }
   */
  async getSourceHealth(statusFilter) {
    const params = new URLSearchParams()
    if (statusFilter) params.append('status', statusFilter)
    const query = params.toString()
    return apiClient.get(`/health/sources${query ? `?${query}` : ''}`)
  },

  /**
   * Get detailed health information for a specific log source
   * @param {string} sourceType - Log source identifier (e.g., "okta", "cloudtrail")
   * @returns {Promise<Object>} { source_type, state, config, baseline }
   */
  async getSourceHealthDetail(sourceType) {
    return apiClient.get(`/health/sources/${sourceType}`)
  },

  /**
   * Trigger an on-demand health check for a specific source
   * @param {string} sourceType - Log source identifier
   * @returns {Promise<Object>} Health check result with old_status, new_status, etc.
   */
  async triggerHealthCheck(sourceType) {
    return apiClient.post(`/health/sources/${sourceType}/check`)
  },

  /**
   * Update the health monitoring configuration for a specific source
   * @param {string} sourceType - Log source identifier
   * @param {Object} config - Partial config overrides to apply
   * @returns {Promise<Object>} { source_type, config, message }
   */
  async updateHealthConfig(sourceType, config) {
    return apiClient.put(`/health/sources/${sourceType}/config`, config)
  },

  /**
   * Get volume history for a specific log source
   * @param {string} sourceType - Log source identifier
   * @param {string} [startTime] - Start time (ISO 8601)
   * @param {string} [endTime] - End time (ISO 8601)
   * @param {string} [granularity] - "hour" or "day" (default: "hour")
   * @returns {Promise<Object>} { source_type, history, baseline, current_state, gap_windows }
   */
  async getVolumeHistory(sourceType, startTime, endTime, granularity) {
    const params = new URLSearchParams()
    if (startTime) params.append('start_time', startTime)
    if (endTime) params.append('end_time', endTime)
    if (granularity) params.append('granularity', granularity)
    const query = params.toString()
    return apiClient.get(`/health/sources/${sourceType}/history${query ? `?${query}` : ''}`)
  },

  /**
   * Acknowledge a health alert and suppress future alerts for a duration
   * @param {string} sourceType - Log source identifier
   * @param {Object} data - { suppression_duration_seconds: number, notes: string }
   * @returns {Promise<Object>} { source_type, acknowledged_by, suppression_until, message }
   */
  async acknowledgeHealthAlert(sourceType, data) {
    return apiClient.post(`/health/sources/${sourceType}/acknowledge`, data)
  },

  /**
   * Get aggregate health summary across all sources
   * @returns {Promise<Object>} { total_sources_monitored, status_counts, longest_unhealthy, approaching_silence_threshold }
   */
  async getHealthSummary() {
    return apiClient.get('/health/summary')
  },
}
