import { apiClient } from './api'

export const alertsApi = {
  /**
   * List all alerts
   * @param {Object} filters - Optional filters
   * @param {string} filters.severity - Filter by severity
   * @param {string} filters.status - Filter by status
   * @param {string} filters.ruleId - Filter by rule ID
   * @param {string} filters.startTime - Start time (ISO 8601)
   * @param {string} filters.endTime - End time (ISO 8601)
   * @param {string} filters.search - Search query
   * @param {number} page - Page number
   * @param {number} pageSize - Page size
   * @returns {Promise<Object>} Alerts list response
   */
  async listAlerts(filters = {}, page = 1, pageSize = 50) {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    })

    if (filters.severity) params.append('severity', filters.severity)
    if (filters.status) params.append('status', filters.status)
    if (filters.ruleId) params.append('rule_id', filters.ruleId)
    if (filters.startTime) params.append('start_time', filters.startTime)
    if (filters.endTime) params.append('end_time', filters.endTime)
    if (filters.search) params.append('search', filters.search)

    return apiClient.get(`/alerts?${params.toString()}`)
  },

  /**
   * Get a specific alert by ID
   * @param {string} alertId - Alert ID
   * @returns {Promise<Object>} Alert details
   */
  async getAlert(alertId) {
    return apiClient.get(`/alerts/${alertId}`)
  },

  /**
   * Acknowledge an alert
   * @param {string} alertId - Alert ID
   * @returns {Promise<Object>} Updated alert
   */
  async acknowledgeAlert(alertId) {
    return apiClient.post(`/alerts/${alertId}/acknowledge`)
  },

  /**
   * Resolve an alert
   * @param {string} alertId - Alert ID
   * @param {string} resolution - Resolution notes
   * @returns {Promise<Object>} Updated alert
   */
  async resolveAlert(alertId, resolution = '') {
    return apiClient.post(`/alerts/${alertId}/resolve`, { resolution })
  },

  /**
   * Bulk acknowledge alerts
   * @param {string[]} alertIds - Array of alert IDs
   * @returns {Promise<Object>} Bulk update result
   */
  async bulkAcknowledge(alertIds) {
    return apiClient.post('/alerts/bulk-acknowledge', { alert_ids: alertIds })
  },

  /**
   * Bulk resolve alerts
   * @param {string[]} alertIds - Array of alert IDs
   * @param {string} resolution - Resolution notes
   * @returns {Promise<Object>} Bulk update result
   */
  async bulkResolve(alertIds, resolution = '') {
    return apiClient.post('/alerts/bulk-resolve', {
      alert_ids: alertIds,
      resolution,
    })
  },

  /**
   * Get alert statistics
   * @param {string} startTime - Start time (ISO 8601)
   * @param {string} endTime - End time (ISO 8601)
   * @returns {Promise<Object>} Alert statistics
   */
  async getAlertStats(startTime, endTime) {
    const params = new URLSearchParams()
    if (startTime) params.append('start_time', startTime)
    if (endTime) params.append('end_time', endTime)

    return apiClient.get(`/alerts/stats?${params.toString()}`)
  },

  /**
   * Get alert timeline data
   * @param {string} startTime - Start time (ISO 8601)
   * @param {string} endTime - End time (ISO 8601)
   * @param {string} interval - Time interval (1h, 1d, etc.)
   * @returns {Promise<Object>} Timeline data
   */
  async getAlertTimeline(startTime, endTime, interval = '1h') {
    const params = new URLSearchParams({
      interval,
    })
    if (startTime) params.append('start_time', startTime)
    if (endTime) params.append('end_time', endTime)

    return apiClient.get(`/alerts/timeline?${params.toString()}`)
  },

  /**
   * Get related alerts for a specific alert
   * @param {string} alertId - Alert ID
   * @returns {Promise<Object>} Related alerts
   */
  async getRelatedAlerts(alertId) {
    return apiClient.get(`/alerts/${alertId}/related`)
  },
}
