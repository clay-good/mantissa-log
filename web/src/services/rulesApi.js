import { apiClient } from './api'

export const rulesApi = {
  /**
   * List all detection rules
   * @param {Object} filters - Optional filters
   * @param {string} filters.category - Filter by category
   * @param {string} filters.severity - Filter by severity
   * @param {boolean} filters.enabled - Filter by enabled status
   * @param {string} filters.search - Search query
   * @param {number} page - Page number
   * @param {number} pageSize - Page size
   * @returns {Promise<Object>} Rules list response
   */
  async listRules(filters = {}, page = 1, pageSize = 50) {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    })

    if (filters.category) params.append('category', filters.category)
    if (filters.severity) params.append('severity', filters.severity)
    if (filters.enabled !== undefined) params.append('enabled', filters.enabled.toString())
    if (filters.search) params.append('search', filters.search)

    return apiClient.get(`/rules?${params.toString()}`)
  },

  /**
   * Get a specific rule by ID
   * @param {string} ruleId - Rule ID
   * @returns {Promise<Object>} Rule details
   */
  async getRule(ruleId) {
    return apiClient.get(`/rules/${ruleId}`)
  },

  /**
   * Create a new detection rule
   * @param {Object} rule - Rule data
   * @returns {Promise<Object>} Created rule
   */
  async createRule(rule) {
    return apiClient.post('/rules', rule)
  },

  /**
   * Update an existing rule
   * @param {string} ruleId - Rule ID
   * @param {Object} updates - Rule updates
   * @returns {Promise<Object>} Updated rule
   */
  async updateRule(ruleId, updates) {
    return apiClient.put(`/rules/${ruleId}`, updates)
  },

  /**
   * Delete a rule
   * @param {string} ruleId - Rule ID
   * @returns {Promise<Object>} Delete confirmation
   */
  async deleteRule(ruleId) {
    return apiClient.delete(`/rules/${ruleId}`)
  },

  /**
   * Enable or disable a rule
   * @param {string} ruleId - Rule ID
   * @param {boolean} enabled - Enabled status
   * @returns {Promise<Object>} Updated rule
   */
  async toggleRule(ruleId, enabled) {
    return apiClient.put(`/rules/${ruleId}`, { enabled })
  },

  /**
   * Bulk enable/disable rules
   * @param {string[]} ruleIds - Array of rule IDs
   * @param {boolean} enabled - Enabled status
   * @returns {Promise<Object>} Bulk update result
   */
  async bulkToggleRules(ruleIds, enabled) {
    return apiClient.post('/rules/bulk-update', {
      rule_ids: ruleIds,
      enabled,
    })
  },

  /**
   * Test a rule (dry run)
   * @param {string} ruleId - Rule ID
   * @returns {Promise<Object>} Test results
   */
  async testRule(ruleId) {
    return apiClient.post(`/rules/${ruleId}/test`)
  },

  /**
   * Validate a rule's SQL query
   * @param {string} query - SQL query
   * @returns {Promise<Object>} Validation result
   */
  async validateQuery(query) {
    return apiClient.post('/rules/validate', { query })
  },

  /**
   * Get rule execution history
   * @param {string} ruleId - Rule ID
   * @param {number} page - Page number
   * @param {number} pageSize - Page size
   * @returns {Promise<Object>} Execution history
   */
  async getRuleHistory(ruleId, page = 1, pageSize = 20) {
    return apiClient.get(`/rules/${ruleId}/history?page=${page}&page_size=${pageSize}`)
  },

  /**
   * Get rules that have triggered alerts
   * @param {string} ruleId - Rule ID
   * @param {number} page - Page number
   * @param {number} pageSize - Page size
   * @returns {Promise<Object>} Alert history
   */
  async getRuleAlerts(ruleId, page = 1, pageSize = 20) {
    return apiClient.get(`/rules/${ruleId}/alerts?page=${page}&page_size=${pageSize}`)
  },
}
