/**
 * SOAR API Service
 *
 * Provides API methods for SOAR operations including:
 * - Playbook management (CRUD)
 * - Playbook execution
 * - Approval workflow
 * - Quick actions on alerts
 */

import { apiClient } from './api'

export const soarApi = {
  // ============================================
  // Playbook Management
  // ============================================

  /**
   * List playbooks with optional filters
   */
  async listPlaybooks(filters = {}, page = 1, pageSize = 50) {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    })

    if (filters.enabled !== undefined) {
      params.append('enabled', filters.enabled.toString())
    }
    if (filters.trigger_type) {
      params.append('trigger_type', filters.trigger_type)
    }
    if (filters.tags?.length) {
      params.append('tags', filters.tags.join(','))
    }
    if (filters.search) {
      params.append('search', filters.search)
    }

    return apiClient.get(`/playbooks?${params.toString()}`)
  },

  /**
   * Get a single playbook by ID
   */
  async getPlaybook(playbookId) {
    return apiClient.get(`/playbooks/${playbookId}`)
  },

  /**
   * Create a new playbook
   */
  async createPlaybook(playbookData) {
    return apiClient.post('/playbooks', playbookData)
  },

  /**
   * Update an existing playbook
   */
  async updatePlaybook(playbookId, updates) {
    return apiClient.put(`/playbooks/${playbookId}`, updates)
  },

  /**
   * Delete (archive) a playbook
   */
  async deletePlaybook(playbookId) {
    return apiClient.delete(`/playbooks/${playbookId}`)
  },

  /**
   * List all versions of a playbook
   */
  async listPlaybookVersions(playbookId) {
    return apiClient.get(`/playbooks/${playbookId}/versions`)
  },

  /**
   * Get a specific version of a playbook
   */
  async getPlaybookVersion(playbookId, version) {
    return apiClient.get(`/playbooks/${playbookId}/versions/${version}`)
  },

  /**
   * Get generated Lambda code for a playbook
   */
  async getPlaybookCode(playbookId) {
    return apiClient.get(`/playbooks/${playbookId}/code`)
  },

  /**
   * Deploy a playbook as Lambda
   */
  async deployPlaybook(playbookId) {
    return apiClient.post(`/playbooks/${playbookId}/deploy`, {})
  },

  /**
   * Generate playbook from natural language description
   */
  async generatePlaybook(description, name = null) {
    return apiClient.post('/playbooks/generate', { description, name })
  },

  /**
   * Parse IR plan text into a playbook
   */
  async parseIRPlan(planText, planName = null, format = 'markdown') {
    return apiClient.post('/playbooks/parse-ir-plan', {
      plan_text: planText,
      name: planName,
      format,
    })
  },

  /**
   * Get playbooks matching an alert's trigger conditions
   */
  async getMatchingPlaybooks(alertId) {
    return apiClient.get(`/playbooks?alert_id=${alertId}&enabled=true`)
  },

  // ============================================
  // Playbook Execution
  // ============================================

  /**
   * Execute a playbook
   */
  async executePlaybook(playbookId, alertId = null, dryRun = false, parameters = {}) {
    return apiClient.post('/executions', {
      playbook_id: playbookId,
      trigger_type: alertId ? 'alert' : 'manual',
      alert_id: alertId,
      parameters,
      dry_run: dryRun,
    })
  },

  /**
   * Get execution details
   */
  async getExecution(executionId) {
    return apiClient.get(`/executions/${executionId}`)
  },

  /**
   * List executions with filters
   */
  async listExecutions(filters = {}, page = 1, pageSize = 50) {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    })

    if (filters.playbook_id) {
      params.append('playbook_id', filters.playbook_id)
    }
    if (filters.status) {
      params.append('status', filters.status)
    }

    return apiClient.get(`/executions?${params.toString()}`)
  },

  /**
   * Get action logs for an execution
   */
  async getExecutionLogs(executionId, limit = 100) {
    return apiClient.get(`/executions/${executionId}/logs?limit=${limit}`)
  },

  /**
   * Cancel a running execution
   */
  async cancelExecution(executionId, reason = '') {
    return apiClient.post(`/executions/${executionId}/cancel`, { reason })
  },

  // ============================================
  // Approval Workflow
  // ============================================

  /**
   * List pending approvals for current user
   */
  async listPendingApprovals(limit = 50) {
    return apiClient.get(`/approvals?limit=${limit}`)
  },

  /**
   * Get approval request details
   */
  async getApproval(approvalId) {
    return apiClient.get(`/approvals/${approvalId}`)
  },

  /**
   * Approve an action
   */
  async approveAction(approvalId, notes = '') {
    return apiClient.post(`/approvals/${approvalId}/approve`, { notes })
  },

  /**
   * Deny an action
   */
  async denyAction(approvalId, reason) {
    return apiClient.post(`/approvals/${approvalId}/deny`, { notes: reason })
  },

  // ============================================
  // Quick Actions
  // ============================================

  /**
   * Execute a quick action on an alert
   */
  async executeQuickAction(actionType, alertId, parameters = {}) {
    return apiClient.post('/quick-actions', {
      action_type: actionType,
      alert_id: alertId,
      parameters,
    })
  },

  /**
   * Get available quick actions for an alert
   */
  async getAvailableActions(alertId) {
    return apiClient.get(`/quick-actions/available?alert_id=${alertId}`)
  },
}

export default soarApi
