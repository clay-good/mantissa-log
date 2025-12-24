import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { soarApi } from '../services/soarApi'
import toast from 'react-hot-toast'

// ============================================
// Quick Actions
// ============================================

/**
 * Hook to execute a quick action on an alert
 */
export function useQuickAction() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ actionType, alertId, parameters }) =>
      soarApi.executeQuickAction(actionType, alertId, parameters),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['alert', variables.alertId] })
      queryClient.invalidateQueries({ queryKey: ['executions'] })
      toast.success(`Action "${variables.actionType}" started`)
    },
    onError: (error, variables) => {
      toast.error(error.message || `Failed to execute ${variables.actionType}`)
    },
  })
}

/**
 * Hook to get available quick actions for an alert
 */
export function useAvailableActions(alertId, options = {}) {
  return useQuery({
    queryKey: ['availableActions', alertId],
    queryFn: () => soarApi.getAvailableActions(alertId),
    enabled: !!alertId && options.enabled !== false,
    staleTime: 60000, // Actions don't change frequently
    ...options,
  })
}

// ============================================
// Playbook Management
// ============================================

/**
 * Hook to list playbooks with filters
 */
export function usePlaybooks(filters = {}, page = 1, pageSize = 50, options = {}) {
  return useQuery({
    queryKey: ['playbooks', filters, page, pageSize],
    queryFn: () => soarApi.listPlaybooks(filters, page, pageSize),
    ...options,
  })
}

/**
 * Hook to get a single playbook
 */
export function usePlaybook(playbookId, options = {}) {
  return useQuery({
    queryKey: ['playbook', playbookId],
    queryFn: () => soarApi.getPlaybook(playbookId),
    enabled: !!playbookId && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to get playbooks matching an alert's conditions
 */
export function useMatchingPlaybooks(alertId, options = {}) {
  return useQuery({
    queryKey: ['matchingPlaybooks', alertId],
    queryFn: () => soarApi.getMatchingPlaybooks(alertId),
    enabled: !!alertId && options.enabled !== false,
    staleTime: 30000,
    ...options,
  })
}

/**
 * Hook to create a new playbook
 */
export function useCreatePlaybook() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (playbookData) => soarApi.createPlaybook(playbookData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['playbooks'] })
      toast.success('Playbook created successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to create playbook')
    },
  })
}

/**
 * Hook to update a playbook
 */
export function useUpdatePlaybook() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ playbookId, updates }) => soarApi.updatePlaybook(playbookId, updates),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['playbooks'] })
      queryClient.invalidateQueries({ queryKey: ['playbook', variables.playbookId] })
      toast.success('Playbook updated successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to update playbook')
    },
  })
}

/**
 * Hook to delete a playbook
 */
export function useDeletePlaybook() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (playbookId) => soarApi.deletePlaybook(playbookId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['playbooks'] })
      toast.success('Playbook deleted')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to delete playbook')
    },
  })
}

/**
 * Hook to generate a playbook from description
 */
export function useGeneratePlaybook() {
  return useMutation({
    mutationFn: ({ description, name }) => soarApi.generatePlaybook(description, name),
    onSuccess: () => {
      toast.success('Playbook generated. Please review before saving.')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to generate playbook')
    },
  })
}

/**
 * Hook to parse IR plan into playbook
 */
export function useParseIRPlan() {
  return useMutation({
    mutationFn: ({ planText, planName, format }) =>
      soarApi.parseIRPlan(planText, planName, format),
    onSuccess: () => {
      toast.success('IR plan parsed successfully. Please review before saving.')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to parse IR plan')
    },
  })
}

/**
 * Hook to get playbook code
 */
export function usePlaybookCode(playbookId, options = {}) {
  return useQuery({
    queryKey: ['playbookCode', playbookId],
    queryFn: () => soarApi.getPlaybookCode(playbookId),
    enabled: !!playbookId && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to deploy a playbook
 */
export function useDeployPlaybook() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (playbookId) => soarApi.deployPlaybook(playbookId),
    onSuccess: (data, playbookId) => {
      queryClient.invalidateQueries({ queryKey: ['playbook', playbookId] })
      toast.success('Playbook deployed successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to deploy playbook')
    },
  })
}

/**
 * Hook to list playbook versions
 */
export function usePlaybookVersions(playbookId, options = {}) {
  return useQuery({
    queryKey: ['playbookVersions', playbookId],
    queryFn: () => soarApi.listPlaybookVersions(playbookId),
    enabled: !!playbookId && options.enabled !== false,
    ...options,
  })
}

// ============================================
// Playbook Execution
// ============================================

/**
 * Hook to execute a playbook
 */
export function useExecutePlaybook() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ playbookId, alertId, dryRun, parameters }) =>
      soarApi.executePlaybook(playbookId, alertId, dryRun, parameters),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['executions'] })
      if (variables.alertId) {
        queryClient.invalidateQueries({ queryKey: ['alert', variables.alertId] })
      }
      const message = variables.dryRun
        ? 'Dry run completed'
        : 'Playbook execution started'
      toast.success(message)
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to execute playbook')
    },
  })
}

/**
 * Hook to list executions
 */
export function useExecutions(filters = {}, page = 1, pageSize = 50, options = {}) {
  return useQuery({
    queryKey: ['executions', filters, page, pageSize],
    queryFn: () => soarApi.listExecutions(filters, page, pageSize),
    refetchInterval: options.polling ? 10000 : false,
    ...options,
  })
}

/**
 * Hook to get execution details with polling for active executions
 */
export function useExecution(executionId, options = {}) {
  return useQuery({
    queryKey: ['execution', executionId],
    queryFn: () => soarApi.getExecution(executionId),
    enabled: !!executionId && options.enabled !== false,
    refetchInterval: (query) => {
      // Poll every 2 seconds if execution is still running
      const data = query.state.data
      if (data?.execution?.is_complete === false) {
        return 2000
      }
      return false
    },
    ...options,
  })
}

/**
 * Hook to get execution logs
 */
export function useExecutionLogs(executionId, limit = 100, options = {}) {
  return useQuery({
    queryKey: ['executionLogs', executionId, limit],
    queryFn: () => soarApi.getExecutionLogs(executionId, limit),
    enabled: !!executionId && options.enabled !== false,
    refetchInterval: (query) => {
      // Poll if parent execution is still running
      if (options.isRunning) {
        return 3000
      }
      return false
    },
    ...options,
  })
}

/**
 * Hook to cancel an execution
 */
export function useCancelExecution() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ executionId, reason }) => soarApi.cancelExecution(executionId, reason),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['execution', variables.executionId] })
      queryClient.invalidateQueries({ queryKey: ['executions'] })
      toast.success('Execution cancelled')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to cancel execution')
    },
  })
}

// ============================================
// Approval Workflow
// ============================================

/**
 * Hook to list pending approvals
 */
export function usePendingApprovals(limit = 50, options = {}) {
  return useQuery({
    queryKey: ['pendingApprovals', limit],
    queryFn: () => soarApi.listPendingApprovals(limit),
    refetchInterval: options.polling ? 30000 : false,
    ...options,
  })
}

/**
 * Hook to get approval details
 */
export function useApproval(approvalId, options = {}) {
  return useQuery({
    queryKey: ['approval', approvalId],
    queryFn: () => soarApi.getApproval(approvalId),
    enabled: !!approvalId && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to approve an action
 */
export function useApproveAction() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ approvalId, notes }) => soarApi.approveAction(approvalId, notes),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['pendingApprovals'] })
      queryClient.invalidateQueries({ queryKey: ['approval', variables.approvalId] })
      queryClient.invalidateQueries({ queryKey: ['executions'] })
      if (data.execution_id) {
        queryClient.invalidateQueries({ queryKey: ['execution', data.execution_id] })
      }
      toast.success('Action approved')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to approve action')
    },
  })
}

/**
 * Hook to deny an action
 */
export function useDenyAction() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ approvalId, reason }) => soarApi.denyAction(approvalId, reason),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['pendingApprovals'] })
      queryClient.invalidateQueries({ queryKey: ['approval', variables.approvalId] })
      queryClient.invalidateQueries({ queryKey: ['executions'] })
      if (data.execution_id) {
        queryClient.invalidateQueries({ queryKey: ['execution', data.execution_id] })
      }
      toast.success('Action denied')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to deny action')
    },
  })
}

// ============================================
// Combined Hooks for Common Workflows
// ============================================

/**
 * Hook for the complete quick action workflow with confirmation
 * Returns state and handlers for the action flow
 */
export function useQuickActionWorkflow(alertId) {
  const quickAction = useQuickAction()
  const { data: availableActions, isLoading: actionsLoading } = useAvailableActions(alertId)

  return {
    availableActions: availableActions?.actions || [],
    actionsLoading,
    executeAction: quickAction.mutate,
    isExecuting: quickAction.isPending,
    executionResult: quickAction.data,
    executionError: quickAction.error,
    reset: quickAction.reset,
  }
}

/**
 * Hook for playbook execution workflow with progress tracking
 */
export function usePlaybookExecutionWorkflow(alertId) {
  const executePlaybook = useExecutePlaybook()
  const { data: matchingPlaybooks, isLoading: playbooksLoading } = useMatchingPlaybooks(alertId)

  // Track the current execution
  const executionId = executePlaybook.data?.execution_id
  const { data: executionData } = useExecution(executionId, {
    enabled: !!executionId,
  })

  return {
    matchingPlaybooks: matchingPlaybooks?.playbooks || [],
    playbooksLoading,
    execute: executePlaybook.mutate,
    isExecuting: executePlaybook.isPending,
    executionId,
    execution: executionData?.execution,
    isComplete: executionData?.execution?.is_complete,
    reset: executePlaybook.reset,
  }
}
