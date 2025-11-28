import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../services/rulesApi'
import toast from 'react-hot-toast'

/**
 * Hook to fetch list of rules with filters
 */
export function useRules(filters = {}, page = 1, pageSize = 50, options = {}) {
  return useQuery({
    queryKey: ['rules', filters, page, pageSize],
    queryFn: () => rulesApi.listRules(filters, page, pageSize),
    ...options,
  })
}

/**
 * Hook to fetch a single rule by ID
 */
export function useRule(ruleId, options = {}) {
  return useQuery({
    queryKey: ['rule', ruleId],
    queryFn: () => rulesApi.getRule(ruleId),
    enabled: !!ruleId && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to create a new rule
 */
export function useCreateRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (rule) => rulesApi.createRule(rule),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      toast.success('Detection rule created successfully')
      return data
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to create rule')
    },
  })
}

/**
 * Hook to update an existing rule
 */
export function useUpdateRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ ruleId, updates }) => rulesApi.updateRule(ruleId, updates),
    onMutate: async ({ ruleId, updates }) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['rule', ruleId] })

      // Snapshot the previous value
      const previousRule = queryClient.getQueryData(['rule', ruleId])

      // Optimistically update
      queryClient.setQueryData(['rule', ruleId], (old) => ({
        ...old,
        ...updates,
      }))

      return { previousRule, ruleId }
    },
    onError: (error, variables, context) => {
      // Rollback on error
      if (context?.previousRule) {
        queryClient.setQueryData(['rule', context.ruleId], context.previousRule)
      }
      toast.error(error.message || 'Failed to update rule')
    },
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['rule', variables.ruleId] })
      toast.success('Rule updated successfully')
    },
  })
}

/**
 * Hook to delete a rule
 */
export function useDeleteRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (ruleId) => rulesApi.deleteRule(ruleId),
    onSuccess: (data, ruleId) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.removeQueries({ queryKey: ['rule', ruleId] })
      toast.success('Rule deleted successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to delete rule')
    },
  })
}

/**
 * Hook to toggle a rule's enabled status
 */
export function useToggleRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ ruleId, enabled }) => rulesApi.toggleRule(ruleId, enabled),
    onMutate: async ({ ruleId, enabled }) => {
      await queryClient.cancelQueries({ queryKey: ['rule', ruleId] })

      const previousRule = queryClient.getQueryData(['rule', ruleId])

      queryClient.setQueryData(['rule', ruleId], (old) => ({
        ...old,
        enabled,
      }))

      return { previousRule, ruleId }
    },
    onError: (error, variables, context) => {
      if (context?.previousRule) {
        queryClient.setQueryData(['rule', context.ruleId], context.previousRule)
      }
      toast.error(error.message || 'Failed to toggle rule')
    },
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['rule', variables.ruleId] })
      toast.success(`Rule ${variables.enabled ? 'enabled' : 'disabled'}`)
    },
  })
}

/**
 * Hook to bulk toggle rules
 */
export function useBulkToggleRules() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ ruleIds, enabled }) => rulesApi.bulkToggleRules(ruleIds, enabled),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      toast.success(
        `${variables.ruleIds.length} rules ${variables.enabled ? 'enabled' : 'disabled'}`
      )
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to update rules')
    },
  })
}

/**
 * Hook to test a rule (dry run)
 */
export function useTestRule() {
  return useMutation({
    mutationFn: (ruleId) => rulesApi.testRule(ruleId),
    onSuccess: (data) => {
      if (data.match_count > 0) {
        toast.success(`Rule matched ${data.match_count} events`)
      } else {
        toast.info('Rule did not match any events')
      }
      return data
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to test rule')
    },
  })
}

/**
 * Hook to validate a SQL query
 */
export function useValidateQuery() {
  return useMutation({
    mutationFn: (query) => rulesApi.validateQuery(query),
    onSuccess: (data) => {
      if (data.valid) {
        toast.success('Query is valid')
      } else {
        toast.error(`Invalid query: ${data.error}`)
      }
      return data
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to validate query')
    },
  })
}

/**
 * Hook to get rule execution history
 */
export function useRuleHistory(ruleId, page = 1, pageSize = 20, options = {}) {
  return useQuery({
    queryKey: ['ruleHistory', ruleId, page, pageSize],
    queryFn: () => rulesApi.getRuleHistory(ruleId, page, pageSize),
    enabled: !!ruleId && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to get alerts triggered by a rule
 */
export function useRuleAlerts(ruleId, page = 1, pageSize = 20, options = {}) {
  return useQuery({
    queryKey: ['ruleAlerts', ruleId, page, pageSize],
    queryFn: () => rulesApi.getRuleAlerts(ruleId, page, pageSize),
    enabled: !!ruleId && options.enabled !== false,
    ...options,
  })
}
