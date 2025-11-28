import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi } from '../services/alertsApi'
import toast from 'react-hot-toast'

/**
 * Hook to fetch list of alerts with filters
 */
export function useAlerts(filters = {}, page = 1, pageSize = 50, options = {}) {
  return useQuery({
    queryKey: ['alerts', filters, page, pageSize],
    queryFn: () => alertsApi.listAlerts(filters, page, pageSize),
    refetchInterval: options.polling ? 30000 : false, // Poll every 30 seconds if enabled
    ...options,
  })
}

/**
 * Hook to fetch a single alert by ID
 */
export function useAlert(alertId, options = {}) {
  return useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => alertsApi.getAlert(alertId),
    enabled: !!alertId && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to acknowledge an alert
 */
export function useAcknowledgeAlert() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (alertId) => alertsApi.acknowledgeAlert(alertId),
    onMutate: async (alertId) => {
      await queryClient.cancelQueries({ queryKey: ['alert', alertId] })

      const previousAlert = queryClient.getQueryData(['alert', alertId])

      queryClient.setQueryData(['alert', alertId], (old) => ({
        ...old,
        status: 'acknowledged',
        acknowledged_at: new Date().toISOString(),
      }))

      return { previousAlert, alertId }
    },
    onError: (error, variables, context) => {
      if (context?.previousAlert) {
        queryClient.setQueryData(['alert', context.alertId], context.previousAlert)
      }
      toast.error(error.message || 'Failed to acknowledge alert')
    },
    onSuccess: (data, alertId) => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['alert', alertId] })
      queryClient.invalidateQueries({ queryKey: ['alertStats'] })
      toast.success('Alert acknowledged')
    },
  })
}

/**
 * Hook to resolve an alert
 */
export function useResolveAlert() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ alertId, resolution }) => alertsApi.resolveAlert(alertId, resolution),
    onMutate: async ({ alertId }) => {
      await queryClient.cancelQueries({ queryKey: ['alert', alertId] })

      const previousAlert = queryClient.getQueryData(['alert', alertId])

      queryClient.setQueryData(['alert', alertId], (old) => ({
        ...old,
        status: 'resolved',
        resolved_at: new Date().toISOString(),
      }))

      return { previousAlert, alertId }
    },
    onError: (error, variables, context) => {
      if (context?.previousAlert) {
        queryClient.setQueryData(['alert', context.alertId], context.previousAlert)
      }
      toast.error(error.message || 'Failed to resolve alert')
    },
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['alert', variables.alertId] })
      queryClient.invalidateQueries({ queryKey: ['alertStats'] })
      toast.success('Alert resolved')
    },
  })
}

/**
 * Hook to bulk acknowledge alerts
 */
export function useBulkAcknowledge() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (alertIds) => alertsApi.bulkAcknowledge(alertIds),
    onSuccess: (data, alertIds) => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['alertStats'] })
      toast.success(`${alertIds.length} alerts acknowledged`)
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to acknowledge alerts')
    },
  })
}

/**
 * Hook to bulk resolve alerts
 */
export function useBulkResolve() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ alertIds, resolution }) => alertsApi.bulkResolve(alertIds, resolution),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['alertStats'] })
      toast.success(`${variables.alertIds.length} alerts resolved`)
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to resolve alerts')
    },
  })
}

/**
 * Hook to get alert statistics
 */
export function useAlertStats(startTime, endTime, options = {}) {
  return useQuery({
    queryKey: ['alertStats', startTime, endTime],
    queryFn: () => alertsApi.getAlertStats(startTime, endTime),
    refetchInterval: options.polling ? 60000 : false, // Poll every 60 seconds if enabled
    ...options,
  })
}

/**
 * Hook to get alert timeline data
 */
export function useAlertTimeline(startTime, endTime, interval = '1h', options = {}) {
  return useQuery({
    queryKey: ['alertTimeline', startTime, endTime, interval],
    queryFn: () => alertsApi.getAlertTimeline(startTime, endTime, interval),
    ...options,
  })
}

/**
 * Hook to get related alerts
 */
export function useRelatedAlerts(alertId, options = {}) {
  return useQuery({
    queryKey: ['relatedAlerts', alertId],
    queryFn: () => alertsApi.getRelatedAlerts(alertId),
    enabled: !!alertId && options.enabled !== false,
    ...options,
  })
}
