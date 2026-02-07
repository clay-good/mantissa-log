import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { healthApi } from '../services/healthApi'
import toast from 'react-hot-toast'

/**
 * Hook to fetch list of all log source health statuses
 */
export function useSourceHealthList(statusFilter = '', options = {}) {
  return useQuery({
    queryKey: ['sourceHealth', statusFilter],
    queryFn: () => healthApi.getSourceHealth(statusFilter || undefined),
    refetchInterval: options.polling ? 60000 : false,
    ...options,
  })
}

/**
 * Hook to fetch detailed health information for a single source
 */
export function useSourceHealthDetail(sourceType, options = {}) {
  return useQuery({
    queryKey: ['sourceHealthDetail', sourceType],
    queryFn: () => healthApi.getSourceHealthDetail(sourceType),
    enabled: !!sourceType && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to fetch volume history for a single source
 */
export function useSourceHealthHistory(sourceType, startTime, endTime, granularity, options = {}) {
  return useQuery({
    queryKey: ['sourceHealthHistory', sourceType, startTime, endTime, granularity],
    queryFn: () => healthApi.getVolumeHistory(sourceType, startTime, endTime, granularity),
    enabled: !!sourceType && options.enabled !== false,
    ...options,
  })
}

/**
 * Hook to fetch aggregate health summary across all sources
 */
export function useHealthSummary(options = {}) {
  return useQuery({
    queryKey: ['healthSummary'],
    queryFn: () => healthApi.getHealthSummary(),
    refetchInterval: options.polling ? 60000 : false,
    ...options,
  })
}

/**
 * Hook to trigger an on-demand health check for a source
 */
export function useTriggerHealthCheck() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (sourceType) => healthApi.triggerHealthCheck(sourceType),
    onSuccess: (data, sourceType) => {
      queryClient.invalidateQueries({ queryKey: ['sourceHealth'] })
      queryClient.invalidateQueries({ queryKey: ['sourceHealthDetail', sourceType] })
      queryClient.invalidateQueries({ queryKey: ['healthSummary'] })
      toast.success(`Health check completed for ${sourceType}`)
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to trigger health check')
    },
  })
}

/**
 * Hook to update health monitoring configuration for a source
 */
export function useUpdateHealthConfig() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ sourceType, config }) => healthApi.updateHealthConfig(sourceType, config),
    onSuccess: (data, { sourceType }) => {
      queryClient.invalidateQueries({ queryKey: ['sourceHealth'] })
      queryClient.invalidateQueries({ queryKey: ['sourceHealthDetail', sourceType] })
      toast.success(`Configuration updated for ${sourceType}`)
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to update configuration')
    },
  })
}

/**
 * Hook to acknowledge a health alert and suppress future alerts
 */
export function useAcknowledgeHealthAlert() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ sourceType, suppression_duration_seconds, notes }) =>
      healthApi.acknowledgeHealthAlert(sourceType, {
        suppression_duration_seconds,
        notes,
      }),
    onSuccess: (data, { sourceType }) => {
      queryClient.invalidateQueries({ queryKey: ['sourceHealth'] })
      queryClient.invalidateQueries({ queryKey: ['sourceHealthDetail', sourceType] })
      queryClient.invalidateQueries({ queryKey: ['healthSummary'] })
      toast.success(`Health alert acknowledged for ${sourceType}`)
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to acknowledge health alert')
    },
  })
}
