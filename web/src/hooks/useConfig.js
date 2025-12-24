import { useQuery } from '@tanstack/react-query'
import { configApi } from '../services/configApi'

/**
 * Hook to fetch platform configuration including enabled features
 */
export function useConfig(options = {}) {
  return useQuery({
    queryKey: ['config'],
    queryFn: () => configApi.getConfig(),
    staleTime: 5 * 60 * 1000, // Config rarely changes, cache for 5 minutes
    refetchOnWindowFocus: false,
    ...options,
  })
}

/**
 * Hook to check if a specific feature is enabled
 */
export function useFeatureEnabled(feature) {
  const { data, isLoading, error } = useConfig()

  if (isLoading || error || !data) {
    // Default to showing SIEM features during loading
    return feature === 'siem'
  }

  return data.features?.[feature] ?? false
}

/**
 * Hook to get upsell info for disabled modules
 */
export function useUpsell() {
  const { data, isLoading, error } = useConfig()

  if (isLoading || error || !data) {
    return {}
  }

  return data.upsell ?? {}
}

/**
 * Hook to get all enabled features as an object
 */
export function useFeatures() {
  const { data, isLoading, error } = useConfig()

  if (isLoading || error || !data) {
    return {
      siem: true,
      apm: false,
      soar: false,
    }
  }

  return data.features ?? {
    siem: true,
    apm: false,
    soar: false,
  }
}
