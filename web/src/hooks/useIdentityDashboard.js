import { useEffect, useCallback, useRef } from 'react'
import { useIdentityStore } from '../stores/identityStore'

/**
 * Custom hook for identity dashboard data fetching
 * Provides auto-refresh, loading states, and error handling
 */
export function useIdentityDashboard(options = {}) {
  const {
    autoRefresh = true,
    refreshInterval = 30000, // 30 seconds
    timeRange = '24h',
  } = options

  const {
    highRiskUsers,
    activeIncidents,
    metrics,
    selectedIncident,
    filters,
    isLoading,
    error,
    lastUpdated,
    fetchHighRiskUsers,
    fetchActiveIncidents,
    fetchMetrics,
    setFilters,
    refreshAll,
  } = useIdentityStore()

  const refreshTimerRef = useRef(null)

  // Initial data fetch
  const loadData = useCallback(async () => {
    await Promise.all([
      fetchHighRiskUsers(),
      fetchActiveIncidents(),
      fetchMetrics(timeRange),
    ])
  }, [fetchHighRiskUsers, fetchActiveIncidents, fetchMetrics, timeRange])

  // Set up auto-refresh
  useEffect(() => {
    // Initial load
    loadData()

    // Set up refresh interval
    if (autoRefresh && refreshInterval > 0) {
      refreshTimerRef.current = setInterval(() => {
        refreshAll()
      }, refreshInterval)
    }

    // Cleanup
    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current)
      }
    }
  }, [loadData, autoRefresh, refreshInterval, refreshAll])

  // Update data when filters change
  useEffect(() => {
    fetchActiveIncidents()
    fetchMetrics(filters.timeRange)
  }, [filters, fetchActiveIncidents, fetchMetrics])

  // Manual refresh function
  const refresh = useCallback(() => {
    return refreshAll()
  }, [refreshAll])

  // Computed values
  const highRiskCount = highRiskUsers.length
  const criticalIncidentsCount = activeIncidents.filter(
    (i) => i.severity === 'critical'
  ).length
  const highIncidentsCount = activeIncidents.filter(
    (i) => i.severity === 'high'
  ).length

  return {
    // Data
    highRiskUsers,
    activeIncidents,
    metrics,
    selectedIncident,
    filters,

    // Computed
    highRiskCount,
    criticalIncidentsCount,
    highIncidentsCount,
    totalActiveIncidents: activeIncidents.length,

    // State
    isLoading,
    error,
    lastUpdated,

    // Actions
    setFilters,
    refresh,
  }
}

/**
 * Hook for user risk profile data
 */
export function useUserRiskProfile(userEmail) {
  const {
    selectedUser,
    isLoading,
    error,
    fetchUserRiskProfile,
    fetchUserTimeline,
  } = useIdentityStore()

  const timelineRef = useRef([])

  useEffect(() => {
    if (userEmail) {
      fetchUserRiskProfile(userEmail)
      fetchUserTimeline(userEmail).then((timeline) => {
        timelineRef.current = timeline
      })
    }
  }, [userEmail, fetchUserRiskProfile, fetchUserTimeline])

  return {
    user: selectedUser,
    timeline: timelineRef.current,
    isLoading,
    error,
    refresh: () => {
      if (userEmail) {
        fetchUserRiskProfile(userEmail)
        fetchUserTimeline(userEmail)
      }
    },
  }
}

/**
 * Hook for incident details
 */
export function useIncidentDetails(incidentId) {
  const {
    selectedIncident,
    fetchIncidentDetails,
    acknowledgeIncident,
    dismissIncident,
    escalateIncident,
  } = useIdentityStore()

  useEffect(() => {
    if (incidentId) {
      fetchIncidentDetails(incidentId)
    }
  }, [incidentId, fetchIncidentDetails])

  return {
    incident: selectedIncident,
    acknowledge: () => acknowledgeIncident(incidentId),
    dismiss: (reason) => dismissIncident(incidentId, reason),
    escalate: (notes) => escalateIncident(incidentId, notes),
  }
}

export default useIdentityDashboard
