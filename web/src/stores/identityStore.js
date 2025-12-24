import { create } from 'zustand'
import * as identityApi from '../services/identityApi'

export const useIdentityStore = create((set, get) => ({
  // State
  highRiskUsers: [],
  activeIncidents: [],
  metrics: {
    authFailures24h: 0,
    unusualLogins24h: 0,
    mfaBypassAttempts: 0,
    attacksByProvider: {},
    attacksByType: {},
    riskDistribution: {},
    attacksOverTime: [],
  },
  selectedIncident: null,
  selectedUser: null,
  filters: {
    timeRange: '24h',
    severity: 'all',
    provider: 'all',
    attackType: 'all',
  },
  isLoading: false,
  error: null,
  lastUpdated: null,

  // Actions
  setFilters: (newFilters) => {
    set({ filters: { ...get().filters, ...newFilters } })
  },

  setSelectedIncident: (incidentId) => {
    const incident = get().activeIncidents.find((i) => i.id === incidentId) || null
    set({ selectedIncident: incident })
  },

  setSelectedUser: (user) => {
    set({ selectedUser: user })
  },

  clearSelectedIncident: () => {
    set({ selectedIncident: null })
  },

  fetchHighRiskUsers: async () => {
    try {
      set({ isLoading: true, error: null })
      const users = await identityApi.getHighRiskUsers()
      set({ highRiskUsers: users, isLoading: false })
      return users
    } catch (error) {
      set({ error: error.message, isLoading: false })
      console.error('Error fetching high risk users:', error)
      return []
    }
  },

  fetchActiveIncidents: async () => {
    try {
      set({ isLoading: true, error: null })
      const { filters } = get()
      const incidents = await identityApi.getActiveIncidents(filters)
      set({ activeIncidents: incidents, isLoading: false, lastUpdated: new Date() })
      return incidents
    } catch (error) {
      set({ error: error.message, isLoading: false })
      console.error('Error fetching active incidents:', error)
      return []
    }
  },

  fetchMetrics: async (timeRange = '24h') => {
    try {
      set({ isLoading: true, error: null })
      const metrics = await identityApi.getIdentityMetrics(timeRange)
      set({ metrics, isLoading: false })
      return metrics
    } catch (error) {
      set({ error: error.message, isLoading: false })
      console.error('Error fetching metrics:', error)
      return null
    }
  },

  fetchIncidentDetails: async (incidentId) => {
    try {
      const incident = await identityApi.getIncidentDetails(incidentId)
      set({ selectedIncident: incident })
      return incident
    } catch (error) {
      console.error('Error fetching incident details:', error)
      return null
    }
  },

  acknowledgeIncident: async (incidentId) => {
    try {
      await identityApi.acknowledgeIncident(incidentId)
      // Update local state
      const incidents = get().activeIncidents.map((i) =>
        i.id === incidentId ? { ...i, status: 'acknowledged' } : i
      )
      set({ activeIncidents: incidents })

      // Update selected incident if it's the one being acknowledged
      const { selectedIncident } = get()
      if (selectedIncident?.id === incidentId) {
        set({ selectedIncident: { ...selectedIncident, status: 'acknowledged' } })
      }
      return true
    } catch (error) {
      console.error('Error acknowledging incident:', error)
      return false
    }
  },

  dismissIncident: async (incidentId) => {
    try {
      await identityApi.dismissIncident(incidentId)
      // Remove from active incidents
      const incidents = get().activeIncidents.filter((i) => i.id !== incidentId)
      set({ activeIncidents: incidents })

      // Clear selected if it was dismissed
      const { selectedIncident } = get()
      if (selectedIncident?.id === incidentId) {
        set({ selectedIncident: null })
      }
      return true
    } catch (error) {
      console.error('Error dismissing incident:', error)
      return false
    }
  },

  escalateIncident: async (incidentId) => {
    try {
      await identityApi.escalateIncident(incidentId)
      // Refresh incidents
      await get().fetchActiveIncidents()
      return true
    } catch (error) {
      console.error('Error escalating incident:', error)
      return false
    }
  },

  fetchUserRiskProfile: async (userEmail) => {
    try {
      set({ isLoading: true, error: null })
      const user = await identityApi.getUserRiskProfile(userEmail)
      set({ selectedUser: user, isLoading: false })
      return user
    } catch (error) {
      set({ error: error.message, isLoading: false })
      console.error('Error fetching user risk profile:', error)
      return null
    }
  },

  fetchUserTimeline: async (userEmail, timeRange = '7d') => {
    try {
      const timeline = await identityApi.getUserTimeline(userEmail, timeRange)
      return timeline
    } catch (error) {
      console.error('Error fetching user timeline:', error)
      return []
    }
  },

  // Refresh all data
  refreshAll: async () => {
    const { filters } = get()
    await Promise.all([
      get().fetchHighRiskUsers(),
      get().fetchActiveIncidents(),
      get().fetchMetrics(filters.timeRange),
    ])
    set({ lastUpdated: new Date() })
  },
}))
