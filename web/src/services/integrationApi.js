import { apiClient } from './api'

export const integrationApi = {
  listIntegrations: async () => {
    return apiClient.get('/integrations')
  },

  getIntegration: async (integrationId) => {
    return apiClient.get(`/integrations/${integrationId}`)
  },

  createIntegration: async (integrationType, config) => {
    return apiClient.post('/integrations', {
      type: integrationType,
      config,
    })
  },

  updateIntegration: async (integrationId, config) => {
    return apiClient.put(`/integrations/${integrationId}`, {
      config,
    })
  },

  deleteIntegration: async (integrationId) => {
    return apiClient.delete(`/integrations/${integrationId}`)
  },

  testIntegration: async (integrationId) => {
    return apiClient.post(`/integrations/${integrationId}/test`, {})
  },

  toggleIntegration: async (integrationId, enabled) => {
    return apiClient.put(`/integrations/${integrationId}`, {
      enabled,
    })
  },

  getIntegrationHealth: async (integrationId) => {
    return apiClient.get(`/integrations/${integrationId}/health`)
  },
}
