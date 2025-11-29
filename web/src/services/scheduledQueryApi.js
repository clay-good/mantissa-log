import { apiClient } from './api'

export const scheduledQueryApi = {
  list: async () => {
    return apiClient.get('/scheduled-queries')
  },

  get: async (queryId) => {
    return apiClient.get(`/scheduled-queries/${queryId}`)
  },

  create: async (queryText, schedule, destination) => {
    return apiClient.post('/scheduled-queries', {
      query: queryText,
      schedule,
      destination,
    })
  },

  update: async (queryId, updates) => {
    return apiClient.put(`/scheduled-queries/${queryId}`, updates)
  },

  delete: async (queryId) => {
    return apiClient.delete(`/scheduled-queries/${queryId}`)
  },

  enable: async (queryId) => {
    return apiClient.put(`/scheduled-queries/${queryId}`, {
      enabled: true,
    })
  },

  disable: async (queryId) => {
    return apiClient.put(`/scheduled-queries/${queryId}`, {
      enabled: false,
    })
  },

  testExecution: async (queryId) => {
    return apiClient.post(`/scheduled-queries/${queryId}/test`, {})
  },

  getExecutionHistory: async (queryId, limit = 50) => {
    return apiClient.get(`/scheduled-queries/${queryId}/history?limit=${limit}`)
  },
}
