import { apiClient } from './api'

export const queryApi = {
  generateQuery: async (question, options = {}) => {
    return apiClient.post('/query', {
      question,
      execute: options.execute || false,
      session_id: options.sessionId,
      include_explanation: options.includeExplanation || false,
    })
  },

  executeQuery: async (queryId) => {
    return apiClient.post(`/query/${queryId}/execute`)
  },

  getQueryResults: async (queryId, page = 1, pageSize = 100) => {
    return apiClient.get(`/query/${queryId}/results?page=${page}&page_size=${pageSize}`)
  },
}
