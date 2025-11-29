import { apiClient } from './api'

export const conversationApi = {
  createConversation: async () => {
    return apiClient.post('/conversations', {})
  },

  getConversation: async (conversationId) => {
    return apiClient.get(`/conversations/${conversationId}`)
  },

  listConversations: async (limit = 50, offset = 0) => {
    return apiClient.get(`/conversations?limit=${limit}&offset=${offset}`)
  },

  queryConversation: async (conversationId, question) => {
    return apiClient.post(`/conversations/${conversationId}/query`, {
      question,
    })
  },

  deleteConversation: async (conversationId) => {
    return apiClient.delete(`/conversations/${conversationId}`)
  },
}
