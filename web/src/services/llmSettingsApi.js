import { apiClient } from './api'

export const llmSettingsApi = {
  getSettings: async () => {
    return apiClient.get('/settings/llm')
  },

  updateSettings: async (settings) => {
    return apiClient.put('/settings/llm', settings)
  },

  testConnection: async (provider, apiKey, model) => {
    return apiClient.post('/settings/llm/test', {
      provider,
      api_key: apiKey,
      model,
    })
  },

  getProviderModels: async (provider) => {
    return apiClient.get(`/settings/llm/providers/${provider}/models`)
  },

  getUsageStats: async (startDate = null, endDate = null) => {
    const params = new URLSearchParams()
    if (startDate) params.append('start_date', startDate)
    if (endDate) params.append('end_date', endDate)

    return apiClient.get(`/settings/llm/usage?${params.toString()}`)
  },
}
