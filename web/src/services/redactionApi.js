import { apiClient } from './api'

export const redactionApi = {
  getConfig: async () => {
    return apiClient.get('/settings/redaction')
  },

  updateConfig: async (config) => {
    return apiClient.put('/settings/redaction', config)
  },

  testRedaction: async (text, patterns = null) => {
    return apiClient.post('/settings/redaction/test', {
      text,
      patterns,
    })
  },

  getPatternTypes: async () => {
    return apiClient.get('/settings/redaction/pattern-types')
  },

  addCustomPattern: async (name, regex, description) => {
    return apiClient.post('/settings/redaction/patterns', {
      name,
      regex,
      description,
    })
  },

  deleteCustomPattern: async (patternId) => {
    return apiClient.delete(`/settings/redaction/patterns/${patternId}`)
  },

  getRedactionStats: async (startDate = null, endDate = null) => {
    const params = new URLSearchParams()
    if (startDate) params.append('start_date', startDate)
    if (endDate) params.append('end_date', endDate)

    return apiClient.get(`/settings/redaction/stats?${params.toString()}`)
  },
}
