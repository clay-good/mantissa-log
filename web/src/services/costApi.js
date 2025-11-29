import { apiClient } from './api'

export const costApi = {
  estimateCost: async (query, schedule = null) => {
    return apiClient.post('/cost/estimate', {
      query,
      schedule,
    })
  },

  getMetrics: async (startDate = null, endDate = null, groupBy = 'day') => {
    const params = new URLSearchParams()
    if (startDate) params.append('start_date', startDate)
    if (endDate) params.append('end_date', endDate)
    params.append('group_by', groupBy)

    return apiClient.get(`/cost/metrics?${params.toString()}`)
  },

  getQueryCostHistory: async (queryId) => {
    return apiClient.get(`/cost/query/${queryId}/history`)
  },

  getUserCostSummary: async (userId = null) => {
    const endpoint = userId ? `/cost/user/${userId}` : '/cost/user/me'
    return apiClient.get(endpoint)
  },
}
