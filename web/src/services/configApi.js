import { apiClient } from './api'

/**
 * API service for platform configuration
 */
export const configApi = {
  /**
   * Get platform configuration including enabled features
   */
  async getConfig() {
    return apiClient.get('/api/config')
  },
}
