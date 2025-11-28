import { appConfig } from '../config/aws-config'
import { useAuthStore } from '../stores/authStore'

class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL
  }

  async request(endpoint, options = {}) {
    const token = useAuthStore.getState().token

    if (!token) {
      throw new Error('No authentication token available')
    }

    const url = `${this.baseURL}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...options.headers,
    }

    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (response.status === 401) {
      const newToken = await useAuthStore.getState().refreshToken()
      if (newToken) {
        headers.Authorization = `Bearer ${newToken}`
        return fetch(url, { ...options, headers })
      }
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        error: { message: 'Request failed' },
      }))
      throw new Error(error.error?.message || 'Request failed')
    }

    return response.json()
  }

  get(endpoint) {
    return this.request(endpoint, { method: 'GET' })
  }

  post(endpoint, data) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  put(endpoint, data) {
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    })
  }

  delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' })
  }
}

export const apiClient = new ApiClient(appConfig.apiEndpoint)
