import { create } from 'zustand'
import { signIn, signOut, getCurrentUser, fetchAuthSession } from 'aws-amplify/auth'

export const useAuthStore = create((set, get) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  token: null,

  initialize: async () => {
    try {
      const user = await getCurrentUser()
      const session = await fetchAuthSession()
      const token = session.tokens?.idToken?.toString()

      set({
        user,
        isAuthenticated: true,
        isLoading: false,
        token,
      })
    } catch (error) {
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        token: null,
      })
    }
  },

  login: async (username, password) => {
    try {
      await signIn({ username, password })
      await get().initialize()
      return { success: true }
    } catch (error) {
      return {
        success: false,
        error: error.message || 'Login failed',
      }
    }
  },

  logout: async () => {
    try {
      await signOut()
      set({
        user: null,
        isAuthenticated: false,
        token: null,
      })
    } catch (error) {
      console.error('Logout error:', error)
    }
  },

  refreshToken: async () => {
    try {
      const session = await fetchAuthSession({ forceRefresh: true })
      const token = session.tokens?.idToken?.toString()
      set({ token })
      return token
    } catch (error) {
      console.error('Token refresh error:', error)
      return null
    }
  },
}))
