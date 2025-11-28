import { createContext, useContext, useState, useCallback } from 'react'
import { v4 as uuidv4 } from 'uuid'

const ConversationContext = createContext(null)

export function ConversationProvider({ children }) {
  const [currentSessionId, setCurrentSessionId] = useState(null)
  const [sessions, setSessions] = useState({})

  const createSession = useCallback(() => {
    const sessionId = uuidv4()
    setSessions(prev => ({
      ...prev,
      [sessionId]: {
        id: sessionId,
        messages: [],
        context: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }
    }))
    setCurrentSessionId(sessionId)
    return sessionId
  }, [])

  const getSession = useCallback((sessionId) => {
    return sessions[sessionId] || null
  }, [sessions])

  const getCurrentSession = useCallback(() => {
    return currentSessionId ? sessions[currentSessionId] : null
  }, [currentSessionId, sessions])

  const addMessage = useCallback((sessionId, role, content, metadata = {}) => {
    setSessions(prev => {
      const session = prev[sessionId]
      if (!session) return prev

      return {
        ...prev,
        [sessionId]: {
          ...session,
          messages: [
            ...session.messages,
            {
              role,
              content,
              metadata,
              timestamp: new Date().toISOString(),
            }
          ],
          updatedAt: new Date().toISOString(),
        }
      }
    })
  }, [])

  const updateContext = useCallback((sessionId, key, value) => {
    setSessions(prev => {
      const session = prev[sessionId]
      if (!session) return prev

      return {
        ...prev,
        [sessionId]: {
          ...session,
          context: {
            ...session.context,
            [key]: value,
          },
          updatedAt: new Date().toISOString(),
        }
      }
    })
  }, [])

  const getContext = useCallback((sessionId, key) => {
    const session = sessions[sessionId]
    return session?.context[key]
  }, [sessions])

  const clearSession = useCallback((sessionId) => {
    setSessions(prev => {
      const newSessions = { ...prev }
      delete newSessions[sessionId]
      return newSessions
    })
    if (currentSessionId === sessionId) {
      setCurrentSessionId(null)
    }
  }, [currentSessionId])

  const startNewConversation = useCallback(() => {
    return createSession()
  }, [createSession])

  const value = {
    currentSessionId,
    sessions,
    createSession,
    getSession,
    getCurrentSession,
    addMessage,
    updateContext,
    getContext,
    clearSession,
    startNewConversation,
    setCurrentSessionId,
  }

  return (
    <ConversationContext.Provider value={value}>
      {children}
    </ConversationContext.Provider>
  )
}

export function useConversation() {
  const context = useContext(ConversationContext)
  if (!context) {
    throw new Error('useConversation must be used within ConversationProvider')
  }
  return context
}
