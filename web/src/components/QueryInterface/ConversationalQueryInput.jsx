import { useState, useEffect } from 'react'
import { MagnifyingGlassIcon, ChatBubbleLeftRightIcon, XMarkIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'
import { useConversation } from '../../context/ConversationContext'

const SUGGESTED_QUERIES = [
  'Show me failed login attempts in the last hour',
  'List all root account activity today',
  'Find S3 bucket policy changes this week',
  'Show unusual API calls from the last 24 hours',
]

const FOLLOW_UP_SUGGESTIONS = [
  'Show me more details',
  'Save this as a detection rule',
  'Send alerts to Slack when this happens',
  'Filter by source IP address',
]

export default function ConversationalQueryInput({ onSubmit, isLoading }) {
  const [question, setQuestion] = useState('')
  const [showConversation, setShowConversation] = useState(false)
  const {
    currentSessionId,
    getCurrentSession,
    startNewConversation,
  } = useConversation()

  const currentSession = getCurrentSession()

  useEffect(() => {
    if (!currentSessionId && question.trim()) {
      // Auto-create session when user starts typing
      startNewConversation()
    }
  }, [question, currentSessionId, startNewConversation])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (question.trim()) {
      onSubmit(question.trim(), currentSessionId)
      setQuestion('')
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const selectQuery = (query) => {
    setQuestion(query)
  }

  const handleNewConversation = () => {
    startNewConversation()
    setQuestion('')
    setShowConversation(false)
  }

  const hasMessages = currentSession?.messages?.length > 0

  return (
    <div className="space-y-4">
      {/* Conversation History Toggle */}
      {hasMessages && (
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowConversation(!showConversation)}
            className="flex items-center gap-2 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
          >
            <ChatBubbleLeftRightIcon className="h-4 w-4" />
            {showConversation ? 'Hide' : 'Show'} conversation history ({currentSession.messages.length} messages)
          </button>
          <button
            onClick={handleNewConversation}
            className="flex items-center gap-2 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
          >
            <XMarkIcon className="h-4 w-4" />
            New conversation
          </button>
        </div>
      )}

      {/* Conversation History */}
      {showConversation && currentSession && (
        <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-900 p-4 space-y-3 max-h-96 overflow-y-auto">
          {currentSession.messages.map((msg, idx) => (
            <div
              key={idx}
              className={clsx(
                'p-3 rounded-lg',
                msg.role === 'user'
                  ? 'bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 ml-8'
                  : 'bg-white dark:bg-mono-850 text-mono-950 dark:text-mono-50 mr-8'
              )}
            >
              <div className="text-xs font-medium mb-1 opacity-70">
                {msg.role === 'user' ? 'You' : 'Assistant'}
              </div>
              <div className="text-sm whitespace-pre-wrap">{msg.content}</div>
              {msg.metadata?.sql && (
                <div className="mt-2 p-2 rounded bg-mono-100 dark:bg-mono-800 font-mono text-xs overflow-x-auto">
                  {msg.metadata.sql}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Query Input */}
      <form onSubmit={handleSubmit}>
        <div className="relative">
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={
              hasMessages
                ? "Ask a follow-up question or refine your query...\nExample: and send alerts to Slack"
                : "Ask a question about your logs in natural language...\nExample: Show me failed SSH attempts from the last 24 hours"
            }
            className="w-full rounded-lg border border-mono-300 dark:border-mono-700 bg-white dark:bg-mono-950 p-4 pr-12 text-base text-mono-950 dark:text-mono-50 placeholder-mono-500 focus:border-mono-950 dark:focus:border-mono-50 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 transition-all"
            rows={3}
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !question.trim()}
            className={clsx(
              'absolute bottom-4 right-4 rounded-lg p-2 transition-all',
              isLoading || !question.trim()
                ? 'bg-mono-300 dark:bg-mono-700 text-mono-500 dark:text-mono-400 cursor-not-allowed'
                : 'bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 hover:bg-mono-800 dark:hover:bg-mono-200'
            )}
          >
            <MagnifyingGlassIcon className="h-5 w-5" />
          </button>
        </div>
      </form>

      {/* Suggestions */}
      <div>
        <p className="mb-2 text-xs font-medium text-mono-600 dark:text-mono-400">
          {hasMessages ? 'Follow-up suggestions:' : 'Suggested queries:'}
        </p>
        <div className="flex flex-wrap gap-2">
          {(hasMessages ? FOLLOW_UP_SUGGESTIONS : SUGGESTED_QUERIES).map((query, index) => (
            <button
              key={index}
              onClick={() => selectQuery(query)}
              className="rounded-full bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 px-3 py-1 text-xs text-mono-700 dark:text-mono-300 hover:bg-mono-200 dark:hover:bg-mono-800 transition-colors"
            >
              {query}
            </button>
          ))}
        </div>
      </div>

      {/* Session Indicator */}
      {currentSessionId && (
        <div className="flex items-center gap-2 text-xs text-mono-500 dark:text-mono-500">
          <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse"></div>
          Active conversation session
        </div>
      )}
    </div>
  )
}
