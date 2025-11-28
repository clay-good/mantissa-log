import { useState } from 'react'
import { MagnifyingGlassIcon, ClockIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

const SUGGESTED_QUERIES = [
  'Show me failed login attempts in the last hour',
  'List all root account activity today',
  'Find S3 bucket policy changes this week',
  'Show unusual API calls from the last 24 hours',
]

export default function QueryInput({ onSubmit, isLoading, recentQueries = [] }) {
  const [question, setQuestion] = useState('')
  const [showHistory, setShowHistory] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (question.trim()) {
      onSubmit(question.trim())
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
    setShowHistory(false)
  }

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit}>
        <div className="relative">
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={handleKeyDown}
            onFocus={() => setShowHistory(false)}
            placeholder="Ask a question about your logs in natural language...&#10;Example: Show me failed SSH attempts from the last 24 hours"
            className="w-full rounded-lg border border-gray-300 p-4 pr-12 text-base focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            rows={3}
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !question.trim()}
            className={clsx(
              'absolute bottom-4 right-4 rounded-lg p-2',
              isLoading || !question.trim()
                ? 'bg-gray-300 text-gray-500'
                : 'bg-primary-600 text-white hover:bg-primary-700'
            )}
          >
            <MagnifyingGlassIcon className="h-5 w-5" />
          </button>
        </div>
      </form>

      {recentQueries.length > 0 && (
        <div className="relative">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-900"
          >
            <ClockIcon className="h-4 w-4" />
            Recent queries
          </button>

          {showHistory && (
            <div className="absolute left-0 top-8 z-10 w-full rounded-lg border border-gray-200 bg-white shadow-lg">
              {recentQueries.map((query, index) => (
                <button
                  key={index}
                  onClick={() => selectQuery(query)}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-gray-50"
                >
                  {query}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div>
        <p className="mb-2 text-xs font-medium text-gray-500">Suggested queries:</p>
        <div className="flex flex-wrap gap-2">
          {SUGGESTED_QUERIES.map((query, index) => (
            <button
              key={index}
              onClick={() => selectQuery(query)}
              className="rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-700 hover:bg-gray-200"
            >
              {query}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
