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

      {recentQueries.length > 0 && (
        <div className="relative">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center gap-2 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
          >
            <ClockIcon className="h-4 w-4" />
            Recent queries
          </button>

          {showHistory && (
            <div className="absolute left-0 top-8 z-10 w-full rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 shadow-lg animate-scale-in">
              {recentQueries.map((query, index) => (
                <button
                  key={index}
                  onClick={() => selectQuery(query)}
                  className="w-full px-4 py-2 text-left text-sm text-mono-900 dark:text-mono-100 hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors first:rounded-t-lg last:rounded-b-lg"
                >
                  {query}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div>
        <p className="mb-2 text-xs font-medium text-mono-600 dark:text-mono-400">Suggested queries:</p>
        <div className="flex flex-wrap gap-2">
          {SUGGESTED_QUERIES.map((query, index) => (
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
    </div>
  )
}
