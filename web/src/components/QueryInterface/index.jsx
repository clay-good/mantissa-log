import { useState } from 'react'
import { useQueryGeneration, useQueryResults } from '../../hooks/useQuery'
import QueryInput from './QueryInput'
import SQLDisplay from './SQLDisplay'
import ResultsTable from './ResultsTable'
import RuleFromQuery from '../RulesManager/RuleFromQuery'
import toast from 'react-hot-toast'

export default function QueryInterface() {
  const [currentQueryId, setCurrentQueryId] = useState(null)
  const [currentSql, setCurrentSql] = useState(null)
  const [recentQueries, setRecentQueries] = useState([])
  const [showRuleModal, setShowRuleModal] = useState(false)

  const { generate, isGenerating, data: queryData } = useQueryGeneration()

  const {
    data: resultsData,
    isLoading: isLoadingResults,
    refetch: refetchResults,
  } = useQueryResults(currentQueryId, {
    enabled: !!currentQueryId,
  })

  const handleSubmit = (question) => {
    generate(
      { question, execute: true, includeExplanation: true },
      {
        onSuccess: (data) => {
          setCurrentQueryId(data.query_id)
          setCurrentSql(data.sql)
          setRecentQueries((prev) => [question, ...prev.slice(0, 4)])
        },
      }
    )
  }

  const handleSqlEdit = (newSql) => {
    setCurrentSql(newSql)
    toast.info('SQL updated. Click Execute to run the modified query.')
  }

  const handleSaveAsRule = () => {
    setShowRuleModal(true)
  }

  const handleRuleModalClose = () => {
    setShowRuleModal(false)
  }

  const handleRuleCreated = () => {
    toast.success('Detection rule created successfully!')
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="mb-2 text-2xl font-bold text-mono-950 dark:text-mono-50">Natural Language Query</h1>
        <p className="text-mono-600 dark:text-mono-400">
          Ask questions about your logs in plain English
        </p>
      </div>

      <div className="card">
        <QueryInput
          onSubmit={handleSubmit}
          isLoading={isGenerating}
          recentQueries={recentQueries}
        />
      </div>

      {isGenerating && (
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-mono-950 dark:border-mono-50 border-t-transparent"></div>
            <p className="text-mono-600 dark:text-mono-400">Generating SQL query...</p>
          </div>
        </div>
      )}

      {currentSql && !isGenerating && (
        <div className="card">
          <SQLDisplay
            sql={currentSql}
            warnings={queryData?.warnings || []}
            onEdit={handleSqlEdit}
          />

          {queryData?.explanation && (
            <div className="mt-4 rounded-lg bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 p-4">
              <h4 className="text-sm font-medium text-mono-950 dark:text-mono-50">Explanation</h4>
              <p className="mt-1 text-sm text-mono-700 dark:text-mono-300">{queryData.explanation}</p>
            </div>
          )}
        </div>
      )}

      {currentQueryId && (
        <div className="card">
          {resultsData?.status === 'RUNNING' || resultsData?.status === 'QUEUED' ? (
            <div className="flex items-center gap-3 py-8">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-mono-950 dark:border-mono-50 border-t-transparent"></div>
              <p className="text-mono-600 dark:text-mono-400">Executing query...</p>
            </div>
          ) : resultsData?.status === 'FAILED' ? (
            <div className="rounded-lg bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 p-4">
              <h4 className="text-sm font-medium text-mono-950 dark:text-mono-50">Query Failed</h4>
              <p className="mt-1 text-sm text-mono-700 dark:text-mono-300">
                {resultsData.error || 'An error occurred while executing the query'}
              </p>
            </div>
          ) : resultsData?.status === 'SUCCEEDED' ? (
            <>
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-medium text-mono-950 dark:text-mono-50">Results</h3>
                <button
                  onClick={handleSaveAsRule}
                  className="btn btn-secondary text-sm"
                >
                  Save as Detection Rule
                </button>
              </div>

              <ResultsTable results={resultsData.results} isLoading={false} />

              {resultsData.results && (
                <div className="mt-4 flex gap-4 text-xs text-mono-600 dark:text-mono-400">
                  <span>
                    Data scanned:{' '}
                    {(resultsData.results.data_scanned_bytes / 1024 / 1024).toFixed(2)} MB
                  </span>
                  <span>
                    Execution time: {(resultsData.results.execution_time_ms / 1000).toFixed(2)}s
                  </span>
                </div>
              )}
            </>
          ) : null}
        </div>
      )}

      {showRuleModal && currentSql && (
        <RuleFromQuery
          query={currentSql}
          explanation={queryData?.explanation}
          onClose={handleRuleModalClose}
          onSuccess={handleRuleCreated}
        />
      )}
    </div>
  )
}
