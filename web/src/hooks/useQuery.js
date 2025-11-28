import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { queryApi } from '../services/queryApi'
import toast from 'react-hot-toast'

export function useQueryGeneration() {
  const [sessionId, setSessionId] = useState(null)

  const generateMutation = useMutation({
    mutationFn: ({ question, execute, includeExplanation }) =>
      queryApi.generateQuery(question, { sessionId, execute, includeExplanation }),
    onSuccess: (data) => {
      if (data.session_id) {
        setSessionId(data.session_id)
      }
      if (data.warnings && data.warnings.length > 0) {
        data.warnings.forEach((warning) => toast.warning(warning))
      }
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to generate query')
    },
  })

  const resetSession = () => setSessionId(null)

  return {
    generate: generateMutation.mutate,
    isGenerating: generateMutation.isPending,
    data: generateMutation.data,
    error: generateMutation.error,
    resetSession,
  }
}

export function useQueryExecution(queryId) {
  return useMutation({
    mutationFn: () => queryApi.executeQuery(queryId),
    onError: (error) => {
      toast.error(error.message || 'Failed to execute query')
    },
  })
}

export function useQueryResults(queryId, options = {}) {
  return useQuery({
    queryKey: ['queryResults', queryId, options.page],
    queryFn: () => queryApi.getQueryResults(queryId, options.page, options.pageSize),
    enabled: !!queryId && options.enabled !== false,
    refetchInterval: (data) => {
      if (data?.status === 'RUNNING' || data?.status === 'QUEUED') {
        return 2000
      }
      return false
    },
  })
}
