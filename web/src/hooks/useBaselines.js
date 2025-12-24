import { useState, useEffect, useCallback } from 'react'
import {
  getBaselines,
  getBaselineDetail,
  resetBaseline,
  updateBaselineSettings,
  markAsServiceAccount,
  excludeFromAnomalyDetection,
  forceRebuildBaseline,
  getBaselineStats,
} from '../services/baselineApi'

/**
 * Hook for fetching and managing baseline data with pagination.
 */
export function useBaselines(initialFilters = {}, initialPagination = {}) {
  const [baselines, setBaselines] = useState([])
  const [total, setTotal] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)

  const [filters, setFilters] = useState({
    search: '',
    status: 'all',
    provider: 'all',
    ...initialFilters,
  })

  const [pagination, setPagination] = useState({
    page: 1,
    pageSize: 25,
    sortBy: 'last_updated',
    sortOrder: 'desc',
    ...initialPagination,
  })

  const fetchBaselines = useCallback(async () => {
    setIsLoading(true)
    setError(null)

    try {
      const data = await getBaselines(filters, pagination)
      setBaselines(data.baselines || [])
      setTotal(data.total || 0)
    } catch (err) {
      setError(err.message)
      setBaselines([])
    } finally {
      setIsLoading(false)
    }
  }, [filters, pagination])

  useEffect(() => {
    fetchBaselines()
  }, [fetchBaselines])

  const updateFilters = useCallback((newFilters) => {
    setFilters((prev) => ({ ...prev, ...newFilters }))
    // Reset to first page when filters change
    setPagination((prev) => ({ ...prev, page: 1 }))
  }, [])

  const updatePagination = useCallback((newPagination) => {
    setPagination((prev) => ({ ...prev, ...newPagination }))
  }, [])

  const goToPage = useCallback((page) => {
    setPagination((prev) => ({ ...prev, page }))
  }, [])

  const changeSort = useCallback((sortBy) => {
    setPagination((prev) => ({
      ...prev,
      sortBy,
      sortOrder: prev.sortBy === sortBy && prev.sortOrder === 'desc' ? 'asc' : 'desc',
    }))
  }, [])

  const refresh = useCallback(() => {
    fetchBaselines()
  }, [fetchBaselines])

  return {
    baselines,
    total,
    isLoading,
    error,
    filters,
    pagination,
    updateFilters,
    updatePagination,
    goToPage,
    changeSort,
    refresh,
    totalPages: Math.ceil(total / pagination.pageSize),
  }
}

/**
 * Hook for fetching and managing a single baseline detail.
 */
export function useBaselineDetail(userEmail) {
  const [baseline, setBaseline] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [isUpdating, setIsUpdating] = useState(false)

  const fetchBaseline = useCallback(async () => {
    if (!userEmail) {
      setBaseline(null)
      setIsLoading(false)
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const data = await getBaselineDetail(userEmail)
      setBaseline(data)
    } catch (err) {
      setError(err.message)
      setBaseline(null)
    } finally {
      setIsLoading(false)
    }
  }, [userEmail])

  useEffect(() => {
    fetchBaseline()
  }, [fetchBaseline])

  const handleReset = useCallback(async () => {
    if (!userEmail) return

    setIsUpdating(true)
    try {
      await resetBaseline(userEmail)
      await fetchBaseline()
    } catch (err) {
      setError(err.message)
    } finally {
      setIsUpdating(false)
    }
  }, [userEmail, fetchBaseline])

  const handleUpdateSettings = useCallback(
    async (settings) => {
      if (!userEmail) return

      setIsUpdating(true)
      try {
        const updated = await updateBaselineSettings(userEmail, settings)
        setBaseline(updated)
      } catch (err) {
        setError(err.message)
      } finally {
        setIsUpdating(false)
      }
    },
    [userEmail]
  )

  const handleMarkServiceAccount = useCallback(
    async (isServiceAccount) => {
      if (!userEmail) return

      setIsUpdating(true)
      try {
        const updated = await markAsServiceAccount(userEmail, isServiceAccount)
        setBaseline(updated)
      } catch (err) {
        setError(err.message)
      } finally {
        setIsUpdating(false)
      }
    },
    [userEmail]
  )

  const handleExclude = useCallback(
    async (exclude, reason) => {
      if (!userEmail) return

      setIsUpdating(true)
      try {
        const updated = await excludeFromAnomalyDetection(userEmail, exclude, reason)
        setBaseline(updated)
      } catch (err) {
        setError(err.message)
      } finally {
        setIsUpdating(false)
      }
    },
    [userEmail]
  )

  const handleForceRebuild = useCallback(
    async (daysBack = 30) => {
      if (!userEmail) return

      setIsUpdating(true)
      try {
        await forceRebuildBaseline(userEmail, daysBack)
        // Refetch after rebuild is triggered
        setTimeout(fetchBaseline, 1000)
      } catch (err) {
        setError(err.message)
      } finally {
        setIsUpdating(false)
      }
    },
    [userEmail, fetchBaseline]
  )

  return {
    baseline,
    isLoading,
    error,
    isUpdating,
    refresh: fetchBaseline,
    reset: handleReset,
    updateSettings: handleUpdateSettings,
    markServiceAccount: handleMarkServiceAccount,
    exclude: handleExclude,
    forceRebuild: handleForceRebuild,
  }
}

/**
 * Hook for baseline statistics.
 */
export function useBaselineStats() {
  const [stats, setStats] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await getBaselineStats()
        setStats(data)
      } catch (err) {
        setError(err.message)
      } finally {
        setIsLoading(false)
      }
    }

    fetchStats()
  }, [])

  return { stats, isLoading, error }
}
