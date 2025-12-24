import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeftIcon, UserGroupIcon } from '@heroicons/react/24/outline'
import { useBaselines, useBaselineDetail } from '../hooks/useBaselines'
import BaselineList from '../components/Baselines/BaselineList'
import BaselineDetail from '../components/Baselines/BaselineDetail'

export default function Baselines() {
  const [selectedEmail, setSelectedEmail] = useState(null)

  const {
    baselines,
    total,
    isLoading,
    error,
    filters,
    pagination,
    updateFilters,
    goToPage,
    changeSort,
    refresh,
  } = useBaselines()

  const {
    baseline: selectedBaseline,
    isLoading: isLoadingDetail,
    error: detailError,
    isUpdating,
    reset,
    markServiceAccount,
    exclude,
    forceRebuild,
    refresh: refreshDetail,
  } = useBaselineDetail(selectedEmail)

  const handleSelectBaseline = (baseline) => {
    setSelectedEmail(baseline.user_email)
  }

  const handleReset = async () => {
    await reset()
    refresh()
  }

  const handleMarkServiceAccount = async (isService) => {
    await markServiceAccount(isService)
    refresh()
  }

  const handleExclude = async (excludeFlag, reason) => {
    await exclude(excludeFlag, reason)
    refresh()
  }

  const handleForceRebuild = async (daysBack) => {
    await forceRebuild(daysBack)
    refresh()
  }

  return (
    <div className="min-h-screen bg-mono-50 dark:bg-mono-950">
      {/* Header */}
      <div className="border-b border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 px-6 py-4">
        <div className="flex items-center gap-4">
          <Link
            to="/identity"
            className="flex items-center gap-2 text-sm font-medium text-mono-600 hover:text-mono-900 dark:text-mono-400 dark:hover:text-mono-100"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Identity Dashboard
          </Link>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <UserGroupIcon className="h-8 w-8 text-primary-600" />
          <div>
            <h1 className="text-2xl font-bold text-mono-900 dark:text-mono-100">
              User Baselines
            </h1>
            <p className="text-sm text-mono-500 dark:text-mono-400">
              View and manage behavioral baselines for identity threat detection
            </p>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Baseline List */}
          <div className="lg:col-span-2">
            <BaselineList
              baselines={baselines}
              total={total}
              isLoading={isLoading}
              filters={filters}
              pagination={pagination}
              onFilterChange={updateFilters}
              onSort={changeSort}
              onPageChange={goToPage}
              onSelectBaseline={handleSelectBaseline}
              selectedEmail={selectedEmail}
            />
          </div>

          {/* Baseline Detail Panel */}
          <div className="lg:col-span-1">
            <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 sticky top-6 max-h-[calc(100vh-8rem)] overflow-y-auto">
              <BaselineDetail
                baseline={selectedBaseline}
                isLoading={isLoadingDetail}
                error={detailError}
                isUpdating={isUpdating}
                onReset={handleReset}
                onMarkServiceAccount={handleMarkServiceAccount}
                onExclude={handleExclude}
                onForceRebuild={handleForceRebuild}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
