import clsx from 'clsx'
import {
  ChevronUpDownIcon,
  ChevronUpIcon,
  ChevronDownIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  UserCircleIcon,
} from '@heroicons/react/24/outline'

const STATUS_STYLES = {
  mature: {
    label: 'Mature',
    color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  },
  learning: {
    label: 'Learning',
    color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  },
  stale: {
    label: 'Stale',
    color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  },
  new: {
    label: 'New',
    color: 'bg-mono-100 text-mono-800 dark:bg-mono-800 dark:text-mono-300',
  },
}

const STATUS_OPTIONS = [
  { value: 'all', label: 'All Statuses' },
  { value: 'mature', label: 'Mature' },
  { value: 'learning', label: 'Learning' },
  { value: 'stale', label: 'Stale' },
  { value: 'new', label: 'New' },
]

const PROVIDER_OPTIONS = [
  { value: 'all', label: 'All Providers' },
  { value: 'okta', label: 'Okta' },
  { value: 'azure', label: 'Azure AD' },
  { value: 'google', label: 'Google Workspace' },
  { value: 'duo', label: 'Duo' },
  { value: 'm365', label: 'Microsoft 365' },
]

function SortIcon({ sortKey, currentSort, currentDirection }) {
  if (currentSort !== sortKey) {
    return <ChevronUpDownIcon className="h-4 w-4 text-mono-400" />
  }
  return currentDirection === 'asc' ? (
    <ChevronUpIcon className="h-4 w-4 text-primary-600" />
  ) : (
    <ChevronDownIcon className="h-4 w-4 text-primary-600" />
  )
}

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

function formatNumber(num) {
  if (num === undefined || num === null) return '-'
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

function ConfidenceBar({ confidence }) {
  const percentage = Math.min(100, Math.max(0, confidence || 0))

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-2 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
        <div
          className={clsx(
            'h-full rounded-full transition-all',
            percentage >= 80
              ? 'bg-green-500'
              : percentage >= 50
              ? 'bg-yellow-500'
              : 'bg-red-500'
          )}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="text-xs text-mono-500 dark:text-mono-400 w-8">
        {percentage}%
      </span>
    </div>
  )
}

function Pagination({ page, totalPages, onPageChange }) {
  if (totalPages <= 1) return null

  const pages = []
  const maxVisible = 5

  let start = Math.max(1, page - Math.floor(maxVisible / 2))
  let end = Math.min(totalPages, start + maxVisible - 1)

  if (end - start + 1 < maxVisible) {
    start = Math.max(1, end - maxVisible + 1)
  }

  for (let i = start; i <= end; i++) {
    pages.push(i)
  }

  return (
    <div className="flex items-center justify-center gap-1 mt-4">
      <button
        onClick={() => onPageChange(page - 1)}
        disabled={page <= 1}
        className="px-3 py-1 text-sm font-medium text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800 rounded disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Previous
      </button>

      {start > 1 && (
        <>
          <button
            onClick={() => onPageChange(1)}
            className="px-3 py-1 text-sm font-medium text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800 rounded"
          >
            1
          </button>
          {start > 2 && <span className="px-2 text-mono-400">...</span>}
        </>
      )}

      {pages.map((p) => (
        <button
          key={p}
          onClick={() => onPageChange(p)}
          className={clsx(
            'px-3 py-1 text-sm font-medium rounded',
            p === page
              ? 'bg-primary-600 text-white'
              : 'text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800'
          )}
        >
          {p}
        </button>
      ))}

      {end < totalPages && (
        <>
          {end < totalPages - 1 && <span className="px-2 text-mono-400">...</span>}
          <button
            onClick={() => onPageChange(totalPages)}
            className="px-3 py-1 text-sm font-medium text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800 rounded"
          >
            {totalPages}
          </button>
        </>
      )}

      <button
        onClick={() => onPageChange(page + 1)}
        disabled={page >= totalPages}
        className="px-3 py-1 text-sm font-medium text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800 rounded disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Next
      </button>
    </div>
  )
}

export default function BaselineList({
  baselines,
  total,
  isLoading,
  filters,
  pagination,
  onFilterChange,
  onSort,
  onPageChange,
  onSelectBaseline,
  selectedEmail,
}) {
  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      {/* Search and Filters */}
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-mono-400" />
            <input
              type="text"
              placeholder="Search by email..."
              value={filters.search || ''}
              onChange={(e) => onFilterChange({ search: e.target.value })}
              className="w-full pl-9 pr-3 py-2 rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 text-sm text-mono-900 dark:text-mono-100"
            />
          </div>

          {/* Status Filter */}
          <select
            value={filters.status || 'all'}
            onChange={(e) => onFilterChange({ status: e.target.value })}
            className="rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
          >
            {STATUS_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          {/* Provider Filter */}
          <select
            value={filters.provider || 'all'}
            onChange={(e) => onFilterChange({ provider: e.target.value })}
            className="rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
          >
            {PROVIDER_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="mt-2 text-xs text-mono-500 dark:text-mono-400">
          {total} baseline{total !== 1 ? 's' : ''} found
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-mono-200 dark:divide-mono-800">
          <thead className="bg-mono-50 dark:bg-mono-800/50">
            <tr>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => onSort('user_email')}
              >
                <div className="flex items-center gap-1">
                  User
                  <SortIcon
                    sortKey="user_email"
                    currentSort={pagination.sortBy}
                    currentDirection={pagination.sortOrder}
                  />
                </div>
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => onSort('maturity_days')}
              >
                <div className="flex items-center gap-1">
                  Maturity
                  <SortIcon
                    sortKey="maturity_days"
                    currentSort={pagination.sortBy}
                    currentDirection={pagination.sortOrder}
                  />
                </div>
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => onSort('confidence')}
              >
                <div className="flex items-center gap-1">
                  Confidence
                  <SortIcon
                    sortKey="confidence"
                    currentSort={pagination.sortBy}
                    currentDirection={pagination.sortOrder}
                  />
                </div>
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => onSort('event_count')}
              >
                <div className="flex items-center gap-1">
                  Events
                  <SortIcon
                    sortKey="event_count"
                    currentSort={pagination.sortBy}
                    currentDirection={pagination.sortOrder}
                  />
                </div>
              </th>
              <th
                className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-700"
                onClick={() => onSort('last_updated')}
              >
                <div className="flex items-center gap-1">
                  Last Updated
                  <SortIcon
                    sortKey="last_updated"
                    currentSort={pagination.sortBy}
                    currentDirection={pagination.sortOrder}
                  />
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-500 dark:text-mono-400">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-mono-200 dark:divide-mono-800">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center">
                  <div className="h-8 w-8 mx-auto animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
                </td>
              </tr>
            ) : baselines.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-mono-500 dark:text-mono-400">
                  No baselines found
                </td>
              </tr>
            ) : (
              baselines.map((baseline) => {
                const status = STATUS_STYLES[baseline.status] || STATUS_STYLES.new
                const isSelected = selectedEmail === baseline.user_email

                return (
                  <tr
                    key={baseline.user_email}
                    className={clsx(
                      'cursor-pointer transition-colors',
                      isSelected
                        ? 'bg-primary-50 dark:bg-primary-900/20'
                        : 'hover:bg-mono-50 dark:hover:bg-mono-800/50'
                    )}
                    onClick={() => onSelectBaseline(baseline)}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <UserCircleIcon className="h-8 w-8 text-mono-400" />
                        <div>
                          <div className="text-sm font-medium text-mono-900 dark:text-mono-100">
                            {baseline.user_email}
                          </div>
                          {baseline.display_name && (
                            <div className="text-xs text-mono-500 dark:text-mono-400">
                              {baseline.display_name}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-mono-700 dark:text-mono-300">
                        {baseline.maturity_days || 0} days
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <ConfidenceBar confidence={baseline.confidence} />
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-mono-700 dark:text-mono-300">
                        {formatNumber(baseline.event_count)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-mono-700 dark:text-mono-300">
                        {formatDate(baseline.last_updated)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={clsx(
                          'inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold',
                          status.color
                        )}
                      >
                        {status.label}
                      </span>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="border-t border-mono-200 dark:border-mono-800 px-4 py-3">
        <Pagination
          page={pagination.page}
          totalPages={Math.ceil(total / pagination.pageSize)}
          onPageChange={onPageChange}
        />
      </div>
    </div>
  )
}
