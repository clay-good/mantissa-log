import { useState } from 'react'
import clsx from 'clsx'
import {
  ArrowPathIcon,
  UserIcon,
  ShieldExclamationIcon,
  ClockIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline'

/**
 * Action buttons for baseline management.
 */
export default function BaselineActions({
  baseline,
  onReset,
  onMarkServiceAccount,
  onExclude,
  onForceRebuild,
  isUpdating,
}) {
  const [showExcludeModal, setShowExcludeModal] = useState(false)
  const [showRebuildModal, setShowRebuildModal] = useState(false)
  const [exclusionReason, setExclusionReason] = useState('')
  const [rebuildDays, setRebuildDays] = useState(30)

  const handleReset = () => {
    if (window.confirm('Are you sure you want to reset this baseline? All learned behavior will be lost.')) {
      onReset?.()
    }
  }

  const handleToggleServiceAccount = () => {
    const isCurrentlyService = baseline?.is_service_account
    const message = isCurrentlyService
      ? 'Remove service account designation? Normal detection rules will apply.'
      : 'Mark as service account? Different detection rules will apply for automated accounts.'

    if (window.confirm(message)) {
      onMarkServiceAccount?.(!isCurrentlyService)
    }
  }

  const handleExclude = () => {
    if (baseline?.excluded_from_detection) {
      // Re-enable detection
      if (window.confirm('Re-enable anomaly detection for this user?')) {
        onExclude?.(false, '')
      }
    } else {
      // Show exclusion modal
      setShowExcludeModal(true)
    }
  }

  const handleConfirmExclude = () => {
    onExclude?.(true, exclusionReason)
    setShowExcludeModal(false)
    setExclusionReason('')
  }

  const handleConfirmRebuild = () => {
    onForceRebuild?.(rebuildDays)
    setShowRebuildModal(false)
  }

  return (
    <div className="space-y-4">
      {/* Action Buttons */}
      <div className="grid grid-cols-2 gap-3">
        {/* Reset Baseline */}
        <button
          onClick={handleReset}
          disabled={isUpdating}
          className={clsx(
            'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors',
            'border-mono-200 dark:border-mono-700 hover:bg-mono-50 dark:hover:bg-mono-800',
            isUpdating && 'opacity-50 cursor-not-allowed'
          )}
        >
          <ArrowPathIcon className="h-6 w-6 text-mono-500" />
          <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
            Reset Baseline
          </span>
          <span className="text-xs text-mono-500 dark:text-mono-400 text-center">
            Start learning fresh
          </span>
        </button>

        {/* Mark as Service Account */}
        <button
          onClick={handleToggleServiceAccount}
          disabled={isUpdating}
          className={clsx(
            'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors',
            baseline?.is_service_account
              ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
              : 'border-mono-200 dark:border-mono-700 hover:bg-mono-50 dark:hover:bg-mono-800',
            isUpdating && 'opacity-50 cursor-not-allowed'
          )}
        >
          <UserIcon
            className={clsx(
              'h-6 w-6',
              baseline?.is_service_account ? 'text-blue-500' : 'text-mono-500'
            )}
          />
          <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
            {baseline?.is_service_account ? 'Service Account' : 'Mark as Service'}
          </span>
          <span className="text-xs text-mono-500 dark:text-mono-400 text-center">
            {baseline?.is_service_account ? 'Click to unmark' : 'Different rules apply'}
          </span>
        </button>

        {/* Exclude from Detection */}
        <button
          onClick={handleExclude}
          disabled={isUpdating}
          className={clsx(
            'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors',
            baseline?.excluded_from_detection
              ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20'
              : 'border-mono-200 dark:border-mono-700 hover:bg-mono-50 dark:hover:bg-mono-800',
            isUpdating && 'opacity-50 cursor-not-allowed'
          )}
        >
          <ShieldExclamationIcon
            className={clsx(
              'h-6 w-6',
              baseline?.excluded_from_detection ? 'text-orange-500' : 'text-mono-500'
            )}
          />
          <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
            {baseline?.excluded_from_detection ? 'Excluded' : 'Exclude'}
          </span>
          <span className="text-xs text-mono-500 dark:text-mono-400 text-center">
            {baseline?.excluded_from_detection
              ? 'Click to re-enable'
              : 'Skip anomaly detection'}
          </span>
        </button>

        {/* Force Rebuild */}
        <button
          onClick={() => setShowRebuildModal(true)}
          disabled={isUpdating}
          className={clsx(
            'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors',
            'border-mono-200 dark:border-mono-700 hover:bg-mono-50 dark:hover:bg-mono-800',
            isUpdating && 'opacity-50 cursor-not-allowed'
          )}
        >
          <ClockIcon className="h-6 w-6 text-mono-500" />
          <span className="text-sm font-medium text-mono-700 dark:text-mono-300">
            Force Rebuild
          </span>
          <span className="text-xs text-mono-500 dark:text-mono-400 text-center">
            Rebuild from history
          </span>
        </button>
      </div>

      {/* Status Indicators */}
      {(baseline?.is_service_account || baseline?.excluded_from_detection) && (
        <div className="space-y-2">
          {baseline?.is_service_account && (
            <div className="flex items-center gap-2 p-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300">
              <UserIcon className="h-4 w-4" />
              <span className="text-sm">Marked as service account</span>
            </div>
          )}
          {baseline?.excluded_from_detection && (
            <div className="flex items-start gap-2 p-2 rounded-lg bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300">
              <ExclamationTriangleIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <div>
                <span className="text-sm">Excluded from anomaly detection</span>
                {baseline.exclusion_reason && (
                  <p className="text-xs mt-1 opacity-80">
                    Reason: {baseline.exclusion_reason}
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Exclusion Modal */}
      {showExcludeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-mono-900/50">
          <div className="bg-white dark:bg-mono-900 rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100 mb-4">
              Exclude from Anomaly Detection
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 mb-4">
              This user will be excluded from all anomaly detection. Please provide a reason.
            </p>
            <textarea
              value={exclusionReason}
              onChange={(e) => setExclusionReason(e.target.value)}
              placeholder="Reason for exclusion (e.g., 'Executive with frequent travel', 'Known VPN user')"
              className="w-full rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100 mb-4"
              rows={3}
            />
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowExcludeModal(false)}
                className="px-4 py-2 text-sm font-medium text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmExclude}
                disabled={!exclusionReason.trim()}
                className="px-4 py-2 text-sm font-medium bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Exclude User
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rebuild Modal */}
      {showRebuildModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-mono-900/50">
          <div className="bg-white dark:bg-mono-900 rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100 mb-4">
              Force Rebuild Baseline
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 mb-4">
              Rebuild this user's baseline from historical data. This will replace the current baseline.
            </p>
            <div className="mb-4">
              <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-1">
                Days of history to use
              </label>
              <select
                value={rebuildDays}
                onChange={(e) => setRebuildDays(Number(e.target.value))}
                className="w-full rounded-lg border border-mono-300 dark:border-mono-600 bg-white dark:bg-mono-800 px-3 py-2 text-sm text-mono-900 dark:text-mono-100"
              >
                <option value={14}>14 days</option>
                <option value={30}>30 days</option>
                <option value={60}>60 days</option>
                <option value={90}>90 days</option>
              </select>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowRebuildModal(false)}
                className="px-4 py-2 text-sm font-medium text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmRebuild}
                className="px-4 py-2 text-sm font-medium bg-primary-600 text-white rounded-lg hover:bg-primary-700"
              >
                Rebuild Baseline
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
