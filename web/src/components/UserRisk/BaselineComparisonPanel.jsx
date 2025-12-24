import clsx from 'clsx'
import {
  ClockIcon,
  MapPinIcon,
  ComputerDesktopIcon,
  Square3Stack3DIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
} from '@heroicons/react/24/outline'

function ComparisonSection({ title, icon: Icon, baseline, current, renderItem }) {
  const baselineItems = baseline || []
  const currentItems = current || []

  // Find new items (in current but not in baseline)
  const newItems = currentItems.filter((item) => !baselineItems.includes(item))
  const knownItems = currentItems.filter((item) => baselineItems.includes(item))

  const hasDeviations = newItems.length > 0

  return (
    <div className="py-3">
      <div className="flex items-center gap-2 mb-2">
        <Icon className="h-4 w-4 text-mono-400" />
        <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300">{title}</h4>
        {hasDeviations && (
          <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />
        )}
      </div>

      <div className="space-y-2">
        {/* Known items */}
        {knownItems.length > 0 && (
          <div className="space-y-1">
            {knownItems.map((item, i) => (
              <div
                key={i}
                className="flex items-center gap-2 text-sm text-mono-600 dark:text-mono-400"
              >
                <CheckCircleIcon className="h-3 w-3 text-green-500" />
                {renderItem ? renderItem(item) : item}
              </div>
            ))}
          </div>
        )}

        {/* New/deviation items */}
        {newItems.length > 0 && (
          <div className="space-y-1">
            {newItems.map((item, i) => (
              <div
                key={i}
                className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400 font-medium"
              >
                <ExclamationTriangleIcon className="h-3 w-3" />
                {renderItem ? renderItem(item) : item}
                <span className="text-xs bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 px-1.5 py-0.5 rounded">
                  New
                </span>
              </div>
            ))}
          </div>
        )}

        {knownItems.length === 0 && newItems.length === 0 && (
          <p className="text-xs text-mono-500 dark:text-mono-500">No data available</p>
        )}
      </div>
    </div>
  )
}

function LoginHoursComparison({ baseline, current }) {
  // baseline and current are arrays like [9, 10, 11, 12, 13, 14, 15, 16, 17]
  const baselineHours = baseline?.typical_hours || []
  const currentHour = current?.recent_hours || []

  // Check for off-hours activity
  const offHoursActivity = currentHour.filter((h) => !baselineHours.includes(h))
  const hasDeviation = offHoursActivity.length > 0

  const formatHour = (hour) => {
    const suffix = hour >= 12 ? 'PM' : 'AM'
    const displayHour = hour > 12 ? hour - 12 : hour === 0 ? 12 : hour
    return `${displayHour}${suffix}`
  }

  return (
    <div className="py-3">
      <div className="flex items-center gap-2 mb-2">
        <ClockIcon className="h-4 w-4 text-mono-400" />
        <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300">Login Hours</h4>
        {hasDeviation && (
          <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />
        )}
      </div>

      {/* Hour visualization */}
      <div className="flex gap-0.5 mb-2">
        {Array.from({ length: 24 }, (_, hour) => {
          const isBaseline = baselineHours.includes(hour)
          const isCurrent = currentHour.includes(hour)
          const isDeviation = isCurrent && !isBaseline

          return (
            <div
              key={hour}
              className={clsx(
                'h-6 w-2 rounded-sm',
                isDeviation
                  ? 'bg-red-500'
                  : isCurrent
                  ? 'bg-green-500'
                  : isBaseline
                  ? 'bg-mono-300 dark:bg-mono-600'
                  : 'bg-mono-100 dark:bg-mono-800'
              )}
              title={`${formatHour(hour)}${isDeviation ? ' (unusual)' : isCurrent ? ' (recent)' : isBaseline ? ' (normal)' : ''}`}
            />
          )
        })}
      </div>

      <div className="flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-sm bg-mono-300 dark:bg-mono-600" />
          <span className="text-mono-500">Normal</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-sm bg-green-500" />
          <span className="text-mono-500">Recent</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-sm bg-red-500" />
          <span className="text-mono-500">Unusual</span>
        </div>
      </div>
    </div>
  )
}

export default function BaselineComparisonPanel({ baseline, current }) {
  const hasBaseline = baseline && Object.keys(baseline).length > 0

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-mono-900 dark:text-mono-100">
          Baseline Comparison
        </h3>
        <p className="text-xs text-mono-500 dark:text-mono-400">
          Current behavior vs established baseline
        </p>
      </div>

      <div className="px-4 divide-y divide-mono-200 dark:divide-mono-800">
        {!hasBaseline ? (
          <div className="py-6 text-center">
            <ClockIcon className="mx-auto h-8 w-8 text-mono-400" />
            <p className="mt-2 text-sm text-mono-500 dark:text-mono-400">
              Baseline not yet established
            </p>
            <p className="text-xs text-mono-400">
              Requires 14 days of activity data
            </p>
          </div>
        ) : (
          <>
            {/* Login Hours */}
            <LoginHoursComparison
              baseline={baseline?.login_hours}
              current={current?.login_hours}
            />

            {/* Locations */}
            <ComparisonSection
              title="Locations"
              icon={MapPinIcon}
              baseline={baseline?.locations}
              current={current?.locations}
            />

            {/* Devices */}
            <ComparisonSection
              title="Devices"
              icon={ComputerDesktopIcon}
              baseline={baseline?.devices}
              current={current?.devices}
            />

            {/* Applications */}
            <ComparisonSection
              title="Applications"
              icon={Square3Stack3DIcon}
              baseline={baseline?.applications}
              current={current?.applications}
            />
          </>
        )}
      </div>

      {hasBaseline && baseline?.baseline_period && (
        <div className="border-t border-mono-200 dark:border-mono-800 px-4 py-2">
          <p className="text-xs text-mono-500 dark:text-mono-500">
            Baseline period: {baseline.baseline_period}
          </p>
        </div>
      )}
    </div>
  )
}
