import clsx from 'clsx'
import { MapPinIcon, GlobeAltIcon } from '@heroicons/react/24/outline'

/**
 * Component to display known login locations.
 * Shows a simple list of locations with counts.
 */
export default function LocationsMap({ locations, className }) {
  if (!locations || locations.length === 0) {
    return (
      <div className={clsx('text-center py-4', className)}>
        <GlobeAltIcon className="mx-auto h-8 w-8 text-mono-400" />
        <p className="mt-2 text-sm text-mono-500 dark:text-mono-400">
          No location data available
        </p>
      </div>
    )
  }

  // Sort by count descending
  const sortedLocations = [...locations].sort((a, b) => {
    const countA = typeof a === 'object' ? a.count || 0 : 1
    const countB = typeof b === 'object' ? b.count || 0 : 1
    return countB - countA
  })

  // Normalize location data
  const normalizedLocations = sortedLocations.map((loc) => {
    if (typeof loc === 'string') {
      return { name: loc, count: 1, primary: false }
    }
    return {
      name: loc.name || loc.city || loc.country || 'Unknown',
      city: loc.city,
      country: loc.country,
      count: loc.count || 1,
      primary: loc.primary || false,
      lat: loc.lat,
      lon: loc.lon,
    }
  })

  const totalCount = normalizedLocations.reduce((sum, loc) => sum + loc.count, 0)

  return (
    <div className={className}>
      <div className="space-y-2">
        {normalizedLocations.slice(0, 10).map((location, index) => {
          const percentage = totalCount > 0 ? (location.count / totalCount) * 100 : 0

          return (
            <div
              key={index}
              className={clsx(
                'flex items-center gap-3 p-2 rounded-lg',
                location.primary && 'bg-primary-50 dark:bg-primary-900/20'
              )}
            >
              <MapPinIcon
                className={clsx(
                  'h-4 w-4 flex-shrink-0',
                  location.primary
                    ? 'text-primary-500'
                    : 'text-mono-400'
                )}
              />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-mono-900 dark:text-mono-100 truncate">
                    {location.name}
                  </span>
                  {location.primary && (
                    <span className="text-xs bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 px-1.5 py-0.5 rounded">
                      Primary
                    </span>
                  )}
                </div>
                {location.city && location.country && location.city !== location.name && (
                  <span className="text-xs text-mono-500 dark:text-mono-400">
                    {location.city}, {location.country}
                  </span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <div className="w-16 h-1.5 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary-500 rounded-full"
                    style={{ width: `${percentage}%` }}
                  />
                </div>
                <span className="text-xs font-medium text-mono-600 dark:text-mono-400 w-8 text-right">
                  {location.count}
                </span>
              </div>
            </div>
          )
        })}

        {normalizedLocations.length > 10 && (
          <p className="text-xs text-mono-500 dark:text-mono-400 text-center pt-2">
            +{normalizedLocations.length - 10} more locations
          </p>
        )}
      </div>

      {/* Summary */}
      <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-700">
        <div className="flex justify-between text-sm">
          <span className="text-mono-500 dark:text-mono-400">Total Locations</span>
          <span className="font-medium text-mono-700 dark:text-mono-300">
            {normalizedLocations.length}
          </span>
        </div>
        <div className="flex justify-between text-sm mt-1">
          <span className="text-mono-500 dark:text-mono-400">Total Logins</span>
          <span className="font-medium text-mono-700 dark:text-mono-300">
            {totalCount}
          </span>
        </div>
      </div>
    </div>
  )
}
