import clsx from 'clsx'

/**
 * 24-hour heatmap showing typical login hours.
 * Darker colors indicate more activity.
 */
export default function LoginHoursChart({ hours, currentHour }) {
  // hours is expected to be an object { 0: count, 1: count, ... 23: count }
  // or an array of hour numbers [9, 10, 11, ...]

  // Normalize to counts object
  const hourCounts = {}
  for (let i = 0; i < 24; i++) {
    hourCounts[i] = 0
  }

  if (Array.isArray(hours)) {
    hours.forEach((hour) => {
      hourCounts[hour] = (hourCounts[hour] || 0) + 1
    })
  } else if (hours && typeof hours === 'object') {
    Object.entries(hours).forEach(([hour, count]) => {
      hourCounts[parseInt(hour, 10)] = count
    })
  }

  const maxCount = Math.max(...Object.values(hourCounts), 1)

  const formatHour = (hour) => {
    if (hour === 0) return '12a'
    if (hour === 12) return '12p'
    if (hour < 12) return `${hour}a`
    return `${hour - 12}p`
  }

  const getIntensity = (count) => {
    if (count === 0) return 0
    return Math.ceil((count / maxCount) * 4)
  }

  const intensityClasses = {
    0: 'bg-mono-100 dark:bg-mono-800',
    1: 'bg-primary-200 dark:bg-primary-900/40',
    2: 'bg-primary-400 dark:bg-primary-700/60',
    3: 'bg-primary-500 dark:bg-primary-600/80',
    4: 'bg-primary-600 dark:bg-primary-500',
  }

  return (
    <div>
      <div className="flex gap-0.5">
        {Array.from({ length: 24 }, (_, hour) => {
          const count = hourCounts[hour] || 0
          const intensity = getIntensity(count)
          const isCurrent = currentHour === hour

          return (
            <div
              key={hour}
              className={clsx(
                'flex-1 h-8 rounded-sm transition-all relative group',
                intensityClasses[intensity],
                isCurrent && 'ring-2 ring-yellow-400'
              )}
              title={`${formatHour(hour)}: ${count} login${count !== 1 ? 's' : ''}`}
            >
              {/* Tooltip */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block z-10">
                <div className="bg-mono-900 text-white text-xs px-2 py-1 rounded whitespace-nowrap">
                  {formatHour(hour)}: {count}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Hour labels */}
      <div className="flex justify-between mt-1 text-xs text-mono-500 dark:text-mono-400">
        <span>12a</span>
        <span>6a</span>
        <span>12p</span>
        <span>6p</span>
        <span>12a</span>
      </div>

      {/* Legend */}
      <div className="flex items-center justify-end gap-2 mt-2">
        <span className="text-xs text-mono-500 dark:text-mono-400">Less</span>
        <div className="flex gap-0.5">
          {[0, 1, 2, 3, 4].map((level) => (
            <div
              key={level}
              className={clsx('w-3 h-3 rounded-sm', intensityClasses[level])}
            />
          ))}
        </div>
        <span className="text-xs text-mono-500 dark:text-mono-400">More</span>
      </div>
    </div>
  )
}
