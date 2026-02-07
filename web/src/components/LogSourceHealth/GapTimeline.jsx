import { useState, useMemo } from 'react'
import clsx from 'clsx'

function formatDuration(seconds) {
  if (seconds < 60) return `${Math.round(seconds)}s`
  const mins = Math.floor(seconds / 60)
  const hours = Math.floor(seconds / 3600)
  const days = Math.floor(seconds / 86400)
  if (days > 0) {
    const remainingHours = Math.floor((seconds % 86400) / 3600)
    return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`
  }
  if (hours > 0) {
    const remainingMins = Math.floor((seconds % 3600) / 60)
    return remainingMins > 0 ? `${hours}h ${remainingMins}m` : `${hours}h`
  }
  return `${mins}m`
}

function formatTimestamp(iso) {
  if (!iso) return ''
  const date = new Date(iso)
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

export default function GapTimeline({ gaps = [], startTime, endTime, height = 40 }) {
  const [hoveredGap, setHoveredGap] = useState(null)

  const { timelineStart, totalDuration } = useMemo(() => {
    const start = new Date(startTime).getTime()
    const end = new Date(endTime).getTime()
    return { timelineStart: start, totalDuration: end - start }
  }, [startTime, endTime])

  const gapPositions = useMemo(() => {
    if (totalDuration <= 0) return []
    return gaps.map((gap) => {
      const gapStart = new Date(gap.start).getTime()
      const gapEnd = new Date(gap.end).getTime()
      const leftPercent = Math.max(0, ((gapStart - timelineStart) / totalDuration) * 100)
      const widthPercent = Math.max(0.5, Math.min(100 - leftPercent, ((gapEnd - gapStart) / totalDuration) * 100))
      return { leftPercent, widthPercent }
    })
  }, [gaps, timelineStart, totalDuration])

  return (
    <div className="card">
      <h4 className="text-sm font-medium text-mono-900 dark:text-mono-100 mb-3">Data Gaps</h4>

      {gaps.length === 0 ? (
        <p className="text-sm text-mono-500 dark:text-mono-400">
          No gaps detected in the selected time range
        </p>
      ) : (
        <>
          <div
            className="relative rounded-lg bg-mono-100 dark:bg-mono-800 overflow-hidden"
            style={{ height }}
          >
            {gaps.map((gap, index) => (
              <div
                key={index}
                className={clsx(
                  'absolute top-0 bottom-0 bg-red-400/60 dark:bg-red-500/40',
                  'border-l border-r border-red-500/30',
                  hoveredGap === index && 'bg-red-500/80 dark:bg-red-500/60 z-10',
                )}
                style={{
                  left: `${gapPositions[index]?.leftPercent || 0}%`,
                  width: `${gapPositions[index]?.widthPercent || 0.5}%`,
                }}
                onMouseEnter={() => setHoveredGap(index)}
                onMouseLeave={() => setHoveredGap(null)}
              >
                {hoveredGap === index && (
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-20 pointer-events-none">
                    <div className="bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-900 text-xs rounded-lg px-3 py-2 whitespace-nowrap shadow-lg">
                      <p className="font-medium">Gap: {formatDuration(gap.duration_seconds)}</p>
                      <p>{formatTimestamp(gap.start)} &mdash; {formatTimestamp(gap.end)}</p>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="flex justify-between mt-1 text-xs text-mono-500 dark:text-mono-400">
            <span>{formatTimestamp(startTime)}</span>
            <span>{formatTimestamp(endTime)}</span>
          </div>

          <p className="mt-2 text-xs text-mono-500 dark:text-mono-400">
            {gaps.length} gap{gaps.length !== 1 ? 's' : ''} detected
          </p>
        </>
      )}
    </div>
  )
}
