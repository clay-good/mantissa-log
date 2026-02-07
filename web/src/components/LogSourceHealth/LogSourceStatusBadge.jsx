import clsx from 'clsx'

const STATUS_COLORS = {
  HEALTHY: {
    bg: 'bg-green-100 dark:bg-green-900/30',
    text: 'text-green-700 dark:text-green-400',
    border: 'border-green-300 dark:border-green-700',
    dot: 'bg-green-500',
  },
  DELAYED: {
    bg: 'bg-yellow-100 dark:bg-yellow-900/30',
    text: 'text-yellow-700 dark:text-yellow-400',
    border: 'border-yellow-300 dark:border-yellow-700',
    dot: 'bg-yellow-500',
  },
  SILENT: {
    bg: 'bg-red-100 dark:bg-red-900/30',
    text: 'text-red-700 dark:text-red-400',
    border: 'border-red-300 dark:border-red-700',
    dot: 'bg-red-500',
  },
  VOLUME_ANOMALY: {
    bg: 'bg-orange-100 dark:bg-orange-900/30',
    text: 'text-orange-700 dark:text-orange-400',
    border: 'border-orange-300 dark:border-orange-700',
    dot: 'bg-orange-500',
  },
  UNKNOWN: {
    bg: 'bg-mono-100 dark:bg-mono-800',
    text: 'text-mono-600 dark:text-mono-400',
    border: 'border-mono-300 dark:border-mono-700',
    dot: 'bg-mono-400',
  },
}

const STATUS_LABELS = {
  HEALTHY: 'Healthy',
  DELAYED: 'Delayed',
  SILENT: 'Silent',
  VOLUME_ANOMALY: 'Volume Anomaly',
  UNKNOWN: 'Unknown',
}

const STATUS_DESCRIPTIONS = {
  HEALTHY: 'Source is reporting events within expected parameters',
  DELAYED: 'Source events are arriving later than the expected latency threshold',
  SILENT: 'No events received within the silence threshold period',
  VOLUME_ANOMALY: 'Event volume deviates significantly from the established baseline',
  UNKNOWN: 'Source health has not been evaluated yet',
}

export default function LogSourceStatusBadge({ status, size = 'default', showDot = true }) {
  const colors = STATUS_COLORS[status] || STATUS_COLORS.UNKNOWN
  const label = STATUS_LABELS[status] || 'Unknown'
  const description = STATUS_DESCRIPTIONS[status] || STATUS_DESCRIPTIONS.UNKNOWN
  const shouldPulse = status === 'DELAYED' || status === 'SILENT' || status === 'VOLUME_ANOMALY'

  return (
    <div className="tooltip inline-flex">
      <span
        className={clsx(
          'badge border',
          colors.bg,
          colors.text,
          colors.border,
          size === 'sm' && 'text-xs px-2 py-0.5',
        )}
      >
        {showDot && (
          <span
            className={clsx(
              'status-dot mr-1.5',
              colors.dot,
              shouldPulse && 'animate-pulse',
            )}
          />
        )}
        {label}
      </span>
      <span className="tooltip-content">{description}</span>
    </div>
  )
}
