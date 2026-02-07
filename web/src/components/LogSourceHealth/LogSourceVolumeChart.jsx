import { useMemo } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  ReferenceArea,
} from 'recharts'

const CHART_COLORS = {
  volume: '#525252',
  volumeGradientStart: 'rgba(82, 82, 82, 0.3)',
  volumeGradientEnd: 'rgba(82, 82, 82, 0)',
  baseline: '#3b82f6',
  stddevBand: 'rgba(59, 130, 246, 0.12)',
  gapOverlay: 'rgba(239, 68, 68, 0.2)',
}

function formatXAxisTick(epochMs, timeRange) {
  const date = new Date(epochMs)
  if (timeRange === '24h') {
    return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
  }
  if (timeRange === '7d') {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function formatFullDate(epochMs) {
  return new Date(epochMs).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg bg-mono-900 dark:bg-mono-100 px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-mono-50 dark:text-mono-900">
        {formatFullDate(label)}
      </p>
      <p className="text-mono-300 dark:text-mono-600">
        Events: {payload[0]?.value?.toLocaleString() ?? 0}
      </p>
    </div>
  )
}

export default function LogSourceVolumeChart({
  data = [],
  baseline = null,
  gapWindows = [],
  timeRange = '24h',
  isLoading = false,
}) {
  const chartData = useMemo(() => {
    return data.map((point) => ({
      timestamp: new Date(point.timestamp).getTime(),
      event_count: point.event_count,
    }))
  }, [data])

  const gapAreas = useMemo(() => {
    return gapWindows.map((gap) => ({
      x1: new Date(gap.start).getTime(),
      x2: new Date(gap.end).getTime(),
    }))
  }, [gapWindows])

  const baselineBounds = useMemo(() => {
    if (!baseline) return null
    return {
      mean: baseline.hourly_volume,
      upper: baseline.hourly_volume + baseline.hourly_stddev,
      lower: Math.max(0, baseline.hourly_volume - baseline.hourly_stddev),
    }
  }, [baseline])

  if (isLoading) {
    return (
      <div className="card">
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-mono-600 border-t-transparent" />
        </div>
      </div>
    )
  }

  if (!chartData || chartData.length === 0) {
    return (
      <div className="card">
        <div className="flex h-64 items-center justify-center">
          <p className="text-mono-500 dark:text-mono-400">No volume data available</p>
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="colorVolume" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={CHART_COLORS.volume} stopOpacity={0.3} />
              <stop offset="95%" stopColor={CHART_COLORS.volume} stopOpacity={0} />
            </linearGradient>
          </defs>

          <CartesianGrid strokeDasharray="3 3" stroke="#e5e5e5" />

          <XAxis
            dataKey="timestamp"
            type="number"
            domain={['dataMin', 'dataMax']}
            tickFormatter={(val) => formatXAxisTick(val, timeRange)}
            tick={{ fontSize: 12 }}
          />
          <YAxis tick={{ fontSize: 12 }} />

          <Tooltip content={<CustomTooltip />} />

          {baselineBounds && (
            <ReferenceArea
              y1={baselineBounds.lower}
              y2={baselineBounds.upper}
              fill={CHART_COLORS.stddevBand}
              strokeOpacity={0}
              ifOverflow="extendDomain"
            />
          )}

          {baselineBounds && (
            <ReferenceLine
              y={baselineBounds.mean}
              stroke={CHART_COLORS.baseline}
              strokeDasharray="5 5"
              label={{
                value: 'Baseline',
                position: 'right',
                fontSize: 11,
                fill: CHART_COLORS.baseline,
              }}
            />
          )}

          {gapAreas.map((gap, i) => (
            <ReferenceArea
              key={i}
              x1={gap.x1}
              x2={gap.x2}
              fill={CHART_COLORS.gapOverlay}
              strokeOpacity={0}
              ifOverflow="extendDomain"
            />
          ))}

          <Area
            type="monotone"
            dataKey="event_count"
            stroke={CHART_COLORS.volume}
            fillOpacity={1}
            fill="url(#colorVolume)"
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
