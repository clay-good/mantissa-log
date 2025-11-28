import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#2563eb',
}

export default function AlertTimeline({ data, isLoading }) {
  if (isLoading) {
    return (
      <div className="card">
        <h3 className="mb-4 text-lg font-medium text-gray-900">Alert Timeline</h3>
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent"></div>
        </div>
      </div>
    )
  }

  if (!data || !data.timeline || data.timeline.length === 0) {
    return (
      <div className="card">
        <h3 className="mb-4 text-lg font-medium text-gray-900">Alert Timeline</h3>
        <div className="flex h-64 items-center justify-center">
          <p className="text-gray-500">No timeline data available</p>
        </div>
      </div>
    )
  }

  const formatXAxis = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }

  const formatTooltip = (value, name) => {
    return [value, name.charAt(0).toUpperCase() + name.slice(1)]
  }

  return (
    <div className="card">
      <h3 className="mb-4 text-lg font-medium text-gray-900">Alert Timeline</h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart
          data={data.timeline}
          margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
        >
          <defs>
            <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={SEVERITY_COLORS.critical} stopOpacity={0.8} />
              <stop offset="95%" stopColor={SEVERITY_COLORS.critical} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={SEVERITY_COLORS.high} stopOpacity={0.8} />
              <stop offset="95%" stopColor={SEVERITY_COLORS.high} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={SEVERITY_COLORS.medium} stopOpacity={0.8} />
              <stop offset="95%" stopColor={SEVERITY_COLORS.medium} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={SEVERITY_COLORS.low} stopOpacity={0.8} />
              <stop offset="95%" stopColor={SEVERITY_COLORS.low} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={formatXAxis}
            tick={{ fontSize: 12 }}
          />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip formatter={formatTooltip} />
          <Area
            type="monotone"
            dataKey="critical"
            stackId="1"
            stroke={SEVERITY_COLORS.critical}
            fillOpacity={1}
            fill="url(#colorCritical)"
          />
          <Area
            type="monotone"
            dataKey="high"
            stackId="1"
            stroke={SEVERITY_COLORS.high}
            fillOpacity={1}
            fill="url(#colorHigh)"
          />
          <Area
            type="monotone"
            dataKey="medium"
            stackId="1"
            stroke={SEVERITY_COLORS.medium}
            fillOpacity={1}
            fill="url(#colorMedium)"
          />
          <Area
            type="monotone"
            dataKey="low"
            stackId="1"
            stroke={SEVERITY_COLORS.low}
            fillOpacity={1}
            fill="url(#colorLow)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
