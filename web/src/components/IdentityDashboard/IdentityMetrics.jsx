import { useMemo } from 'react'
import clsx from 'clsx'
import {
  ChartBarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
} from '@heroicons/react/24/outline'

const PROVIDER_COLORS = {
  okta: '#007DC1',
  azure: '#0078D4',
  google: '#4285F4',
  duo: '#6DC04B',
  m365: '#D83B01',
}

const SEVERITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#22C55E',
}

const ATTACK_TYPE_LABELS = {
  brute_force: 'Brute Force',
  credential_stuffing: 'Credential Stuffing',
  password_spray: 'Password Spray',
  mfa_fatigue: 'MFA Fatigue',
  mfa_bypass: 'MFA Bypass',
  impossible_travel: 'Impossible Travel',
  session_hijack: 'Session Hijack',
  privilege_escalation: 'Privilege Escalation',
  account_takeover: 'Account Takeover',
  token_theft: 'Token Theft',
  dormant_account: 'Dormant Account',
}

function PieChart({ data, colors, size = 120 }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  if (total === 0) return null

  let currentAngle = -90

  const segments = data.map((item) => {
    const percentage = (item.value / total) * 100
    const angle = (item.value / total) * 360
    const startAngle = currentAngle
    const endAngle = currentAngle + angle
    currentAngle = endAngle

    const startRad = (startAngle * Math.PI) / 180
    const endRad = (endAngle * Math.PI) / 180
    const radius = size / 2 - 2
    const cx = size / 2
    const cy = size / 2

    const x1 = cx + radius * Math.cos(startRad)
    const y1 = cy + radius * Math.sin(startRad)
    const x2 = cx + radius * Math.cos(endRad)
    const y2 = cy + radius * Math.sin(endRad)

    const largeArc = angle > 180 ? 1 : 0

    const pathData =
      angle >= 360
        ? `M ${cx} ${cy - radius} A ${radius} ${radius} 0 1 1 ${cx - 0.01} ${cy - radius} Z`
        : `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`

    return {
      ...item,
      percentage,
      pathData,
      color: colors[item.name.toLowerCase()] || '#94A3B8',
    }
  })

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {segments.map((segment, i) => (
        <path
          key={i}
          d={segment.pathData}
          fill={segment.color}
          className="transition-opacity hover:opacity-80"
        >
          <title>{`${segment.name}: ${segment.value} (${segment.percentage.toFixed(1)}%)`}</title>
        </path>
      ))}
      {/* Inner circle for donut effect */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={size / 4}
        fill="currentColor"
        className="text-white dark:text-mono-900"
      />
    </svg>
  )
}

function BarChart({ data, maxValue, colors }) {
  if (!data || data.length === 0) return null

  const max = maxValue || Math.max(...data.map((d) => d.value))

  return (
    <div className="space-y-2">
      {data.map((item, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="w-24 text-xs text-mono-600 dark:text-mono-400 truncate" title={item.name}>
            {item.name}
          </div>
          <div className="flex-1 h-4 bg-mono-100 dark:bg-mono-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${max > 0 ? (item.value / max) * 100 : 0}%`,
                backgroundColor: colors[item.name.toLowerCase()] || '#6366F1',
              }}
            />
          </div>
          <div className="w-8 text-xs font-medium text-mono-700 dark:text-mono-300 text-right">
            {item.value}
          </div>
        </div>
      ))}
    </div>
  )
}

function SparklineChart({ data, color = '#6366F1', height = 40 }) {
  if (!data || data.length < 2) return null

  const max = Math.max(...data.map((d) => d.value))
  const min = Math.min(...data.map((d) => d.value))
  const range = max - min || 1

  const width = 200
  const padding = 4

  const points = data.map((d, i) => {
    const x = padding + (i / (data.length - 1)) * (width - padding * 2)
    const y = height - padding - ((d.value - min) / range) * (height - padding * 2)
    return `${x},${y}`
  })

  const pathData = `M ${points.join(' L ')}`
  const areaPath = `${pathData} L ${width - padding},${height - padding} L ${padding},${height - padding} Z`

  return (
    <svg width={width} height={height} className="overflow-visible">
      <defs>
        <linearGradient id={`gradient-${color}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#gradient-${color})`} />
      <path d={pathData} fill="none" stroke={color} strokeWidth="2" />
      {/* Latest point */}
      <circle
        cx={width - padding}
        cy={height - padding - ((data[data.length - 1].value - min) / range) * (height - padding * 2)}
        r="3"
        fill={color}
      />
    </svg>
  )
}

function MetricCard({ title, children, className }) {
  return (
    <div
      className={clsx(
        'rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-4',
        className
      )}
    >
      <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300 mb-4">{title}</h4>
      {children}
    </div>
  )
}

function ChartLegend({ items, colors }) {
  return (
    <div className="flex flex-wrap gap-3 mt-4">
      {items.map((item, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <div
            className="h-2.5 w-2.5 rounded-full"
            style={{ backgroundColor: colors[item.name.toLowerCase()] || '#94A3B8' }}
          />
          <span className="text-xs text-mono-600 dark:text-mono-400">{item.name}</span>
        </div>
      ))}
    </div>
  )
}

export default function IdentityMetrics({ metrics, incidents }) {
  // Calculate auth failures by provider
  const authFailuresByProvider = useMemo(() => {
    if (!metrics?.auth_failures_by_provider) {
      // Derive from incidents if metrics not available
      const counts = {}
      incidents?.forEach((incident) => {
        if (incident.provider) {
          counts[incident.provider] = (counts[incident.provider] || 0) + 1
        }
      })
      return Object.entries(counts).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
      }))
    }
    return Object.entries(metrics.auth_failures_by_provider).map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
    }))
  }, [metrics, incidents])

  // Calculate attack type distribution
  const attackTypeDistribution = useMemo(() => {
    if (!metrics?.attack_type_distribution) {
      const counts = {}
      incidents?.forEach((incident) => {
        if (incident.attack_type) {
          const label = ATTACK_TYPE_LABELS[incident.attack_type] || incident.attack_type
          counts[label] = (counts[label] || 0) + 1
        }
      })
      return Object.entries(counts)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 5)
    }
    return Object.entries(metrics.attack_type_distribution)
      .map(([type, value]) => ({
        name: ATTACK_TYPE_LABELS[type] || type,
        value,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5)
  }, [metrics, incidents])

  // Calculate severity distribution
  const severityDistribution = useMemo(() => {
    if (!metrics?.severity_distribution) {
      const counts = { critical: 0, high: 0, medium: 0, low: 0 }
      incidents?.forEach((incident) => {
        if (incident.severity && counts.hasOwnProperty(incident.severity)) {
          counts[incident.severity]++
        }
      })
      return Object.entries(counts).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
      }))
    }
    return Object.entries(metrics.severity_distribution).map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
    }))
  }, [metrics, incidents])

  // Calculate attacks over time (hourly for last 24h)
  const attacksOverTime = useMemo(() => {
    if (metrics?.attacks_over_time) {
      return metrics.attacks_over_time.map((d) => ({
        time: d.time,
        value: d.count,
      }))
    }
    // Generate from incidents
    const now = new Date()
    const hourlyBuckets = Array.from({ length: 24 }, (_, i) => {
      const hour = new Date(now.getTime() - (23 - i) * 3600000)
      return {
        time: hour.toISOString(),
        value: 0,
      }
    })

    incidents?.forEach((incident) => {
      const incidentTime = new Date(incident.timestamp)
      const hoursDiff = Math.floor((now - incidentTime) / 3600000)
      if (hoursDiff >= 0 && hoursDiff < 24) {
        const bucketIndex = 23 - hoursDiff
        hourlyBuckets[bucketIndex].value++
      }
    })

    return hourlyBuckets
  }, [metrics, incidents])

  // Calculate trend
  const trend = useMemo(() => {
    if (attacksOverTime.length < 12) return null
    const firstHalf = attacksOverTime.slice(0, 12).reduce((sum, d) => sum + d.value, 0)
    const secondHalf = attacksOverTime.slice(12).reduce((sum, d) => sum + d.value, 0)
    if (firstHalf === 0) return secondHalf > 0 ? 100 : 0
    return Math.round(((secondHalf - firstHalf) / firstHalf) * 100)
  }, [attacksOverTime])

  if (!incidents || incidents.length === 0) {
    return (
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-8">
        <div className="text-center text-mono-500 dark:text-mono-400">
          <ChartBarIcon className="mx-auto h-12 w-12 text-mono-400" />
          <p className="mt-2">No metrics data available</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
          Identity Threat Metrics
        </h3>
        {trend !== null && (
          <div
            className={clsx(
              'flex items-center gap-1 text-sm font-medium',
              trend > 0 ? 'text-red-600' : trend < 0 ? 'text-green-600' : 'text-mono-500'
            )}
          >
            {trend > 0 ? (
              <ArrowTrendingUpIcon className="h-4 w-4" />
            ) : trend < 0 ? (
              <ArrowTrendingDownIcon className="h-4 w-4" />
            ) : null}
            {Math.abs(trend)}% vs previous 12h
          </div>
        )}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Auth Failures by Provider */}
        <MetricCard title="Auth Failures by Provider">
          <div className="flex items-center gap-4">
            <PieChart data={authFailuresByProvider} colors={PROVIDER_COLORS} size={100} />
            <ChartLegend items={authFailuresByProvider} colors={PROVIDER_COLORS} />
          </div>
        </MetricCard>

        {/* Attack Types Distribution */}
        <MetricCard title="Top Attack Types">
          <BarChart
            data={attackTypeDistribution}
            colors={{
              'brute force': '#EF4444',
              'credential stuffing': '#F97316',
              'password spray': '#EAB308',
              'mfa fatigue': '#8B5CF6',
              'impossible travel': '#06B6D4',
              'session hijack': '#EC4899',
              'privilege escalation': '#F43F5E',
              'account takeover': '#DC2626',
              'token theft': '#7C3AED',
            }}
          />
        </MetricCard>

        {/* Severity Distribution */}
        <MetricCard title="Severity Distribution">
          <div className="flex items-center gap-4">
            <PieChart data={severityDistribution} colors={SEVERITY_COLORS} size={100} />
            <div className="flex-1 space-y-1">
              {severityDistribution.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div
                      className="h-2.5 w-2.5 rounded-full"
                      style={{
                        backgroundColor: SEVERITY_COLORS[item.name.toLowerCase()] || '#94A3B8',
                      }}
                    />
                    <span className="text-xs text-mono-600 dark:text-mono-400">{item.name}</span>
                  </div>
                  <span className="text-xs font-medium text-mono-700 dark:text-mono-300">
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </MetricCard>

        {/* Attacks Over Time */}
        <MetricCard title="Attacks Over Time (24h)">
          <div className="flex items-center justify-center">
            <SparklineChart data={attacksOverTime} color="#6366F1" height={60} />
          </div>
          <div className="flex justify-between text-xs text-mono-500 dark:text-mono-400 mt-2">
            <span>24h ago</span>
            <span>Now</span>
          </div>
        </MetricCard>
      </div>
    </div>
  )
}
