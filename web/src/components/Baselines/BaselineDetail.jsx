import clsx from 'clsx'
import {
  UserCircleIcon,
  ClockIcon,
  ChartBarIcon,
  MapPinIcon,
  ComputerDesktopIcon,
  Square3Stack3DIcon,
  ShieldCheckIcon,
  CalendarIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import LoginHoursChart from './LoginHoursChart'
import LocationsMap from './LocationsMap'
import BaselineActions from './BaselineActions'

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

const DAYS_OF_WEEK = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function Section({ title, icon: Icon, children }) {
  return (
    <div className="py-4">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="h-5 w-5 text-mono-400" />
        <h4 className="text-sm font-semibold text-mono-900 dark:text-mono-100">{title}</h4>
      </div>
      {children}
    </div>
  )
}

function StatCard({ label, value, subValue }) {
  return (
    <div className="text-center p-3 rounded-lg bg-mono-50 dark:bg-mono-800">
      <div className="text-2xl font-bold text-mono-900 dark:text-mono-100">{value}</div>
      <div className="text-xs text-mono-500 dark:text-mono-400">{label}</div>
      {subValue && (
        <div className="text-xs text-mono-400 dark:text-mono-500 mt-1">{subValue}</div>
      )}
    </div>
  )
}

function WeekDaysChart({ days }) {
  // days is expected to be an object { 0: count, 1: count, ... 6: count }
  // or an array of day numbers

  const dayCounts = {}
  for (let i = 0; i < 7; i++) {
    dayCounts[i] = 0
  }

  if (Array.isArray(days)) {
    days.forEach((day) => {
      dayCounts[day] = (dayCounts[day] || 0) + 1
    })
  } else if (days && typeof days === 'object') {
    Object.entries(days).forEach(([day, count]) => {
      dayCounts[parseInt(day, 10)] = count
    })
  }

  const maxCount = Math.max(...Object.values(dayCounts), 1)

  return (
    <div className="flex gap-1">
      {DAYS_OF_WEEK.map((dayName, index) => {
        const count = dayCounts[index] || 0
        const intensity = count > 0 ? Math.ceil((count / maxCount) * 4) : 0

        const intensityClasses = {
          0: 'bg-mono-100 dark:bg-mono-800',
          1: 'bg-primary-200 dark:bg-primary-900/40',
          2: 'bg-primary-400 dark:bg-primary-700/60',
          3: 'bg-primary-500 dark:bg-primary-600/80',
          4: 'bg-primary-600 dark:bg-primary-500',
        }

        return (
          <div key={index} className="flex-1 text-center">
            <div
              className={clsx(
                'h-8 rounded-md mb-1 transition-colors',
                intensityClasses[intensity]
              )}
              title={`${dayName}: ${count} login${count !== 1 ? 's' : ''}`}
            />
            <span className="text-xs text-mono-500 dark:text-mono-400">{dayName}</span>
          </div>
        )
      })}
    </div>
  )
}

function DevicesList({ devices }) {
  if (!devices || devices.length === 0) {
    return (
      <p className="text-sm text-mono-500 dark:text-mono-400">No devices recorded</p>
    )
  }

  return (
    <div className="space-y-2">
      {devices.slice(0, 5).map((device, index) => {
        const deviceInfo = typeof device === 'string' ? { name: device } : device

        return (
          <div
            key={index}
            className="flex items-start gap-3 p-2 rounded-lg bg-mono-50 dark:bg-mono-800"
          >
            <ComputerDesktopIcon className="h-4 w-4 text-mono-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-mono-900 dark:text-mono-100 truncate">
                {deviceInfo.name || deviceInfo.device_type || 'Unknown Device'}
              </div>
              {deviceInfo.user_agent && (
                <div className="text-xs text-mono-500 dark:text-mono-400 truncate">
                  {deviceInfo.user_agent}
                </div>
              )}
              {deviceInfo.count && (
                <div className="text-xs text-mono-400">{deviceInfo.count} logins</div>
              )}
            </div>
          </div>
        )
      })}
      {devices.length > 5 && (
        <p className="text-xs text-mono-500 dark:text-mono-400">
          +{devices.length - 5} more devices
        </p>
      )}
    </div>
  )
}

function ApplicationsList({ applications }) {
  if (!applications || applications.length === 0) {
    return (
      <p className="text-sm text-mono-500 dark:text-mono-400">No applications recorded</p>
    )
  }

  return (
    <div className="flex flex-wrap gap-2">
      {applications.slice(0, 10).map((app, index) => {
        const appInfo = typeof app === 'string' ? { name: app } : app

        return (
          <span
            key={index}
            className="inline-flex items-center gap-1 rounded-full bg-mono-100 dark:bg-mono-800 px-2.5 py-1 text-xs font-medium text-mono-700 dark:text-mono-300"
          >
            {appInfo.name || 'Unknown'}
            {appInfo.count && (
              <span className="text-mono-500">({appInfo.count})</span>
            )}
          </span>
        )
      })}
      {applications.length > 10 && (
        <span className="text-xs text-mono-500">+{applications.length - 10} more</span>
      )}
    </div>
  )
}

function AuthMethodsList({ methods }) {
  if (!methods || methods.length === 0) {
    return (
      <p className="text-sm text-mono-500 dark:text-mono-400">No auth methods recorded</p>
    )
  }

  return (
    <div className="flex flex-wrap gap-2">
      {methods.map((method, index) => {
        const methodInfo = typeof method === 'string' ? { name: method } : method

        return (
          <span
            key={index}
            className="inline-flex items-center gap-1 rounded-lg bg-primary-100 dark:bg-primary-900/30 px-2.5 py-1 text-xs font-medium text-primary-700 dark:text-primary-300"
          >
            <ShieldCheckIcon className="h-3 w-3" />
            {methodInfo.name || 'Unknown'}
          </span>
        )
      })}
    </div>
  )
}

export default function BaselineDetail({
  baseline,
  isLoading,
  error,
  isUpdating,
  onReset,
  onMarkServiceAccount,
  onExclude,
  onForceRebuild,
}) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 text-center">
        <p className="text-red-600 dark:text-red-400">{error}</p>
      </div>
    )
  }

  if (!baseline) {
    return (
      <div className="p-6 text-center">
        <UserCircleIcon className="mx-auto h-12 w-12 text-mono-400" />
        <p className="mt-2 text-mono-500 dark:text-mono-400">
          Select a user to view their baseline
        </p>
      </div>
    )
  }

  const status = STATUS_STYLES[baseline.status] || STATUS_STYLES.new
  const currentHour = new Date().getHours()

  return (
    <div className="divide-y divide-mono-200 dark:divide-mono-800">
      {/* Header */}
      <div className="px-4 py-4">
        <div className="flex items-start gap-4">
          <UserCircleIcon className="h-12 w-12 text-mono-400" />
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
              {baseline.display_name || baseline.user_email}
            </h3>
            <p className="text-sm text-mono-500 dark:text-mono-400">
              {baseline.user_email}
            </p>
            <div className="mt-2 flex items-center gap-3">
              <span className={clsx('inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold', status.color)}>
                {status.label}
              </span>
              {baseline.provider && (
                <span className="text-xs text-mono-500 capitalize">{baseline.provider}</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="px-4">
        <Section title="Overview" icon={ChartBarIcon}>
          <div className="grid grid-cols-3 gap-3">
            <StatCard
              label="Maturity"
              value={`${baseline.maturity_days || 0}d`}
              subValue={baseline.maturity_days >= 14 ? 'Complete' : 'Building'}
            />
            <StatCard
              label="Confidence"
              value={`${baseline.confidence || 0}%`}
            />
            <StatCard
              label="Events"
              value={baseline.event_count?.toLocaleString() || 0}
            />
          </div>
          <div className="mt-3 text-xs text-mono-500 dark:text-mono-400 flex items-center gap-1">
            <ArrowPathIcon className="h-3 w-3" />
            Last updated: {formatDate(baseline.last_updated)}
          </div>
        </Section>
      </div>

      {/* Login Hours */}
      <div className="px-4">
        <Section title="Typical Login Hours" icon={ClockIcon}>
          <LoginHoursChart hours={baseline.login_hours} currentHour={currentHour} />
        </Section>
      </div>

      {/* Login Days */}
      <div className="px-4">
        <Section title="Typical Login Days" icon={CalendarIcon}>
          <WeekDaysChart days={baseline.login_days} />
        </Section>
      </div>

      {/* Locations */}
      <div className="px-4">
        <Section title="Known Locations" icon={MapPinIcon}>
          <LocationsMap locations={baseline.locations} />
        </Section>
      </div>

      {/* Devices */}
      <div className="px-4">
        <Section title="Known Devices" icon={ComputerDesktopIcon}>
          <DevicesList devices={baseline.devices} />
        </Section>
      </div>

      {/* Applications */}
      <div className="px-4">
        <Section title="Typical Applications" icon={Square3Stack3DIcon}>
          <ApplicationsList applications={baseline.applications} />
        </Section>
      </div>

      {/* Auth Methods */}
      <div className="px-4">
        <Section title="Auth Methods Used" icon={ShieldCheckIcon}>
          <AuthMethodsList methods={baseline.auth_methods} />
        </Section>
      </div>

      {/* Volume Metrics */}
      {baseline.volume_metrics && (
        <div className="px-4">
          <Section title="Volume Metrics" icon={ChartBarIcon}>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-mono-50 dark:bg-mono-800">
                <div className="text-lg font-bold text-mono-900 dark:text-mono-100">
                  {baseline.volume_metrics.avg_events_per_day?.toFixed(1) || 0}
                </div>
                <div className="text-xs text-mono-500">Avg events/day</div>
              </div>
              <div className="p-3 rounded-lg bg-mono-50 dark:bg-mono-800">
                <div className="text-lg font-bold text-mono-900 dark:text-mono-100">
                  ±{baseline.volume_metrics.variance?.toFixed(1) || 0}
                </div>
                <div className="text-xs text-mono-500">Variance</div>
              </div>
            </div>
          </Section>
        </div>
      )}

      {/* Actions */}
      <div className="px-4 py-4">
        <h4 className="text-sm font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Actions
        </h4>
        <BaselineActions
          baseline={baseline}
          onReset={onReset}
          onMarkServiceAccount={onMarkServiceAccount}
          onExclude={onExclude}
          onForceRebuild={onForceRebuild}
          isUpdating={isUpdating}
        />
      </div>
    </div>
  )
}
