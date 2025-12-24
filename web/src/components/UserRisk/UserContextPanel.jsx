import clsx from 'clsx'
import {
  UserIcon,
  BuildingOfficeIcon,
  BriefcaseIcon,
  ShieldCheckIcon,
  CalendarIcon,
  KeyIcon,
  DevicePhoneMobileIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline'

function InfoRow({ icon: Icon, label, value, status }) {
  return (
    <div className="flex items-start gap-3 py-2">
      <Icon className="h-4 w-4 text-mono-400 mt-0.5" />
      <div className="flex-1 min-w-0">
        <p className="text-xs text-mono-500 dark:text-mono-400">{label}</p>
        <p className="text-sm font-medium text-mono-900 dark:text-mono-100 truncate">
          {value || '-'}
        </p>
      </div>
      {status && (
        <div className="flex-shrink-0">
          {status === 'active' && (
            <CheckCircleIcon className="h-4 w-4 text-green-500" />
          )}
          {status === 'inactive' && (
            <XCircleIcon className="h-4 w-4 text-red-500" />
          )}
          {status === 'warning' && (
            <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500" />
          )}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }) {
  const statusConfig = {
    active: { label: 'Active', color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' },
    disabled: { label: 'Disabled', color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' },
    locked: { label: 'Locked', color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' },
    suspended: { label: 'Suspended', color: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300' },
    pending: { label: 'Pending', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' },
  }

  const config = statusConfig[status?.toLowerCase()] || statusConfig.active

  return (
    <span className={clsx('inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold', config.color)}>
      {config.label}
    </span>
  )
}

function PrivilegeBadge({ level }) {
  const levelConfig = {
    admin: { label: 'Admin', color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' },
    privileged: { label: 'Privileged', color: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300' },
    standard: { label: 'Standard', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' },
    limited: { label: 'Limited', color: 'bg-mono-100 text-mono-800 dark:bg-mono-800 dark:text-mono-300' },
  }

  const config = levelConfig[level?.toLowerCase()] || levelConfig.standard

  return (
    <span className={clsx('inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold', config.color)}>
      {config.label}
    </span>
  )
}

function MFAStatus({ mfa }) {
  if (!mfa) {
    return (
      <div className="flex items-center gap-2">
        <XCircleIcon className="h-4 w-4 text-red-500" />
        <span className="text-sm text-red-600 dark:text-red-400 font-medium">Not Enrolled</span>
      </div>
    )
  }

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <CheckCircleIcon className="h-4 w-4 text-green-500" />
        <span className="text-sm text-green-600 dark:text-green-400 font-medium">Enrolled</span>
      </div>
      {mfa.methods && mfa.methods.length > 0 && (
        <div className="flex flex-wrap gap-1 ml-6">
          {mfa.methods.map((method, i) => (
            <span
              key={i}
              className="inline-flex rounded bg-mono-100 dark:bg-mono-800 px-1.5 py-0.5 text-xs text-mono-600 dark:text-mono-400"
            >
              {method}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function formatTimeAgo(dateString) {
  if (!dateString) return ''
  const date = new Date(dateString)
  const now = new Date()
  const diffDays = Math.floor((now - date) / (1000 * 60 * 60 * 24))

  if (diffDays < 1) return '(today)'
  if (diffDays < 30) return `(${diffDays}d ago)`
  if (diffDays < 365) return `(${Math.floor(diffDays / 30)}mo ago)`
  return `(${Math.floor(diffDays / 365)}y ago)`
}

export default function UserContextPanel({ user }) {
  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
      <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-mono-900 dark:text-mono-100">
          User Context
        </h3>
      </div>

      <div className="px-4 divide-y divide-mono-200 dark:divide-mono-800">
        {/* Account Status */}
        <div className="py-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-mono-500 dark:text-mono-400">Account Status</span>
            <StatusBadge status={user?.account_status} />
          </div>
        </div>

        {/* Privilege Level */}
        <div className="py-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-mono-500 dark:text-mono-400">Privilege Level</span>
            <PrivilegeBadge level={user?.privilege_level} />
          </div>
        </div>

        {/* Directory Info */}
        <div className="py-2">
          <InfoRow
            icon={BuildingOfficeIcon}
            label="Department"
            value={user?.department}
          />
          <InfoRow
            icon={UserIcon}
            label="Manager"
            value={user?.manager}
          />
          <InfoRow
            icon={BriefcaseIcon}
            label="Title"
            value={user?.title}
          />
        </div>

        {/* Security Info */}
        <div className="py-2">
          <InfoRow
            icon={KeyIcon}
            label="Last Password Change"
            value={
              user?.last_password_change
                ? `${formatDate(user.last_password_change)} ${formatTimeAgo(user.last_password_change)}`
                : '-'
            }
            status={
              user?.last_password_change
                ? new Date() - new Date(user.last_password_change) > 90 * 24 * 60 * 60 * 1000
                  ? 'warning'
                  : 'active'
                : undefined
            }
          />
          <InfoRow
            icon={CalendarIcon}
            label="Account Created"
            value={formatDate(user?.created_at)}
          />
          <InfoRow
            icon={ShieldCheckIcon}
            label="Last Login"
            value={
              user?.last_login
                ? `${formatDate(user.last_login)} ${formatTimeAgo(user.last_login)}`
                : 'Never'
            }
          />
        </div>

        {/* MFA Status */}
        <div className="py-3">
          <div className="flex items-center gap-2 mb-2">
            <DevicePhoneMobileIcon className="h-4 w-4 text-mono-400" />
            <span className="text-xs text-mono-500 dark:text-mono-400">MFA Status</span>
          </div>
          <MFAStatus mfa={user?.mfa} />
        </div>

        {/* Provider */}
        {user?.provider && (
          <div className="py-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-mono-500 dark:text-mono-400">Identity Provider</span>
              <span className="text-sm font-medium text-mono-700 dark:text-mono-300 capitalize">
                {user.provider}
              </span>
            </div>
          </div>
        )}

        {/* Groups */}
        {user?.groups && user.groups.length > 0 && (
          <div className="py-3">
            <p className="text-xs text-mono-500 dark:text-mono-400 mb-2">Groups</p>
            <div className="flex flex-wrap gap-1">
              {user.groups.slice(0, 5).map((group, i) => (
                <span
                  key={i}
                  className="inline-flex rounded bg-mono-100 dark:bg-mono-800 px-2 py-0.5 text-xs text-mono-600 dark:text-mono-400"
                >
                  {group}
                </span>
              ))}
              {user.groups.length > 5 && (
                <span className="text-xs text-mono-500">
                  +{user.groups.length - 5} more
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
