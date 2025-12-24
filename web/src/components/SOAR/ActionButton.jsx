import { useState } from 'react'
import clsx from 'clsx'
import {
  ShieldExclamationIcon,
  NoSymbolIcon,
  UserMinusIcon,
  ServerIcon,
  PlayIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline'

// Map action types to icons and colors
const ACTION_CONFIG = {
  isolate_host: {
    icon: ServerIcon,
    label: 'Isolate Host',
    color: 'bg-red-600 hover:bg-red-700',
    dangerous: true,
    description: 'Isolate this host from the network',
  },
  block_ip: {
    icon: NoSymbolIcon,
    label: 'Block IP',
    color: 'bg-orange-600 hover:bg-orange-700',
    dangerous: true,
    description: 'Block this IP address at the firewall',
  },
  disable_user: {
    icon: UserMinusIcon,
    label: 'Disable User',
    color: 'bg-yellow-600 hover:bg-yellow-700',
    dangerous: true,
    description: 'Disable this user account',
  },
  quarantine_file: {
    icon: ShieldExclamationIcon,
    label: 'Quarantine',
    color: 'bg-purple-600 hover:bg-purple-700',
    dangerous: true,
    description: 'Quarantine the suspicious file',
  },
  run_playbook: {
    icon: PlayIcon,
    label: 'Run Playbook',
    color: 'bg-primary-600 hover:bg-primary-700',
    dangerous: false,
    description: 'Execute an automated playbook',
  },
}

export default function ActionButton({
  actionType,
  label,
  onClick,
  disabled = false,
  loading = false,
  size = 'md',
  variant = 'primary',
  requireConfirmation = true,
  className,
}) {
  const [showConfirm, setShowConfirm] = useState(false)

  const config = ACTION_CONFIG[actionType] || {
    icon: ExclamationTriangleIcon,
    label: label || actionType,
    color: 'bg-gray-600 hover:bg-gray-700',
    dangerous: false,
    description: '',
  }

  const Icon = config.icon
  const displayLabel = label || config.label
  const isDangerous = config.dangerous && requireConfirmation

  const handleClick = () => {
    if (isDangerous && !showConfirm) {
      setShowConfirm(true)
      return
    }
    setShowConfirm(false)
    onClick?.()
  }

  const handleCancel = (e) => {
    e.stopPropagation()
    setShowConfirm(false)
  }

  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-3 py-1.5 text-sm',
    lg: 'px-4 py-2 text-base',
  }

  const variantClasses = {
    primary: config.color,
    outline: 'border border-gray-300 bg-white hover:bg-gray-50 text-gray-700',
    ghost: 'bg-transparent hover:bg-gray-100 text-gray-700',
  }

  if (showConfirm) {
    return (
      <div className={clsx('flex items-center gap-2', className)}>
        <span className="text-sm text-gray-600">Confirm?</span>
        <button
          onClick={handleClick}
          disabled={disabled || loading}
          className={clsx(
            'rounded-lg font-medium text-white transition-colors',
            sizeClasses[size],
            'bg-red-600 hover:bg-red-700',
            (disabled || loading) && 'cursor-not-allowed opacity-50'
          )}
        >
          Yes
        </button>
        <button
          onClick={handleCancel}
          className={clsx(
            'rounded-lg font-medium text-gray-700 transition-colors',
            sizeClasses[size],
            'border border-gray-300 bg-white hover:bg-gray-50'
          )}
        >
          No
        </button>
      </div>
    )
  }

  return (
    <button
      onClick={handleClick}
      disabled={disabled || loading}
      title={config.description}
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-lg font-medium transition-colors',
        sizeClasses[size],
        variant === 'primary' ? 'text-white' : '',
        variantClasses[variant],
        (disabled || loading) && 'cursor-not-allowed opacity-50',
        className
      )}
    >
      {loading ? (
        <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
      ) : (
        <Icon className="h-4 w-4" />
      )}
      <span>{displayLabel}</span>
    </button>
  )
}
