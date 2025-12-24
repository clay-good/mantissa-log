import { Fragment, useEffect, useState } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { useIdentityStore } from '../../stores/identityStore'
import { getIncidentDetails } from '../../services/identityApi'
import clsx from 'clsx'
import {
  XMarkIcon,
  ShieldExclamationIcon,
  UserIcon,
  ClockIcon,
  MapPinIcon,
  ComputerDesktopIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ArrowUpIcon,
  DocumentTextIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline'

const SEVERITY_STYLES = {
  critical: {
    badge: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    border: 'border-red-500',
  },
  high: {
    badge: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
    border: 'border-orange-500',
  },
  medium: {
    badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    border: 'border-yellow-500',
  },
  low: {
    badge: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
    border: 'border-green-500',
  },
}

const ATTACK_TYPE_LABELS = {
  brute_force: 'Brute Force Attack',
  credential_stuffing: 'Credential Stuffing',
  password_spray: 'Password Spray Attack',
  mfa_fatigue: 'MFA Fatigue Attack',
  mfa_bypass: 'MFA Bypass Attempt',
  impossible_travel: 'Impossible Travel',
  session_hijack: 'Session Hijacking',
  privilege_escalation: 'Privilege Escalation',
  account_takeover: 'Account Takeover',
  token_theft: 'Token Theft',
  dormant_account: 'Dormant Account Activity',
}

const KILL_CHAIN_STAGES = {
  RECONNAISSANCE: { label: 'Reconnaissance', description: 'Gathering information about target' },
  INITIAL_ACCESS: { label: 'Initial Access', description: 'Gaining initial foothold' },
  CREDENTIAL_ACCESS: { label: 'Credential Access', description: 'Stealing credentials' },
  PERSISTENCE: { label: 'Persistence', description: 'Maintaining access' },
  PRIVILEGE_ESCALATION: { label: 'Privilege Escalation', description: 'Gaining higher privileges' },
  LATERAL_MOVEMENT: { label: 'Lateral Movement', description: 'Moving through network' },
  COLLECTION: { label: 'Collection', description: 'Gathering data' },
  OBJECTIVES: { label: 'Objectives', description: 'Achieving final goals' },
}

const STATUS_LABELS = {
  new: 'New',
  acknowledged: 'Acknowledged',
  investigating: 'Investigating',
  resolved: 'Resolved',
}

function formatTimestamp(timestamp) {
  if (!timestamp) return 'Unknown'
  const date = new Date(timestamp)
  return date.toLocaleString()
}

function DetailSection({ title, icon: Icon, children }) {
  return (
    <div className="py-4">
      <div className="flex items-center gap-2 mb-3">
        {Icon && <Icon className="h-5 w-5 text-mono-400" />}
        <h4 className="text-sm font-semibold text-mono-900 dark:text-mono-100">{title}</h4>
      </div>
      {children}
    </div>
  )
}

function InfoRow({ label, value, className }) {
  return (
    <div className={clsx('flex justify-between py-1.5', className)}>
      <span className="text-sm text-mono-500 dark:text-mono-400">{label}</span>
      <span className="text-sm font-medium text-mono-900 dark:text-mono-100">{value || '-'}</span>
    </div>
  )
}

function KillChainProgress({ stage }) {
  const stageKeys = Object.keys(KILL_CHAIN_STAGES)
  const currentIndex = stageKeys.indexOf(stage)

  return (
    <div className="space-y-2">
      {stageKeys.map((key, index) => {
        const stageInfo = KILL_CHAIN_STAGES[key]
        const isCurrent = key === stage
        const isPast = index < currentIndex
        const isFuture = index > currentIndex

        return (
          <div
            key={key}
            className={clsx(
              'flex items-center gap-3 p-2 rounded-lg transition-colors',
              isCurrent && 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800',
              isPast && 'opacity-60'
            )}
          >
            <div
              className={clsx(
                'h-6 w-6 rounded-full flex items-center justify-center text-xs font-medium',
                isCurrent && 'bg-red-500 text-white',
                isPast && 'bg-mono-400 text-white',
                isFuture && 'bg-mono-200 dark:bg-mono-700 text-mono-400'
              )}
            >
              {index + 1}
            </div>
            <div className="flex-1">
              <div
                className={clsx(
                  'text-sm font-medium',
                  isCurrent
                    ? 'text-red-700 dark:text-red-300'
                    : 'text-mono-700 dark:text-mono-300'
                )}
              >
                {stageInfo.label}
              </div>
              {isCurrent && (
                <div className="text-xs text-red-600 dark:text-red-400">{stageInfo.description}</div>
              )}
            </div>
            {isCurrent && (
              <ChevronRightIcon className="h-4 w-4 text-red-500" />
            )}
          </div>
        )
      })}
    </div>
  )
}

export default function IncidentDetailPanel({ incidentId, isOpen, onClose }) {
  const [incident, setIncident] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const { acknowledgeIncident, dismissIncident, escalateIncident } = useIdentityStore()

  useEffect(() => {
    if (incidentId && isOpen) {
      setIsLoading(true)
      setError(null)
      getIncidentDetails(incidentId)
        .then((data) => {
          setIncident(data)
        })
        .catch((err) => {
          setError(err.message)
        })
        .finally(() => {
          setIsLoading(false)
        })
    }
  }, [incidentId, isOpen])

  const handleAcknowledge = async () => {
    await acknowledgeIncident(incidentId)
    setIncident((prev) => (prev ? { ...prev, status: 'acknowledged' } : prev))
  }

  const handleEscalate = async () => {
    await escalateIncident(incidentId)
    setIncident((prev) => (prev ? { ...prev, status: 'investigating' } : prev))
  }

  const handleDismiss = async () => {
    await dismissIncident(incidentId)
    onClose()
  }

  const severityStyle = incident ? SEVERITY_STYLES[incident.severity] || SEVERITY_STYLES.medium : null

  return (
    <Transition.Root show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-in-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in-out duration-300"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-mono-900/50 transition-opacity" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-hidden">
          <div className="absolute inset-0 overflow-hidden">
            <div className="pointer-events-none fixed inset-y-0 right-0 flex max-w-full pl-10">
              <Transition.Child
                as={Fragment}
                enter="transform transition ease-in-out duration-300"
                enterFrom="translate-x-full"
                enterTo="translate-x-0"
                leave="transform transition ease-in-out duration-300"
                leaveFrom="translate-x-0"
                leaveTo="translate-x-full"
              >
                <Dialog.Panel className="pointer-events-auto w-screen max-w-lg">
                  <div className="flex h-full flex-col bg-white dark:bg-mono-900 shadow-xl">
                    {/* Header */}
                    <div
                      className={clsx(
                        'px-6 py-4 border-b-4',
                        severityStyle?.border || 'border-mono-300'
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <Dialog.Title className="text-lg font-semibold text-mono-900 dark:text-mono-100">
                            {incident
                              ? ATTACK_TYPE_LABELS[incident.attack_type] || incident.attack_type
                              : 'Incident Details'}
                          </Dialog.Title>
                          {incident && (
                            <div className="mt-1 flex items-center gap-2">
                              <span
                                className={clsx(
                                  'inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize',
                                  severityStyle?.badge
                                )}
                              >
                                {incident.severity}
                              </span>
                              <span className="text-sm text-mono-500 dark:text-mono-400">
                                {STATUS_LABELS[incident.status] || incident.status}
                              </span>
                            </div>
                          )}
                        </div>
                        <button
                          type="button"
                          className="rounded-md text-mono-400 hover:text-mono-500 dark:hover:text-mono-300"
                          onClick={onClose}
                        >
                          <XMarkIcon className="h-6 w-6" />
                        </button>
                      </div>
                    </div>

                    {/* Content */}
                    <div className="flex-1 overflow-y-auto px-6">
                      {isLoading ? (
                        <div className="flex items-center justify-center py-12">
                          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
                        </div>
                      ) : error ? (
                        <div className="py-12 text-center">
                          <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-red-400" />
                          <p className="mt-2 text-sm text-red-600">{error}</p>
                        </div>
                      ) : incident ? (
                        <div className="divide-y divide-mono-200 dark:divide-mono-800">
                          {/* Overview */}
                          <DetailSection title="Overview" icon={ShieldExclamationIcon}>
                            <p className="text-sm text-mono-600 dark:text-mono-400">
                              {incident.description || 'No description available.'}
                            </p>
                            <div className="mt-3 space-y-1">
                              <InfoRow label="Provider" value={incident.provider} />
                              <InfoRow label="Detected" value={formatTimestamp(incident.timestamp)} />
                              <InfoRow label="Incident ID" value={incident.id} />
                            </div>
                          </DetailSection>

                          {/* Affected Users */}
                          <DetailSection title="Affected Users" icon={UserIcon}>
                            <div className="flex flex-wrap gap-2">
                              {incident.target_users?.map((user) => (
                                <span
                                  key={user}
                                  className="inline-flex items-center gap-1 rounded-full bg-mono-100 dark:bg-mono-800 px-3 py-1 text-sm text-mono-700 dark:text-mono-300"
                                >
                                  <UserIcon className="h-3 w-3" />
                                  {user}
                                </span>
                              )) || (
                                <span className="text-sm text-mono-500">No users identified</span>
                              )}
                            </div>
                          </DetailSection>

                          {/* Attack Context */}
                          {(incident.source_ip || incident.location || incident.device) && (
                            <DetailSection title="Attack Context" icon={MapPinIcon}>
                              <div className="space-y-1">
                                {incident.source_ip && (
                                  <InfoRow label="Source IP" value={incident.source_ip} />
                                )}
                                {incident.location && (
                                  <InfoRow label="Location" value={incident.location} />
                                )}
                                {incident.device && (
                                  <InfoRow label="Device" value={incident.device} />
                                )}
                                {incident.user_agent && (
                                  <InfoRow label="User Agent" value={incident.user_agent} />
                                )}
                              </div>
                            </DetailSection>
                          )}

                          {/* Kill Chain Stage */}
                          {incident.kill_chain_stage && (
                            <DetailSection title="Kill Chain Progress" icon={DocumentTextIcon}>
                              <KillChainProgress stage={incident.kill_chain_stage} />
                            </DetailSection>
                          )}

                          {/* Risk Indicators */}
                          {incident.risk_indicators && incident.risk_indicators.length > 0 && (
                            <DetailSection title="Risk Indicators" icon={ExclamationTriangleIcon}>
                              <ul className="space-y-2">
                                {incident.risk_indicators.map((indicator, i) => (
                                  <li
                                    key={i}
                                    className="flex items-start gap-2 text-sm text-mono-600 dark:text-mono-400"
                                  >
                                    <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                                    {indicator}
                                  </li>
                                ))}
                              </ul>
                            </DetailSection>
                          )}

                          {/* Timeline */}
                          {incident.timeline && incident.timeline.length > 0 && (
                            <DetailSection title="Event Timeline" icon={ClockIcon}>
                              <div className="space-y-3">
                                {incident.timeline.map((event, i) => (
                                  <div key={i} className="flex gap-3">
                                    <div className="relative">
                                      <div className="h-2 w-2 mt-1.5 rounded-full bg-mono-400" />
                                      {i < incident.timeline.length - 1 && (
                                        <div className="absolute left-0.5 top-3 bottom-0 w-0.5 bg-mono-200 dark:bg-mono-700" />
                                      )}
                                    </div>
                                    <div className="flex-1 pb-3">
                                      <div className="text-xs text-mono-500 dark:text-mono-400">
                                        {formatTimestamp(event.timestamp)}
                                      </div>
                                      <div className="text-sm text-mono-700 dark:text-mono-300">
                                        {event.description}
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </DetailSection>
                          )}

                          {/* Recommended Actions */}
                          {incident.recommended_actions && incident.recommended_actions.length > 0 && (
                            <DetailSection title="Recommended Actions" icon={CheckCircleIcon}>
                              <ul className="space-y-2">
                                {incident.recommended_actions.map((action, i) => (
                                  <li
                                    key={i}
                                    className="flex items-start gap-2 text-sm text-mono-600 dark:text-mono-400"
                                  >
                                    <span className="h-5 w-5 rounded-full bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400 flex items-center justify-center text-xs font-medium">
                                      {i + 1}
                                    </span>
                                    {action}
                                  </li>
                                ))}
                              </ul>
                            </DetailSection>
                          )}
                        </div>
                      ) : null}
                    </div>

                    {/* Footer Actions */}
                    {incident && incident.status !== 'resolved' && (
                      <div className="border-t border-mono-200 dark:border-mono-800 px-6 py-4">
                        <div className="flex gap-3">
                          <button
                            onClick={handleAcknowledge}
                            disabled={incident.status === 'acknowledged'}
                            className={clsx(
                              'flex-1 flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
                              incident.status === 'acknowledged'
                                ? 'bg-mono-100 text-mono-400 cursor-not-allowed'
                                : 'bg-blue-600 text-white hover:bg-blue-700'
                            )}
                          >
                            <CheckCircleIcon className="h-4 w-4" />
                            Acknowledge
                          </button>
                          <button
                            onClick={handleEscalate}
                            className="flex-1 flex items-center justify-center gap-2 rounded-lg border border-orange-500 px-4 py-2 text-sm font-medium text-orange-600 hover:bg-orange-50 dark:hover:bg-orange-900/20 transition-colors"
                          >
                            <ArrowUpIcon className="h-4 w-4" />
                            Escalate
                          </button>
                          <button
                            onClick={handleDismiss}
                            className="flex items-center justify-center gap-2 rounded-lg border border-mono-300 dark:border-mono-600 px-4 py-2 text-sm font-medium text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
                          >
                            <XMarkIcon className="h-4 w-4" />
                            Dismiss
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  )
}
