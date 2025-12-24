import { useState } from 'react'
import clsx from 'clsx'
import {
  ExclamationTriangleIcon,
  CheckIcon,
  XMarkIcon,
  ClockIcon,
  EyeIcon,
} from '@heroicons/react/24/outline'
import { usePendingApprovals, useApproveAction, useDenyAction } from '../../hooks/useSOAR'

export default function ApprovalsList() {
  const [denyingId, setDenyingId] = useState(null)
  const [denyReason, setDenyReason] = useState('')

  const { data, isLoading, error } = usePendingApprovals(50, { polling: true })
  const { mutate: approve, isPending: isApproving } = useApproveAction()
  const { mutate: deny, isPending: isDenying } = useDenyAction()

  const approvals = data?.approvals || []

  const handleApprove = (approvalId) => {
    approve({ approvalId, notes: '' })
  }

  const handleDeny = (approvalId) => {
    if (!denyReason.trim()) return
    deny(
      { approvalId, reason: denyReason },
      {
        onSuccess: () => {
          setDenyingId(null)
          setDenyReason('')
        },
      }
    )
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
  }

  const getTimeRemaining = (expiresAt) => {
    if (!expiresAt) return null
    const remaining = new Date(expiresAt) - new Date()
    if (remaining <= 0) return 'Expired'
    const minutes = Math.floor(remaining / 60000)
    if (minutes < 60) return `${minutes}m`
    const hours = Math.floor(minutes / 60)
    return `${hours}h ${minutes % 60}m`
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
        Failed to load approvals. Please try again.
      </div>
    )
  }

  if (approvals.length === 0) {
    return (
      <div className="py-12 text-center">
        <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-sm font-medium text-gray-900">No pending approvals</h3>
        <p className="mt-1 text-sm text-gray-500">
          You&apos;re all caught up! No actions require your approval.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {approvals.map((approval) => {
        const timeRemaining = getTimeRemaining(approval.expires_at)
        const isExpired = timeRemaining === 'Expired'
        const isShowingDeny = denyingId === approval.id

        return (
          <div
            key={approval.id}
            className={clsx(
              'rounded-lg border p-4',
              isExpired
                ? 'border-gray-200 bg-gray-50'
                : 'border-yellow-200 bg-yellow-50'
            )}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div
                  className={clsx(
                    'flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full',
                    isExpired ? 'bg-gray-200' : 'bg-yellow-200'
                  )}
                >
                  <ExclamationTriangleIcon
                    className={clsx(
                      'h-5 w-5',
                      isExpired ? 'text-gray-500' : 'text-yellow-600'
                    )}
                  />
                </div>
                <div>
                  <h4 className="font-medium text-gray-900">{approval.action_type}</h4>
                  {approval.step_name && (
                    <p className="text-sm text-gray-600">Step: {approval.step_name}</p>
                  )}
                  <p className="mt-1 text-sm text-gray-500">
                    Playbook: {approval.playbook_name || approval.playbook_id}
                  </p>
                  <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
                    <span>Requested: {formatDate(approval.created_at)}</span>
                    {timeRemaining && (
                      <span
                        className={clsx(
                          'flex items-center gap-1',
                          isExpired ? 'text-red-500' : 'text-yellow-600'
                        )}
                      >
                        <ClockIcon className="h-3 w-3" />
                        {isExpired ? 'Expired' : `Expires in ${timeRemaining}`}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {!isExpired && !isShowingDeny && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleApprove(approval.id)}
                    disabled={isApproving || isDenying}
                    className="inline-flex items-center gap-1 rounded-lg bg-green-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
                  >
                    <CheckIcon className="h-4 w-4" />
                    Approve
                  </button>
                  <button
                    onClick={() => setDenyingId(approval.id)}
                    disabled={isApproving || isDenying}
                    className="inline-flex items-center gap-1 rounded-lg bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                  >
                    <XMarkIcon className="h-4 w-4" />
                    Deny
                  </button>
                </div>
              )}

              {isExpired && (
                <span className="rounded-full bg-gray-200 px-3 py-1 text-xs font-medium text-gray-600">
                  Expired
                </span>
              )}
            </div>

            {approval.parameters && Object.keys(approval.parameters).length > 0 && (
              <div className="mt-4 rounded bg-white p-3">
                <p className="mb-2 text-xs font-medium text-gray-500">Parameters</p>
                <dl className="grid grid-cols-2 gap-2 text-sm">
                  {Object.entries(approval.parameters).map(([key, value]) => (
                    <div key={key}>
                      <dt className="text-gray-500">{key}</dt>
                      <dd className="font-medium text-gray-900">
                        {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}

            {isShowingDeny && (
              <div className="mt-4 space-y-3 rounded-lg bg-white p-4">
                <p className="text-sm font-medium text-gray-900">
                  Please provide a reason for denial:
                </p>
                <textarea
                  value={denyReason}
                  onChange={(e) => setDenyReason(e.target.value)}
                  placeholder="Enter reason..."
                  rows={2}
                  className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => {
                      setDenyingId(null)
                      setDenyReason('')
                    }}
                    className="rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleDeny(approval.id)}
                    disabled={isDenying || !denyReason.trim()}
                    className="inline-flex items-center gap-1 rounded-lg bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                  >
                    {isDenying ? 'Denying...' : 'Confirm Denial'}
                  </button>
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
