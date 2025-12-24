import { useState } from 'react'
import clsx from 'clsx'
import {
  ExclamationTriangleIcon,
  CheckIcon,
  XMarkIcon,
  ClockIcon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/outline'
import { useApproval, useApproveAction, useDenyAction } from '../../hooks/useSOAR'

export default function ApprovalPrompt({
  approvalId,
  approval: externalApproval,
  onComplete,
  compact = false,
}) {
  const [notes, setNotes] = useState('')
  const [denyReason, setDenyReason] = useState('')
  const [showDenyForm, setShowDenyForm] = useState(false)

  const { data, isLoading } = useApproval(approvalId, {
    enabled: !!approvalId && !externalApproval,
  })

  const { mutate: approve, isPending: isApproving } = useApproveAction()
  const { mutate: deny, isPending: isDenying } = useDenyAction()

  const approval = externalApproval || data?.approval

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-gray-500">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-gray-300 border-t-primary-600" />
        <span className="text-sm">Loading approval...</span>
      </div>
    )
  }

  if (!approval) {
    return null
  }

  const handleApprove = () => {
    approve(
      { approvalId: approval.id, notes },
      {
        onSuccess: () => onComplete?.('approved'),
      }
    )
  }

  const handleDeny = () => {
    if (!denyReason.trim()) {
      return
    }
    deny(
      { approvalId: approval.id, reason: denyReason },
      {
        onSuccess: () => onComplete?.('denied'),
      }
    )
  }

  const isExpired = approval.is_expired
  const isPending = approval.status === 'pending'
  const canApprove = approval.can_approve && isPending && !isExpired

  // Format time remaining
  const expiresAt = approval.expires_at ? new Date(approval.expires_at) : null
  const timeRemaining = expiresAt
    ? Math.max(0, Math.floor((expiresAt - new Date()) / 60000))
    : null

  if (compact) {
    return (
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <ShieldExclamationIcon className="h-5 w-5 text-yellow-500" />
          <span className="text-sm font-medium text-gray-700">
            {approval.action_type}
          </span>
        </div>
        {canApprove ? (
          <div className="flex items-center gap-2">
            <button
              onClick={handleApprove}
              disabled={isApproving || isDenying}
              className="inline-flex items-center gap-1 rounded bg-green-600 px-2 py-1 text-xs font-medium text-white hover:bg-green-700 disabled:opacity-50"
            >
              <CheckIcon className="h-3 w-3" />
              Approve
            </button>
            <button
              onClick={() => setShowDenyForm(true)}
              disabled={isApproving || isDenying}
              className="inline-flex items-center gap-1 rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              <XMarkIcon className="h-3 w-3" />
              Deny
            </button>
          </div>
        ) : (
          <span
            className={clsx(
              'rounded-full px-2 py-0.5 text-xs font-medium',
              isExpired
                ? 'bg-gray-100 text-gray-600'
                : 'bg-yellow-100 text-yellow-700'
            )}
          >
            {isExpired ? 'Expired' : approval.status}
          </span>
        )}
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
      <div className="flex items-start gap-4">
        <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-yellow-100">
          <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
        </div>

        <div className="flex-1">
          <h4 className="font-medium text-yellow-800">Approval Required</h4>
          <p className="mt-1 text-sm text-yellow-700">
            The following action requires manual approval before execution.
          </p>

          <div className="mt-3 rounded-lg bg-white p-3 shadow-sm">
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-gray-500">Action:</dt>
                <dd className="font-medium text-gray-900">
                  {approval.action_type}
                </dd>
              </div>
              {approval.step_name && (
                <div className="flex justify-between">
                  <dt className="text-gray-500">Step:</dt>
                  <dd className="font-medium text-gray-900">
                    {approval.step_name}
                  </dd>
                </div>
              )}
              {approval.parameters && Object.keys(approval.parameters).length > 0 && (
                <div>
                  <dt className="mb-1 text-gray-500">Parameters:</dt>
                  <dd className="rounded bg-gray-50 p-2 font-mono text-xs">
                    {JSON.stringify(approval.parameters, null, 2)}
                  </dd>
                </div>
              )}
              {approval.reason && (
                <div className="flex justify-between">
                  <dt className="text-gray-500">Reason:</dt>
                  <dd className="font-medium text-gray-900">{approval.reason}</dd>
                </div>
              )}
            </dl>
          </div>

          {timeRemaining !== null && isPending && (
            <div className="mt-2 flex items-center gap-1 text-xs text-yellow-600">
              <ClockIcon className="h-4 w-4" />
              {timeRemaining > 0
                ? `Expires in ${timeRemaining} minutes`
                : 'Expired'}
            </div>
          )}

          {canApprove && !showDenyForm && (
            <div className="mt-4 space-y-3">
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Add notes (optional)"
                rows={2}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
              />
              <div className="flex gap-2">
                <button
                  onClick={handleApprove}
                  disabled={isApproving || isDenying}
                  className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
                >
                  {isApproving ? (
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  ) : (
                    <CheckIcon className="h-4 w-4" />
                  )}
                  Approve
                </button>
                <button
                  onClick={() => setShowDenyForm(true)}
                  disabled={isApproving || isDenying}
                  className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                >
                  <XMarkIcon className="h-4 w-4" />
                  Deny
                </button>
              </div>
            </div>
          )}

          {canApprove && showDenyForm && (
            <div className="mt-4 space-y-3">
              <textarea
                value={denyReason}
                onChange={(e) => setDenyReason(e.target.value)}
                placeholder="Reason for denial (required)"
                rows={2}
                className="w-full rounded-lg border border-red-300 px-3 py-2 text-sm focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500"
              />
              <div className="flex gap-2">
                <button
                  onClick={handleDeny}
                  disabled={isApproving || isDenying || !denyReason.trim()}
                  className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                >
                  {isDenying ? (
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  ) : (
                    <XMarkIcon className="h-4 w-4" />
                  )}
                  Confirm Denial
                </button>
                <button
                  onClick={() => {
                    setShowDenyForm(false)
                    setDenyReason('')
                  }}
                  disabled={isApproving || isDenying}
                  className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {!canApprove && (
            <div className="mt-3">
              {isExpired ? (
                <p className="text-sm text-gray-600">
                  This approval request has expired.
                </p>
              ) : !isPending ? (
                <p className="text-sm text-gray-600">
                  This action has been{' '}
                  <span
                    className={clsx(
                      'font-medium',
                      approval.status === 'approved'
                        ? 'text-green-600'
                        : 'text-red-600'
                    )}
                  >
                    {approval.status}
                  </span>
                  {approval.decided_by && ` by ${approval.decided_by}`}.
                </p>
              ) : (
                <p className="text-sm text-gray-600">
                  You are not authorized to approve this action.
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
