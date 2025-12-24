import { useState } from 'react'
import clsx from 'clsx'
import {
  PlayIcon,
  ShieldExclamationIcon,
  EllipsisHorizontalIcon,
  ChevronDownIcon,
  ChevronUpIcon,
} from '@heroicons/react/24/outline'
import ActionButton from './ActionButton'
import ConfirmActionModal from './ConfirmActionModal'
import PlaybookSelector from './PlaybookSelector'
import ExecutionProgress from './ExecutionProgress'
import { useQuickActionWorkflow, useExecutePlaybook } from '../../hooks/useSOAR'

// Quick action configurations based on alert context
const QUICK_ACTIONS = [
  {
    actionType: 'isolate_host',
    requiredFields: ['host', 'hostname', 'endpoint'],
    severity: 'critical',
  },
  {
    actionType: 'block_ip',
    requiredFields: ['source_ip', 'dest_ip', 'ip_address'],
    severity: 'high',
  },
  {
    actionType: 'disable_user',
    requiredFields: ['user', 'username', 'user_id'],
    severity: 'high',
  },
  {
    actionType: 'quarantine_file',
    requiredFields: ['file_hash', 'file_path'],
    severity: 'medium',
  },
]

function extractAlertContext(alert) {
  const context = {}
  const evidence = alert?.evidence || {}

  // Extract host info
  const host = evidence.host || evidence.hostname || evidence.endpoint || alert?.host
  if (host) context.host = host

  // Extract IP info
  const ip = evidence.source_ip || evidence.dest_ip || evidence.ip_address || alert?.source_ip
  if (ip) context.ip = ip

  // Extract user info
  const user = evidence.user || evidence.username || evidence.user_id || alert?.user
  if (user) context.user = user

  // Extract file info
  const fileHash = evidence.file_hash || evidence.sha256 || evidence.md5
  const filePath = evidence.file_path || evidence.path
  if (fileHash) context.file_hash = fileHash
  if (filePath) context.file_path = filePath

  return context
}

function getAvailableActions(alert) {
  const context = extractAlertContext(alert)
  const available = []

  for (const action of QUICK_ACTIONS) {
    const hasRequiredField = action.requiredFields.some((field) => {
      const normalizedField = field.replace('_', '')
      return Object.keys(context).some((key) =>
        key.toLowerCase().includes(normalizedField.toLowerCase())
      )
    })

    if (hasRequiredField) {
      available.push({
        ...action,
        parameters: context,
      })
    }
  }

  return available
}

export default function AlertActions({
  alert,
  alertId,
  compact = false,
  showPlaybooks = true,
  className,
}) {
  const [expanded, setExpanded] = useState(false)
  const [confirmAction, setConfirmAction] = useState(null)
  const [showPlaybookSelector, setShowPlaybookSelector] = useState(false)
  const [activeExecution, setActiveExecution] = useState(null)

  const {
    executeAction,
    isExecuting,
    executionResult,
    reset: resetQuickAction,
  } = useQuickActionWorkflow(alertId)

  const {
    mutate: executePlaybook,
    isPending: isExecutingPlaybook,
    data: playbookExecutionResult,
  } = useExecutePlaybook()

  const effectiveAlertId = alertId || alert?.id
  const availableActions = getAvailableActions(alert)
  const alertContext = extractAlertContext(alert)

  const handleQuickAction = (action) => {
    setConfirmAction({
      ...action,
      title: `Execute ${action.actionType.replace('_', ' ')}?`,
      message: `This will ${action.actionType.replace('_', ' ')} based on the alert evidence.`,
      details: action.parameters,
    })
  }

  const handleConfirmAction = () => {
    if (!confirmAction) return

    executeAction({
      actionType: confirmAction.actionType,
      alertId: effectiveAlertId,
      parameters: confirmAction.parameters,
    })
    setConfirmAction(null)
  }

  const handlePlaybookSelect = ({ playbookId, dryRun }) => {
    executePlaybook({
      playbookId,
      alertId: effectiveAlertId,
      dryRun,
      parameters: alertContext,
    })
    setShowPlaybookSelector(false)
  }

  // Handle execution result
  const currentExecutionId =
    executionResult?.execution_id || playbookExecutionResult?.execution_id

  if (currentExecutionId && currentExecutionId !== activeExecution) {
    setActiveExecution(currentExecutionId)
  }

  // Show execution progress if active
  if (activeExecution) {
    return (
      <div className={clsx('rounded-lg border border-gray-200 p-4', className)}>
        <ExecutionProgress
          executionId={activeExecution}
          onComplete={() => {
            setActiveExecution(null)
            resetQuickAction()
          }}
        />
      </div>
    )
  }

  if (compact) {
    return (
      <div className={clsx('flex items-center gap-2', className)}>
        {availableActions.slice(0, 2).map((action) => (
          <ActionButton
            key={action.actionType}
            actionType={action.actionType}
            size="sm"
            onClick={() => handleQuickAction(action)}
            disabled={isExecuting || isExecutingPlaybook}
            loading={isExecuting}
          />
        ))}
        {(availableActions.length > 2 || showPlaybooks) && (
          <button
            onClick={() => setExpanded(true)}
            className="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
          >
            <EllipsisHorizontalIcon className="h-5 w-5" />
          </button>
        )}

        <ConfirmActionModal
          isOpen={!!confirmAction}
          onClose={() => setConfirmAction(null)}
          onConfirm={handleConfirmAction}
          title={confirmAction?.title}
          message={confirmAction?.message}
          details={confirmAction?.details}
          severity={confirmAction?.severity || 'high'}
          actionLabel="Execute"
          isLoading={isExecuting}
        />
      </div>
    )
  }

  return (
    <div className={clsx('space-y-4', className)}>
      <div className="flex items-center justify-between">
        <h4 className="flex items-center gap-2 font-medium text-gray-900">
          <ShieldExclamationIcon className="h-5 w-5 text-primary-600" />
          Response Actions
        </h4>
        {availableActions.length > 3 && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"
          >
            {expanded ? (
              <>
                <ChevronUpIcon className="h-4 w-4" />
                Show less
              </>
            ) : (
              <>
                <ChevronDownIcon className="h-4 w-4" />
                Show all ({availableActions.length})
              </>
            )}
          </button>
        )}
      </div>

      {availableActions.length === 0 && !showPlaybooks ? (
        <p className="text-sm text-gray-500">
          No quick actions available for this alert.
        </p>
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            {(expanded ? availableActions : availableActions.slice(0, 3)).map(
              (action) => (
                <ActionButton
                  key={action.actionType}
                  actionType={action.actionType}
                  size="md"
                  onClick={() => handleQuickAction(action)}
                  disabled={isExecuting || isExecutingPlaybook}
                  loading={isExecuting}
                />
              )
            )}
          </div>

          {showPlaybooks && (
            <button
              onClick={() => setShowPlaybookSelector(true)}
              disabled={isExecuting || isExecutingPlaybook}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-primary-300 bg-primary-50 px-4 py-2 text-sm font-medium text-primary-700 hover:bg-primary-100 disabled:opacity-50"
            >
              <PlayIcon className="h-5 w-5" />
              Run Playbook
            </button>
          )}
        </>
      )}

      <ConfirmActionModal
        isOpen={!!confirmAction}
        onClose={() => setConfirmAction(null)}
        onConfirm={handleConfirmAction}
        title={confirmAction?.title}
        message={confirmAction?.message}
        details={confirmAction?.details}
        severity={confirmAction?.severity || 'high'}
        actionLabel="Execute"
        isLoading={isExecuting}
      />

      <PlaybookSelector
        isOpen={showPlaybookSelector}
        onClose={() => setShowPlaybookSelector(false)}
        onSelect={handlePlaybookSelect}
        alertId={effectiveAlertId}
      />
    </div>
  )
}
