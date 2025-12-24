import { useState } from 'react'
import {
  PlayIcon,
  DocumentArrowUpIcon,
  PlusIcon,
  ClockIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline'
import PlaybookList from './PlaybookList'
import PlaybookDetail from './PlaybookDetail'
import PlaybookEditor from './PlaybookEditor'
import IRPlanUploader from './IRPlanUploader'
import ExecutionHistory from './ExecutionHistory'
import ExecutionDetail from './ExecutionDetail'
import ApprovalsList from './ApprovalsList'
import { usePlaybooks, useExecutions, usePendingApprovals } from '../../hooks/useSOAR'

const TABS = [
  { id: 'playbooks', label: 'All Playbooks', icon: PlayIcon },
  { id: 'executions', label: 'Executions', icon: ClockIcon },
  { id: 'approvals', label: 'Pending Approvals', icon: ExclamationCircleIcon },
]

export default function PlaybooksDashboard() {
  const [activeTab, setActiveTab] = useState('playbooks')
  const [selectedPlaybookId, setSelectedPlaybookId] = useState(null)
  const [selectedExecutionId, setSelectedExecutionId] = useState(null)
  const [showEditor, setShowEditor] = useState(false)
  const [editingPlaybook, setEditingPlaybook] = useState(null)
  const [showIRUploader, setShowIRUploader] = useState(false)

  const { data: approvalsData } = usePendingApprovals(10, { polling: true })
  const pendingCount = approvalsData?.approvals?.length || 0

  const handleCreatePlaybook = () => {
    setEditingPlaybook(null)
    setShowEditor(true)
  }

  const handleEditPlaybook = (playbook) => {
    setEditingPlaybook(playbook)
    setShowEditor(true)
  }

  const handleCloseEditor = () => {
    setShowEditor(false)
    setEditingPlaybook(null)
  }

  const handlePlaybookSaved = () => {
    setShowEditor(false)
    setEditingPlaybook(null)
  }

  const handleIRPlanParsed = (playbookData) => {
    setShowIRUploader(false)
    setEditingPlaybook(playbookData)
    setShowEditor(true)
  }

  const handleViewPlaybook = (playbookId) => {
    setSelectedPlaybookId(playbookId)
  }

  const handleViewExecution = (executionId) => {
    setSelectedExecutionId(executionId)
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 'playbooks':
        return (
          <PlaybookList
            onView={handleViewPlaybook}
            onEdit={handleEditPlaybook}
          />
        )
      case 'executions':
        return (
          <ExecutionHistory
            onViewExecution={handleViewExecution}
          />
        )
      case 'approvals':
        return <ApprovalsList />
      default:
        return null
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="mb-2">Playbooks</h1>
          <p className="text-gray-600">
            Manage automated response playbooks for security incidents
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowIRUploader(true)}
            className="flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            <DocumentArrowUpIcon className="h-5 w-5" />
            Upload IR Plan
          </button>
          <button
            onClick={handleCreatePlaybook}
            className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700"
          >
            <PlusIcon className="h-5 w-5" />
            Create Playbook
          </button>
        </div>
      </div>

      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {TABS.map((tab) => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 border-b-2 px-1 py-4 text-sm font-medium transition-colors ${
                  isActive
                    ? 'border-primary-500 text-primary-600'
                    : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
                }`}
              >
                <Icon className="h-5 w-5" />
                {tab.label}
                {tab.id === 'approvals' && pendingCount > 0 && (
                  <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-700">
                    {pendingCount}
                  </span>
                )}
              </button>
            )
          })}
        </nav>
      </div>

      <div className="card">{renderTabContent()}</div>

      {selectedPlaybookId && (
        <PlaybookDetail
          playbookId={selectedPlaybookId}
          onClose={() => setSelectedPlaybookId(null)}
          onEdit={handleEditPlaybook}
        />
      )}

      {selectedExecutionId && (
        <ExecutionDetail
          executionId={selectedExecutionId}
          onClose={() => setSelectedExecutionId(null)}
        />
      )}

      {showEditor && (
        <PlaybookEditor
          playbook={editingPlaybook}
          onClose={handleCloseEditor}
          onSave={handlePlaybookSaved}
        />
      )}

      {showIRUploader && (
        <IRPlanUploader
          isOpen={showIRUploader}
          onClose={() => setShowIRUploader(false)}
          onParsed={handleIRPlanParsed}
        />
      )}
    </div>
  )
}
