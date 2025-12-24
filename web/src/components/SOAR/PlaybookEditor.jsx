import { Fragment, useState, useEffect } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import clsx from 'clsx'
import {
  XMarkIcon,
  PlusIcon,
  TrashIcon,
  ArrowsUpDownIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CodeBracketIcon,
} from '@heroicons/react/24/outline'
import StepEditor from './StepEditor'
import { useCreatePlaybook, useUpdatePlaybook } from '../../hooks/useSOAR'
import yaml from 'js-yaml'

const TRIGGER_TYPES = [
  { value: 'manual', label: 'Manual', description: 'Triggered manually by a user' },
  { value: 'alert', label: 'Alert', description: 'Triggered when an alert matches conditions' },
  { value: 'scheduled', label: 'Scheduled', description: 'Runs on a schedule' },
  { value: 'webhook', label: 'Webhook', description: 'Triggered by external HTTP request' },
]

export default function PlaybookEditor({ playbook, onClose, onSave }) {
  const [showYaml, setShowYaml] = useState(false)
  const [yamlError, setYamlError] = useState(null)
  const [expandedStep, setExpandedStep] = useState(null)

  const isEditing = !!playbook?.id

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    tags: [],
    enabled: false,
    trigger: {
      trigger_type: 'manual',
      conditions: {},
    },
    steps: [],
  })

  const [tagInput, setTagInput] = useState('')

  useEffect(() => {
    if (playbook) {
      setFormData({
        name: playbook.name || '',
        description: playbook.description || '',
        tags: playbook.tags || [],
        enabled: playbook.enabled || false,
        trigger: playbook.trigger || { trigger_type: 'manual', conditions: {} },
        steps: playbook.steps || [],
      })
    }
  }, [playbook])

  const { mutate: createPlaybook, isPending: isCreating } = useCreatePlaybook()
  const { mutate: updatePlaybook, isPending: isUpdating } = useUpdatePlaybook()

  const isSaving = isCreating || isUpdating

  const handleChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }))
  }

  const handleTriggerChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      trigger: {
        ...prev.trigger,
        [field]: value,
      },
    }))
  }

  const handleAddTag = () => {
    if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
      handleChange('tags', [...formData.tags, tagInput.trim()])
      setTagInput('')
    }
  }

  const handleRemoveTag = (tag) => {
    handleChange(
      'tags',
      formData.tags.filter((t) => t !== tag)
    )
  }

  const handleAddStep = () => {
    const newStep = {
      id: `step_${Date.now()}`,
      name: `Step ${formData.steps.length + 1}`,
      action_type: 'notify',
      provider: 'slack',
      parameters: {},
      condition: '',
      on_success: null,
      on_failure: null,
      requires_approval: false,
      timeout_seconds: 300,
      retry_count: 0,
    }
    handleChange('steps', [...formData.steps, newStep])
    setExpandedStep(newStep.id)
  }

  const handleUpdateStep = (stepId, updates) => {
    handleChange(
      'steps',
      formData.steps.map((step) =>
        step.id === stepId ? { ...step, ...updates } : step
      )
    )
  }

  const handleRemoveStep = (stepId) => {
    handleChange(
      'steps',
      formData.steps.filter((step) => step.id !== stepId)
    )
  }

  const handleMoveStep = (fromIndex, toIndex) => {
    const newSteps = [...formData.steps]
    const [removed] = newSteps.splice(fromIndex, 1)
    newSteps.splice(toIndex, 0, removed)
    handleChange('steps', newSteps)
  }

  const handleYamlChange = (yamlText) => {
    try {
      const parsed = yaml.load(yamlText)
      setFormData((prev) => ({
        ...prev,
        ...parsed,
      }))
      setYamlError(null)
    } catch (e) {
      setYamlError(e.message)
    }
  }

  const handleSave = (deploy = false) => {
    const playbookData = {
      ...formData,
      enabled: deploy ? true : formData.enabled,
    }

    if (isEditing) {
      updatePlaybook(
        { playbookId: playbook.id, updates: playbookData },
        { onSuccess: onSave }
      )
    } else {
      createPlaybook(playbookData, { onSuccess: onSave })
    }
  }

  const yamlContent = yaml.dump(formData, { skipInvalid: true })

  return (
    <Transition appear show={true} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/50" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-4xl transform overflow-hidden rounded-2xl bg-white shadow-xl transition-all">
                <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
                  <Dialog.Title className="text-xl font-semibold text-gray-900">
                    {isEditing ? 'Edit Playbook' : 'Create Playbook'}
                  </Dialog.Title>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setShowYaml(!showYaml)}
                      className={clsx(
                        'flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium',
                        showYaml
                          ? 'bg-gray-200 text-gray-700'
                          : 'text-gray-600 hover:bg-gray-100'
                      )}
                    >
                      <CodeBracketIcon className="h-4 w-4" />
                      YAML
                    </button>
                    <button
                      onClick={onClose}
                      className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                    >
                      <XMarkIcon className="h-5 w-5" />
                    </button>
                  </div>
                </div>

                <div className="max-h-[70vh] overflow-y-auto p-6">
                  {showYaml ? (
                    <div className="space-y-4">
                      {yamlError && (
                        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                          YAML Error: {yamlError}
                        </div>
                      )}
                      <textarea
                        value={yamlContent}
                        onChange={(e) => handleYamlChange(e.target.value)}
                        className="h-96 w-full rounded-lg border border-gray-300 p-4 font-mono text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                        spellCheck={false}
                      />
                    </div>
                  ) : (
                    <div className="space-y-6">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="col-span-2">
                          <label className="block text-sm font-medium text-gray-700">
                            Name <span className="text-red-500">*</span>
                          </label>
                          <input
                            type="text"
                            value={formData.name}
                            onChange={(e) => handleChange('name', e.target.value)}
                            placeholder="Enter playbook name"
                            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                          />
                        </div>

                        <div className="col-span-2">
                          <label className="block text-sm font-medium text-gray-700">
                            Description
                          </label>
                          <textarea
                            value={formData.description}
                            onChange={(e) => handleChange('description', e.target.value)}
                            placeholder="Describe what this playbook does"
                            rows={2}
                            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                          />
                        </div>

                        <div className="col-span-2">
                          <label className="block text-sm font-medium text-gray-700">
                            Tags
                          </label>
                          <div className="mt-1 flex flex-wrap items-center gap-2">
                            {formData.tags.map((tag) => (
                              <span
                                key={tag}
                                className="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-sm text-gray-700"
                              >
                                {tag}
                                <button
                                  onClick={() => handleRemoveTag(tag)}
                                  className="ml-1 text-gray-500 hover:text-gray-700"
                                >
                                  <XMarkIcon className="h-3 w-3" />
                                </button>
                              </span>
                            ))}
                            <input
                              type="text"
                              value={tagInput}
                              onChange={(e) => setTagInput(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  e.preventDefault()
                                  handleAddTag()
                                }
                              }}
                              placeholder="Add tag..."
                              className="rounded border border-gray-300 px-2 py-1 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                            />
                          </div>
                        </div>
                      </div>

                      <div>
                        <h3 className="mb-3 font-medium text-gray-900">Trigger</h3>
                        <div className="rounded-lg border border-gray-200 p-4">
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <label className="block text-sm font-medium text-gray-700">
                                Trigger Type
                              </label>
                              <select
                                value={formData.trigger.trigger_type}
                                onChange={(e) =>
                                  handleTriggerChange('trigger_type', e.target.value)
                                }
                                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                              >
                                {TRIGGER_TYPES.map((trigger) => (
                                  <option key={trigger.value} value={trigger.value}>
                                    {trigger.label}
                                  </option>
                                ))}
                              </select>
                              <p className="mt-1 text-xs text-gray-500">
                                {
                                  TRIGGER_TYPES.find(
                                    (t) => t.value === formData.trigger.trigger_type
                                  )?.description
                                }
                              </p>
                            </div>

                            {formData.trigger.trigger_type === 'alert' && (
                              <div>
                                <label className="block text-sm font-medium text-gray-700">
                                  Severity Filter
                                </label>
                                <select
                                  value={formData.trigger.conditions?.severity || ''}
                                  onChange={(e) =>
                                    handleTriggerChange('conditions', {
                                      ...formData.trigger.conditions,
                                      severity: e.target.value,
                                    })
                                  }
                                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                                >
                                  <option value="">Any Severity</option>
                                  <option value="critical">Critical</option>
                                  <option value="high">High</option>
                                  <option value="medium">Medium</option>
                                  <option value="low">Low</option>
                                </select>
                              </div>
                            )}

                            {formData.trigger.trigger_type === 'scheduled' && (
                              <div>
                                <label className="block text-sm font-medium text-gray-700">
                                  Schedule (Cron)
                                </label>
                                <input
                                  type="text"
                                  value={formData.trigger.conditions?.schedule || ''}
                                  onChange={(e) =>
                                    handleTriggerChange('conditions', {
                                      ...formData.trigger.conditions,
                                      schedule: e.target.value,
                                    })
                                  }
                                  placeholder="0 */6 * * *"
                                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                                />
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="mb-3 flex items-center justify-between">
                          <h3 className="font-medium text-gray-900">
                            Steps ({formData.steps.length})
                          </h3>
                          <button
                            onClick={handleAddStep}
                            className="flex items-center gap-1 rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
                          >
                            <PlusIcon className="h-4 w-4" />
                            Add Step
                          </button>
                        </div>

                        {formData.steps.length === 0 ? (
                          <div className="rounded-lg border-2 border-dashed border-gray-300 p-8 text-center">
                            <p className="text-gray-500">
                              No steps defined. Click "Add Step" to create your first step.
                            </p>
                          </div>
                        ) : (
                          <div className="space-y-3">
                            {formData.steps.map((step, index) => (
                              <div
                                key={step.id}
                                className="rounded-lg border border-gray-200"
                              >
                                <div
                                  className="flex cursor-pointer items-center justify-between p-3"
                                  onClick={() =>
                                    setExpandedStep(
                                      expandedStep === step.id ? null : step.id
                                    )
                                  }
                                >
                                  <div className="flex items-center gap-3">
                                    <span className="flex h-6 w-6 items-center justify-center rounded bg-gray-100 text-xs font-medium text-gray-600">
                                      {index + 1}
                                    </span>
                                    <div>
                                      <p className="font-medium text-gray-900">
                                        {step.name}
                                      </p>
                                      <p className="text-sm text-gray-500">
                                        {step.action_type}
                                        {step.provider && ` • ${step.provider}`}
                                      </p>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    {index > 0 && (
                                      <button
                                        onClick={(e) => {
                                          e.stopPropagation()
                                          handleMoveStep(index, index - 1)
                                        }}
                                        className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                                        title="Move up"
                                      >
                                        <ArrowsUpDownIcon className="h-4 w-4" />
                                      </button>
                                    )}
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        handleRemoveStep(step.id)
                                      }}
                                      className="rounded p-1 text-gray-400 hover:bg-red-50 hover:text-red-600"
                                    >
                                      <TrashIcon className="h-4 w-4" />
                                    </button>
                                    {expandedStep === step.id ? (
                                      <ChevronDownIcon className="h-5 w-5 text-gray-400" />
                                    ) : (
                                      <ChevronRightIcon className="h-5 w-5 text-gray-400" />
                                    )}
                                  </div>
                                </div>

                                {expandedStep === step.id && (
                                  <div className="border-t border-gray-200 p-4">
                                    <StepEditor
                                      step={step}
                                      allSteps={formData.steps}
                                      onChange={(updates) =>
                                        handleUpdateStep(step.id, updates)
                                      }
                                    />
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between border-t border-gray-200 px-6 py-4">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="enabled"
                      checked={formData.enabled}
                      onChange={(e) => handleChange('enabled', e.target.checked)}
                      className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                    />
                    <label htmlFor="enabled" className="text-sm text-gray-700">
                      Enable playbook after saving
                    </label>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={onClose}
                      className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => handleSave(false)}
                      disabled={isSaving || !formData.name}
                      className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                    >
                      {isSaving ? 'Saving...' : 'Save Draft'}
                    </button>
                    <button
                      onClick={() => handleSave(true)}
                      disabled={isSaving || !formData.name}
                      className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
                    >
                      {isSaving ? 'Saving...' : 'Save & Enable'}
                    </button>
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
