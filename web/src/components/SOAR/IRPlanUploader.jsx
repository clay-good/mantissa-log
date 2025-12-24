import { Fragment, useState, useRef } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import {
  XMarkIcon,
  DocumentArrowUpIcon,
  DocumentTextIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import { useParseIRPlan } from '../../hooks/useSOAR'

export default function IRPlanUploader({ isOpen, onClose, onParsed }) {
  const [planText, setPlanText] = useState('')
  const [planName, setPlanName] = useState('')
  const [format, setFormat] = useState('markdown')
  const [parsedPlaybook, setParsedPlaybook] = useState(null)
  const fileInputRef = useRef(null)

  const { mutate: parseIRPlan, isPending: isParsing, error: parseError } = useParseIRPlan()

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      setPlanText(event.target?.result || '')
      if (!planName) {
        setPlanName(file.name.replace(/\.(md|txt)$/, ''))
      }
    }
    reader.readAsText(file)
  }

  const handleParse = () => {
    parseIRPlan(
      { planText, planName, format },
      {
        onSuccess: (data) => {
          setParsedPlaybook(data.playbook)
        },
      }
    )
  }

  const handleEdit = () => {
    if (parsedPlaybook) {
      onParsed(parsedPlaybook)
    }
  }

  const handleSaveDirectly = () => {
    if (parsedPlaybook) {
      onParsed(parsedPlaybook)
    }
  }

  const handleReset = () => {
    setPlanText('')
    setPlanName('')
    setParsedPlaybook(null)
  }

  return (
    <Transition appear show={isOpen} as={Fragment}>
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
              <Dialog.Panel className="w-full max-w-3xl transform overflow-hidden rounded-2xl bg-white shadow-xl transition-all">
                <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
                  <div className="flex items-center gap-3">
                    <DocumentArrowUpIcon className="h-6 w-6 text-primary-600" />
                    <Dialog.Title className="text-xl font-semibold text-gray-900">
                      Upload IR Plan
                    </Dialog.Title>
                  </div>
                  <button
                    onClick={onClose}
                    className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>

                <div className="max-h-[70vh] overflow-y-auto p-6">
                  {!parsedPlaybook ? (
                    <div className="space-y-6">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Playbook Name
                        </label>
                        <input
                          type="text"
                          value={planName}
                          onChange={(e) => setPlanName(e.target.value)}
                          placeholder="e.g., Credential Compromise Response"
                          className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Format
                        </label>
                        <div className="mt-1 flex gap-4">
                          <label className="flex items-center gap-2">
                            <input
                              type="radio"
                              name="format"
                              value="markdown"
                              checked={format === 'markdown'}
                              onChange={(e) => setFormat(e.target.value)}
                              className="h-4 w-4 border-gray-300 text-primary-600 focus:ring-primary-500"
                            />
                            <span className="text-sm text-gray-700">Markdown</span>
                          </label>
                          <label className="flex items-center gap-2">
                            <input
                              type="radio"
                              name="format"
                              value="text"
                              checked={format === 'text'}
                              onChange={(e) => setFormat(e.target.value)}
                              className="h-4 w-4 border-gray-300 text-primary-600 focus:ring-primary-500"
                            />
                            <span className="text-sm text-gray-700">Plain Text</span>
                          </label>
                        </div>
                      </div>

                      <div>
                        <div className="mb-2 flex items-center justify-between">
                          <label className="block text-sm font-medium text-gray-700">
                            IR Plan Content
                          </label>
                          <button
                            onClick={() => fileInputRef.current?.click()}
                            className="flex items-center gap-1 text-sm text-primary-600 hover:text-primary-700"
                          >
                            <DocumentTextIcon className="h-4 w-4" />
                            Upload File
                          </button>
                          <input
                            ref={fileInputRef}
                            type="file"
                            accept=".md,.txt,.markdown"
                            onChange={handleFileUpload}
                            className="hidden"
                          />
                        </div>
                        <textarea
                          value={planText}
                          onChange={(e) => setPlanText(e.target.value)}
                          placeholder={`Paste your IR plan here...

Example:
# Credential Compromise Response

## Steps
1. Disable the compromised user account
2. Revoke all active sessions
3. Notify the security team via Slack
4. Create a JIRA ticket for investigation`}
                          rows={12}
                          className="block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                        />
                      </div>

                      {parseError && (
                        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                          Failed to parse IR plan. Please check the format and try again.
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-6">
                      <div className="rounded-lg border border-green-200 bg-green-50 p-4">
                        <h3 className="font-medium text-green-800">
                          IR Plan Parsed Successfully
                        </h3>
                        <p className="mt-1 text-sm text-green-700">
                          Review the generated playbook below before saving.
                        </p>
                      </div>

                      <div>
                        <h3 className="mb-2 font-medium text-gray-900">
                          {parsedPlaybook.name}
                        </h3>
                        {parsedPlaybook.description && (
                          <p className="text-sm text-gray-600">
                            {parsedPlaybook.description}
                          </p>
                        )}
                      </div>

                      <div>
                        <h4 className="mb-2 text-sm font-medium text-gray-700">
                          Generated Steps ({parsedPlaybook.steps?.length || 0})
                        </h4>
                        <div className="space-y-2">
                          {parsedPlaybook.steps?.map((step, index) => (
                            <div
                              key={step.id}
                              className="flex items-center gap-3 rounded-lg border border-gray-200 p-3"
                            >
                              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-gray-100 text-xs font-medium text-gray-600">
                                {index + 1}
                              </span>
                              <div>
                                <p className="font-medium text-gray-900">{step.name}</p>
                                <p className="text-sm text-gray-500">
                                  {step.action_type}
                                  {step.provider && ` • ${step.provider}`}
                                </p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="flex gap-3">
                        <button
                          onClick={handleReset}
                          className="flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                        >
                          <ArrowPathIcon className="h-4 w-4" />
                          Start Over
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-200 px-6 py-4">
                  <button
                    onClick={onClose}
                    className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  {!parsedPlaybook ? (
                    <button
                      onClick={handleParse}
                      disabled={isParsing || !planText.trim()}
                      className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
                    >
                      {isParsing ? (
                        <>
                          <ArrowPathIcon className="h-4 w-4 animate-spin" />
                          Parsing...
                        </>
                      ) : (
                        'Parse IR Plan'
                      )}
                    </button>
                  ) : (
                    <>
                      <button
                        onClick={handleEdit}
                        className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                      >
                        Edit in Editor
                      </button>
                      <button
                        onClick={handleSaveDirectly}
                        className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700"
                      >
                        Save Playbook
                      </button>
                    </>
                  )}
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
