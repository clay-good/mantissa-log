import { useState, useEffect, useMemo } from 'react'
import Modal from '../common/Modal'
import clsx from 'clsx'

const SOURCE_DISPLAY_NAMES = {
  okta: 'Okta',
  google_workspace: 'Google Workspace',
  microsoft365: 'Microsoft 365',
  duo: 'Duo Security',
  cloudtrail: 'AWS CloudTrail',
  vpc_flow_logs: 'VPC Flow Logs',
  guardduty: 'AWS GuardDuty',
  gcp_logging: 'GCP Cloud Logging',
  azure_monitor: 'Azure Monitor',
  crowdstrike: 'CrowdStrike',
  jamf: 'Jamf',
  snowflake: 'Snowflake',
  salesforce: 'Salesforce',
  slack: 'Slack',
  onepassword: '1Password',
  github: 'GitHub',
  kubernetes: 'Kubernetes',
  docker: 'Docker',
  syslog: 'Syslog',
  json_generic: 'Generic JSON',
  otlp: 'OTLP',
}

const DEFAULT_CONFIG = {
  enabled: true,
  expected_max_latency_seconds: 300,
  silence_threshold_seconds: 3600,
  volume_anomaly_stddev_threshold: 3.0,
  volume_drop_percentage_threshold: 0.5,
  volume_spike_percentage_threshold: 3.0,
  baseline_learning_period_days: 7,
  check_interval_seconds: 300,
  alert_suppression_seconds: 3600,
  alert_destinations: [],
  gap_detection_enabled: true,
  gap_minimum_duration_seconds: 900,
}

const CONFIG_FIELDS = [
  { key: 'enabled', label: 'Monitoring Enabled', type: 'toggle', group: 'General', description: 'Enable or disable health monitoring for this source' },
  { key: 'check_interval_seconds', label: 'Check Interval', type: 'number', unit: 'seconds', min: 60, max: 86400, group: 'General', description: 'How often to evaluate the health of this source' },
  { key: 'expected_max_latency_seconds', label: 'Max Expected Latency', type: 'number', unit: 'seconds', min: 1, max: 86400, group: 'Thresholds', description: 'Maximum time between events before source is marked as delayed' },
  { key: 'silence_threshold_seconds', label: 'Silence Threshold', type: 'number', unit: 'seconds', min: 1, max: 604800, group: 'Thresholds', description: 'Time without events before source is marked as silent' },
  { key: 'volume_anomaly_stddev_threshold', label: 'Volume Anomaly (Stddev)', type: 'number', unit: 'stddev', min: 0.1, max: 10.0, step: 0.1, group: 'Volume', description: 'Number of standard deviations from baseline to trigger a volume anomaly' },
  { key: 'volume_drop_percentage_threshold', label: 'Volume Drop Threshold', type: 'number', unit: 'ratio (0\u20131)', min: 0.01, max: 0.99, step: 0.05, group: 'Volume', description: 'Fraction of baseline volume below which a drop anomaly is triggered' },
  { key: 'volume_spike_percentage_threshold', label: 'Volume Spike Threshold', type: 'number', unit: '\u00d7 multiplier', min: 1.01, max: 100.0, step: 0.5, group: 'Volume', description: 'Multiple of baseline volume above which a spike anomaly is triggered' },
  { key: 'baseline_learning_period_days', label: 'Baseline Learning Period', type: 'number', unit: 'days', min: 1, max: 90, group: 'Baseline', description: 'Number of days of historical data used to compute the volume baseline' },
  { key: 'alert_suppression_seconds', label: 'Alert Suppression Duration', type: 'number', unit: 'seconds', min: 0, max: 604800, group: 'Alerting', description: 'Minimum time between repeated alerts for the same source' },
  { key: 'gap_detection_enabled', label: 'Gap Detection Enabled', type: 'toggle', group: 'Gaps', description: 'Enable detection of data gaps (periods with no events)' },
  { key: 'gap_minimum_duration_seconds', label: 'Minimum Gap Duration', type: 'number', unit: 'seconds', min: 60, max: 86400, group: 'Gaps', description: 'Minimum duration of a data-free period to be considered a gap' },
]

const FIELD_GROUPS = ['General', 'Thresholds', 'Volume', 'Baseline', 'Alerting', 'Gaps']

function formatUnit(value, unit) {
  if (!unit) return ''
  if (unit === 'seconds') {
    if (value >= 86400) return `${(value / 86400).toFixed(1)} days`
    if (value >= 3600) return `${(value / 3600).toFixed(1)} hours`
    if (value >= 60) return `${(value / 60).toFixed(0)} min`
    return `${value}s`
  }
  return unit
}

export default function LogSourceHealthConfig({
  isOpen,
  onClose,
  sourceType,
  currentConfig,
  onSave,
  isSaving = false,
}) {
  const [formData, setFormData] = useState({})
  const [errors, setErrors] = useState({})
  const [isDirty, setIsDirty] = useState(false)
  const [alertDestText, setAlertDestText] = useState('')

  useEffect(() => {
    if (isOpen) {
      const config = currentConfig
        ? { ...DEFAULT_CONFIG, ...currentConfig }
        : { ...DEFAULT_CONFIG }
      setFormData(config)
      setAlertDestText((config.alert_destinations || []).join(', '))
      setErrors({})
      setIsDirty(false)
    }
  }, [isOpen, currentConfig])

  const handleFieldChange = (key, value) => {
    setFormData((prev) => ({ ...prev, [key]: value }))
    setIsDirty(true)
    if (errors[key]) {
      setErrors((prev) => {
        const next = { ...prev }
        delete next[key]
        return next
      })
    }
  }

  const validate = () => {
    const newErrors = {}

    CONFIG_FIELDS.forEach((field) => {
      if (field.type === 'number') {
        const val = formData[field.key]
        if (val === '' || val === null || val === undefined) {
          newErrors[field.key] = 'Required'
        } else {
          const num = Number(val)
          if (isNaN(num)) {
            newErrors[field.key] = 'Must be a number'
          } else if (field.min !== undefined && num < field.min) {
            newErrors[field.key] = `Must be at least ${field.min}`
          } else if (field.max !== undefined && num > field.max) {
            newErrors[field.key] = `Must be at most ${field.max}`
          }
        }
      }
    })

    // Cross-field validation: silence > latency
    const latency = Number(formData.expected_max_latency_seconds)
    const silence = Number(formData.silence_threshold_seconds)
    if (!isNaN(latency) && !isNaN(silence) && silence <= latency) {
      newErrors.silence_threshold_seconds = 'Must be greater than max expected latency'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSave = () => {
    if (!validate()) return
    const overrides = {}
    CONFIG_FIELDS.forEach((field) => {
      if (field.type === 'number') {
        overrides[field.key] = Number(formData[field.key])
      } else {
        overrides[field.key] = formData[field.key]
      }
    })
    // Parse alert destinations
    overrides.alert_destinations = alertDestText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    onSave(sourceType, overrides)
  }

  const handleReset = () => {
    setFormData({ ...DEFAULT_CONFIG })
    setAlertDestText('')
    setIsDirty(true)
    setErrors({})
  }

  const groupedFields = useMemo(() => {
    const groups = {}
    FIELD_GROUPS.forEach((g) => {
      groups[g] = CONFIG_FIELDS.filter((f) => f.group === g)
    })
    return groups
  }, [])

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Configure: ${SOURCE_DISPLAY_NAMES[sourceType] || sourceType}`}
      size="lg"
      footer={
        <>
          <button className="btn-secondary" onClick={handleReset} disabled={isSaving}>
            Reset to Defaults
          </button>
          <button className="btn-secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </button>
          <button
            className="btn-primary"
            onClick={handleSave}
            disabled={isSaving || !isDirty}
          >
            {isSaving ? 'Saving...' : 'Save Configuration'}
          </button>
        </>
      }
    >
      <div className="space-y-6">
        {FIELD_GROUPS.map((group) => {
          const fields = groupedFields[group]
          if (!fields || fields.length === 0) return null
          return (
            <div key={group}>
              <h4 className="text-sm font-semibold text-mono-900 dark:text-mono-100 mb-3 border-b border-mono-200 dark:border-mono-800 pb-2">
                {group}
              </h4>
              <div className="space-y-4">
                {fields.map((field) => {
                  if (field.type === 'toggle') {
                    return (
                      <div key={field.key} className="flex items-center justify-between">
                        <div>
                          <label className="text-sm font-medium text-mono-900 dark:text-mono-100">
                            {field.label}
                          </label>
                          <p className="text-xs text-mono-500 dark:text-mono-400">
                            {field.description}
                          </p>
                        </div>
                        <button
                          type="button"
                          role="switch"
                          aria-checked={!!formData[field.key]}
                          onClick={() => handleFieldChange(field.key, !formData[field.key])}
                          className={clsx(
                            'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200',
                            formData[field.key]
                              ? 'bg-mono-900 dark:bg-mono-100'
                              : 'bg-mono-300 dark:bg-mono-700',
                          )}
                        >
                          <span
                            className={clsx(
                              'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white dark:bg-mono-900 shadow ring-0 transition duration-200',
                              formData[field.key] ? 'translate-x-5' : 'translate-x-0',
                            )}
                          />
                        </button>
                      </div>
                    )
                  }

                  return (
                    <div key={field.key}>
                      <label className="label">{field.label}</label>
                      <p className="text-xs text-mono-500 dark:text-mono-400 mb-1">
                        {field.description}
                      </p>
                      <div className="flex items-center gap-2">
                        <input
                          type="number"
                          value={formData[field.key] ?? ''}
                          onChange={(e) => handleFieldChange(field.key, e.target.value)}
                          min={field.min}
                          max={field.max}
                          step={field.step || 1}
                          className={clsx(
                            'input w-40',
                            errors[field.key] && 'border-red-500 dark:border-red-500',
                          )}
                        />
                        <span className="text-xs text-mono-500 dark:text-mono-400">
                          {field.unit === 'seconds' && formData[field.key]
                            ? formatUnit(Number(formData[field.key]), 'seconds')
                            : field.unit || ''}
                        </span>
                      </div>
                      {errors[field.key] && (
                        <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                          {errors[field.key]}
                        </p>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}

        {/* Alert destinations */}
        <div>
          <h4 className="text-sm font-semibold text-mono-900 dark:text-mono-100 mb-3 border-b border-mono-200 dark:border-mono-800 pb-2">
            Alerting
          </h4>
          <label className="label">Alert Destinations</label>
          <p className="text-xs text-mono-500 dark:text-mono-400 mb-1">
            Comma-separated list of alert destination identifiers
          </p>
          <textarea
            value={alertDestText}
            onChange={(e) => {
              setAlertDestText(e.target.value)
              setIsDirty(true)
            }}
            placeholder="slack-ops, pagerduty-oncall"
            rows={2}
            className="input"
          />
        </div>
      </div>
    </Modal>
  )
}
