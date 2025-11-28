import { useState, useEffect } from 'react';
import { X, Check, AlertCircle, Loader2 } from 'lucide-react';

const SCHEDULE_PRESETS = [
  { label: 'Every 5 minutes', value: 'rate(5 minutes)' },
  { label: 'Every 15 minutes', value: 'rate(15 minutes)' },
  { label: 'Every 30 minutes', value: 'rate(30 minutes)' },
  { label: 'Hourly', value: 'rate(1 hour)' },
  { label: 'Daily at midnight', value: 'cron(0 0 * * ? *)' },
  { label: 'Custom', value: 'custom' }
];

const SEVERITY_LEVELS = [
  { value: 'critical', label: 'Critical', color: 'bg-red-600' },
  { value: 'high', label: 'High', color: 'bg-orange-600' },
  { value: 'medium', label: 'Medium', color: 'bg-yellow-600' },
  { value: 'low', label: 'Low', color: 'bg-blue-600' },
  { value: 'info', label: 'Info', color: 'bg-gray-600' }
];

export default function DetectionRuleWizard({ query, onClose, onSave, integrations }) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    ruleName: '',
    description: '',
    schedule: 'rate(5 minutes)',
    customSchedule: '',
    threshold: 1,
    severity: 'medium',
    alertDestinations: []
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const updateField = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setError('');
  };

  const toggleDestination = (dest) => {
    setFormData(prev => ({
      ...prev,
      alertDestinations: prev.alertDestinations.includes(dest)
        ? prev.alertDestinations.filter(d => d !== dest)
        : [...prev.alertDestinations, dest]
    }));
  };

  const validateStep = () => {
    switch (step) {
      case 1:
        if (!formData.ruleName.trim()) {
          setError('Rule name is required');
          return false;
        }
        if (!formData.description.trim()) {
          setError('Description is required');
          return false;
        }
        return true;
      case 2:
        if (formData.schedule === 'custom' && !formData.customSchedule.trim()) {
          setError('Custom schedule expression is required');
          return false;
        }
        if (formData.threshold < 1) {
          setError('Threshold must be at least 1');
          return false;
        }
        return true;
      default:
        return true;
    }
  };

  const nextStep = () => {
    if (validateStep()) {
      setStep(prev => prev + 1);
    }
  };

  const previousStep = () => {
    setError('');
    setStep(prev => prev - 1);
  };

  const handleSave = async () => {
    if (!validateStep()) return;

    setLoading(true);
    setError('');

    try {
      const scheduleValue = formData.schedule === 'custom'
        ? formData.customSchedule
        : formData.schedule;

      await onSave({
        query,
        ruleName: formData.ruleName,
        description: formData.description,
        schedule: scheduleValue,
        threshold: formData.threshold,
        severity: formData.severity,
        alertDestinations: formData.alertDestinations
      });
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to create detection rule');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b flex justify-between items-center">
          <h2 className="text-xl font-semibold">Create Detection Rule</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Progress Indicator */}
        <div className="px-6 py-4 border-b bg-gray-50">
          <div className="flex items-center justify-between">
            {['Rule Details', 'Schedule & Threshold', 'Alert Routing', 'Review'].map((label, idx) => (
              <div key={idx} className="flex items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step > idx + 1 ? 'bg-green-600 text-white' :
                  step === idx + 1 ? 'bg-blue-600 text-white' :
                  'bg-gray-300 text-gray-600'
                }`}>
                  {step > idx + 1 ? <Check className="w-4 h-4" /> : idx + 1}
                </div>
                <span className="ml-2 text-sm font-medium hidden sm:inline">{label}</span>
                {idx < 3 && <div className="w-8 sm:w-16 h-1 mx-2 bg-gray-300" />}
              </div>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-6">
          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded flex items-start">
              <AlertCircle className="w-5 h-5 text-red-600 mr-2 mt-0.5" />
              <span className="text-sm text-red-800">{error}</span>
            </div>
          )}

          {/* Step 1: Rule Details */}
          {step === 1 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Rule Name *
                </label>
                <input
                  type="text"
                  value={formData.ruleName}
                  onChange={(e) => updateField('ruleName', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  placeholder="e.g., failed_login_attempts"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Description *
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => updateField('description', e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Describe what this detection identifies..."
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Severity *
                </label>
                <div className="grid grid-cols-5 gap-2">
                  {SEVERITY_LEVELS.map(level => (
                    <button
                      key={level.value}
                      onClick={() => updateField('severity', level.value)}
                      className={`px-3 py-2 rounded-md text-white text-sm font-medium ${level.color} ${
                        formData.severity === level.value ? 'ring-2 ring-offset-2 ring-gray-900' : 'opacity-60 hover:opacity-100'
                      }`}
                    >
                      {level.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-4 p-3 bg-blue-50 rounded-md">
                <p className="text-sm text-blue-800">
                  This detection will run the following query:
                </p>
                <pre className="mt-2 text-xs bg-white p-2 rounded border border-blue-200 overflow-x-auto">
                  {query}
                </pre>
              </div>
            </div>
          )}

          {/* Step 2: Schedule & Threshold */}
          {step === 2 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Execution Schedule *
                </label>
                <select
                  value={formData.schedule}
                  onChange={(e) => updateField('schedule', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                >
                  {SCHEDULE_PRESETS.map(preset => (
                    <option key={preset.value} value={preset.value}>
                      {preset.label}
                    </option>
                  ))}
                </select>
              </div>

              {formData.schedule === 'custom' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Custom Schedule Expression
                  </label>
                  <input
                    type="text"
                    value={formData.customSchedule}
                    onChange={(e) => updateField('customSchedule', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    placeholder="rate(10 minutes) or cron(0 12 * * ? *)"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Use AWS EventBridge schedule expression format
                  </p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Alert Threshold
                </label>
                <input
                  type="number"
                  min="1"
                  value={formData.threshold}
                  onChange={(e) => updateField('threshold', parseInt(e.target.value) || 1)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Trigger alert when query returns at least this many results
                </p>
              </div>
            </div>
          )}

          {/* Step 3: Alert Routing */}
          {step === 3 && (
            <div className="space-y-4">
              <p className="text-sm text-gray-600">
                Select where alerts should be sent when this detection triggers:
              </p>

              <div className="space-y-3">
                {integrations && integrations.map(integration => (
                  <div
                    key={integration.id}
                    className={`border rounded-lg p-4 cursor-pointer transition ${
                      formData.alertDestinations.includes(integration.id)
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-300 hover:border-gray-400'
                    }`}
                    onClick={() => toggleDestination(integration.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <input
                          type="checkbox"
                          checked={formData.alertDestinations.includes(integration.id)}
                          onChange={() => {}}
                          className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                        />
                        <div className="ml-3">
                          <p className="font-medium text-gray-900">{integration.name}</p>
                          <p className="text-sm text-gray-500">{integration.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center">
                        {integration.configured ? (
                          <span className="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded">
                            Configured
                          </span>
                        ) : (
                          <span className="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded">
                            Setup Required
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-4 p-3 bg-gray-50 rounded-md">
                <p className="text-sm text-gray-700">
                  {formData.alertDestinations.length === 0
                    ? 'No alert destinations selected. The detection will run but not send alerts.'
                    : `Alerts will be sent to ${formData.alertDestinations.length} destination(s).`
                  }
                </p>
              </div>
            </div>
          )}

          {/* Step 4: Review */}
          {step === 4 && (
            <div className="space-y-4">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-semibold text-gray-900 mb-3">Detection Rule Summary</h3>

                <dl className="space-y-2">
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Name</dt>
                    <dd className="text-sm text-gray-900">{formData.ruleName}</dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Description</dt>
                    <dd className="text-sm text-gray-900">{formData.description}</dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Severity</dt>
                    <dd className="text-sm">
                      <span className={`px-2 py-1 rounded text-white text-xs ${
                        SEVERITY_LEVELS.find(s => s.value === formData.severity)?.color
                      }`}>
                        {formData.severity.toUpperCase()}
                      </span>
                    </dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Schedule</dt>
                    <dd className="text-sm text-gray-900">
                      {formData.schedule === 'custom' ? formData.customSchedule : formData.schedule}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Threshold</dt>
                    <dd className="text-sm text-gray-900">{formData.threshold} result(s)</dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Alert Destinations</dt>
                    <dd className="text-sm text-gray-900">
                      {formData.alertDestinations.length > 0
                        ? formData.alertDestinations.join(', ')
                        : 'None'
                      }
                    </dd>
                  </div>
                </dl>
              </div>

              <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
                <h4 className="font-medium text-blue-900 mb-2">Query</h4>
                <pre className="text-xs bg-white p-3 rounded border border-blue-200 overflow-x-auto">
                  {query}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t bg-gray-50 flex justify-between">
          <button
            onClick={previousStep}
            disabled={step === 1}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Previous
          </button>

          <div className="flex space-x-2">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
            >
              Cancel
            </button>
            {step < 4 ? (
              <button
                onClick={nextStep}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
              >
                Next
              </button>
            ) : (
              <button
                onClick={handleSave}
                disabled={loading}
                className="px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-md hover:bg-green-700 disabled:opacity-50 flex items-center"
              >
                {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Create Detection Rule
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
