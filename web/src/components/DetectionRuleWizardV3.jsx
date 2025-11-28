import { useState, useEffect } from 'react';
import { X, Check, AlertCircle, Loader2 } from 'lucide-react';
import CostProjectionV2 from './CostProjectionV2';

const SCHEDULE_PRESETS = [
  { label: 'Every 5 minutes', value: 'rate(5 minutes)' },
  { label: 'Every 15 minutes', value: 'rate(15 minutes)' },
  { label: 'Every 30 minutes', value: 'rate(30 minutes)' },
  { label: 'Hourly', value: 'rate(1 hour)' },
  { label: 'Every 6 hours', value: 'rate(6 hours)' },
  { label: 'Daily at midnight', value: 'cron(0 0 * * *)' },
  { label: 'Custom', value: 'custom' }
];

const SEVERITY_LEVELS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' }
];

export default function DetectionRuleWizardV3({ query, queryStats, onClose, onSave, integrations }) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    ruleName: '',
    description: '',
    schedule: 'rate(5 minutes)',
    customSchedule: '',
    threshold: 1,
    severity: 'medium',
    estimatedAlerts: 10,
    alertDestinations: []
  });
  const [costData, setCostData] = useState(null);
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

  const handleCostUpdate = (cost) => {
    setCostData(cost);
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
        alertDestinations: formData.alertDestinations,
        projectedCost: costData?.total_monthly_cost || 0
      });
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to create detection rule');
    } finally {
      setLoading(false);
    }
  };

  const getScheduleValue = () => {
    return formData.schedule === 'custom' ? formData.customSchedule : formData.schedule;
  };

  return (
    <div className="fixed inset-0 bg-mono-950/50 dark:bg-mono-950/70 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
      <div className="bg-white dark:bg-mono-900 rounded-lg shadow-2xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-hidden flex flex-col animate-scale-in">
        <div className="px-6 py-4 border-b border-mono-200 dark:border-mono-800 flex justify-between items-center">
          <h2 className="text-xl font-semibold text-mono-950 dark:text-mono-50">Create Detection Rule</h2>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-mono-600 dark:text-mono-400 hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-4 border-b border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-850">
          <div className="flex items-center justify-between">
            {['Details', 'Schedule & Cost', 'Routing', 'Review'].map((label, idx) => (
              <div key={idx} className="flex items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center font-medium text-sm transition-all ${
                  step > idx + 1 ? 'bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950' :
                  step === idx + 1 ? 'bg-mono-700 dark:bg-mono-300 text-mono-50 dark:text-mono-950' :
                  'bg-mono-200 dark:bg-mono-800 text-mono-600 dark:text-mono-400'
                }`}>
                  {step > idx + 1 ? <Check className="w-4 h-4" /> : idx + 1}
                </div>
                <span className="ml-2 text-sm font-medium hidden sm:inline text-mono-700 dark:text-mono-300">{label}</span>
                {idx < 3 && <div className="w-8 sm:w-16 h-0.5 mx-2 bg-mono-200 dark:bg-mono-800" />}
              </div>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-6">
          {error && (
            <div className="mb-4 p-3 bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded-lg flex items-start animate-slide-down">
              <AlertCircle className="w-5 h-5 text-mono-900 dark:text-mono-100 mr-2 mt-0.5" />
              <span className="text-sm text-mono-900 dark:text-mono-100">{error}</span>
            </div>
          )}

          {step === 1 && (
            <div className="space-y-5 animate-slide-up">
              <div>
                <label className="label">Rule Name</label>
                <input
                  type="text"
                  value={formData.ruleName}
                  onChange={(e) => updateField('ruleName', e.target.value)}
                  className="input"
                  placeholder="e.g., failed_login_attempts"
                />
              </div>

              <div>
                <label className="label">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => updateField('description', e.target.value)}
                  rows={3}
                  className="input"
                  placeholder="Describe what this detection identifies..."
                />
              </div>

              <div>
                <label className="label">Severity</label>
                <div className="grid grid-cols-5 gap-2">
                  {SEVERITY_LEVELS.map(level => (
                    <button
                      key={level.value}
                      onClick={() => updateField('severity', level.value)}
                      className={`px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                        formData.severity === level.value
                          ? 'bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 ring-2 ring-mono-700 dark:ring-mono-300'
                          : 'bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300 hover:bg-mono-200 dark:hover:bg-mono-700'
                      }`}
                    >
                      {level.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-4 p-4 bg-mono-100 dark:bg-mono-850 rounded-lg border border-mono-200 dark:border-mono-800">
                <p className="text-sm text-mono-700 dark:text-mono-300 mb-2">
                  This detection will run the following query:
                </p>
                <pre className="text-xs bg-mono-950 dark:bg-mono-900 text-mono-100 dark:text-mono-200 p-3 rounded-lg overflow-x-auto font-mono border border-mono-800">
                  {query}
                </pre>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-5 animate-slide-up">
              <div>
                <label className="label">Execution Schedule</label>
                <select
                  value={formData.schedule}
                  onChange={(e) => updateField('schedule', e.target.value)}
                  className="input"
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
                  <label className="label">Custom Schedule Expression</label>
                  <input
                    type="text"
                    value={formData.customSchedule}
                    onChange={(e) => updateField('customSchedule', e.target.value)}
                    className="input"
                    placeholder="rate(10 minutes) or cron(0 12 * * *)"
                  />
                  <p className="mt-1 text-xs text-mono-600 dark:text-mono-400">
                    Use AWS EventBridge schedule expression format
                  </p>
                </div>
              )}

              <div>
                <label className="label">Alert Threshold</label>
                <input
                  type="number"
                  min="1"
                  value={formData.threshold}
                  onChange={(e) => updateField('threshold', parseInt(e.target.value) || 1)}
                  className="input"
                />
                <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
                  Trigger alert when query returns at least this many results
                </p>
              </div>

              <div>
                <label className="label">Estimated Alerts Per Month</label>
                <input
                  type="number"
                  min="0"
                  value={formData.estimatedAlerts}
                  onChange={(e) => updateField('estimatedAlerts', parseInt(e.target.value) || 10)}
                  className="input"
                />
                <p className="mt-1 text-sm text-mono-600 dark:text-mono-400">
                  Used for cost estimation
                </p>
              </div>

              {queryStats && getScheduleValue() && (
                <div className="pt-4">
                  <CostProjectionV2
                    queryStats={queryStats}
                    scheduleExpression={getScheduleValue()}
                    estimatedAlerts={formData.estimatedAlerts}
                    onChange={handleCostUpdate}
                  />
                </div>
              )}
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4 animate-slide-up">
              <p className="text-sm text-mono-700 dark:text-mono-300">
                Select where alerts should be sent when this detection triggers:
              </p>

              {integrations && integrations.length > 0 ? (
                <div className="space-y-3">
                  {integrations.map(integration => (
                    <div
                      key={integration.id}
                      className={`border rounded-lg p-4 cursor-pointer transition-all ${
                        formData.alertDestinations.includes(integration.id)
                          ? 'border-mono-700 dark:border-mono-300 bg-mono-100 dark:bg-mono-850'
                          : 'border-mono-200 dark:border-mono-800 hover:border-mono-400 dark:hover:border-mono-600'
                      }`}
                      onClick={() => toggleDestination(integration.id)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center">
                          <input
                            type="checkbox"
                            checked={formData.alertDestinations.includes(integration.id)}
                            onChange={() => {}}
                            className="mr-3"
                          />
                          <div>
                            <div className="font-medium text-mono-900 dark:text-mono-100">{integration.name}</div>
                            <div className="text-xs text-mono-600 dark:text-mono-400">{integration.type}</div>
                          </div>
                        </div>
                        <div className={`text-xs px-2 py-1 rounded ${
                          integration.health_status === 'healthy'
                            ? 'bg-mono-900 dark:bg-mono-100 text-mono-100 dark:text-mono-900'
                            : 'bg-mono-300 dark:bg-mono-700 text-mono-900 dark:text-mono-100'
                        }`}>
                          {integration.health_status || 'unknown'}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-mono-600 dark:text-mono-400">
                  No integrations configured. Go to Settings to add integrations.
                </div>
              )}
            </div>
          )}

          {step === 4 && (
            <div className="space-y-6 animate-slide-up">
              <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50">Review Detection Rule</h3>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Rule Name</div>
                    <div className="text-sm text-mono-900 dark:text-mono-100 font-medium">{formData.ruleName}</div>
                  </div>
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Severity</div>
                    <div className="text-sm text-mono-900 dark:text-mono-100 font-medium capitalize">{formData.severity}</div>
                  </div>
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Schedule</div>
                    <div className="text-sm text-mono-900 dark:text-mono-100 font-medium">{getScheduleValue()}</div>
                  </div>
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Threshold</div>
                    <div className="text-sm text-mono-900 dark:text-mono-100 font-medium">{formData.threshold} matches</div>
                  </div>
                </div>

                <div>
                  <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Description</div>
                  <div className="text-sm text-mono-900 dark:text-mono-100">{formData.description}</div>
                </div>

                {formData.alertDestinations.length > 0 && (
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Alert Destinations</div>
                    <div className="flex flex-wrap gap-2">
                      {formData.alertDestinations.map(destId => {
                        const integration = integrations?.find(i => i.id === destId);
                        return integration ? (
                          <div key={destId} className="px-3 py-1 bg-mono-100 dark:bg-mono-850 rounded text-sm text-mono-900 dark:text-mono-100">
                            {integration.name}
                          </div>
                        ) : null;
                      })}
                    </div>
                  </div>
                )}

                {costData && (
                  <div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">Projected Monthly Cost</div>
                    <div className="text-2xl text-mono-900 dark:text-mono-100 font-bold">
                      ${costData.total_monthly_cost.toFixed(2)}
                    </div>
                    <div className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                      {costData.executions_per_month.toLocaleString()} executions per month
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t border-mono-200 dark:border-mono-800 flex justify-between">
          <button
            onClick={step > 1 ? previousStep : onClose}
            className="btn-secondary"
            disabled={loading}
          >
            {step > 1 ? 'Back' : 'Cancel'}
          </button>
          <button
            onClick={step < 4 ? nextStep : handleSave}
            className="btn-primary"
            disabled={loading}
          >
            {loading ? (
              <div className="flex items-center">
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Creating...
              </div>
            ) : step < 4 ? 'Next' : 'Create Detection Rule'}
          </button>
        </div>
      </div>
    </div>
  );
}
