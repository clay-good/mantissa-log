import { useState } from 'react';
import { X, Check, Loader, ExternalLink, AlertCircle } from 'lucide-react';

export default function SlackWizard({ integration, onComplete, onCancel }) {
  const [step, setStep] = useState(1);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    name: integration?.name || '',
    webhook_url: '',
    channel: integration?.config?.channel || '',
    username: integration?.config?.username || 'Mantissa Log',
    mention_users: integration?.config?.mention_users?.join(', ') || '',
    severity_filter: integration?.config?.severity_filter || ['critical', 'high', 'medium', 'low', 'info']
  });

  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSeverityToggle = (severity) => {
    setFormData(prev => ({
      ...prev,
      severity_filter: prev.severity_filter.includes(severity)
        ? prev.severity_filter.filter(s => s !== severity)
        : [...prev.severity_filter, severity]
    }));
  };

  const handleNext = () => {
    setError(null);

    if (step === 1) {
      if (!formData.webhook_url) {
        setError('Webhook URL is required');
        return;
      }
      if (!formData.channel) {
        setError('Channel is required');
        return;
      }
    }

    setStep(step + 1);
  };

  const handleBack = () => {
    setError(null);
    setStep(step - 1);
  };

  const handleSubmit = async () => {
    setError(null);
    setSaving(true);

    try {
      const config = {
        webhook_url: formData.webhook_url,
        channel: formData.channel,
        username: formData.username,
        mention_users: formData.mention_users
          ? formData.mention_users.split(',').map(u => u.trim()).filter(Boolean)
          : [],
        severity_filter: formData.severity_filter
      };

      await onComplete({
        integration_type: 'slack',
        name: formData.name || `Slack - ${formData.channel}`,
        config,
        enabled: true
      });
    } catch (err) {
      console.error('Error saving Slack integration:', err);
      setError('Failed to save integration. Please try again.');
      setSaving(false);
    }
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold text-mono-950 dark:text-mono-50">
            {integration ? 'Edit' : 'Add'} Slack Integration
          </h2>
          <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
            Step {step} of 3
          </p>
        </div>
        <button
          onClick={onCancel}
          className="p-2 hover:bg-mono-100 dark:hover:bg-mono-850 rounded"
        >
          <X className="w-5 h-5 text-mono-600 dark:text-mono-400" />
        </button>
      </div>

      {/* Progress */}
      <div className="flex items-center mb-6">
        {[1, 2, 3].map(s => (
          <div key={s} className="flex items-center flex-1">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
              s < step
                ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                : s === step
                ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                : 'bg-mono-200 dark:bg-mono-800 text-mono-600 dark:text-mono-400'
            }`}>
              {s < step ? <Check className="w-4 h-4" /> : s}
            </div>
            {s < 3 && (
              <div className={`flex-1 h-1 mx-2 ${
                s < step
                  ? 'bg-mono-900 dark:bg-mono-100'
                  : 'bg-mono-200 dark:bg-mono-800'
              }`} />
            )}
          </div>
        ))}
      </div>

      {error && (
        <div className="mb-6 p-4 bg-mono-100 dark:bg-mono-850 border border-mono-400 dark:border-mono-600 rounded flex items-start">
          <AlertCircle className="w-5 h-5 mr-2 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-mono-900 dark:text-mono-100">Error</p>
            <p className="text-sm text-mono-700 dark:text-mono-300">{error}</p>
          </div>
        </div>
      )}

      {/* Step 1: Get Webhook URL */}
      {step === 1 && (
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">
              Create Slack Webhook
            </h3>
            <div className="text-sm text-mono-700 dark:text-mono-300 space-y-2 mb-4">
              <p>To send alerts to Slack, you need to create an Incoming Webhook:</p>
              <ol className="list-decimal list-inside space-y-1 ml-2">
                <li>Go to your Slack workspace settings</li>
                <li>Navigate to "Apps" and search for "Incoming Webhooks"</li>
                <li>Click "Add to Slack"</li>
                <li>Select a channel and click "Add Incoming Webhooks Integration"</li>
                <li>Copy the Webhook URL provided</li>
              </ol>
            </div>

            <a
              href="https://api.slack.com/messaging/webhooks"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center text-sm text-mono-900 dark:text-mono-100 hover:underline mb-4"
            >
              <ExternalLink className="w-4 h-4 mr-1" />
              Slack Webhook Documentation
            </a>
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Integration Name
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => handleChange('name', e.target.value)}
              placeholder="My Slack Alerts"
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500"
            />
            <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
              Optional - will use channel name if not provided
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Webhook URL <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <input
              type="password"
              value={formData.webhook_url}
              onChange={(e) => handleChange('webhook_url', e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500 font-mono text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Channel <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <input
              type="text"
              value={formData.channel}
              onChange={(e) => handleChange('channel', e.target.value)}
              placeholder="#security-alerts"
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500"
            />
            <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
              Include the # symbol
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Bot Username
            </label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => handleChange('username', e.target.value)}
              placeholder="Mantissa Log"
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500"
            />
          </div>
        </div>
      )}

      {/* Step 2: Configure Routing */}
      {step === 2 && (
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">
              Configure Alert Routing
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              Select which severity levels should be sent to Slack
            </p>
          </div>

          <div className="space-y-2">
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
              Severity Levels
            </label>

            {['critical', 'high', 'medium', 'low', 'info'].map(severity => (
              <label
                key={severity}
                className="flex items-center p-3 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded cursor-pointer hover:bg-mono-50 dark:hover:bg-mono-900"
              >
                <input
                  type="checkbox"
                  checked={formData.severity_filter.includes(severity)}
                  onChange={() => handleSeverityToggle(severity)}
                  className="mr-3"
                />
                <div className="flex-1">
                  <span className="font-medium text-mono-900 dark:text-mono-100 capitalize">
                    {severity}
                  </span>
                </div>
              </label>
            ))}
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              @mention Users for Critical Alerts
            </label>
            <input
              type="text"
              value={formData.mention_users}
              onChange={(e) => handleChange('mention_users', e.target.value)}
              placeholder="@user1, @user2"
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500"
            />
            <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
              Comma-separated list of Slack usernames (optional)
            </p>
          </div>
        </div>
      )}

      {/* Step 3: Review */}
      {step === 3 && (
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">
              Review Configuration
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              Please review your Slack integration settings
            </p>
          </div>

          <div className="bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded-lg p-4 space-y-3">
            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">
                Integration Name
              </p>
              <p className="text-sm text-mono-900 dark:text-mono-100">
                {formData.name || `Slack - ${formData.channel}`}
              </p>
            </div>

            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">
                Channel
              </p>
              <p className="text-sm text-mono-900 dark:text-mono-100">
                {formData.channel}
              </p>
            </div>

            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">
                Bot Username
              </p>
              <p className="text-sm text-mono-900 dark:text-mono-100">
                {formData.username}
              </p>
            </div>

            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">
                Webhook URL
              </p>
              <p className="text-sm text-mono-900 dark:text-mono-100 font-mono">
                {formData.webhook_url ? '••••••••••••••••' : 'Not set'}
              </p>
            </div>

            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">
                Severity Filter
              </p>
              <p className="text-sm text-mono-900 dark:text-mono-100">
                {formData.severity_filter.length === 5
                  ? 'All severities'
                  : formData.severity_filter.map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(', ')
                }
              </p>
            </div>

            {formData.mention_users && (
              <div>
                <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">
                  Mentions for Critical Alerts
                </p>
                <p className="text-sm text-mono-900 dark:text-mono-100">
                  {formData.mention_users}
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-between mt-6 pt-6 border-t border-mono-200 dark:border-mono-800">
        <button
          onClick={step === 1 ? onCancel : handleBack}
          disabled={saving}
          className="px-4 py-2 border border-mono-300 dark:border-mono-700 rounded hover:bg-mono-100 dark:hover:bg-mono-850 disabled:opacity-50 text-mono-900 dark:text-mono-100"
        >
          {step === 1 ? 'Cancel' : 'Back'}
        </button>

        {step < 3 ? (
          <button
            onClick={handleNext}
            className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200"
          >
            Next
          </button>
        ) : (
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 flex items-center"
          >
            {saving ? (
              <>
                <Loader className="w-4 h-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              integration ? 'Update Integration' : 'Create Integration'
            )}
          </button>
        )}
      </div>
    </div>
  );
}
