import { useState } from 'react';
import { Check, X, Loader, ExternalLink, AlertCircle } from 'lucide-react';

export default function SlackWizard({ userId, onComplete, onCancel }) {
  const [step, setStep] = useState(1);
  const [config, setConfig] = useState({
    webhook_url: '',
    channel: '',
    username: 'Mantissa Log',
    icon_emoji: ':shield:'
  });
  const [severityFilter, setSeverityFilter] = useState(['critical', 'high']);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const handleTest = async () => {
    try {
      setTesting(true);
      setError(null);
      setTestResult(null);

      const response = await fetch('/api/integrations/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'slack',
          config
        })
      });

      const data = await response.json();
      setTestResult(data);

      if (data.success) {
        setTimeout(() => setStep(3), 1500);
      }

    } catch (err) {
      setError(err.message);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);

      const response = await fetch(`/api/integrations/wizard/slack/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: 'Slack Security Alerts',
          config,
          severity_filter: severityFilter,
          enabled: true
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to save integration');
      }

      if (onComplete) {
        onComplete(data);
      }

    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const toggleSeverity = (severity) => {
    setSeverityFilter(prev =>
      prev.includes(severity)
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-mono-200 dark:border-mono-800 pb-4">
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
          Slack Integration Setup
        </h2>
        <div className="flex items-center space-x-2 text-sm text-mono-600 dark:text-mono-400">
          <span>Step {step} of 3</span>
        </div>
      </div>

      {error && (
        <div className="bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded-lg p-4 flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-mono-900 dark:text-mono-100">Error</p>
            <p className="text-sm text-mono-700 dark:text-mono-300">{error}</p>
          </div>
        </div>
      )}

      <div className="flex items-center space-x-2 mb-6">
        {[1, 2, 3].map(i => (
          <div key={i} className="flex items-center flex-1">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full border-2 ${
              i < step
                ? 'bg-mono-950 dark:bg-mono-50 border-mono-950 dark:border-mono-50'
                : i === step
                ? 'border-mono-950 dark:border-mono-50 text-mono-950 dark:text-mono-50'
                : 'border-mono-300 dark:border-mono-700 text-mono-500 dark:text-mono-500'
            }`}>
              {i < step ? (
                <Check className="w-4 h-4 text-mono-50 dark:text-mono-950" />
              ) : (
                <span className="text-sm font-medium">{i}</span>
              )}
            </div>
            {i < 3 && (
              <div className={`flex-1 h-0.5 mx-2 ${
                i < step
                  ? 'bg-mono-950 dark:bg-mono-50'
                  : 'bg-mono-300 dark:bg-mono-700'
              }`} />
            )}
          </div>
        ))}
      </div>

      {step === 1 && (
        <div className="space-y-6">
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Create Slack App
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              To send alerts to Slack, you need to create an Incoming Webhook.
            </p>
            <ol className="space-y-3 text-sm text-mono-700 dark:text-mono-300">
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">1</span>
                <div>
                  Go to <a href="https://api.slack.com/apps" target="_blank" rel="noopener noreferrer" className="inline-flex items-center underline hover:text-mono-900 dark:hover:text-mono-100">
                    api.slack.com/apps
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </a> and click "Create New App"
                </div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">2</span>
                <div>Select "From scratch" and name it "Mantissa Log"</div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">3</span>
                <div>Go to "Incoming Webhooks" and toggle "Activate Incoming Webhooks" to On</div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">4</span>
                <div>Click "Add New Webhook to Workspace"</div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">5</span>
                <div>Select the channel for alerts and authorize</div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">6</span>
                <div>Copy the Webhook URL</div>
              </li>
            </ol>
          </div>

          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Webhook Configuration
            </h3>
            <div className="space-y-4">
              <div>
                <label className="label">Webhook URL</label>
                <input
                  type="text"
                  value={config.webhook_url}
                  onChange={(e) => setConfig({ ...config, webhook_url: e.target.value })}
                  placeholder="https://hooks.slack.com/services/..."
                  className="input font-mono text-sm"
                />
              </div>

              <div>
                <label className="label">Channel (optional)</label>
                <input
                  type="text"
                  value={config.channel}
                  onChange={(e) => setConfig({ ...config, channel: e.target.value })}
                  placeholder="#security-alerts"
                  className="input"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  Leave blank to use the default channel configured in the webhook
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Bot Username</label>
                  <input
                    type="text"
                    value={config.username}
                    onChange={(e) => setConfig({ ...config, username: e.target.value })}
                    className="input"
                  />
                </div>
                <div>
                  <label className="label">Icon Emoji</label>
                  <input
                    type="text"
                    value={config.icon_emoji}
                    onChange={(e) => setConfig({ ...config, icon_emoji: e.target.value })}
                    className="input font-mono"
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-3">
            <button onClick={onCancel} className="btn-secondary">
              Cancel
            </button>
            <button
              onClick={() => setStep(2)}
              disabled={!config.webhook_url}
              className="btn-primary"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-6">
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Test Connection
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              Send a test message to verify the webhook is working correctly.
            </p>

            <button
              onClick={handleTest}
              disabled={testing || (testResult && testResult.success)}
              className="btn-primary flex items-center space-x-2"
            >
              {testing ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Sending Test Message...</span>
                </>
              ) : (
                <span>Send Test Message</span>
              )}
            </button>

            {testResult && (
              <div className={`mt-4 p-3 rounded-lg border ${
                testResult.success
                  ? 'bg-mono-100 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                  : 'bg-mono-150 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
              }`}>
                <div className="flex items-center space-x-2">
                  {testResult.success ? (
                    <>
                      <Check className="w-5 h-5 text-mono-900 dark:text-mono-100" />
                      <span className="text-sm text-mono-900 dark:text-mono-100">
                        {testResult.message}
                      </span>
                    </>
                  ) : (
                    <>
                      <X className="w-5 h-5 text-mono-700 dark:text-mono-300" />
                      <span className="text-sm text-mono-700 dark:text-mono-300">
                        {testResult.message}
                      </span>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(1)} className="btn-secondary">
              Back
            </button>
            <button
              onClick={() => setStep(3)}
              disabled={!testResult || !testResult.success}
              className="btn-primary"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="space-y-6">
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Alert Routing
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              Choose which severity levels should trigger Slack alerts.
            </p>

            <div className="space-y-2">
              {[
                { value: 'critical', label: 'Critical' },
                { value: 'high', label: 'High' },
                { value: 'medium', label: 'Medium' },
                { value: 'low', label: 'Low' },
                { value: 'info', label: 'Info' }
              ].map(severity => (
                <label key={severity.value} className="flex items-center space-x-3 p-3 rounded-lg border border-mono-200 dark:border-mono-800 hover:bg-mono-50 dark:hover:bg-mono-850 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={severityFilter.includes(severity.value)}
                    onChange={() => toggleSeverity(severity.value)}
                    className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
                  />
                  <span className="text-sm text-mono-900 dark:text-mono-100">{severity.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="card bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
              Configuration Summary
            </h3>
            <div className="text-sm text-mono-700 dark:text-mono-300 space-y-1">
              <div>Channel: {config.channel || 'Default webhook channel'}</div>
              <div>Username: {config.username}</div>
              <div>Severity Filter: {severityFilter.join(', ')}</div>
            </div>
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(2)} className="btn-secondary">
              Back
            </button>
            <button
              onClick={handleSave}
              disabled={saving || severityFilter.length === 0}
              className="btn-primary flex items-center space-x-2"
            >
              {saving ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Check className="w-5 h-5" />
                  <span>Complete Setup</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
