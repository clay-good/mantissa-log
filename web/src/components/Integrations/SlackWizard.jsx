import { useState } from 'react';
import { MessageSquare, ExternalLink, Check, AlertTriangle, Loader2, ArrowRight, ArrowLeft } from 'lucide-react';

const STEPS = [
  { id: 'intro', title: 'Introduction', description: 'Getting started with Slack integration' },
  { id: 'app', title: 'Create Slack App', description: 'Set up your Slack application' },
  { id: 'webhook', title: 'Get Webhook URL', description: 'Configure incoming webhook' },
  { id: 'config', title: 'Configure Routing', description: 'Set up alert routing' },
  { id: 'test', title: 'Test & Finish', description: 'Verify your configuration' }
];

export default function SlackWizard({ onComplete, onCancel }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [config, setConfig] = useState({
    webhookUrl: '',
    channel: '#siem-alerts',
    mentionUsers: '',
    severityLevels: ['critical', 'high'],
    messageTemplate: 'default'
  });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const handleNext = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleConfigChange = (field, value) => {
    setConfig(prev => ({ ...prev, [field]: value }));
  };

  const handleSeverityToggle = (severity) => {
    setConfig(prev => ({
      ...prev,
      severityLevels: prev.severityLevels.includes(severity)
        ? prev.severityLevels.filter(s => s !== severity)
        : [...prev.severityLevels, severity]
    }));
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const response = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'slack',
          config: {
            webhook_url: config.webhookUrl,
            channel: config.channel
          }
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setTestResult({ success: true, message: 'Test message sent successfully to Slack!' });
      } else {
        setTestResult({ success: false, message: data.message || 'Test failed' });
      }
    } catch (err) {
      setTestResult({ success: false, message: err.message });
    } finally {
      setTesting(false);
    }
  };

  const handleFinish = () => {
    if (onComplete) {
      onComplete({
        type: 'slack',
        config: {
          webhook_url: config.webhookUrl,
          channel: config.channel,
          mention_users: config.mentionUsers,
          severity_levels: config.severityLevels,
          message_template: config.messageTemplate
        }
      });
    }
  };

  const canProceed = () => {
    if (currentStep === 0) return true;
    if (currentStep === 1) return true;
    if (currentStep === 2) return config.webhookUrl.trim() !== '';
    if (currentStep === 3) return true;
    if (currentStep === 4) return testResult?.success;
    return false;
  };

  return (
    <div className="fixed inset-0 bg-mono-950/50 dark:bg-mono-950/80 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-mono-900 rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-mono-200 dark:border-mono-800">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2 bg-mono-900 dark:bg-mono-100 rounded-lg">
              <MessageSquare className="w-6 h-6 text-mono-50 dark:text-mono-950" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                Slack Integration Setup
              </h2>
              <p className="text-sm text-mono-600 dark:text-mono-400">
                {STEPS[currentStep].description}
              </p>
            </div>
          </div>

          {/* Progress Steps */}
          <div className="flex items-center justify-between">
            {STEPS.map((step, index) => (
              <div key={step.id} className="flex items-center flex-1">
                <div className="flex flex-col items-center flex-1">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold transition-colors ${
                    index < currentStep
                      ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                      : index === currentStep
                      ? 'bg-mono-700 dark:bg-mono-300 text-mono-50 dark:text-mono-950'
                      : 'bg-mono-200 dark:bg-mono-800 text-mono-600 dark:text-mono-400'
                  }`}>
                    {index < currentStep ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      index + 1
                    )}
                  </div>
                  <div className={`text-xs mt-1 text-center ${
                    index === currentStep
                      ? 'text-mono-900 dark:text-mono-100 font-medium'
                      : 'text-mono-600 dark:text-mono-400'
                  }`}>
                    {step.title}
                  </div>
                </div>
                {index < STEPS.length - 1 && (
                  <div className={`h-0.5 flex-1 mx-2 transition-colors ${
                    index < currentStep
                      ? 'bg-mono-900 dark:bg-mono-100'
                      : 'bg-mono-200 dark:bg-mono-800'
                  }`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto" style={{ maxHeight: 'calc(90vh - 280px)' }}>
          {/* Step 0: Introduction */}
          {currentStep === 0 && (
            <div className="space-y-4">
              <p className="text-mono-700 dark:text-mono-300">
                This wizard will guide you through setting up Slack integration for Mantissa Log alerts.
              </p>
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  What you'll need:
                </h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-mono-700 dark:text-mono-300">
                  <li>Slack workspace admin access (or permission to create apps)</li>
                  <li>A channel where alerts will be posted</li>
                  <li>About 5 minutes to complete setup</li>
                </ul>
              </div>
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  What you'll get:
                </h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-mono-700 dark:text-mono-300">
                  <li>Real-time security alerts posted to Slack</li>
                  <li>Customizable message formatting</li>
                  <li>Severity-based routing</li>
                  <li>User mentions for critical alerts</li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 1: Create Slack App */}
          {currentStep === 1 && (
            <div className="space-y-4">
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
                  Step 1: Create a Slack App
                </h3>
                <ol className="list-decimal list-inside space-y-3 text-sm text-mono-700 dark:text-mono-300">
                  <li>
                    Go to the Slack API portal
                    <a
                      href="https://api.slack.com/apps"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 inline-flex items-center text-mono-900 dark:text-mono-100 hover:underline"
                    >
                      Open Slack API
                      <ExternalLink className="w-3 h-3 ml-1" />
                    </a>
                  </li>
                  <li>Click "Create New App"</li>
                  <li>Choose "From scratch"</li>
                  <li>
                    Name your app (e.g., "Mantissa Log Alerts")
                  </li>
                  <li>Select your workspace</li>
                  <li>Click "Create App"</li>
                </ol>
              </div>

              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  Required Scopes:
                </h3>
                <p className="text-sm text-mono-600 dark:text-mono-400 mb-2">
                  Your app will need the following permissions:
                </p>
                <ul className="list-disc list-inside space-y-1 text-sm text-mono-700 dark:text-mono-300">
                  <li><code className="bg-mono-100 dark:bg-mono-900 px-1 rounded">incoming-webhook</code> - Post messages to channels</li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 2: Get Webhook URL */}
          {currentStep === 2 && (
            <div className="space-y-4">
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
                  Step 2: Enable Incoming Webhooks
                </h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-mono-700 dark:text-mono-300">
                  <li>In your Slack app settings, click "Incoming Webhooks" in the left sidebar</li>
                  <li>Toggle "Activate Incoming Webhooks" to On</li>
                  <li>Click "Add New Webhook to Workspace"</li>
                  <li>Select the channel where alerts should be posted</li>
                  <li>Click "Allow"</li>
                  <li>Copy the Webhook URL (starts with https://hooks.slack.com/services/...)</li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Webhook URL
                </label>
                <input
                  type="text"
                  value={config.webhookUrl}
                  onChange={(e) => handleConfigChange('webhookUrl', e.target.value)}
                  placeholder="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
                  className="input font-mono text-sm"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  Paste the webhook URL you copied from Slack
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Default Channel
                </label>
                <input
                  type="text"
                  value={config.channel}
                  onChange={(e) => handleConfigChange('channel', e.target.value)}
                  placeholder="#siem-alerts"
                  className="input"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  Channel where alerts will be posted (can override per detection rule)
                </p>
              </div>
            </div>
          )}

          {/* Step 3: Configure Routing */}
          {currentStep === 3 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Severity Levels to Route
                </label>
                <p className="text-xs text-mono-600 dark:text-mono-400 mb-3">
                  Select which severity levels should trigger Slack notifications
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {['critical', 'high', 'medium', 'low', 'info'].map(severity => (
                    <label key={severity} className="flex items-center space-x-2 cursor-pointer p-3 border border-mono-200 dark:border-mono-800 rounded-lg hover:border-mono-400 dark:hover:border-mono-600 transition-colors">
                      <input
                        type="checkbox"
                        checked={config.severityLevels.includes(severity)}
                        onChange={() => handleSeverityToggle(severity)}
                        className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
                      />
                      <span className="text-sm text-mono-900 dark:text-mono-100 capitalize">
                        {severity}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  User Mentions for Critical Alerts
                </label>
                <input
                  type="text"
                  value={config.mentionUsers}
                  onChange={(e) => handleConfigChange('mentionUsers', e.target.value)}
                  placeholder="@oncall, @security-team"
                  className="input"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  Users or groups to mention when critical alerts are triggered (comma-separated)
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Message Template
                </label>
                <select
                  value={config.messageTemplate}
                  onChange={(e) => handleConfigChange('messageTemplate', e.target.value)}
                  className="input"
                >
                  <option value="default">Default (Alert name, severity, details)</option>
                  <option value="detailed">Detailed (Includes query results)</option>
                  <option value="minimal">Minimal (Alert name only)</option>
                </select>
              </div>
            </div>
          )}

          {/* Step 4: Test & Finish */}
          {currentStep === 4 && (
            <div className="space-y-4">
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  Configuration Summary
                </h3>
                <dl className="space-y-2 text-sm">
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Channel:</dt>
                    <dd className="text-mono-900 dark:text-mono-100 font-mono">{config.channel}</dd>
                  </div>
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Severity Levels:</dt>
                    <dd className="text-mono-900 dark:text-mono-100">
                      {config.severityLevels.map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(', ')}
                    </dd>
                  </div>
                  {config.mentionUsers && (
                    <div>
                      <dt className="text-mono-600 dark:text-mono-400">Mentions:</dt>
                      <dd className="text-mono-900 dark:text-mono-100">{config.mentionUsers}</dd>
                    </div>
                  )}
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Template:</dt>
                    <dd className="text-mono-900 dark:text-mono-100 capitalize">{config.messageTemplate}</dd>
                  </div>
                </dl>
              </div>

              <div>
                <button
                  onClick={handleTest}
                  disabled={testing || !config.webhookUrl}
                  className="btn-secondary w-full"
                >
                  {testing ? (
                    <>
                      <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                      Sending Test Message...
                    </>
                  ) : (
                    <>
                      <MessageSquare className="w-5 h-5 mr-2" />
                      Send Test Message to Slack
                    </>
                  )}
                </button>
              </div>

              {testResult && (
                <div className={`p-4 rounded-lg border text-sm ${
                  testResult.success
                    ? 'bg-mono-50 dark:bg-mono-900 border-mono-300 dark:border-mono-700'
                    : 'bg-mono-100 dark:bg-mono-850 border-mono-400 dark:border-mono-600'
                }`}>
                  <div className="flex items-start space-x-2">
                    {testResult.success ? (
                      <Check className="w-5 h-5 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <p className={testResult.success
                        ? 'text-mono-700 dark:text-mono-300'
                        : 'text-mono-900 dark:text-mono-100'
                      }>
                        {testResult.message}
                      </p>
                      {testResult.success && (
                        <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                          Check your Slack channel to verify the test message was received.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-mono-200 dark:border-mono-800 flex items-center justify-between">
          <button
            onClick={onCancel}
            className="btn-secondary"
          >
            Cancel
          </button>

          <div className="flex items-center space-x-2">
            {currentStep > 0 && (
              <button
                onClick={handleBack}
                className="btn-secondary"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </button>
            )}

            {currentStep < STEPS.length - 1 ? (
              <button
                onClick={handleNext}
                disabled={!canProceed()}
                className="btn-primary"
              >
                Next
                <ArrowRight className="w-4 h-4 ml-2" />
              </button>
            ) : (
              <button
                onClick={handleFinish}
                disabled={!canProceed()}
                className="btn-primary"
              >
                <Check className="w-4 h-4 mr-2" />
                Finish Setup
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
