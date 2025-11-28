import React, { useState } from 'react';
import { Check, AlertCircle, ChevronRight, Loader2, Plus, X } from 'lucide-react';

export default function WebhookWizard({ onComplete, onCancel }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [config, setConfig] = useState({
    url: '',
    method: 'POST',
    headers: {},
    payloadTemplate: 'default'
  });
  const [newHeaderKey, setNewHeaderKey] = useState('');
  const [newHeaderValue, setNewHeaderValue] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const STEPS = [
    { id: 'intro', title: 'Introduction', description: 'Getting started with Webhooks' },
    { id: 'endpoint', title: 'Webhook Endpoint', description: 'Configure webhook URL' },
    { id: 'headers', title: 'Authentication', description: 'Add custom headers' },
    { id: 'payload', title: 'Payload Format', description: 'Customize request body' },
    { id: 'test', title: 'Test & Finish', description: 'Verify your configuration' }
  ];

  const PAYLOAD_TEMPLATES = {
    default: {
      name: 'Default',
      description: 'Standard JSON payload with all alert details',
      example: {
        severity: '{severity}',
        rule_name: '{rule_name}',
        timestamp: '{timestamp}',
        details: '{details}'
      }
    },
    minimal: {
      name: 'Minimal',
      description: 'Compact payload with essential information',
      example: {
        alert: '{rule_name}',
        level: '{severity}'
      }
    },
    custom: {
      name: 'Custom',
      description: 'Define your own JSON structure',
      example: {}
    }
  };

  const addHeader = () => {
    if (newHeaderKey && newHeaderValue) {
      setConfig({
        ...config,
        headers: { ...config.headers, [newHeaderKey]: newHeaderValue }
      });
      setNewHeaderKey('');
      setNewHeaderValue('');
    }
  };

  const removeHeader = (key) => {
    const newHeaders = { ...config.headers };
    delete newHeaders[key];
    setConfig({ ...config, headers: newHeaders });
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const response = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'webhook',
          config: {
            url: config.url,
            method: config.method,
            headers: config.headers,
            payload_template: config.payloadTemplate
          }
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setTestResult({
          success: true,
          message: `Webhook responded with status ${data.details?.status_code || 200}`,
          details: data.details
        });
      } else {
        setTestResult({ success: false, message: data.message || 'Test failed' });
      }
    } catch (err) {
      setTestResult({ success: false, message: err.message });
    } finally {
      setTesting(false);
    }
  };

  const handleComplete = () => {
    if (onComplete) {
      onComplete({
        type: 'webhook',
        config: {
          url: config.url,
          method: config.method,
          headers: config.headers,
          payload_template: config.payloadTemplate
        }
      });
    }
  };

  const canProceed = () => {
    if (currentStep === 0) return true;
    if (currentStep === 1) return config.url.trim() !== '' && config.url.startsWith('https://');
    if (currentStep === 2) return true; // Headers optional
    if (currentStep === 3) return true;
    if (currentStep === 4) return testResult?.success;
    return false;
  };

  const nextStep = () => {
    if (currentStep < STEPS.length - 1 && canProceed()) {
      setCurrentStep(currentStep + 1);
    }
  };

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  return (
    <div className="fixed inset-0 bg-mono-950/50 dark:bg-mono-950/80 flex items-center justify-center z-50 p-4">
      <div className="bg-mono-50 dark:bg-mono-900 rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="border-b border-mono-200 dark:border-mono-800 p-6">
          <h2 className="text-2xl font-bold text-mono-900 dark:text-mono-50">
            Custom Webhook Setup
          </h2>
          <p className="text-mono-600 dark:text-mono-400 mt-1">
            Configure a custom webhook endpoint for alert notifications
          </p>
        </div>

        {/* Progress Indicator */}
        <div className="px-6 py-4 bg-mono-100 dark:bg-mono-850">
          <div className="flex items-center justify-between">
            {STEPS.map((step, index) => (
              <React.Fragment key={step.id}>
                <div className="flex flex-col items-center">
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all ${
                      index < currentStep
                        ? 'bg-mono-950 dark:bg-mono-50 border-mono-950 dark:border-mono-50'
                        : index === currentStep
                        ? 'bg-mono-200 dark:bg-mono-700 border-mono-950 dark:border-mono-50'
                        : 'bg-mono-50 dark:bg-mono-900 border-mono-300 dark:border-mono-700'
                    }`}
                  >
                    {index < currentStep ? (
                      <Check className="w-5 h-5 text-mono-50 dark:text-mono-950" />
                    ) : (
                      <span
                        className={`text-sm font-semibold ${
                          index === currentStep
                            ? 'text-mono-950 dark:text-mono-50'
                            : 'text-mono-400 dark:text-mono-600'
                        }`}
                      >
                        {index + 1}
                      </span>
                    )}
                  </div>
                  <span className="text-xs mt-2 text-mono-600 dark:text-mono-400 text-center max-w-[100px]">
                    {step.title}
                  </span>
                </div>
                {index < STEPS.length - 1 && (
                  <div
                    className={`flex-1 h-0.5 mx-2 ${
                      index < currentStep
                        ? 'bg-mono-950 dark:bg-mono-50'
                        : 'bg-mono-300 dark:bg-mono-700'
                    }`}
                  />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="p-6 min-h-[400px]">
          {/* Step 0: Introduction */}
          {currentStep === 0 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Welcome to Custom Webhook Integration
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                This wizard will help you set up a custom webhook endpoint to receive security alerts from Mantissa Log.
              </p>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  What you'll need:
                </h4>
                <ul className="space-y-2 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>An HTTPS endpoint URL to receive webhooks</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Authentication headers (API keys, tokens, etc.)</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Knowledge of your endpoint's expected payload format</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>5 minutes to complete the setup</span>
                  </li>
                </ul>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Use Cases:
                </h4>
                <ul className="space-y-2 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Send alerts to custom automation platforms</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Integrate with internal ticketing systems</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Forward events to SIEM or log aggregation tools</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Trigger custom workflows and remediation scripts</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 1: Webhook Endpoint */}
          {currentStep === 1 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Configure Webhook Endpoint
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Enter the URL where Mantissa Log will send alert notifications.
              </p>

              <div>
                <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                  Webhook URL *
                </label>
                <input
                  type="url"
                  value={config.url}
                  onChange={(e) => setConfig({ ...config, url: e.target.value })}
                  placeholder="https://your-api.example.com/webhooks/mantissa-log"
                  className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 font-mono text-sm"
                />
                {config.url && !config.url.startsWith('https://') && (
                  <p className="text-xs text-mono-700 dark:text-mono-300 mt-1">
                    ⚠ URL must use HTTPS for security
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                  HTTP Method *
                </label>
                <div className="flex space-x-4">
                  {['POST', 'PUT'].map((method) => (
                    <label key={method} className="flex items-center cursor-pointer">
                      <input
                        type="radio"
                        name="method"
                        value={method}
                        checked={config.method === method}
                        onChange={(e) => setConfig({ ...config, method: e.target.value })}
                        className="mr-2"
                      />
                      <span className="text-mono-700 dark:text-mono-300 font-mono">{method}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Security Requirements:
                </h4>
                <ul className="space-y-2 text-sm text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Only HTTPS URLs are supported for security</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Your endpoint must accept JSON payloads</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Response status codes 200-299 are considered successful</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 2: Headers */}
          {currentStep === 2 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Add Authentication Headers
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Configure custom HTTP headers for authentication and authorization.
              </p>

              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <input
                      type="text"
                      value={newHeaderKey}
                      onChange={(e) => setNewHeaderKey(e.target.value)}
                      placeholder="Header name"
                      className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 font-mono text-sm"
                    />
                  </div>
                  <div className="flex space-x-2">
                    <input
                      type="text"
                      value={newHeaderValue}
                      onChange={(e) => setNewHeaderValue(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && addHeader()}
                      placeholder="Header value"
                      className="flex-1 px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 font-mono text-sm"
                    />
                    <button
                      onClick={addHeader}
                      disabled={!newHeaderKey || !newHeaderValue}
                      className="px-4 py-2 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors disabled:opacity-30 flex items-center"
                    >
                      <Plus className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {Object.keys(config.headers).length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-sm font-medium text-mono-700 dark:text-mono-300">
                      Configured Headers:
                    </h4>
                    {Object.entries(config.headers).map(([key, value]) => (
                      <div
                        key={key}
                        className="flex items-center justify-between bg-mono-100 dark:bg-mono-850 px-3 py-2 rounded-lg border border-mono-200 dark:border-mono-800"
                      >
                        <div className="flex-1 font-mono text-sm">
                          <span className="text-mono-900 dark:text-mono-50 font-semibold">
                            {key}:
                          </span>{' '}
                          <span className="text-mono-700 dark:text-mono-300">
                            {value.substring(0, 30)}
                            {value.length > 30 ? '...' : ''}
                          </span>
                        </div>
                        <button
                          onClick={() => removeHeader(key)}
                          className="text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 ml-3"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Common Authentication Headers:
                </h4>
                <ul className="space-y-2 text-sm text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span className="font-mono">Authorization: Bearer &lt;token&gt;</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span className="font-mono">X-API-Key: &lt;api-key&gt;</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span className="font-mono">X-Custom-Auth: &lt;custom-token&gt;</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 3: Payload Format */}
          {currentStep === 3 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Configure Payload Format
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Choose how alert data will be formatted in the webhook payload.
              </p>

              <div className="space-y-3">
                {Object.entries(PAYLOAD_TEMPLATES).map(([key, template]) => (
                  <label
                    key={key}
                    className={`block cursor-pointer border-2 rounded-lg p-4 transition-all ${
                      config.payloadTemplate === key
                        ? 'border-mono-950 dark:border-mono-50 bg-mono-100 dark:bg-mono-850'
                        : 'border-mono-200 dark:border-mono-800 hover:border-mono-400 dark:hover:border-mono-600'
                    }`}
                  >
                    <div className="flex items-start">
                      <input
                        type="radio"
                        name="payloadTemplate"
                        value={key}
                        checked={config.payloadTemplate === key}
                        onChange={(e) => setConfig({ ...config, payloadTemplate: e.target.value })}
                        className="mt-1 mr-3"
                      />
                      <div className="flex-1">
                        <h4 className="font-semibold text-mono-900 dark:text-mono-50">
                          {template.name}
                        </h4>
                        <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
                          {template.description}
                        </p>
                        <pre className="mt-3 p-3 bg-mono-50 dark:bg-mono-900 rounded border border-mono-200 dark:border-mono-800 text-xs font-mono text-mono-900 dark:text-mono-50 overflow-x-auto">
                          {JSON.stringify(template.example, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </label>
                ))}
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Available Variables:
                </h4>
                <div className="grid grid-cols-2 gap-2 text-sm text-mono-700 dark:text-mono-300 font-mono">
                  <span>• {'{severity}'}</span>
                  <span>• {'{rule_name}'}</span>
                  <span>• {'{timestamp}'}</span>
                  <span>• {'{details}'}</span>
                  <span>• {'{query}'}</span>
                  <span>• {'{result_count}'}</span>
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Test & Finish */}
          {currentStep === 4 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Test Your Webhook
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Send a test request to verify your webhook endpoint is configured correctly.
              </p>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-3">
                  Configuration Summary:
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">Endpoint:</span>
                    <span className="text-mono-900 dark:text-mono-50 font-mono text-xs break-all ml-4 text-right">
                      {config.url.substring(0, 50)}
                      {config.url.length > 50 ? '...' : ''}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">Method:</span>
                    <span className="text-mono-900 dark:text-mono-50 font-mono">
                      {config.method}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">Headers:</span>
                    <span className="text-mono-900 dark:text-mono-50">
                      {Object.keys(config.headers).length} configured
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">Payload:</span>
                    <span className="text-mono-900 dark:text-mono-50">
                      {PAYLOAD_TEMPLATES[config.payloadTemplate].name}
                    </span>
                  </div>
                </div>
              </div>

              <button
                onClick={handleTest}
                disabled={testing}
                className="w-full px-4 py-3 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors disabled:opacity-50 flex items-center justify-center"
              >
                {testing ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Sending test request...
                  </>
                ) : (
                  'Send Test Request'
                )}
              </button>

              {testResult && (
                <div
                  className={`p-4 rounded-lg border ${
                    testResult.success
                      ? 'bg-mono-100 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                      : 'bg-mono-150 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                  }`}
                >
                  <div className="flex items-start">
                    {testResult.success ? (
                      <Check className="w-5 h-5 text-mono-900 dark:text-mono-100 mr-3 flex-shrink-0 mt-0.5" />
                    ) : (
                      <AlertCircle className="w-5 h-5 text-mono-700 dark:text-mono-300 mr-3 flex-shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <p
                        className={
                          testResult.success
                            ? 'text-mono-900 dark:text-mono-100 font-medium'
                            : 'text-mono-700 dark:text-mono-300 font-medium'
                        }
                      >
                        {testResult.message}
                      </p>
                      {testResult.details?.latency_ms && (
                        <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
                          Response time: {testResult.details.latency_ms}ms
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
        <div className="border-t border-mono-200 dark:border-mono-800 p-6 flex justify-between">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <div className="flex space-x-3">
            {currentStep > 0 && (
              <button
                onClick={prevStep}
                className="px-4 py-2 border border-mono-300 dark:border-mono-700 text-mono-900 dark:text-mono-100 rounded-lg hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors"
              >
                Back
              </button>
            )}
            {currentStep < STEPS.length - 1 ? (
              <button
                onClick={nextStep}
                disabled={!canProceed()}
                className="px-4 py-2 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors disabled:opacity-30 disabled:cursor-not-allowed flex items-center"
              >
                Next
                <ChevronRight className="w-4 h-4 ml-1" />
              </button>
            ) : (
              <button
                onClick={handleComplete}
                disabled={!canProceed()}
                className="px-4 py-2 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                Complete Setup
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
