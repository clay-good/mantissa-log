import React, { useState } from 'react';
import { Check, AlertCircle, ChevronRight, Loader2 } from 'lucide-react';

export default function PagerDutyWizard({ onComplete, onCancel }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [config, setConfig] = useState({
    integrationKey: '',
    urgencyMap: {
      critical: 'high',
      high: 'high',
      medium: 'low',
      low: 'low',
      info: 'low'
    }
  });
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const STEPS = [
    { id: 'intro', title: 'Introduction', description: 'Getting started with PagerDuty' },
    { id: 'key', title: 'Integration Key', description: 'Configure PagerDuty integration' },
    { id: 'urgency', title: 'Urgency Mapping', description: 'Map alert severity to urgency' },
    { id: 'test', title: 'Test & Finish', description: 'Verify your configuration' }
  ];

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const response = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'pagerduty',
          config: {
            integration_key: config.integrationKey
          }
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setTestResult({
          success: true,
          message: 'Test event sent successfully to PagerDuty!',
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
        type: 'pagerduty',
        config: {
          integration_key: config.integrationKey,
          urgency_map: config.urgencyMap
        }
      });
    }
  };

  const canProceed = () => {
    if (currentStep === 0) return true;
    if (currentStep === 1) return config.integrationKey.trim() !== '';
    if (currentStep === 2) return true;
    if (currentStep === 3) return testResult?.success;
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
            PagerDuty Integration Setup
          </h2>
          <p className="text-mono-600 dark:text-mono-400 mt-1">
            Connect Mantissa Log to PagerDuty for incident management
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
                Welcome to PagerDuty Integration
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                This wizard will help you set up PagerDuty integration for incident management and on-call alerting.
              </p>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  What you'll need:
                </h4>
                <ul className="space-y-2 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>A PagerDuty account with admin access</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>An Integration Key from a PagerDuty service</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>5 minutes to complete the setup</span>
                  </li>
                </ul>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Features:
                </h4>
                <ul className="space-y-2 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Automatic incident creation from security alerts</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Severity-based urgency mapping</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Event deduplication support</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>On-call escalation policies</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 1: Integration Key */}
          {currentStep === 1 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Get Your Integration Key
              </h3>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-3">
                  How to find your Integration Key:
                </h4>
                <ol className="space-y-3 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="font-semibold mr-2">1.</span>
                    <span>Go to your PagerDuty dashboard</span>
                  </li>
                  <li className="flex items-start">
                    <span className="font-semibold mr-2">2.</span>
                    <span>Navigate to <strong>Services → Service Directory</strong></span>
                  </li>
                  <li className="flex items-start">
                    <span className="font-semibold mr-2">3.</span>
                    <span>Select an existing service or create a new one</span>
                  </li>
                  <li className="flex items-start">
                    <span className="font-semibold mr-2">4.</span>
                    <span>Go to the <strong>Integrations</strong> tab</span>
                  </li>
                  <li className="flex items-start">
                    <span className="font-semibold mr-2">5.</span>
                    <span>Add a new integration with type <strong>Events API v2</strong></span>
                  </li>
                  <li className="flex items-start">
                    <span className="font-semibold mr-2">6.</span>
                    <span>Copy the <strong>Integration Key</strong> that appears</span>
                  </li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                  Integration Key *
                </label>
                <input
                  type="password"
                  value={config.integrationKey}
                  onChange={(e) => setConfig({ ...config, integrationKey: e.target.value })}
                  placeholder="Enter your PagerDuty integration key"
                  className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 font-mono text-sm"
                />
                <p className="text-xs text-mono-500 dark:text-mono-500 mt-1">
                  Your integration key will be stored securely
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Urgency Mapping */}
          {currentStep === 2 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Map Alert Severity to Urgency
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Configure how Mantissa Log alert severities map to PagerDuty incident urgencies.
              </p>

              <div className="space-y-3">
                {[
                  { severity: 'critical', label: 'Critical', description: 'Highest priority alerts' },
                  { severity: 'high', label: 'High', description: 'Important security events' },
                  { severity: 'medium', label: 'Medium', description: 'Moderate priority alerts' },
                  { severity: 'low', label: 'Low', description: 'Low priority events' },
                  { severity: 'info', label: 'Info', description: 'Informational alerts' }
                ].map(({ severity, label, description }) => (
                  <div
                    key={severity}
                    className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-semibold text-mono-900 dark:text-mono-50">
                          {label}
                        </h4>
                        <p className="text-sm text-mono-600 dark:text-mono-400">
                          {description}
                        </p>
                      </div>
                      <select
                        value={config.urgencyMap[severity]}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            urgencyMap: { ...config.urgencyMap, [severity]: e.target.value }
                          })
                        }
                        className="px-3 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                      >
                        <option value="high">High Urgency</option>
                        <option value="low">Low Urgency</option>
                      </select>
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Urgency Levels:
                </h4>
                <ul className="space-y-2 text-sm text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span><strong>High Urgency:</strong> Pages responders immediately</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span><strong>Low Urgency:</strong> Notifies without paging, follows escalation policy</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 3: Test & Finish */}
          {currentStep === 3 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Test Your PagerDuty Integration
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Send a test event to verify your PagerDuty integration is working correctly.
              </p>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-3">
                  Configuration Summary:
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">Integration Key:</span>
                    <span className="text-mono-900 dark:text-mono-50 font-mono">
                      {config.integrationKey.substring(0, 8)}...
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">Critical Alerts:</span>
                    <span className="text-mono-900 dark:text-mono-50">
                      {config.urgencyMap.critical === 'high' ? 'High Urgency' : 'Low Urgency'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">High Alerts:</span>
                    <span className="text-mono-900 dark:text-mono-50">
                      {config.urgencyMap.high === 'high' ? 'High Urgency' : 'Low Urgency'}
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
                    Sending test event...
                  </>
                ) : (
                  'Send Test Event'
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
                      {testResult.details && (
                        <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
                          Dedup Key: {testResult.details.dedup_key}
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
