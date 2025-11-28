import React, { useState } from 'react';
import { Check, AlertCircle, ChevronRight, Loader2, Plus, X } from 'lucide-react';

export default function EmailWizard({ onComplete, onCancel }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [config, setConfig] = useState({
    smtpHost: '',
    smtpPort: '587',
    smtpUser: '',
    smtpPassword: '',
    fromAddress: '',
    fromName: 'Mantissa Log',
    recipients: [],
    ccRecipients: [],
    subjectTemplate: '[{severity}] Security Alert: {rule_name}',
    useTLS: true
  });
  const [newRecipient, setNewRecipient] = useState('');
  const [newCC, setNewCC] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const STEPS = [
    { id: 'intro', title: 'Introduction', description: 'Getting started with Email alerts' },
    { id: 'smtp', title: 'SMTP Settings', description: 'Configure email server' },
    { id: 'recipients', title: 'Recipients', description: 'Set up alert recipients' },
    { id: 'template', title: 'Email Template', description: 'Customize alert format' },
    { id: 'test', title: 'Test & Finish', description: 'Verify your configuration' }
  ];

  const addRecipient = () => {
    if (newRecipient && !config.recipients.includes(newRecipient)) {
      setConfig({ ...config, recipients: [...config.recipients, newRecipient] });
      setNewRecipient('');
    }
  };

  const removeRecipient = (email) => {
    setConfig({ ...config, recipients: config.recipients.filter((r) => r !== email) });
  };

  const addCC = () => {
    if (newCC && !config.ccRecipients.includes(newCC)) {
      setConfig({ ...config, ccRecipients: [...config.ccRecipients, newCC] });
      setNewCC('');
    }
  };

  const removeCC = (email) => {
    setConfig({ ...config, ccRecipients: config.ccRecipients.filter((r) => r !== email) });
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const response = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'email',
          config: {
            smtp_host: config.smtpHost,
            smtp_port: parseInt(config.smtpPort),
            smtp_user: config.smtpUser,
            smtp_password: config.smtpPassword,
            from_address: config.fromAddress,
            from_name: config.fromName,
            recipients: config.recipients,
            use_tls: config.useTLS
          }
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setTestResult({
          success: true,
          message: `Test email sent successfully to ${config.recipients.length} recipient(s)!`
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
        type: 'email',
        config: {
          smtp_host: config.smtpHost,
          smtp_port: parseInt(config.smtpPort),
          smtp_user: config.smtpUser,
          smtp_password: config.smtpPassword,
          from_address: config.fromAddress,
          from_name: config.fromName,
          recipients: config.recipients,
          cc_recipients: config.ccRecipients,
          subject_template: config.subjectTemplate,
          use_tls: config.useTLS
        }
      });
    }
  };

  const canProceed = () => {
    if (currentStep === 0) return true;
    if (currentStep === 1)
      return (
        config.smtpHost.trim() !== '' &&
        config.smtpPort.trim() !== '' &&
        config.smtpUser.trim() !== '' &&
        config.smtpPassword.trim() !== '' &&
        config.fromAddress.trim() !== ''
      );
    if (currentStep === 2) return config.recipients.length > 0;
    if (currentStep === 3) return config.subjectTemplate.trim() !== '';
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
            Email Integration Setup
          </h2>
          <p className="text-mono-600 dark:text-mono-400 mt-1">
            Configure email alerts for security events
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
                Welcome to Email Integration
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                This wizard will help you set up email notifications for security alerts from Mantissa Log.
              </p>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  What you'll need:
                </h4>
                <ul className="space-y-2 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>SMTP server details (host, port, credentials)</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Sender email address</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Recipient email addresses</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>5 minutes to complete the setup</span>
                  </li>
                </ul>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Supported Email Providers:
                </h4>
                <ul className="space-y-2 text-mono-700 dark:text-mono-300">
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Gmail (smtp.gmail.com:587)</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Office 365 (smtp.office365.com:587)</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>AWS SES (email-smtp.{'{region}'}.amazonaws.com:587)</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">•</span>
                    <span>Any SMTP server with TLS/SSL support</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 1: SMTP Settings */}
          {currentStep === 1 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Configure SMTP Server
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Enter your email server details to send alert notifications.
              </p>

              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                    SMTP Host *
                  </label>
                  <input
                    type="text"
                    value={config.smtpHost}
                    onChange={(e) => setConfig({ ...config, smtpHost: e.target.value })}
                    placeholder="smtp.gmail.com"
                    className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                    SMTP Port *
                  </label>
                  <input
                    type="number"
                    value={config.smtpPort}
                    onChange={(e) => setConfig({ ...config, smtpPort: e.target.value })}
                    placeholder="587"
                    className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                </div>

                <div className="flex items-center">
                  <label className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={config.useTLS}
                      onChange={(e) => setConfig({ ...config, useTLS: e.target.checked })}
                      className="mr-2"
                    />
                    <span className="text-sm text-mono-700 dark:text-mono-300">Use TLS/STARTTLS</span>
                  </label>
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                    SMTP Username *
                  </label>
                  <input
                    type="text"
                    value={config.smtpUser}
                    onChange={(e) => setConfig({ ...config, smtpUser: e.target.value })}
                    placeholder="your-email@example.com"
                    className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                    SMTP Password *
                  </label>
                  <input
                    type="password"
                    value={config.smtpPassword}
                    onChange={(e) => setConfig({ ...config, smtpPassword: e.target.value })}
                    placeholder="Enter SMTP password or app password"
                    className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 font-mono text-sm"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                    From Address *
                  </label>
                  <input
                    type="email"
                    value={config.fromAddress}
                    onChange={(e) => setConfig({ ...config, fromAddress: e.target.value })}
                    placeholder="alerts@example.com"
                    className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                    From Name
                  </label>
                  <input
                    type="text"
                    value={config.fromName}
                    onChange={(e) => setConfig({ ...config, fromName: e.target.value })}
                    placeholder="Mantissa Log"
                    className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                </div>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <p className="text-xs text-mono-600 dark:text-mono-400">
                  <strong>Note:</strong> For Gmail, you'll need to use an App Password instead of your regular password.
                  Generate one at: <span className="font-mono">myaccount.google.com/apppasswords</span>
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Recipients */}
          {currentStep === 2 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Configure Recipients
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Add email addresses that will receive security alerts.
              </p>

              <div>
                <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                  To Recipients *
                </label>
                <div className="flex space-x-2">
                  <input
                    type="email"
                    value={newRecipient}
                    onChange={(e) => setNewRecipient(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addRecipient()}
                    placeholder="recipient@example.com"
                    className="flex-1 px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                  <button
                    onClick={addRecipient}
                    className="px-4 py-2 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors flex items-center"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>

                {config.recipients.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {config.recipients.map((email) => (
                      <div
                        key={email}
                        className="flex items-center justify-between bg-mono-100 dark:bg-mono-850 px-3 py-2 rounded-lg border border-mono-200 dark:border-mono-800"
                      >
                        <span className="text-mono-900 dark:text-mono-50 font-mono text-sm">
                          {email}
                        </span>
                        <button
                          onClick={() => removeRecipient(email)}
                          className="text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                  CC Recipients (Optional)
                </label>
                <div className="flex space-x-2">
                  <input
                    type="email"
                    value={newCC}
                    onChange={(e) => setNewCC(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addCC()}
                    placeholder="cc@example.com"
                    className="flex-1 px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-400 dark:placeholder-mono-600 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50"
                  />
                  <button
                    onClick={addCC}
                    className="px-4 py-2 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors flex items-center"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>

                {config.ccRecipients.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {config.ccRecipients.map((email) => (
                      <div
                        key={email}
                        className="flex items-center justify-between bg-mono-100 dark:bg-mono-850 px-3 py-2 rounded-lg border border-mono-200 dark:border-mono-800"
                      >
                        <span className="text-mono-900 dark:text-mono-50 font-mono text-sm">
                          {email}
                        </span>
                        <button
                          onClick={() => removeCC(email)}
                          className="text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 3: Email Template */}
          {currentStep === 3 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Customize Email Template
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Configure the subject line for alert emails.
              </p>

              <div>
                <label className="block text-sm font-medium text-mono-700 dark:text-mono-300 mb-2">
                  Subject Template *
                </label>
                <input
                  type="text"
                  value={config.subjectTemplate}
                  onChange={(e) => setConfig({ ...config, subjectTemplate: e.target.value })}
                  className="w-full px-4 py-2 bg-mono-50 dark:bg-mono-900 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 focus:outline-none focus:ring-2 focus:ring-mono-950 dark:focus:ring-mono-50 font-mono text-sm"
                />
                <p className="text-xs text-mono-500 dark:text-mono-500 mt-1">
                  Available variables: {'{severity}'}, {'{rule_name}'}, {'{timestamp}'}
                </p>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Example Subject Lines:
                </h4>
                <ul className="space-y-2 text-sm text-mono-700 dark:text-mono-300 font-mono">
                  <li>• [{'{severity}'}] Security Alert: {'{rule_name}'}</li>
                  <li>• Mantissa Log - {'{severity}'} - {'{rule_name}'}</li>
                  <li>• Security Event Detected: {'{rule_name}'} at {'{timestamp}'}</li>
                </ul>
              </div>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-2">
                  Preview:
                </h4>
                <p className="text-mono-700 dark:text-mono-300 font-mono text-sm">
                  {config.subjectTemplate
                    .replace('{severity}', 'HIGH')
                    .replace('{rule_name}', 'Failed Login Attempts')
                    .replace('{timestamp}', new Date().toISOString())}
                </p>
              </div>
            </div>
          )}

          {/* Step 4: Test & Finish */}
          {currentStep === 4 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold text-mono-900 dark:text-mono-50">
                Test Your Email Integration
              </h3>
              <p className="text-mono-700 dark:text-mono-300">
                Send a test email to verify your configuration is working correctly.
              </p>

              <div className="bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h4 className="font-semibold text-mono-900 dark:text-mono-50 mb-3">
                  Configuration Summary:
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">SMTP Server:</span>
                    <span className="text-mono-900 dark:text-mono-50 font-mono">
                      {config.smtpHost}:{config.smtpPort}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">From:</span>
                    <span className="text-mono-900 dark:text-mono-50 font-mono">
                      {config.fromName} &lt;{config.fromAddress}&gt;
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">To Recipients:</span>
                    <span className="text-mono-900 dark:text-mono-50">
                      {config.recipients.length} recipient(s)
                    </span>
                  </div>
                  {config.ccRecipients.length > 0 && (
                    <div className="flex justify-between">
                      <span className="text-mono-600 dark:text-mono-400">CC Recipients:</span>
                      <span className="text-mono-900 dark:text-mono-50">
                        {config.ccRecipients.length} recipient(s)
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-mono-600 dark:text-mono-400">TLS:</span>
                    <span className="text-mono-900 dark:text-mono-50">
                      {config.useTLS ? 'Enabled' : 'Disabled'}
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
                    Sending test email...
                  </>
                ) : (
                  'Send Test Email'
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
                    <p
                      className={
                        testResult.success
                          ? 'text-mono-900 dark:text-mono-100 font-medium'
                          : 'text-mono-700 dark:text-mono-300 font-medium'
                      }
                    >
                      {testResult.message}
                    </p>
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
