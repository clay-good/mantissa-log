import { useState, useEffect } from 'react';
import { Shield, Eye, EyeOff, Check, AlertTriangle, Loader2, Plus, X } from 'lucide-react';

const REDACTION_TYPES = {
  email: {
    name: 'Email Addresses',
    description: 'Redacts email addresses (e.g., user@example.com)',
    example: 'user@example.com → [EMAIL_REDACTED]',
    defaultEnabled: true
  },
  phone: {
    name: 'Phone Numbers',
    description: 'Redacts phone numbers in various formats',
    example: '(555) 123-4567 → [PHONE_REDACTED]',
    defaultEnabled: true
  },
  ssn: {
    name: 'Social Security Numbers',
    description: 'Redacts SSN and Tax IDs',
    example: '123-45-6789 → [SSN_REDACTED]',
    defaultEnabled: true
  },
  credit_card: {
    name: 'Credit Card Numbers',
    description: 'Redacts credit card numbers (Visa, MC, Amex, etc.)',
    example: '4111-1111-1111-1111 → [CARD_REDACTED]',
    defaultEnabled: true
  },
  ip_address: {
    name: 'IP Addresses',
    description: 'Redacts IPv4 and IPv6 addresses',
    example: '192.168.1.1 → [IP_REDACTED]',
    defaultEnabled: false,
    warning: 'May remove important security context from alerts'
  },
  mac_address: {
    name: 'MAC Addresses',
    description: 'Redacts hardware addresses',
    example: '00:1B:44:11:3A:B7 → [MAC_REDACTED]',
    defaultEnabled: false
  },
  medical_record: {
    name: 'Medical Record Numbers',
    description: 'Redacts MRN and medical identifiers',
    example: 'MRN:AB123456 → [MRN_REDACTED]',
    defaultEnabled: true
  }
};

export default function RedactionSettings({ userId }) {
  const [config, setConfig] = useState({
    enabled: true,
    enabledPatterns: ['email', 'phone', 'ssn', 'credit_card', 'medical_record'],
    hashRedactedValues: false,
    customPatterns: []
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testInput, setTestInput] = useState('');
  const [newPattern, setNewPattern] = useState({ regex: '', replacement: '', description: '' });
  const [error, setError] = useState(null);

  useEffect(() => {
    loadRedactionConfig();
  }, [userId]);

  const loadRedactionConfig = async () => {
    try {
      const response = await fetch(`/api/settings/redaction?user_id=${userId}`);
      if (!response.ok) throw new Error('Failed to load redaction settings');

      const data = await response.json();
      if (data.config) {
        setConfig(data.config);
      }
    } catch (err) {
      console.error('Error loading redaction config:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const togglePattern = (patternType) => {
    setConfig(prev => ({
      ...prev,
      enabledPatterns: prev.enabledPatterns.includes(patternType)
        ? prev.enabledPatterns.filter(p => p !== patternType)
        : [...prev.enabledPatterns, patternType]
    }));
  };

  const addCustomPattern = () => {
    if (!newPattern.regex || !newPattern.replacement) return;

    // Validate regex
    try {
      new RegExp(newPattern.regex);
    } catch (err) {
      alert('Invalid regular expression: ' + err.message);
      return;
    }

    setConfig(prev => ({
      ...prev,
      customPatterns: [
        ...prev.customPatterns,
        {
          regex: newPattern.regex,
          replacement: newPattern.replacement,
          description: newPattern.description || 'Custom pattern'
        }
      ]
    }));

    setNewPattern({ regex: '', replacement: '', description: '' });
  };

  const removeCustomPattern = (index) => {
    setConfig(prev => ({
      ...prev,
      customPatterns: prev.customPatterns.filter((_, i) => i !== index)
    }));
  };

  const testRedaction = async () => {
    if (!testInput) return;

    setTestResult(null);

    try {
      const response = await fetch('/api/settings/redaction/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          config: config,
          text: testInput
        })
      });

      const data = await response.json();

      if (response.ok) {
        setTestResult({
          success: true,
          redacted: data.redacted_text,
          summary: data.summary
        });
      } else {
        setTestResult({
          success: false,
          message: data.error || 'Test failed'
        });
      }
    } catch (err) {
      setTestResult({
        success: false,
        message: err.message
      });
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    setError(null);

    try {
      const response = await fetch('/api/settings/redaction', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          config: config
        })
      });

      if (!response.ok) throw new Error('Failed to save redaction settings');

      alert('Redaction settings saved successfully!');
    } catch (err) {
      setError(err.message);
      console.error('Error saving redaction config:', err);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="w-8 h-8 animate-spin text-mono-600 dark:text-mono-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-2 flex items-center">
          <Shield className="w-6 h-6 mr-2" />
          PII/PHI Redaction
        </h2>
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Automatically redact sensitive information from alert payloads sent to external integrations.
          Raw logs in storage are never modified.
        </p>
      </div>

      {error && (
        <div className="p-4 bg-mono-100 dark:bg-mono-850 border border-mono-400 dark:border-mono-600 rounded-lg">
          <p className="text-sm text-mono-900 dark:text-mono-100">{error}</p>
        </div>
      )}

      {/* Master Toggle */}
      <div className="card">
        <label className="flex items-center justify-between cursor-pointer">
          <div>
            <div className="font-semibold text-mono-950 dark:text-mono-50">
              Enable PII/PHI Redaction
            </div>
            <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
              Apply redaction to all integration destinations (Slack, Jira, PagerDuty, Email, Webhooks)
            </p>
          </div>
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
            className="w-5 h-5 rounded border-mono-300 dark:border-mono-700"
          />
        </label>
      </div>

      {config.enabled && (
        <>
          {/* Redaction Patterns */}
          <div className="card">
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
              Redaction Patterns
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 mb-4">
              Select which types of sensitive information to redact from alert payloads.
            </p>

            <div className="space-y-3">
              {Object.entries(REDACTION_TYPES).map(([type, info]) => (
                <div
                  key={type}
                  className="flex items-start justify-between p-3 bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg"
                >
                  <div className="flex-1">
                    <label className="flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config.enabledPatterns.includes(type)}
                        onChange={() => togglePattern(type)}
                        className="w-4 h-4 mr-3 rounded border-mono-300 dark:border-mono-700"
                      />
                      <div>
                        <div className="font-medium text-mono-950 dark:text-mono-50">
                          {info.name}
                        </div>
                        <p className="text-xs text-mono-600 dark:text-mono-400 mt-0.5">
                          {info.description}
                        </p>
                        <p className="text-xs text-mono-500 dark:text-mono-500 mt-1 font-mono">
                          {info.example}
                        </p>
                        {info.warning && (
                          <p className="text-xs text-mono-700 dark:text-mono-300 mt-1 flex items-center">
                            <AlertTriangle className="w-3 h-3 mr-1" />
                            {info.warning}
                          </p>
                        )}
                      </div>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Advanced Options */}
          <div className="card">
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
              Advanced Options
            </h3>

            <label className="flex items-center justify-between cursor-pointer">
              <div>
                <div className="font-medium text-mono-950 dark:text-mono-50">
                  Include Hash of Redacted Values
                </div>
                <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
                  Append a hash to redacted values for correlation across alerts
                </p>
                <p className="text-xs text-mono-500 dark:text-mono-500 mt-1 font-mono">
                  Example: user@example.com → [EMAIL_REDACTED]:a1b2c3d4
                </p>
              </div>
              <input
                type="checkbox"
                checked={config.hashRedactedValues}
                onChange={(e) => setConfig({ ...config, hashRedactedValues: e.target.checked })}
                className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
              />
            </label>
          </div>

          {/* Custom Patterns */}
          <div className="card">
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
              Custom Redaction Patterns
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 mb-4">
              Define custom regular expressions to redact organization-specific sensitive data.
            </p>

            {/* Existing Custom Patterns */}
            {config.customPatterns.length > 0 && (
              <div className="space-y-2 mb-4">
                {config.customPatterns.map((pattern, index) => (
                  <div
                    key={index}
                    className="flex items-start justify-between p-3 bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg"
                  >
                    <div className="flex-1 font-mono text-sm">
                      <div className="text-mono-950 dark:text-mono-50 font-semibold">
                        {pattern.description}
                      </div>
                      <div className="text-mono-600 dark:text-mono-400 mt-1">
                        Pattern: /{pattern.regex}/
                      </div>
                      <div className="text-mono-600 dark:text-mono-400">
                        Replace with: {pattern.replacement}
                      </div>
                    </div>
                    <button
                      onClick={() => removeCustomPattern(index)}
                      className="text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 ml-3"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Add Custom Pattern */}
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={newPattern.description}
                  onChange={(e) => setNewPattern({ ...newPattern, description: e.target.value })}
                  placeholder="Employee ID"
                  className="input"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                  Regular Expression
                </label>
                <input
                  type="text"
                  value={newPattern.regex}
                  onChange={(e) => setNewPattern({ ...newPattern, regex: e.target.value })}
                  placeholder="\bEMP-\d{6}\b"
                  className="input font-mono text-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                  Replacement Text
                </label>
                <input
                  type="text"
                  value={newPattern.replacement}
                  onChange={(e) => setNewPattern({ ...newPattern, replacement: e.target.value })}
                  placeholder="[EMP_ID_REDACTED]"
                  className="input font-mono text-sm"
                />
              </div>

              <button
                onClick={addCustomPattern}
                disabled={!newPattern.regex || !newPattern.replacement}
                className="btn-secondary text-sm"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Custom Pattern
              </button>
            </div>
          </div>

          {/* Test Redaction */}
          <div className="card">
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
              Test Redaction
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 mb-4">
              Test your redaction configuration with sample text.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                  Sample Text
                </label>
                <textarea
                  value={testInput}
                  onChange={(e) => setTestInput(e.target.value)}
                  placeholder="Enter text containing PII/PHI to test redaction...&#10;&#10;Example:&#10;User john.doe@example.com called from (555) 123-4567&#10;SSN: 123-45-6789, Card: 4111-1111-1111-1111"
                  className="input min-h-24 resize-y font-mono text-sm"
                />
              </div>

              <button
                onClick={testRedaction}
                disabled={!testInput}
                className="btn-secondary"
              >
                <Eye className="w-4 h-4 mr-2" />
                Test Redaction
              </button>

              {testResult && (
                <div className={`p-4 rounded-lg border ${
                  testResult.success
                    ? 'bg-mono-100 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                    : 'bg-mono-150 dark:bg-mono-850 border-mono-400 dark:border-mono-600'
                }`}>
                  {testResult.success ? (
                    <div className="space-y-3">
                      <div>
                        <div className="text-sm font-semibold text-mono-950 dark:text-mono-50 mb-2">
                          Redacted Output:
                        </div>
                        <div className="p-3 bg-mono-50 dark:bg-mono-900 rounded border border-mono-200 dark:border-mono-800 font-mono text-sm text-mono-900 dark:text-mono-50 whitespace-pre-wrap">
                          {testResult.redacted}
                        </div>
                      </div>

                      {testResult.summary && testResult.summary.types_redacted.length > 0 && (
                        <div>
                          <div className="text-sm font-semibold text-mono-950 dark:text-mono-50 mb-2">
                            Redacted Types:
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {testResult.summary.types_redacted.map(type => (
                              <span
                                key={type}
                                className="px-2 py-1 bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-50 rounded text-xs font-mono"
                              >
                                {type}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-start">
                      <AlertTriangle className="w-5 h-5 text-mono-700 dark:text-mono-300 mr-3 flex-shrink-0 mt-0.5" />
                      <p className="text-mono-700 dark:text-mono-300">
                        {testResult.message}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={saveConfig}
          disabled={saving}
          className="btn-primary"
        >
          {saving ? (
            <>
              <Loader2 className="w-5 h-5 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            'Save Configuration'
          )}
        </button>
      </div>
    </div>
  );
}
