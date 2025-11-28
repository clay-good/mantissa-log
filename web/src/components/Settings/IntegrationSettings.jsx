import { useState, useEffect } from 'react';
import { MessageSquare, GitBranch, Bell, Mail, Webhook, Check, AlertTriangle, Loader2, Eye, EyeOff, Wand2 } from 'lucide-react';
import IntegrationWizardModal from '../Integrations/IntegrationWizardModal';

const INTEGRATION_TYPES = {
  slack: {
    name: 'Slack',
    icon: MessageSquare,
    fields: [
      { id: 'webhook_url', label: 'Webhook URL', type: 'password', required: true },
      { id: 'channel', label: 'Default Channel', type: 'text', placeholder: '#siem-alerts' },
      { id: 'mention_users', label: 'Users to Mention', type: 'text', placeholder: '@oncall, @security' }
    ]
  },
  jira: {
    name: 'Jira',
    icon: GitBranch,
    fields: [
      { id: 'url', label: 'Jira URL', type: 'text', required: true, placeholder: 'https://your-domain.atlassian.net' },
      { id: 'email', label: 'Email', type: 'text', required: true },
      { id: 'api_token', label: 'API Token', type: 'password', required: true },
      { id: 'project_key', label: 'Project Key', type: 'text', required: true, placeholder: 'SEC' },
      { id: 'issue_type', label: 'Issue Type', type: 'text', placeholder: 'Bug' }
    ]
  },
  pagerduty: {
    name: 'PagerDuty',
    icon: Bell,
    fields: [
      { id: 'integration_key', label: 'Integration Key', type: 'password', required: true },
      { id: 'service_name', label: 'Service Name', type: 'text' }
    ]
  },
  email: {
    name: 'Email',
    icon: Mail,
    fields: [
      { id: 'smtp_host', label: 'SMTP Host', type: 'text', required: true },
      { id: 'smtp_port', label: 'SMTP Port', type: 'number', required: true, placeholder: '587' },
      { id: 'smtp_user', label: 'SMTP Username', type: 'text', required: true },
      { id: 'smtp_password', label: 'SMTP Password', type: 'password', required: true },
      { id: 'from_email', label: 'From Email', type: 'email', required: true },
      { id: 'to_emails', label: 'Default Recipients', type: 'text', placeholder: 'security@company.com, soc@company.com' }
    ]
  },
  webhook: {
    name: 'Custom Webhook',
    icon: Webhook,
    fields: [
      { id: 'url', label: 'Webhook URL', type: 'text', required: true },
      { id: 'method', label: 'HTTP Method', type: 'select', options: ['POST', 'PUT'], required: true },
      { id: 'headers', label: 'Custom Headers (JSON)', type: 'textarea', placeholder: '{"Authorization": "Bearer token"}' },
      { id: 'auth_type', label: 'Authentication', type: 'select', options: ['None', 'Basic', 'Bearer'] }
    ]
  }
};

export default function IntegrationSettings({ userId }) {
  const [integrations, setIntegrations] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(null);
  const [testResults, setTestResults] = useState({});
  const [showSecrets, setShowSecrets] = useState({});
  const [error, setError] = useState(null);
  const [wizardType, setWizardType] = useState(null);

  useEffect(() => {
    loadIntegrations();
  }, [userId]);

  const loadIntegrations = async () => {
    try {
      const response = await fetch(`/api/settings/integrations?user_id=${userId}`);
      if (!response.ok) throw new Error('Failed to load integrations');

      const data = await response.json();
      if (data.integrations) {
        setIntegrations(data.integrations);
      }
    } catch (err) {
      console.error('Error loading integrations:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleIntegration = (type) => {
    setIntegrations(prev => ({
      ...prev,
      [type]: {
        ...prev[type],
        enabled: !prev[type]?.enabled
      }
    }));
  };

  const handleFieldChange = (type, fieldId, value) => {
    setIntegrations(prev => ({
      ...prev,
      [type]: {
        ...prev[type],
        config: {
          ...prev[type]?.config,
          [fieldId]: value
        }
      }
    }));
  };

  const testIntegration = async (type) => {
    setTesting(type);
    setTestResults(prev => ({ ...prev, [type]: null }));

    try {
      const response = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          type: type,
          config: integrations[type]?.config
        })
      });

      const data = await response.json();

      if (response.ok) {
        setTestResults(prev => ({
          ...prev,
          [type]: { success: true, message: data.message || 'Test successful' }
        }));
      } else {
        setTestResults(prev => ({
          ...prev,
          [type]: { success: false, message: data.error || 'Test failed' }
        }));
      }
    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [type]: { success: false, message: err.message }
      }));
    } finally {
      setTesting(null);
    }
  };

  const saveIntegrations = async () => {
    setSaving(true);
    setError(null);

    try {
      const response = await fetch('/api/settings/integrations', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          integrations: integrations
        })
      });

      if (!response.ok) throw new Error('Failed to save integrations');

      alert('Integration settings saved successfully!');
    } catch (err) {
      setError(err.message);
      console.error('Error saving integrations:', err);
    } finally {
      setSaving(false);
    }
  };

  const toggleShowSecret = (type, fieldId) => {
    const key = `${type}:${fieldId}`;
    setShowSecrets(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
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
      <div>
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-2">
          Alert Integrations
        </h2>
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Configure destinations for security alerts and detection notifications.
        </p>
      </div>

      {error && (
        <div className="p-4 bg-mono-100 dark:bg-mono-850 border border-mono-400 dark:border-mono-600 rounded-lg">
          <p className="text-sm text-mono-900 dark:text-mono-100">{error}</p>
        </div>
      )}

      {/* Integration Cards */}
      <div className="space-y-4">
        {Object.entries(INTEGRATION_TYPES).map(([type, info]) => {
          const Icon = info.icon;
          const config = integrations[type] || {};
          const testResult = testResults[type];

          return (
            <div key={type} className="card">
              {/* Integration Header */}
              <div className="flex items-center justify-between mb-4">
                <label className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.enabled || false}
                    onChange={() => handleToggleIntegration(type)}
                    className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
                  />
                  <div className="flex items-center space-x-2">
                    <Icon className="w-5 h-5 text-mono-600 dark:text-mono-400" />
                    <div className="font-semibold text-mono-950 dark:text-mono-50">
                      {info.name}
                    </div>
                  </div>
                </label>
                <div className="flex items-center space-x-2">
                  {config.enabled && (
                    <button
                      onClick={() => testIntegration(type)}
                      disabled={testing === type}
                      className="btn-secondary text-sm"
                    >
                      {testing === type ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <Check className="w-4 h-4 mr-2" />
                      )}
                      Test Integration
                    </button>
                  )}
                  {!config.enabled && (
                    <button
                      onClick={() => setWizardType(type)}
                      className="btn-secondary text-sm"
                    >
                      <Wand2 className="w-4 h-4 mr-2" />
                      Setup Wizard
                    </button>
                  )}
                </div>
              </div>

              {/* Integration Configuration */}
              {config.enabled && (
                <div className="space-y-3 pl-7">
                  {info.fields.map(field => {
                    const secretKey = `${type}:${field.id}`;
                    const isSecret = field.type === 'password';
                    const showSecret = showSecrets[secretKey];

                    return (
                      <div key={field.id}>
                        <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                          {field.label}
                          {field.required && <span className="text-mono-600 dark:text-mono-400 ml-1">*</span>}
                        </label>

                        {field.type === 'select' ? (
                          <select
                            value={config.config?.[field.id] || field.options?.[0] || ''}
                            onChange={(e) => handleFieldChange(type, field.id, e.target.value)}
                            className="input"
                          >
                            {field.options.map(option => (
                              <option key={option} value={option}>{option}</option>
                            ))}
                          </select>
                        ) : field.type === 'textarea' ? (
                          <textarea
                            value={config.config?.[field.id] || ''}
                            onChange={(e) => handleFieldChange(type, field.id, e.target.value)}
                            placeholder={field.placeholder}
                            className="input min-h-20 resize-y font-mono text-sm"
                          />
                        ) : (
                          <div className="relative">
                            <input
                              type={isSecret && !showSecret ? 'password' : field.type}
                              value={config.config?.[field.id] || ''}
                              onChange={(e) => handleFieldChange(type, field.id, e.target.value)}
                              placeholder={field.placeholder}
                              className={`input ${isSecret ? 'pr-10' : ''}`}
                            />
                            {isSecret && (
                              <button
                                type="button"
                                onClick={() => toggleShowSecret(type, field.id)}
                                className="absolute right-2 top-1/2 -translate-y-1/2 text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
                              >
                                {showSecret ? (
                                  <EyeOff className="w-4 h-4" />
                                ) : (
                                  <Eye className="w-4 h-4" />
                                )}
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {/* Test Result */}
                  {testResult && (
                    <div className={`p-3 rounded-lg border text-sm ${
                      testResult.success
                        ? 'bg-mono-50 dark:bg-mono-900 border-mono-300 dark:border-mono-700'
                        : 'bg-mono-100 dark:bg-mono-850 border-mono-400 dark:border-mono-600'
                    }`}>
                      <div className="flex items-start space-x-2">
                        {testResult.success ? (
                          <Check className="w-4 h-4 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
                        )}
                        <p className={testResult.success
                          ? 'text-mono-700 dark:text-mono-300'
                          : 'text-mono-900 dark:text-mono-100'
                        }>
                          {testResult.message}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={saveIntegrations}
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

      {/* Integration Wizard Modal */}
      {wizardType && (
        <IntegrationWizardModal
          integrationType={wizardType}
          onComplete={(config) => {
            setIntegrations(prev => ({
              ...prev,
              [config.type]: {
                enabled: true,
                config: config.config
              }
            }));
            setWizardType(null);
            loadIntegrations(); // Reload to get saved state
          }}
          onCancel={() => setWizardType(null)}
        />
      )}
    </div>
  );
}
