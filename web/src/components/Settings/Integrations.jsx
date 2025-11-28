import { useState, useEffect } from 'react';
import { Plus, Settings, Trash2, Check, X, Loader, AlertCircle, ExternalLink } from 'lucide-react';
import SlackWizard from './IntegrationWizards/SlackWizard';
import JiraWizard from './IntegrationWizards/JiraWizard';
import PagerDutyWizard from './IntegrationWizards/PagerDutyWizard';
import WebhookWizard from './IntegrationWizards/WebhookWizard';

export default function Integrations({ userId }) {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showWizard, setShowWizard] = useState(false);
  const [wizardType, setWizardType] = useState(null);
  const [editingIntegration, setEditingIntegration] = useState(null);
  const [testingId, setTestingId] = useState(null);
  const [testResults, setTestResults] = useState({});

  useEffect(() => {
    loadIntegrations();
  }, [userId]);

  const loadIntegrations = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/integrations?user_id=${userId}`);

      if (!response.ok) {
        throw new Error('Failed to load integrations');
      }

      const data = await response.json();
      setIntegrations(data.integrations || []);
    } catch (err) {
      console.error('Error loading integrations:', err);
      setError('Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateIntegration = (type) => {
    setWizardType(type);
    setEditingIntegration(null);
    setShowWizard(true);
  };

  const handleEditIntegration = (integration) => {
    setWizardType(integration.integration_type);
    setEditingIntegration(integration);
    setShowWizard(true);
  };

  const handleWizardComplete = async (integrationData) => {
    try {
      if (editingIntegration) {
        // Update existing
        const response = await fetch(`/api/integrations/${editingIntegration.integration_id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user_id: userId,
            ...integrationData
          })
        });

        if (!response.ok) {
          throw new Error('Failed to update integration');
        }
      } else {
        // Create new
        const response = await fetch('/api/integrations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user_id: userId,
            ...integrationData
          })
        });

        if (!response.ok) {
          throw new Error('Failed to create integration');
        }
      }

      // Reload integrations
      await loadIntegrations();

      // Close wizard
      setShowWizard(false);
      setWizardType(null);
      setEditingIntegration(null);
    } catch (err) {
      console.error('Error saving integration:', err);
      throw err; // Let wizard handle the error
    }
  };

  const handleDeleteIntegration = async (integrationId) => {
    if (!confirm('Are you sure you want to delete this integration?')) {
      return;
    }

    try {
      const response = await fetch(`/api/integrations/${integrationId}?user_id=${userId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Failed to delete integration');
      }

      // Reload integrations
      await loadIntegrations();
    } catch (err) {
      console.error('Error deleting integration:', err);
      alert('Failed to delete integration');
    }
  };

  const handleTestIntegration = async (integrationId) => {
    setTestingId(integrationId);
    setTestResults(prev => ({ ...prev, [integrationId]: null }));

    try {
      const response = await fetch(`/api/integrations/${integrationId}/test?user_id=${userId}`, {
        method: 'POST'
      });

      const result = await response.json();
      setTestResults(prev => ({ ...prev, [integrationId]: result }));

      // Auto-clear result after 5 seconds
      setTimeout(() => {
        setTestResults(prev => {
          const newResults = { ...prev };
          delete newResults[integrationId];
          return newResults;
        });
      }, 5000);
    } catch (err) {
      console.error('Error testing integration:', err);
      setTestResults(prev => ({
        ...prev,
        [integrationId]: {
          success: false,
          error: 'Failed to test integration'
        }
      }));
    } finally {
      setTestingId(null);
    }
  };

  const handleToggleEnabled = async (integration) => {
    try {
      const response = await fetch(`/api/integrations/${integration.integration_id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          enabled: !integration.enabled
        })
      });

      if (!response.ok) {
        throw new Error('Failed to update integration');
      }

      // Reload integrations
      await loadIntegrations();
    } catch (err) {
      console.error('Error toggling integration:', err);
      alert('Failed to update integration');
    }
  };

  const integrationTypes = [
    {
      type: 'slack',
      name: 'Slack',
      description: 'Send alerts to Slack channels',
      icon: '💬'
    },
    {
      type: 'jira',
      name: 'Jira',
      description: 'Create issues in Jira',
      icon: '🎫'
    },
    {
      type: 'pagerduty',
      name: 'PagerDuty',
      description: 'Send incidents to PagerDuty',
      icon: '🔔'
    },
    {
      type: 'webhook',
      name: 'Custom Webhook',
      description: 'Send to any HTTP endpoint',
      icon: '🔗'
    }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader className="w-6 h-6 animate-spin text-mono-600 dark:text-mono-400" />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center">
            <Settings className="w-6 h-6 mr-2 text-mono-900 dark:text-mono-100" />
            <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
              Integrations
            </h1>
          </div>
        </div>
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Configure third-party integrations for alert routing and ticketing
        </p>
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

      {/* Add Integration Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {integrationTypes.map(type => (
          <button
            key={type.type}
            onClick={() => handleCreateIntegration(type.type)}
            className="p-4 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-lg hover:border-mono-400 dark:hover:border-mono-600 hover:bg-mono-50 dark:hover:bg-mono-900 transition-colors text-left"
          >
            <div className="flex items-start justify-between mb-2">
              <span className="text-2xl">{type.icon}</span>
              <Plus className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-1">
              {type.name}
            </h3>
            <p className="text-xs text-mono-600 dark:text-mono-400">
              {type.description}
            </p>
          </button>
        ))}
      </div>

      {/* Configured Integrations */}
      {integrations.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
            Configured Integrations
          </h2>

          <div className="space-y-3">
            {integrations.map(integration => (
              <IntegrationCard
                key={integration.integration_id}
                integration={integration}
                onEdit={() => handleEditIntegration(integration)}
                onDelete={() => handleDeleteIntegration(integration.integration_id)}
                onTest={() => handleTestIntegration(integration.integration_id)}
                onToggle={() => handleToggleEnabled(integration)}
                testing={testingId === integration.integration_id}
                testResult={testResults[integration.integration_id]}
              />
            ))}
          </div>
        </div>
      )}

      {integrations.length === 0 && (
        <div className="text-center py-12">
          <Settings className="w-12 h-12 mx-auto text-mono-400 dark:text-mono-600 mb-4" />
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-2">
            No integrations configured
          </h3>
          <p className="text-sm text-mono-600 dark:text-mono-400">
            Add an integration above to start routing alerts
          </p>
        </div>
      )}

      {/* Integration Wizard Modal */}
      {showWizard && (
        <WizardModal
          type={wizardType}
          integration={editingIntegration}
          onComplete={handleWizardComplete}
          onCancel={() => {
            setShowWizard(false);
            setWizardType(null);
            setEditingIntegration(null);
          }}
        />
      )}
    </div>
  );
}

function IntegrationCard({ integration, onEdit, onDelete, onTest, onToggle, testing, testResult }) {
  const typeIcons = {
    slack: '💬',
    jira: '🎫',
    pagerduty: '🔔',
    webhook: '🔗'
  };

  return (
    <div className="bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-lg p-4">
      <div className="flex items-start justify-between">
        <div className="flex items-start flex-1">
          <span className="text-2xl mr-3">{typeIcons[integration.integration_type] || '⚙️'}</span>

          <div className="flex-1">
            <div className="flex items-center mb-1">
              <h3 className="font-semibold text-mono-950 dark:text-mono-50 mr-2">
                {integration.name}
              </h3>
              <span className="text-xs px-2 py-0.5 bg-mono-100 dark:bg-mono-850 text-mono-700 dark:text-mono-300 rounded">
                {integration.integration_type}
              </span>
            </div>

            <div className="flex items-center space-x-4 text-xs text-mono-600 dark:text-mono-400">
              <div className="flex items-center">
                Status:{' '}
                <span className={`ml-1 font-semibold ${integration.enabled ? 'text-mono-900 dark:text-mono-100' : ''}`}>
                  {integration.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>

              {integration.last_test_at && (
                <div className="flex items-center">
                  Last tested:{' '}
                  <span className="ml-1">
                    {new Date(integration.last_test_at).toLocaleString()}
                  </span>
                  {integration.last_test_status === 'success' && (
                    <Check className="w-3 h-3 ml-1 text-mono-900 dark:text-mono-100" />
                  )}
                  {integration.last_test_status === 'failed' && (
                    <X className="w-3 h-3 ml-1 text-mono-900 dark:text-mono-100" />
                  )}
                </div>
              )}
            </div>

            {/* Test Result */}
            {testResult && (
              <div className={`mt-2 p-2 rounded text-xs flex items-start ${
                testResult.success
                  ? 'bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700'
                  : 'bg-mono-100 dark:bg-mono-850 border border-mono-400 dark:border-mono-600'
              }`}>
                {testResult.success ? (
                  <Check className="w-4 h-4 mr-1 flex-shrink-0 text-mono-900 dark:text-mono-100" />
                ) : (
                  <X className="w-4 h-4 mr-1 flex-shrink-0 text-mono-900 dark:text-mono-100" />
                )}
                <span className="text-mono-900 dark:text-mono-100">
                  {testResult.message || testResult.error}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center space-x-2 ml-4">
          {/* Toggle enabled */}
          <button
            onClick={onToggle}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
              integration.enabled
                ? 'bg-mono-900 dark:bg-mono-100'
                : 'bg-mono-300 dark:bg-mono-700'
            }`}
            title={integration.enabled ? 'Disable' : 'Enable'}
          >
            <span
              className={`inline-block h-3 w-3 transform rounded-full transition-transform ${
                integration.enabled
                  ? 'translate-x-5 bg-mono-50 dark:bg-mono-950'
                  : 'translate-x-1 bg-mono-50 dark:bg-mono-950'
              }`}
            />
          </button>

          {/* Test */}
          <button
            onClick={onTest}
            disabled={testing}
            className="px-3 py-1 text-sm border border-mono-300 dark:border-mono-700 rounded hover:bg-mono-100 dark:hover:bg-mono-850 disabled:opacity-50 text-mono-900 dark:text-mono-100"
            title="Test connection"
          >
            {testing ? (
              <Loader className="w-4 h-4 animate-spin" />
            ) : (
              'Test'
            )}
          </button>

          {/* Edit */}
          <button
            onClick={onEdit}
            className="px-3 py-1 text-sm border border-mono-300 dark:border-mono-700 rounded hover:bg-mono-100 dark:hover:bg-mono-850 text-mono-900 dark:text-mono-100"
            title="Edit"
          >
            Edit
          </button>

          {/* Delete */}
          <button
            onClick={onDelete}
            className="p-1 text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 hover:bg-mono-100 dark:hover:bg-mono-850 rounded"
            title="Delete"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

function WizardModal({ type, integration, onComplete, onCancel }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white dark:bg-mono-950 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        {type === 'slack' && (
          <SlackWizard
            integration={integration}
            onComplete={onComplete}
            onCancel={onCancel}
          />
        )}
        {type === 'jira' && (
          <JiraWizard
            integration={integration}
            onComplete={onComplete}
            onCancel={onCancel}
          />
        )}
        {type === 'pagerduty' && (
          <PagerDutyWizard
            integration={integration}
            onComplete={onComplete}
            onCancel={onCancel}
          />
        )}
        {type === 'webhook' && (
          <WebhookWizard
            integration={integration}
            onComplete={onComplete}
            onCancel={onCancel}
          />
        )}
      </div>
    </div>
  );
}
