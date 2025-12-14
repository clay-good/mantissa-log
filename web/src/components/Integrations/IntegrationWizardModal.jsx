import { useState } from 'react';
import SlackWizard from './SlackWizard';
import JiraWizard from './JiraWizard';
import PagerDutyWizard from './PagerDutyWizard';
import EmailWizard from './EmailWizard';
import WebhookWizard from './WebhookWizard';
import { useAuthStore } from '../../stores/authStore';

/**
 * Unified Integration Wizard Modal
 *
 * Displays the appropriate wizard based on integration type
 */
export default function IntegrationWizardModal({ integrationType, onComplete, onCancel }) {
  const [saving, setSaving] = useState(false);
  const { user } = useAuthStore();

  const handleComplete = async (integrationConfig) => {
    setSaving(true);
    try {
      // Save integration configuration
      const response = await fetch('/api/settings/integrations', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: user?.userId || user?.username,
          integrations: {
            [integrationConfig.type]: {
              enabled: true,
              config: integrationConfig.config
            }
          }
        })
      });

      if (!response.ok) {
        throw new Error('Failed to save integration configuration');
      }

      if (onComplete) {
        onComplete(integrationConfig);
      }
    } catch (err) {
      console.error('Error saving integration:', err);
      alert(`Failed to save integration: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  if (saving) {
    return (
      <div className="fixed inset-0 bg-mono-950/50 dark:bg-mono-950/80 flex items-center justify-center z-50">
        <div className="bg-white dark:bg-mono-900 rounded-lg shadow-xl p-8">
          <div className="flex items-center space-x-3">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-mono-900 dark:border-mono-100" />
            <span className="text-mono-900 dark:text-mono-100">
              Saving integration configuration...
            </span>
          </div>
        </div>
      </div>
    );
  }

  switch (integrationType) {
    case 'slack':
      return <SlackWizard onComplete={handleComplete} onCancel={onCancel} />;

    case 'jira':
      return <JiraWizard onComplete={handleComplete} onCancel={onCancel} />;

    case 'pagerduty':
      return <PagerDutyWizard onComplete={handleComplete} onCancel={onCancel} />;

    case 'email':
      return <EmailWizard onComplete={handleComplete} onCancel={onCancel} />;

    case 'webhook':
      return <WebhookWizard onComplete={handleComplete} onCancel={onCancel} />;

    default:
      return null;
  }
}
