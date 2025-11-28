import { useState } from 'react';
import { X, Check, Loader, ExternalLink, AlertCircle } from 'lucide-react';

export default function PagerDutyWizard({ integration, onComplete, onCancel }) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    name: integration?.name || '',
    integration_key: '',
    severity_filter: integration?.config?.severity_filter || ['critical', 'high']
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

  const handleSubmit = async () => {
    setError(null);

    if (!formData.integration_key) {
      setError('Integration key is required');
      return;
    }

    setSaving(true);

    try {
      const config = {
        integration_key: formData.integration_key,
        severity_filter: formData.severity_filter
      };

      await onComplete({
        integration_type: 'pagerduty',
        name: formData.name || 'PagerDuty Integration',
        config,
        enabled: true
      });
    } catch (err) {
      console.error('Error saving PagerDuty integration:', err);
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
            {integration ? 'Edit' : 'Add'} PagerDuty Integration
          </h2>
        </div>
        <button onClick={onCancel} className="p-2 hover:bg-mono-100 dark:hover:bg-mono-850 rounded">
          <X className="w-5 h-5 text-mono-600 dark:text-mono-400" />
        </button>
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

      <div className="space-y-4">
        <div>
          <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">PagerDuty Events Integration</h3>
          <div className="text-sm text-mono-700 dark:text-mono-300 space-y-2 mb-4">
            <p>To send incidents to PagerDuty, you need an Events API v2 integration key:</p>
            <ol className="list-decimal list-inside space-y-1 ml-2">
              <li>Go to your PagerDuty service</li>
              <li>Click "Integrations"</li>
              <li>Add a new "Events API v2" integration</li>
              <li>Copy the Integration Key</li>
            </ol>
          </div>
          <a href="https://support.pagerduty.com/docs/services-and-integrations" target="_blank" rel="noopener noreferrer" className="inline-flex items-center text-sm text-mono-900 dark:text-mono-100 hover:underline mb-4">
            <ExternalLink className="w-4 h-4 mr-1" />
            PagerDuty Documentation
          </a>
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            Integration Name
          </label>
          <input type="text" value={formData.name} onChange={(e) => handleChange('name', e.target.value)} placeholder="PagerDuty Alerts" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            Integration Key <span className="text-mono-600 dark:text-mono-400">*</span>
          </label>
          <input type="password" value={formData.integration_key} onChange={(e) => handleChange('integration_key', e.target.value)} placeholder="Your PagerDuty integration key" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500 font-mono text-sm" />
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
            Severity Levels
          </label>
          <p className="text-xs text-mono-600 dark:text-mono-400 mb-2">
            Select which severities should trigger PagerDuty incidents
          </p>

          {['critical', 'high', 'medium', 'low', 'info'].map(severity => (
            <label key={severity} className="flex items-center p-3 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded cursor-pointer hover:bg-mono-50 dark:hover:bg-mono-900 mb-2">
              <input type="checkbox" checked={formData.severity_filter.includes(severity)} onChange={() => handleSeverityToggle(severity)} className="mr-3" />
              <div className="flex-1">
                <span className="font-medium text-mono-900 dark:text-mono-100 capitalize">
                  {severity}
                </span>
              </div>
            </label>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-mono-200 dark:border-mono-800">
        <button onClick={onCancel} disabled={saving} className="px-4 py-2 border border-mono-300 dark:border-mono-700 rounded hover:bg-mono-100 dark:hover:bg-mono-850 disabled:opacity-50 text-mono-900 dark:text-mono-100">
          Cancel
        </button>

        <button onClick={handleSubmit} disabled={saving} className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 flex items-center">
          {saving ? (<><Loader className="w-4 h-4 mr-2 animate-spin" />Saving...</>) : (integration ? 'Update Integration' : 'Create Integration')}
        </button>
      </div>
    </div>
  );
}
