import { useState } from 'react';
import { X, Check, Loader, AlertCircle } from 'lucide-react';

export default function WebhookWizard({ integration, onComplete, onCancel }) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    name: integration?.name || '',
    url: integration?.config?.url || '',
    method: integration?.config?.method || 'POST',
    auth_type: integration?.config?.auth_type || 'none',
    auth_value: '',
    headers: integration?.config?.headers ? JSON.stringify(integration.config.headers, null, 2) : '{\n  "Content-Type": "application/json"\n}'
  });

  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async () => {
    setError(null);

    if (!formData.url) {
      setError('Webhook URL is required');
      return;
    }

    // Validate headers JSON
    let headers;
    try {
      headers = JSON.parse(formData.headers);
    } catch (e) {
      setError('Headers must be valid JSON');
      return;
    }

    setSaving(true);

    try {
      const config = {
        url: formData.url,
        method: formData.method,
        auth_type: formData.auth_type,
        headers
      };

      if (formData.auth_type !== 'none' && formData.auth_value) {
        config.auth_value = formData.auth_value;
      }

      await onComplete({
        integration_type: 'webhook',
        name: formData.name || 'Custom Webhook',
        config,
        enabled: true
      });
    } catch (err) {
      console.error('Error saving webhook integration:', err);
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
            {integration ? 'Edit' : 'Add'} Custom Webhook
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
          <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">Webhook Configuration</h3>
          <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
            Send alert data to any HTTP endpoint
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            Integration Name
          </label>
          <input type="text" value={formData.name} onChange={(e) => handleChange('name', e.target.value)} placeholder="My Webhook" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            Webhook URL <span className="text-mono-600 dark:text-mono-400">*</span>
          </label>
          <input type="url" value={formData.url} onChange={(e) => handleChange('url', e.target.value)} placeholder="https://example.com/webhook" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            HTTP Method
          </label>
          <select value={formData.method} onChange={(e) => handleChange('method', e.target.value)} className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50">
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="PATCH">PATCH</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            Authentication
          </label>
          <select value={formData.auth_type} onChange={(e) => handleChange('auth_type', e.target.value)} className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 mb-2">
            <option value="none">None</option>
            <option value="bearer">Bearer Token</option>
            <option value="basic">Basic Auth (Base64)</option>
          </select>

          {formData.auth_type !== 'none' && (
            <input type="password" value={formData.auth_value} onChange={(e) => handleChange('auth_value', e.target.value)} placeholder={formData.auth_type === 'bearer' ? 'Token value' : 'Base64 encoded credentials'} className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500 font-mono text-sm" />
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
            Headers (JSON)
          </label>
          <textarea value={formData.headers} onChange={(e) => handleChange('headers', e.target.value)} rows={6} className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500 font-mono text-sm" />
          <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
            Custom HTTP headers as JSON object
          </p>
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
