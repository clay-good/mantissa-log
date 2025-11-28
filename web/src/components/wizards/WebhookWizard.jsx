import { useState } from 'react';
import { Check, X, Loader, AlertCircle } from 'lucide-react';

export default function WebhookWizard({ userId, onComplete, onCancel }) {
  const [config, setConfig] = useState({
    url: '',
    method: 'POST',
    headers: {}
  });
  const [headerKey, setHeaderKey] = useState('');
  const [headerValue, setHeaderValue] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const addHeader = () => {
    if (headerKey && headerValue) {
      setConfig({
        ...config,
        headers: { ...config.headers, [headerKey]: headerValue }
      });
      setHeaderKey('');
      setHeaderValue('');
    }
  };

  const removeHeader = (key) => {
    const newHeaders = { ...config.headers };
    delete newHeaders[key];
    setConfig({ ...config, headers: newHeaders });
  };

  const handleTest = async () => {
    try {
      setTesting(true);
      setError(null);
      setTestResult(null);
      const response = await fetch('/api/integrations/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'webhook', config })
      });
      const data = await response.json();
      setTestResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      const response = await fetch('/api/integrations/wizard/webhook/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: 'Custom Webhook',
          config,
          severity_filter: ['critical', 'high', 'medium', 'low', 'info'],
          enabled: true
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to save');
      if (onComplete) onComplete(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">Custom Webhook</h2>
      {error && (
        <div className="bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded-lg p-4">
          <AlertCircle className="w-5 h-5 inline-block mr-2" />
          <span className="text-sm">{error}</span>
        </div>
      )}
      <div className="card">
        <div className="space-y-4">
          <div>
            <label className="label">Webhook URL</label>
            <input
              type="text"
              value={config.url}
              onChange={(e) => setConfig({ ...config, url: e.target.value })}
              placeholder="https://example.com/webhook"
              className="input"
            />
          </div>
          <div>
            <label className="label">HTTP Method</label>
            <select value={config.method} onChange={(e) => setConfig({ ...config, method: e.target.value })} className="input">
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
            </select>
          </div>
        </div>
      </div>
      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">Headers</h3>
        <div className="flex space-x-2 mb-3">
          <input
            type="text"
            value={headerKey}
            onChange={(e) => setHeaderKey(e.target.value)}
            placeholder="Header name"
            className="input flex-1"
          />
          <input
            type="text"
            value={headerValue}
            onChange={(e) => setHeaderValue(e.target.value)}
            placeholder="Header value"
            className="input flex-1"
          />
          <button onClick={addHeader} className="btn-secondary">Add</button>
        </div>
        {Object.entries(config.headers).map(([key, value]) => (
          <div key={key} className="flex items-center justify-between p-2 bg-mono-100 dark:bg-mono-850 rounded mb-2">
            <span className="text-sm font-mono">{key}: {value}</span>
            <button onClick={() => removeHeader(key)} className="text-xs text-mono-600 dark:text-mono-400">Remove</button>
          </div>
        ))}
      </div>
      <div className="card">
        <button onClick={handleTest} disabled={!config.url || testing} className="btn-primary">
          {testing ? 'Testing...' : 'Test Webhook'}
        </button>
        {testResult && (
          <div className="mt-4 p-3 rounded-lg border border-mono-300 dark:border-mono-700">
            {testResult.success ? <Check className="w-5 h-5 inline" /> : <X className="w-5 h-5 inline" />}
            <span className="ml-2 text-sm">{testResult.message}</span>
          </div>
        )}
      </div>
      <div className="flex justify-end space-x-3">
        <button onClick={onCancel} className="btn-secondary">Cancel</button>
        <button onClick={handleSave} disabled={!testResult || !testResult.success || saving} className="btn-primary">
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </div>
  );
}
