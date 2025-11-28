import { useState } from 'react';
import { Check, X, Loader, AlertCircle } from 'lucide-react';

export default function PagerDutyWizard({ userId, onComplete, onCancel }) {
  const [config, setConfig] = useState({ integration_key: '', severity: 'critical' });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const handleTest = async () => {
    try {
      setTesting(true);
      setError(null);
      setTestResult(null);
      const response = await fetch('/api/integrations/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'pagerduty', config })
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
      const response = await fetch('/api/integrations/wizard/pagerduty/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: 'PagerDuty Alerts',
          config,
          severity_filter: ['critical', 'high'],
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
      <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">PagerDuty Integration</h2>
      {error && (
        <div className="bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded-lg p-4">
          <AlertCircle className="w-5 h-5 inline-block mr-2" />
          <span className="text-sm">{error}</span>
        </div>
      )}
      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">Integration Key</h3>
        <input
          type="password"
          value={config.integration_key}
          onChange={(e) => setConfig({ ...config, integration_key: e.target.value })}
          placeholder="PagerDuty Integration Key"
          className="input font-mono"
        />
      </div>
      <div className="card">
        <button onClick={handleTest} disabled={!config.integration_key || testing} className="btn-primary">
          {testing ? 'Testing...' : 'Test Connection'}
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
