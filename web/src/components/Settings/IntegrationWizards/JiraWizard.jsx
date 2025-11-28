import { useState } from 'react';
import { X, Check, Loader, ExternalLink, AlertCircle } from 'lucide-react';

export default function JiraWizard({ integration, onComplete, onCancel }) {
  const [step, setStep] = useState(1);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    name: integration?.name || '',
    url: integration?.config?.url || '',
    username: integration?.config?.username || '',
    api_token: '',
    project_key: integration?.config?.project_key || '',
    issue_type: integration?.config?.issue_type || 'Bug',
    priority_mapping: integration?.config?.priority_mapping || {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      info: 'Lowest'
    }
  });

  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handlePriorityChange = (severity, priority) => {
    setFormData(prev => ({
      ...prev,
      priority_mapping: {
        ...prev.priority_mapping,
        [severity]: priority
      }
    }));
  };

  const handleNext = () => {
    setError(null);

    if (step === 1) {
      if (!formData.url || !formData.username || !formData.api_token) {
        setError('All fields are required');
        return;
      }
    }

    if (step === 2) {
      if (!formData.project_key || !formData.issue_type) {
        setError('Project key and issue type are required');
        return;
      }
    }

    setStep(step + 1);
  };

  const handleBack = () => {
    setError(null);
    setStep(step - 1);
  };

  const handleSubmit = async () => {
    setError(null);
    setSaving(true);

    try {
      const config = {
        url: formData.url,
        username: formData.username,
        api_token: formData.api_token,
        project_key: formData.project_key,
        issue_type: formData.issue_type,
        priority_mapping: formData.priority_mapping
      };

      await onComplete({
        integration_type: 'jira',
        name: formData.name || `Jira - ${formData.project_key}`,
        config,
        enabled: true
      });
    } catch (err) {
      console.error('Error saving Jira integration:', err);
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
            {integration ? 'Edit' : 'Add'} Jira Integration
          </h2>
          <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
            Step {step} of 3
          </p>
        </div>
        <button onClick={onCancel} className="p-2 hover:bg-mono-100 dark:hover:bg-mono-850 rounded">
          <X className="w-5 h-5 text-mono-600 dark:text-mono-400" />
        </button>
      </div>

      {/* Progress */}
      <div className="flex items-center mb-6">
        {[1, 2, 3].map(s => (
          <div key={s} className="flex items-center flex-1">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
              s <= step ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950' : 'bg-mono-200 dark:bg-mono-800 text-mono-600 dark:text-mono-400'
            }`}>
              {s < step ? <Check className="w-4 h-4" /> : s}
            </div>
            {s < 3 && <div className={`flex-1 h-1 mx-2 ${s < step ? 'bg-mono-900 dark:bg-mono-100' : 'bg-mono-200 dark:bg-mono-800'}`} />}
          </div>
        ))}
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

      {/* Step 1: Credentials */}
      {step === 1 && (
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">Jira Credentials</h3>
            <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center text-sm text-mono-900 dark:text-mono-100 hover:underline mb-4">
              <ExternalLink className="w-4 h-4 mr-1" />
              Generate API Token
            </a>
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Integration Name
            </label>
            <input type="text" value={formData.name} onChange={(e) => handleChange('name', e.target.value)} placeholder="My Jira Integration" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Jira URL <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <input type="url" value={formData.url} onChange={(e) => handleChange('url', e.target.value)} placeholder="https://your-domain.atlassian.net" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Username/Email <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <input type="email" value={formData.username} onChange={(e) => handleChange('username', e.target.value)} placeholder="user@example.com" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              API Token <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <input type="password" value={formData.api_token} onChange={(e) => handleChange('api_token', e.target.value)} placeholder="Your Jira API token" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500 font-mono text-sm" />
          </div>
        </div>
      )}

      {/* Step 2: Project Configuration */}
      {step === 2 && (
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">Project Configuration</h3>
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Project Key <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <input type="text" value={formData.project_key} onChange={(e) => handleChange('project_key', e.target.value)} placeholder="SEC" className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500" />
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Issue Type <span className="text-mono-600 dark:text-mono-400">*</span>
            </label>
            <select value={formData.issue_type} onChange={(e) => handleChange('issue_type', e.target.value)} className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50">
              <option value="Bug">Bug</option>
              <option value="Task">Task</option>
              <option value="Story">Story</option>
              <option value="Incident">Incident</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
              Priority Mapping
            </label>
            {['critical', 'high', 'medium', 'low', 'info'].map(severity => (
              <div key={severity} className="flex items-center mb-2">
                <span className="w-24 text-sm text-mono-900 dark:text-mono-100 capitalize">{severity}:</span>
                <select value={formData.priority_mapping[severity]} onChange={(e) => handlePriorityChange(severity, e.target.value)} className="flex-1 px-3 py-1 text-sm bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50">
                  <option value="Highest">Highest</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Lowest">Lowest</option>
                </select>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Step 3: Review */}
      {step === 3 && (
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-mono-950 dark:text-mono-50 mb-3">Review Configuration</h3>
          </div>

          <div className="bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded-lg p-4 space-y-3">
            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">Integration Name</p>
              <p className="text-sm text-mono-900 dark:text-mono-100">{formData.name || `Jira - ${formData.project_key}`}</p>
            </div>
            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">Jira URL</p>
              <p className="text-sm text-mono-900 dark:text-mono-100">{formData.url}</p>
            </div>
            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">Username</p>
              <p className="text-sm text-mono-900 dark:text-mono-100">{formData.username}</p>
            </div>
            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">Project Key</p>
              <p className="text-sm text-mono-900 dark:text-mono-100">{formData.project_key}</p>
            </div>
            <div>
              <p className="text-xs font-semibold text-mono-600 dark:text-mono-400 mb-1">Issue Type</p>
              <p className="text-sm text-mono-900 dark:text-mono-100">{formData.issue_type}</p>
            </div>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-between mt-6 pt-6 border-t border-mono-200 dark:border-mono-800">
        <button onClick={step === 1 ? onCancel : handleBack} disabled={saving} className="px-4 py-2 border border-mono-300 dark:border-mono-700 rounded hover:bg-mono-100 dark:hover:bg-mono-850 disabled:opacity-50 text-mono-900 dark:text-mono-100">
          {step === 1 ? 'Cancel' : 'Back'}
        </button>

        {step < 3 ? (
          <button onClick={handleNext} className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200">
            Next
          </button>
        ) : (
          <button onClick={handleSubmit} disabled={saving} className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 flex items-center">
            {saving ? (<><Loader className="w-4 h-4 mr-2 animate-spin" />Saving...</>) : (integration ? 'Update Integration' : 'Create Integration')}
          </button>
        )}
      </div>
    </div>
  );
}
