import { useState } from 'react';
import { Check, X, Loader, ExternalLink, AlertCircle } from 'lucide-react';

export default function JiraWizard({ userId, onComplete, onCancel }) {
  const [step, setStep] = useState(1);
  const [config, setConfig] = useState({
    url: '',
    email: '',
    api_token: '',
    project_key: '',
    issue_type: 'Bug'
  });
  const [projects, setProjects] = useState([]);
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [severityMapping, setSeverityMapping] = useState({
    critical: 'Highest',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Lowest'
  });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const fetchProjects = async () => {
    try {
      setLoadingProjects(true);
      setError(null);

      const response = await fetch('/api/integrations/wizard/jira/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: config.url,
          email: config.email,
          api_token: config.api_token
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch projects');
      }

      setProjects(data.projects || []);
      setStep(2);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingProjects(false);
    }
  };

  const handleTest = async () => {
    try {
      setTesting(true);
      setError(null);
      setTestResult(null);

      const response = await fetch('/api/integrations/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'jira',
          config
        })
      });

      const data = await response.json();
      setTestResult(data);

      if (data.success) {
        setTimeout(() => setStep(3), 1500);
      }

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

      const response = await fetch(`/api/integrations/wizard/jira/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: 'Jira Security Tickets',
          config: {
            ...config,
            severity_mapping: severityMapping
          },
          severity_filter: ['critical', 'high', 'medium', 'low', 'info'],
          enabled: true
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to save integration');
      }

      if (onComplete) {
        onComplete(data);
      }

    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-mono-200 dark:border-mono-800 pb-4">
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
          Jira Integration Setup
        </h2>
        <div className="flex items-center space-x-2 text-sm text-mono-600 dark:text-mono-400">
          <span>Step {step} of 3</span>
        </div>
      </div>

      {error && (
        <div className="bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded-lg p-4 flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-mono-900 dark:text-mono-100">Error</p>
            <p className="text-sm text-mono-700 dark:text-mono-300">{error}</p>
          </div>
        </div>
      )}

      <div className="flex items-center space-x-2 mb-6">
        {[1, 2, 3].map(i => (
          <div key={i} className="flex items-center flex-1">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full border-2 ${
              i < step
                ? 'bg-mono-950 dark:bg-mono-50 border-mono-950 dark:border-mono-50'
                : i === step
                ? 'border-mono-950 dark:border-mono-50 text-mono-950 dark:text-mono-50'
                : 'border-mono-300 dark:border-mono-700 text-mono-500 dark:text-mono-500'
            }`}>
              {i < step ? (
                <Check className="w-4 h-4 text-mono-50 dark:text-mono-950" />
              ) : (
                <span className="text-sm font-medium">{i}</span>
              )}
            </div>
            {i < 3 && (
              <div className={`flex-1 h-0.5 mx-2 ${
                i < step
                  ? 'bg-mono-950 dark:bg-mono-50'
                  : 'bg-mono-300 dark:bg-mono-700'
              }`} />
            )}
          </div>
        ))}
      </div>

      {step === 1 && (
        <div className="space-y-6">
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Generate API Token
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              You need to create an API token to allow Mantissa Log to create Jira issues.
            </p>
            <ol className="space-y-3 text-sm text-mono-700 dark:text-mono-300">
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">1</span>
                <div>
                  Go to <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center underline hover:text-mono-900 dark:hover:text-mono-100">
                    id.atlassian.com/manage-profile/security/api-tokens
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </a>
                </div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">2</span>
                <div>Click "Create API token"</div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">3</span>
                <div>Name it "Mantissa Log" and create</div>
              </li>
              <li className="flex items-start">
                <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 text-xs font-medium mr-3 flex-shrink-0 mt-0.5">4</span>
                <div>Copy the token immediately (you cannot view it again)</div>
              </li>
            </ol>
          </div>

          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Jira Credentials
            </h3>
            <div className="space-y-4">
              <div>
                <label className="label">Jira URL</label>
                <input
                  type="text"
                  value={config.url}
                  onChange={(e) => setConfig({ ...config, url: e.target.value })}
                  placeholder="https://your-domain.atlassian.net"
                  className="input"
                />
              </div>

              <div>
                <label className="label">Email Address</label>
                <input
                  type="email"
                  value={config.email}
                  onChange={(e) => setConfig({ ...config, email: e.target.value })}
                  placeholder="you@example.com"
                  className="input"
                />
              </div>

              <div>
                <label className="label">API Token</label>
                <input
                  type="password"
                  value={config.api_token}
                  onChange={(e) => setConfig({ ...config, api_token: e.target.value })}
                  placeholder="Your API token"
                  className="input font-mono"
                />
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-3">
            <button onClick={onCancel} className="btn-secondary">
              Cancel
            </button>
            <button
              onClick={fetchProjects}
              disabled={!config.url || !config.email || !config.api_token || loadingProjects}
              className="btn-primary flex items-center space-x-2"
            >
              {loadingProjects ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Loading Projects...</span>
                </>
              ) : (
                <span>Next</span>
              )}
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-6">
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Project Configuration
            </h3>
            <div className="space-y-4">
              <div>
                <label className="label">Project</label>
                <select
                  value={config.project_key}
                  onChange={(e) => setConfig({ ...config, project_key: e.target.value })}
                  className="input"
                >
                  <option value="">Select a project</option>
                  {projects.map(project => (
                    <option key={project.key} value={project.key}>
                      {project.name} ({project.key})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="label">Default Issue Type</label>
                <select
                  value={config.issue_type}
                  onChange={(e) => setConfig({ ...config, issue_type: e.target.value })}
                  className="input"
                >
                  <option value="Bug">Bug</option>
                  <option value="Task">Task</option>
                  <option value="Story">Story</option>
                  <option value="Incident">Incident</option>
                </select>
              </div>
            </div>
          </div>

          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Test Connection
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              Verify that Mantissa Log can access your Jira project.
            </p>

            <button
              onClick={handleTest}
              disabled={!config.project_key || testing || (testResult && testResult.success)}
              className="btn-primary flex items-center space-x-2"
            >
              {testing ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Testing Connection...</span>
                </>
              ) : (
                <span>Test Connection</span>
              )}
            </button>

            {testResult && (
              <div className={`mt-4 p-3 rounded-lg border ${
                testResult.success
                  ? 'bg-mono-100 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                  : 'bg-mono-150 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
              }`}>
                <div className="flex items-center space-x-2">
                  {testResult.success ? (
                    <>
                      <Check className="w-5 h-5 text-mono-900 dark:text-mono-100" />
                      <span className="text-sm text-mono-900 dark:text-mono-100">
                        {testResult.message}
                      </span>
                    </>
                  ) : (
                    <>
                      <X className="w-5 h-5 text-mono-700 dark:text-mono-300" />
                      <span className="text-sm text-mono-700 dark:text-mono-300">
                        {testResult.message}
                      </span>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(1)} className="btn-secondary">
              Back
            </button>
            <button
              onClick={() => setStep(3)}
              disabled={!testResult || !testResult.success}
              className="btn-primary"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="space-y-6">
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Priority Mapping
            </h3>
            <p className="text-sm text-mono-700 dark:text-mono-300 mb-4">
              Map alert severity levels to Jira priorities.
            </p>

            <div className="space-y-3">
              {Object.entries(severityMapping).map(([severity, priority]) => (
                <div key={severity} className="flex items-center space-x-3">
                  <div className="w-24 text-sm text-mono-700 dark:text-mono-300 capitalize">
                    {severity}
                  </div>
                  <span className="text-mono-500 dark:text-mono-500">→</span>
                  <select
                    value={priority}
                    onChange={(e) => setSeverityMapping({ ...severityMapping, [severity]: e.target.value })}
                    className="input flex-1"
                  >
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

          <div className="card bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
              Configuration Summary
            </h3>
            <div className="text-sm text-mono-700 dark:text-mono-300 space-y-1">
              <div>Jira URL: {config.url}</div>
              <div>Project: {config.project_key}</div>
              <div>Issue Type: {config.issue_type}</div>
              <div>Email: {config.email}</div>
            </div>
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(2)} className="btn-secondary">
              Back
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="btn-primary flex items-center space-x-2"
            >
              {saving ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Check className="w-5 h-5" />
                  <span>Complete Setup</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
