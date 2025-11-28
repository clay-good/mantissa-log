import { useState, useEffect } from 'react';
import { GitBranch, ExternalLink, Check, AlertTriangle, Loader2, ArrowRight, ArrowLeft } from 'lucide-react';

const STEPS = [
  { id: 'intro', title: 'Introduction', description: 'Getting started with Jira integration' },
  { id: 'credentials', title: 'Jira Credentials', description: 'Connect to your Jira instance' },
  { id: 'project', title: 'Project Configuration', description: 'Select project and issue type' },
  { id: 'mapping', title: 'Field Mapping', description: 'Map alert fields to Jira' },
  { id: 'test', title: 'Test & Finish', description: 'Create a test ticket' }
];

const SEVERITY_PRIORITY_MAP = {
  critical: 'Highest',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Lowest'
};

export default function JiraWizard({ onComplete, onCancel }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [config, setConfig] = useState({
    url: '',
    email: '',
    apiToken: '',
    projectKey: '',
    issueType: 'Bug',
    priorityMapping: SEVERITY_PRIORITY_MAP,
    summaryTemplate: '[{{severity}}] {{rule_name}}',
    descriptionTemplate: 'default'
  });
  const [projects, setProjects] = useState([]);
  const [issueTypes, setIssueTypes] = useState([]);
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const handleNext = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleConfigChange = (field, value) => {
    setConfig(prev => ({ ...prev, [field]: value }));
  };

  const handlePriorityChange = (severity, priority) => {
    setConfig(prev => ({
      ...prev,
      priorityMapping: {
        ...prev.priorityMapping,
        [severity]: priority
      }
    }));
  };

  const loadProjects = async () => {
    if (!config.url || !config.email || !config.apiToken) return;

    setLoadingProjects(true);
    try {
      const response = await fetch('/api/integrations/jira/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: config.url,
          email: config.email,
          api_token: config.apiToken
        })
      });

      if (response.ok) {
        const data = await response.json();
        setProjects(data.projects || []);
        setIssueTypes(data.issue_types || ['Bug', 'Task', 'Story', 'Epic']);
      }
    } catch (err) {
      console.error('Error loading Jira projects:', err);
    } finally {
      setLoadingProjects(false);
    }
  };

  useEffect(() => {
    if (currentStep === 2) {
      loadProjects();
    }
  }, [currentStep]);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const response = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'jira',
          config: {
            url: config.url,
            email: config.email,
            api_token: config.apiToken,
            project_key: config.projectKey,
            issue_type: config.issueType
          }
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setTestResult({
          success: true,
          message: 'Test ticket created successfully!',
          ticketUrl: data.ticket_url
        });
      } else {
        setTestResult({ success: false, message: data.message || 'Test failed' });
      }
    } catch (err) {
      setTestResult({ success: false, message: err.message });
    } finally {
      setTesting(false);
    }
  };

  const handleFinish = () => {
    if (onComplete) {
      onComplete({
        type: 'jira',
        config: {
          url: config.url,
          email: config.email,
          api_token: config.apiToken,
          project_key: config.projectKey,
          issue_type: config.issueType,
          priority_mapping: config.priorityMapping,
          summary_template: config.summaryTemplate,
          description_template: config.descriptionTemplate
        }
      });
    }
  };

  const canProceed = () => {
    if (currentStep === 0) return true;
    if (currentStep === 1) return config.url && config.email && config.apiToken;
    if (currentStep === 2) return config.projectKey && config.issueType;
    if (currentStep === 3) return true;
    if (currentStep === 4) return testResult?.success;
    return false;
  };

  return (
    <div className="fixed inset-0 bg-mono-950/50 dark:bg-mono-950/80 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-mono-900 rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-mono-200 dark:border-mono-800">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2 bg-mono-900 dark:bg-mono-100 rounded-lg">
              <GitBranch className="w-6 h-6 text-mono-50 dark:text-mono-950" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
                Jira Integration Setup
              </h2>
              <p className="text-sm text-mono-600 dark:text-mono-400">
                {STEPS[currentStep].description}
              </p>
            </div>
          </div>

          {/* Progress Steps */}
          <div className="flex items-center justify-between">
            {STEPS.map((step, index) => (
              <div key={step.id} className="flex items-center flex-1">
                <div className="flex flex-col items-center flex-1">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold transition-colors ${
                    index < currentStep
                      ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                      : index === currentStep
                      ? 'bg-mono-700 dark:bg-mono-300 text-mono-50 dark:text-mono-950'
                      : 'bg-mono-200 dark:bg-mono-800 text-mono-600 dark:text-mono-400'
                  }`}>
                    {index < currentStep ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      index + 1
                    )}
                  </div>
                  <div className={`text-xs mt-1 text-center ${
                    index === currentStep
                      ? 'text-mono-900 dark:text-mono-100 font-medium'
                      : 'text-mono-600 dark:text-mono-400'
                  }`}>
                    {step.title}
                  </div>
                </div>
                {index < STEPS.length - 1 && (
                  <div className={`h-0.5 flex-1 mx-2 transition-colors ${
                    index < currentStep
                      ? 'bg-mono-900 dark:bg-mono-100'
                      : 'bg-mono-200 dark:bg-mono-800'
                  }`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto" style={{ maxHeight: 'calc(90vh - 280px)' }}>
          {/* Step 0: Introduction */}
          {currentStep === 0 && (
            <div className="space-y-4">
              <p className="text-mono-700 dark:text-mono-300">
                This wizard will guide you through setting up Jira integration for automatic ticket creation from Mantissa Log alerts.
              </p>
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  What you'll need:
                </h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-mono-700 dark:text-mono-300">
                  <li>Jira Cloud or Jira Server URL</li>
                  <li>Jira account with project access</li>
                  <li>API token (we'll show you how to generate one)</li>
                  <li>About 10 minutes to complete setup</li>
                </ul>
              </div>
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  What you'll get:
                </h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-mono-700 dark:text-mono-300">
                  <li>Automatic ticket creation for security alerts</li>
                  <li>Customizable issue type and priority mapping</li>
                  <li>Rich ticket descriptions with alert details</li>
                  <li>Integration with your existing Jira workflows</li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 1: Credentials */}
          {currentStep === 1 && (
            <div className="space-y-4">
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  Generate Jira API Token
                </h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-mono-700 dark:text-mono-300">
                  <li>
                    Go to Atlassian Account Settings
                    <a
                      href="https://id.atlassian.com/manage-profile/security/api-tokens"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 inline-flex items-center text-mono-900 dark:text-mono-100 hover:underline"
                    >
                      Generate Token
                      <ExternalLink className="w-3 h-3 ml-1" />
                    </a>
                  </li>
                  <li>Click "Create API token"</li>
                  <li>Give it a label (e.g., "Mantissa Log")</li>
                  <li>Click "Create"</li>
                  <li>Copy the token (you won't be able to see it again)</li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Jira URL
                </label>
                <input
                  type="text"
                  value={config.url}
                  onChange={(e) => handleConfigChange('url', e.target.value)}
                  placeholder="https://your-domain.atlassian.net"
                  className="input"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  Your Jira Cloud or Server URL
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Email Address
                </label>
                <input
                  type="email"
                  value={config.email}
                  onChange={(e) => handleConfigChange('email', e.target.value)}
                  placeholder="your.email@company.com"
                  className="input"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  The email address associated with your Jira account
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  API Token
                </label>
                <input
                  type="password"
                  value={config.apiToken}
                  onChange={(e) => handleConfigChange('apiToken', e.target.value)}
                  placeholder="Enter your Jira API token"
                  className="input font-mono text-sm"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  The API token you generated above
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Project Configuration */}
          {currentStep === 2 && (
            <div className="space-y-4">
              {loadingProjects ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-8 h-8 animate-spin text-mono-600 dark:text-mono-400" />
                  <span className="ml-3 text-mono-600 dark:text-mono-400">
                    Loading Jira projects...
                  </span>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                      Project
                    </label>
                    {projects.length > 0 ? (
                      <select
                        value={config.projectKey}
                        onChange={(e) => handleConfigChange('projectKey', e.target.value)}
                        className="input"
                      >
                        <option value="">Select a project...</option>
                        {projects.map(project => (
                          <option key={project.key} value={project.key}>
                            {project.name} ({project.key})
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        value={config.projectKey}
                        onChange={(e) => handleConfigChange('projectKey', e.target.value)}
                        placeholder="PROJECT-KEY"
                        className="input"
                      />
                    )}
                    <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                      The Jira project where tickets will be created
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                      Issue Type
                    </label>
                    <select
                      value={config.issueType}
                      onChange={(e) => handleConfigChange('issueType', e.target.value)}
                      className="input"
                    >
                      {issueTypes.map(type => (
                        <option key={type} value={type}>{type}</option>
                      ))}
                    </select>
                    <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                      The type of issue to create for alerts
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                      Priority Mapping
                    </label>
                    <p className="text-xs text-mono-600 dark:text-mono-400 mb-3">
                      Map alert severity levels to Jira priorities
                    </p>
                    <div className="space-y-2">
                      {Object.entries(config.priorityMapping).map(([severity, priority]) => (
                        <div key={severity} className="flex items-center space-x-3">
                          <div className="w-24 text-sm text-mono-700 dark:text-mono-300 capitalize">
                            {severity}:
                          </div>
                          <select
                            value={priority}
                            onChange={(e) => handlePriorityChange(severity, e.target.value)}
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
                </>
              )}
            </div>
          )}

          {/* Step 3: Field Mapping */}
          {currentStep === 3 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Summary Template
                </label>
                <input
                  type="text"
                  value={config.summaryTemplate}
                  onChange={(e) => handleConfigChange('summaryTemplate', e.target.value)}
                  placeholder="[{{severity}}] {{rule_name}}"
                  className="input font-mono text-sm"
                />
                <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                  Template for the ticket summary. Available variables: {'{'}{'{'} severity {'}'}{'}'},  {'{'}{'{'} rule_name {'}'}{'}'},  {'{'}{'{'} timestamp {'}'}{'}'}
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-2">
                  Description Template
                </label>
                <select
                  value={config.descriptionTemplate}
                  onChange={(e) => handleConfigChange('descriptionTemplate', e.target.value)}
                  className="input"
                >
                  <option value="default">Default (Alert details + query results)</option>
                  <option value="detailed">Detailed (Includes full context)</option>
                  <option value="minimal">Minimal (Alert info only)</option>
                </select>
              </div>

              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2 text-sm">
                  Example Ticket Preview
                </h3>
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-mono-600 dark:text-mono-400">Summary:</span>
                    <div className="text-mono-900 dark:text-mono-100 font-mono text-xs mt-1 p-2 bg-mono-100 dark:bg-mono-900 rounded">
                      [CRITICAL] Failed Login Brute Force Detected
                    </div>
                  </div>
                  <div>
                    <span className="text-mono-600 dark:text-mono-400">Priority:</span>
                    <div className="text-mono-900 dark:text-mono-100 mt-1">
                      {config.priorityMapping.critical}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Test & Finish */}
          {currentStep === 4 && (
            <div className="space-y-4">
              <div className="bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg p-4">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-2">
                  Configuration Summary
                </h3>
                <dl className="space-y-2 text-sm">
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Jira URL:</dt>
                    <dd className="text-mono-900 dark:text-mono-100 font-mono">{config.url}</dd>
                  </div>
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Project:</dt>
                    <dd className="text-mono-900 dark:text-mono-100">{config.projectKey}</dd>
                  </div>
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Issue Type:</dt>
                    <dd className="text-mono-900 dark:text-mono-100">{config.issueType}</dd>
                  </div>
                  <div>
                    <dt className="text-mono-600 dark:text-mono-400">Summary Template:</dt>
                    <dd className="text-mono-900 dark:text-mono-100 font-mono text-xs">{config.summaryTemplate}</dd>
                  </div>
                </dl>
              </div>

              <div>
                <button
                  onClick={handleTest}
                  disabled={testing}
                  className="btn-secondary w-full"
                >
                  {testing ? (
                    <>
                      <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                      Creating Test Ticket...
                    </>
                  ) : (
                    <>
                      <GitBranch className="w-5 h-5 mr-2" />
                      Create Test Ticket in Jira
                    </>
                  )}
                </button>
              </div>

              {testResult && (
                <div className={`p-4 rounded-lg border text-sm ${
                  testResult.success
                    ? 'bg-mono-50 dark:bg-mono-900 border-mono-300 dark:border-mono-700'
                    : 'bg-mono-100 dark:bg-mono-850 border-mono-400 dark:border-mono-600'
                }`}>
                  <div className="flex items-start space-x-2">
                    {testResult.success ? (
                      <Check className="w-5 h-5 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <p className={testResult.success
                        ? 'text-mono-700 dark:text-mono-300'
                        : 'text-mono-900 dark:text-mono-100'
                      }>
                        {testResult.message}
                      </p>
                      {testResult.success && testResult.ticketUrl && (
                        <a
                          href={testResult.ticketUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-mono-900 dark:text-mono-100 hover:underline inline-flex items-center mt-2"
                        >
                          View test ticket in Jira
                          <ExternalLink className="w-3 h-3 ml-1" />
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-mono-200 dark:border-mono-800 flex items-center justify-between">
          <button
            onClick={onCancel}
            className="btn-secondary"
          >
            Cancel
          </button>

          <div className="flex items-center space-x-2">
            {currentStep > 0 && (
              <button
                onClick={handleBack}
                className="btn-secondary"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </button>
            )}

            {currentStep < STEPS.length - 1 ? (
              <button
                onClick={handleNext}
                disabled={!canProceed()}
                className="btn-primary"
              >
                Next
                <ArrowRight className="w-4 h-4 ml-2" />
              </button>
            ) : (
              <button
                onClick={handleFinish}
                disabled={!canProceed()}
                className="btn-primary"
              >
                <Check className="w-4 h-4 mr-2" />
                Finish Setup
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
