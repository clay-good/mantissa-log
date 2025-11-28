import { useState, useEffect } from 'react';
import { Key, Check, X, Loader, AlertCircle, Zap } from 'lucide-react';

const PROVIDERS = [
  {
    id: 'anthropic',
    name: 'Anthropic',
    models: [
      { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', pricing: { input: 3.00, output: 15.00 } },
      { id: 'claude-3-5-haiku-20241022', name: 'Claude 3.5 Haiku', pricing: { input: 0.80, output: 4.00 } },
      { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', pricing: { input: 15.00, output: 75.00 } }
    ],
    requiresKey: true
  },
  {
    id: 'openai',
    name: 'OpenAI',
    models: [
      { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', pricing: { input: 10.00, output: 30.00 } },
      { id: 'gpt-4', name: 'GPT-4', pricing: { input: 30.00, output: 60.00 } },
      { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', pricing: { input: 0.50, output: 1.50 } }
    ],
    requiresKey: true
  },
  {
    id: 'google',
    name: 'Google',
    models: [
      { id: 'gemini-1.5-pro', name: 'Gemini 1.5 Pro', pricing: { input: 3.50, output: 10.50 } },
      { id: 'gemini-pro', name: 'Gemini Pro', pricing: { input: 0.50, output: 1.50 } }
    ],
    requiresKey: true
  },
  {
    id: 'bedrock',
    name: 'AWS Bedrock',
    models: [
      { id: 'anthropic.claude-3-5-sonnet-20241022-v2:0', name: 'Claude 3.5 Sonnet', pricing: { input: 3.00, output: 15.00 } },
      { id: 'anthropic.claude-3-5-haiku-20241022-v1:0', name: 'Claude 3.5 Haiku', pricing: { input: 0.80, output: 4.00 } },
      { id: 'anthropic.claude-3-opus-20240229-v1:0', name: 'Claude 3 Opus', pricing: { input: 15.00, output: 75.00 } }
    ],
    requiresKey: false
  }
];

export default function LLMConfiguration({ userId }) {
  const [preferences, setPreferences] = useState({
    defaultProvider: 'bedrock',
    queryModel: 'claude-3-5-sonnet-20241022',
    detectionModel: 'claude-3-5-sonnet-20241022',
    maxTokens: 2000,
    temperature: 0.0,
    enableCaching: true,
    trackUsage: true
  });

  const [apiKeys, setApiKeys] = useState({
    anthropic: '',
    openai: '',
    google: ''
  });

  const [hasApiKeys, setHasApiKeys] = useState({
    anthropic: false,
    openai: false,
    google: false,
    bedrock: true
  });

  const [testResults, setTestResults] = useState({});
  const [testing, setTesting] = useState({});
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    loadSettings();
  }, [userId]);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/llm-settings/${userId}`);
      const data = await response.json();

      if (data.preferences) {
        setPreferences(data.preferences);
      }
      if (data.hasApiKeys) {
        setHasApiKeys(data.hasApiKeys);
      }
    } catch (err) {
      console.error('Error loading settings:', err);
      setError('Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async () => {
    try {
      setSaving(true);
      setError(null);

      const response = await fetch(`/api/llm-settings/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          preferences,
          apiKeys: Object.fromEntries(
            Object.entries(apiKeys).filter(([_, value]) => value.trim())
          )
        })
      });

      if (!response.ok) {
        throw new Error('Failed to save settings');
      }

      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);

      await loadSettings();

      setApiKeys({
        anthropic: '',
        openai: '',
        google: ''
      });

    } catch (err) {
      console.error('Error saving settings:', err);
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async (provider) => {
    try {
      setTesting(prev => ({ ...prev, [provider]: true }));
      setTestResults(prev => ({ ...prev, [provider]: null }));

      const response = await fetch(`/api/llm-settings/${userId}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider })
      });

      const result = await response.json();
      setTestResults(prev => ({ ...prev, [provider]: result }));

    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [provider]: { success: false, error: err.message }
      }));
    } finally {
      setTesting(prev => ({ ...prev, [provider]: false }));
    }
  };

  const getProviderModels = (providerId) => {
    const provider = PROVIDERS.find(p => p.id === providerId);
    return provider?.models || [];
  };

  const getModelPricing = (providerId, modelId) => {
    const provider = PROVIDERS.find(p => p.id === providerId);
    const model = provider?.models.find(m => m.id === modelId);
    return model?.pricing;
  };

  if (loading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center py-12">
          <Loader className="w-6 h-6 text-mono-500 animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-2">
          LLM Configuration
        </h2>
        <p className="text-mono-600 dark:text-mono-400">
          Configure your LLM provider preferences and API keys. Bring your own keys to use external providers.
        </p>
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

      {success && (
        <div className="bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded-lg p-4 flex items-start space-x-3">
          <Check className="w-5 h-5 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-mono-900 dark:text-mono-100">Settings saved successfully</p>
          </div>
        </div>
      )}

      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Default Provider
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {PROVIDERS.map(provider => (
            <button
              key={provider.id}
              onClick={() => setPreferences({ ...preferences, defaultProvider: provider.id })}
              className={`p-4 rounded-lg border-2 transition-all ${
                preferences.defaultProvider === provider.id
                  ? 'border-mono-950 dark:border-mono-50 bg-mono-100 dark:bg-mono-850'
                  : 'border-mono-200 dark:border-mono-800 hover:border-mono-400 dark:hover:border-mono-600'
              }`}
            >
              <div className="font-medium text-mono-900 dark:text-mono-100 mb-1">
                {provider.name}
              </div>
              {hasApiKeys[provider.id] && (
                <div className="flex items-center text-xs text-mono-600 dark:text-mono-400">
                  <Key className="w-3 h-3 mr-1" />
                  <span>Configured</span>
                </div>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
          API Keys
        </h3>
        <p className="text-sm text-mono-600 dark:text-mono-400 mb-4">
          API keys are securely stored in AWS Secrets Manager. AWS Bedrock uses your AWS credentials.
        </p>

        <div className="space-y-4">
          {PROVIDERS.filter(p => p.requiresKey).map(provider => (
            <div key={provider.id} className="border border-mono-200 dark:border-mono-800 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <span className="font-medium text-mono-900 dark:text-mono-100">
                    {provider.name}
                  </span>
                  {hasApiKeys[provider.id] && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950">
                      <Key className="w-3 h-3 mr-1" />
                      Configured
                    </span>
                  )}
                </div>
                <button
                  onClick={() => handleTestConnection(provider.id)}
                  disabled={!hasApiKeys[provider.id] || testing[provider.id]}
                  className="btn-secondary text-sm flex items-center space-x-1"
                >
                  {testing[provider.id] ? (
                    <>
                      <Loader className="w-4 h-4 animate-spin" />
                      <span>Testing...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4" />
                      <span>Test</span>
                    </>
                  )}
                </button>
              </div>

              <div className="mb-2">
                <input
                  type="password"
                  value={apiKeys[provider.id]}
                  onChange={(e) => setApiKeys({ ...apiKeys, [provider.id]: e.target.value })}
                  placeholder={hasApiKeys[provider.id] ? '••••••••••••••••' : `Enter ${provider.name} API key`}
                  className="input text-sm font-mono"
                />
              </div>

              {testResults[provider.id] && (
                <div className={`mt-2 p-2 rounded text-xs border ${
                  testResults[provider.id].success
                    ? 'bg-mono-100 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                    : 'bg-mono-150 dark:bg-mono-850 border-mono-300 dark:border-mono-700'
                }`}>
                  <div className="flex items-center space-x-2">
                    {testResults[provider.id].success ? (
                      <>
                        <Check className="w-4 h-4 text-mono-900 dark:text-mono-100" />
                        <span className="text-mono-900 dark:text-mono-100">
                          Connection successful ({testResults[provider.id].latency_ms}ms)
                        </span>
                      </>
                    ) : (
                      <>
                        <X className="w-4 h-4 text-mono-700 dark:text-mono-300" />
                        <span className="text-mono-700 dark:text-mono-300">
                          {testResults[provider.id].error}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Model Selection
        </h3>

        <div className="space-y-4">
          <div>
            <label className="label">Query Generation Model</label>
            <select
              value={preferences.queryModel}
              onChange={(e) => setPreferences({ ...preferences, queryModel: e.target.value })}
              className="input"
            >
              {getProviderModels(preferences.defaultProvider).map(model => (
                <option key={model.id} value={model.id}>
                  {model.name} - ${model.pricing.input}/${model.pricing.output} per 1M tokens
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="label">Detection Rule Model</label>
            <select
              value={preferences.detectionModel}
              onChange={(e) => setPreferences({ ...preferences, detectionModel: e.target.value })}
              className="input"
            >
              {getProviderModels(preferences.defaultProvider).map(model => (
                <option key={model.id} value={model.id}>
                  {model.name} - ${model.pricing.input}/${model.pricing.output} per 1M tokens
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 p-3 bg-mono-50 dark:bg-mono-850 rounded-lg border border-mono-200 dark:border-mono-800">
          <div className="text-xs text-mono-600 dark:text-mono-400 mb-2">Estimated Cost (1M input + 1M output tokens)</div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-xs text-mono-500 dark:text-mono-500">Query Model</div>
              <div className="text-lg font-bold text-mono-950 dark:text-mono-50">
                ${(() => {
                  const pricing = getModelPricing(preferences.defaultProvider, preferences.queryModel);
                  return pricing ? (pricing.input + pricing.output).toFixed(2) : '0.00';
                })()}
              </div>
            </div>
            <div>
              <div className="text-xs text-mono-500 dark:text-mono-500">Detection Model</div>
              <div className="text-lg font-bold text-mono-950 dark:text-mono-50">
                ${(() => {
                  const pricing = getModelPricing(preferences.defaultProvider, preferences.detectionModel);
                  return pricing ? (pricing.input + pricing.output).toFixed(2) : '0.00';
                })()}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-4">
          Advanced Settings
        </h3>

        <div className="space-y-4">
          <div>
            <label className="label">Max Tokens</label>
            <input
              type="number"
              value={preferences.maxTokens}
              onChange={(e) => setPreferences({ ...preferences, maxTokens: parseInt(e.target.value) })}
              min="100"
              max="8000"
              step="100"
              className="input"
            />
            <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
              Maximum tokens for LLM responses (100-8000)
            </p>
          </div>

          <div>
            <label className="label">Temperature</label>
            <input
              type="number"
              value={preferences.temperature}
              onChange={(e) => setPreferences({ ...preferences, temperature: parseFloat(e.target.value) })}
              min="0"
              max="1"
              step="0.1"
              className="input"
            />
            <p className="text-xs text-mono-600 dark:text-mono-400 mt-1">
              Randomness of responses (0 = deterministic, 1 = creative)
            </p>
          </div>

          <div className="space-y-2">
            <label className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={preferences.enableCaching}
                onChange={(e) => setPreferences({ ...preferences, enableCaching: e.target.checked })}
                className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
              />
              <span className="text-sm text-mono-900 dark:text-mono-100">Enable prompt caching</span>
            </label>
            <label className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={preferences.trackUsage}
                onChange={(e) => setPreferences({ ...preferences, trackUsage: e.target.checked })}
                className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
              />
              <span className="text-sm text-mono-900 dark:text-mono-100">Track LLM usage and costs</span>
            </label>
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleSaveSettings}
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
              <span>Save Settings</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
