import { useState, useEffect } from 'react';
import { Key, Check, X, AlertCircle, Loader, Eye, EyeOff } from 'lucide-react';

export default function LLMSettings({ userId }) {
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingProvider, setTestingProvider] = useState(null);
  const [testResults, setTestResults] = useState({});
  const [showKeys, setShowKeys] = useState({});
  const [error, setError] = useState(null);

  // Available providers and their models (from backend registry)
  const providers = {
    anthropic: {
      name: 'Anthropic API',
      models: [
        {
          id: 'claude-3-5-sonnet-20241022',
          name: 'Claude 3.5 Sonnet',
          inputCost: 3.0,
          outputCost: 15.0,
          description: 'Best balance - recommended for all tasks'
        },
        {
          id: 'claude-3-opus-20240229',
          name: 'Claude 3 Opus',
          inputCost: 15.0,
          outputCost: 75.0,
          description: 'Highest quality'
        },
        {
          id: 'claude-3-haiku-20240307',
          name: 'Claude 3 Haiku',
          inputCost: 0.25,
          outputCost: 1.25,
          description: 'Fastest, most cost-effective'
        },
        {
          id: 'claude-3-5-haiku-20241022',
          name: 'Claude 3.5 Haiku',
          inputCost: 1.0,
          outputCost: 5.0,
          description: 'New fast model'
        }
      ]
    },
    openai: {
      name: 'OpenAI API',
      models: [
        {
          id: 'gpt-4-turbo-preview',
          name: 'GPT-4 Turbo',
          inputCost: 10.0,
          outputCost: 30.0,
          description: 'Latest GPT-4 model'
        },
        {
          id: 'gpt-4',
          name: 'GPT-4',
          inputCost: 30.0,
          outputCost: 60.0,
          description: 'Original GPT-4'
        },
        {
          id: 'gpt-3.5-turbo',
          name: 'GPT-3.5 Turbo',
          inputCost: 0.5,
          outputCost: 1.5,
          description: 'Fast and cost-effective'
        }
      ]
    },
    google: {
      name: 'Google Gemini API',
      models: [
        {
          id: 'gemini-1.5-pro',
          name: 'Gemini 1.5 Pro',
          inputCost: 3.5,
          outputCost: 10.5,
          description: 'Most capable Gemini model'
        },
        {
          id: 'gemini-1.5-flash',
          name: 'Gemini 1.5 Flash',
          inputCost: 0.35,
          outputCost: 1.05,
          description: 'Fast and efficient'
        },
        {
          id: 'gemini-pro',
          name: 'Gemini Pro',
          inputCost: 0.5,
          outputCost: 1.5,
          description: 'Original Gemini Pro'
        }
      ]
    },
    bedrock: {
      name: 'AWS Bedrock',
      models: [
        {
          id: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
          name: 'Claude 3.5 Sonnet',
          inputCost: 3.0,
          outputCost: 15.0,
          description: 'Best balance - recommended'
        },
        {
          id: 'anthropic.claude-3-opus-20240229-v1:0',
          name: 'Claude 3 Opus',
          inputCost: 15.0,
          outputCost: 75.0,
          description: 'Highest quality'
        },
        {
          id: 'anthropic.claude-3-haiku-20240307-v1:0',
          name: 'Claude 3 Haiku',
          inputCost: 0.25,
          outputCost: 1.25,
          description: 'Fastest, cheapest'
        }
      ]
    }
  };

  const awsRegions = [
    'us-east-1',
    'us-west-2',
    'eu-west-1',
    'eu-central-1',
    'ap-northeast-1',
    'ap-southeast-1'
  ];

  useEffect(() => {
    loadSettings();
  }, [userId]);

  const loadSettings = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/llm/settings?user_id=${userId}`);

      if (!response.ok) {
        throw new Error('Failed to load settings');
      }

      const data = await response.json();
      setSettings(data.settings || getDefaultSettings());
    } catch (err) {
      console.error('Error loading LLM settings:', err);
      setError('Failed to load settings');
      setSettings(getDefaultSettings());
    } finally {
      setLoading(false);
    }
  };

  const getDefaultSettings = () => ({
    providers: {
      anthropic: { enabled: false, apiKey: '', model: 'claude-3-5-sonnet-20241022' },
      openai: { enabled: false, apiKey: '', model: 'gpt-4-turbo-preview' },
      google: { enabled: false, apiKey: '', model: 'gemini-1.5-pro' },
      bedrock: { enabled: false, region: 'us-east-1', model: 'anthropic.claude-3-5-sonnet-20241022-v2:0' }
    },
    preferences: {
      queryModel: 'claude-3-5-sonnet-20241022',
      detectionModel: 'claude-3-5-sonnet-20241022',
      maxTokens: 2000,
      temperature: 0.0
    }
  });

  const handleProviderToggle = (provider) => {
    setSettings(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          enabled: !prev.providers[provider].enabled
        }
      }
    }));
  };

  const handleApiKeyChange = (provider, value) => {
    setSettings(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          apiKey: value
        }
      }
    }));
  };

  const handleModelChange = (provider, value) => {
    setSettings(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          model: value
        }
      }
    }));
  };

  const handleRegionChange = (provider, value) => {
    setSettings(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          region: value
        }
      }
    }));
  };

  const handlePreferenceChange = (key, value) => {
    setSettings(prev => ({
      ...prev,
      preferences: {
        ...prev.preferences,
        [key]: value
      }
    }));
  };

  const testConnection = async (provider) => {
    setTestingProvider(provider);
    setTestResults(prev => ({ ...prev, [provider]: null }));

    try {
      const response = await fetch('/api/llm/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          provider: provider,
          api_key: settings.providers[provider].apiKey,
          model: settings.providers[provider].model,
          region: settings.providers[provider].region
        })
      });

      const data = await response.json();

      setTestResults(prev => ({
        ...prev,
        [provider]: {
          success: data.success,
          message: data.message || (data.success ? 'Connection successful' : 'Connection failed'),
          error: data.error
        }
      }));
    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [provider]: {
          success: false,
          message: 'Test failed',
          error: err.message
        }
      }));
    } finally {
      setTestingProvider(null);
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    setError(null);

    try {
      const response = await fetch('/api/llm/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          settings: settings
        })
      });

      if (!response.ok) {
        throw new Error('Failed to save settings');
      }

      // Show success feedback (could add a toast notification here)
      console.log('Settings saved successfully');
    } catch (err) {
      console.error('Error saving settings:', err);
      setError('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const toggleKeyVisibility = (provider) => {
    setShowKeys(prev => ({ ...prev, [provider]: !prev[provider] }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader className="w-6 h-6 animate-spin text-mono-600 dark:text-mono-400" />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center mb-2">
          <Key className="w-6 h-6 mr-2 text-mono-900 dark:text-mono-100" />
          <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
            LLM Configuration
          </h1>
        </div>
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Configure your LLM providers and API keys. All API keys are stored securely in AWS Secrets Manager.
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

      {/* Provider Configurations */}
      <div className="space-y-6 mb-8">
        {/* AWS Bedrock */}
        <ProviderSection
          title={providers.bedrock.name}
          subtitle="Uses IAM role, no API key needed"
          enabled={settings.providers.bedrock.enabled}
          onToggle={() => handleProviderToggle('bedrock')}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Region
              </label>
              <select
                value={settings.providers.bedrock.region}
                onChange={(e) => handleRegionChange('bedrock', e.target.value)}
                disabled={!settings.providers.bedrock.enabled}
                className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 disabled:opacity-50"
              >
                {awsRegions.map(region => (
                  <option key={region} value={region}>{region}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Model
              </label>
              <ModelSelect
                provider="bedrock"
                models={providers.bedrock.models}
                value={settings.providers.bedrock.model}
                onChange={(value) => handleModelChange('bedrock', value)}
                disabled={!settings.providers.bedrock.enabled}
              />
            </div>

            <button
              onClick={() => testConnection('bedrock')}
              disabled={!settings.providers.bedrock.enabled || testingProvider === 'bedrock'}
              className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
            >
              {testingProvider === 'bedrock' ? (
                <>
                  <Loader className="w-4 h-4 mr-2 animate-spin" />
                  Testing...
                </>
              ) : (
                'Test Connection'
              )}
            </button>

            {testResults.bedrock && (
              <TestResult result={testResults.bedrock} />
            )}
          </div>
        </ProviderSection>

        {/* Anthropic */}
        <ProviderSection
          title={providers.anthropic.name}
          enabled={settings.providers.anthropic.enabled}
          onToggle={() => handleProviderToggle('anthropic')}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                API Key
              </label>
              <div className="flex">
                <input
                  type={showKeys.anthropic ? 'text' : 'password'}
                  value={settings.providers.anthropic.apiKey}
                  onChange={(e) => handleApiKeyChange('anthropic', e.target.value)}
                  disabled={!settings.providers.anthropic.enabled}
                  placeholder="sk-ant-..."
                  className="flex-1 px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-l text-mono-900 dark:text-mono-50 placeholder-mono-500 disabled:opacity-50 font-mono text-sm"
                />
                <button
                  onClick={() => toggleKeyVisibility('anthropic')}
                  disabled={!settings.providers.anthropic.enabled}
                  className="px-3 py-2 bg-mono-100 dark:bg-mono-850 border border-l-0 border-mono-300 dark:border-mono-700 rounded-r hover:bg-mono-200 dark:hover:bg-mono-800 disabled:opacity-50"
                >
                  {showKeys.anthropic ? (
                    <EyeOff className="w-4 h-4 text-mono-600 dark:text-mono-400" />
                  ) : (
                    <Eye className="w-4 h-4 text-mono-600 dark:text-mono-400" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Model
              </label>
              <ModelSelect
                provider="anthropic"
                models={providers.anthropic.models}
                value={settings.providers.anthropic.model}
                onChange={(value) => handleModelChange('anthropic', value)}
                disabled={!settings.providers.anthropic.enabled}
              />
            </div>

            <button
              onClick={() => testConnection('anthropic')}
              disabled={!settings.providers.anthropic.enabled || !settings.providers.anthropic.apiKey || testingProvider === 'anthropic'}
              className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
            >
              {testingProvider === 'anthropic' ? (
                <>
                  <Loader className="w-4 h-4 mr-2 animate-spin" />
                  Testing...
                </>
              ) : (
                'Test Connection'
              )}
            </button>

            {testResults.anthropic && (
              <TestResult result={testResults.anthropic} />
            )}
          </div>
        </ProviderSection>

        {/* OpenAI */}
        <ProviderSection
          title={providers.openai.name}
          enabled={settings.providers.openai.enabled}
          onToggle={() => handleProviderToggle('openai')}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                API Key
              </label>
              <div className="flex">
                <input
                  type={showKeys.openai ? 'text' : 'password'}
                  value={settings.providers.openai.apiKey}
                  onChange={(e) => handleApiKeyChange('openai', e.target.value)}
                  disabled={!settings.providers.openai.enabled}
                  placeholder="sk-..."
                  className="flex-1 px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-l text-mono-900 dark:text-mono-50 placeholder-mono-500 disabled:opacity-50 font-mono text-sm"
                />
                <button
                  onClick={() => toggleKeyVisibility('openai')}
                  disabled={!settings.providers.openai.enabled}
                  className="px-3 py-2 bg-mono-100 dark:bg-mono-850 border border-l-0 border-mono-300 dark:border-mono-700 rounded-r hover:bg-mono-200 dark:hover:bg-mono-800 disabled:opacity-50"
                >
                  {showKeys.openai ? (
                    <EyeOff className="w-4 h-4 text-mono-600 dark:text-mono-400" />
                  ) : (
                    <Eye className="w-4 h-4 text-mono-600 dark:text-mono-400" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Model
              </label>
              <ModelSelect
                provider="openai"
                models={providers.openai.models}
                value={settings.providers.openai.model}
                onChange={(value) => handleModelChange('openai', value)}
                disabled={!settings.providers.openai.enabled}
              />
            </div>

            <button
              onClick={() => testConnection('openai')}
              disabled={!settings.providers.openai.enabled || !settings.providers.openai.apiKey || testingProvider === 'openai'}
              className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
            >
              {testingProvider === 'openai' ? (
                <>
                  <Loader className="w-4 h-4 mr-2 animate-spin" />
                  Testing...
                </>
              ) : (
                'Test Connection'
              )}
            </button>

            {testResults.openai && (
              <TestResult result={testResults.openai} />
            )}
          </div>
        </ProviderSection>

        {/* Google Gemini */}
        <ProviderSection
          title={providers.google.name}
          enabled={settings.providers.google.enabled}
          onToggle={() => handleProviderToggle('google')}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                API Key
              </label>
              <div className="flex">
                <input
                  type={showKeys.google ? 'text' : 'password'}
                  value={settings.providers.google.apiKey}
                  onChange={(e) => handleApiKeyChange('google', e.target.value)}
                  disabled={!settings.providers.google.enabled}
                  placeholder="AIza..."
                  className="flex-1 px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-l text-mono-900 dark:text-mono-50 placeholder-mono-500 disabled:opacity-50 font-mono text-sm"
                />
                <button
                  onClick={() => toggleKeyVisibility('google')}
                  disabled={!settings.providers.google.enabled}
                  className="px-3 py-2 bg-mono-100 dark:bg-mono-850 border border-l-0 border-mono-300 dark:border-mono-700 rounded-r hover:bg-mono-200 dark:hover:bg-mono-800 disabled:opacity-50"
                >
                  {showKeys.google ? (
                    <EyeOff className="w-4 h-4 text-mono-600 dark:text-mono-400" />
                  ) : (
                    <Eye className="w-4 h-4 text-mono-600 dark:text-mono-400" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Model
              </label>
              <ModelSelect
                provider="google"
                models={providers.google.models}
                value={settings.providers.google.model}
                onChange={(value) => handleModelChange('google', value)}
                disabled={!settings.providers.google.enabled}
              />
            </div>

            <button
              onClick={() => testConnection('google')}
              disabled={!settings.providers.google.enabled || !settings.providers.google.apiKey || testingProvider === 'google'}
              className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
            >
              {testingProvider === 'google' ? (
                <>
                  <Loader className="w-4 h-4 mr-2 animate-spin" />
                  Testing...
                </>
              ) : (
                'Test Connection'
              )}
            </button>

            {testResults.google && (
              <TestResult result={testResults.google} />
            )}
          </div>
        </ProviderSection>
      </div>

      {/* Usage Preferences */}
      <div className="bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded-lg p-6 mb-6">
        <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
          Usage Preferences
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Query Generation Model
            </label>
            <p className="text-xs text-mono-600 dark:text-mono-400 mb-2">
              Model used for converting natural language to SQL
            </p>
            <input
              type="text"
              value={settings.preferences.queryModel}
              onChange={(e) => handlePreferenceChange('queryModel', e.target.value)}
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 font-mono text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
              Detection Engineering Model
            </label>
            <p className="text-xs text-mono-600 dark:text-mono-400 mb-2">
              Model used for creating detection rules
            </p>
            <input
              type="text"
              value={settings.preferences.detectionModel}
              onChange={(e) => handlePreferenceChange('detectionModel', e.target.value)}
              className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 font-mono text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Max Tokens per Request
              </label>
              <input
                type="number"
                value={settings.preferences.maxTokens}
                onChange={(e) => handlePreferenceChange('maxTokens', parseInt(e.target.value))}
                min="100"
                max="8192"
                className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Temperature (0-1)
              </label>
              <p className="text-xs text-mono-600 dark:text-mono-400 mb-1">
                0 = deterministic
              </p>
              <input
                type="number"
                value={settings.preferences.temperature}
                onChange={(e) => handlePreferenceChange('temperature', parseFloat(e.target.value))}
                min="0"
                max="1"
                step="0.1"
                className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={saveSettings}
          disabled={saving}
          className="px-6 py-3 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed font-semibold flex items-center"
        >
          {saving ? (
            <>
              <Loader className="w-5 h-5 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            'Save Configuration'
          )}
        </button>
      </div>
    </div>
  );
}

function ProviderSection({ title, subtitle, enabled, onToggle, children }) {
  return (
    <div className="bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
            {title}
          </h3>
          {subtitle && (
            <p className="text-sm text-mono-600 dark:text-mono-400 mt-1">
              {subtitle}
            </p>
          )}
        </div>

        <button
          onClick={onToggle}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
            enabled
              ? 'bg-mono-900 dark:bg-mono-100'
              : 'bg-mono-300 dark:bg-mono-700'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full transition-transform ${
              enabled
                ? 'translate-x-6 bg-mono-50 dark:bg-mono-950'
                : 'translate-x-1 bg-mono-50 dark:bg-mono-950'
            }`}
          />
        </button>
      </div>

      {enabled && <div className="pt-4 border-t border-mono-200 dark:border-mono-800">{children}</div>}
    </div>
  );
}

function ModelSelect({ provider, models, value, onChange, disabled }) {
  return (
    <div className="space-y-2">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 disabled:opacity-50"
      >
        {models.map(model => (
          <option key={model.id} value={model.id}>
            {model.name}
          </option>
        ))}
      </select>

      {/* Show details for selected model */}
      {models.find(m => m.id === value) && (
        <div className="text-xs space-y-1">
          <p className="text-mono-700 dark:text-mono-300">
            {models.find(m => m.id === value).description}
          </p>
          <p className="text-mono-600 dark:text-mono-400">
            Cost: ${models.find(m => m.id === value).inputCost} per 1M input tokens,
            ${models.find(m => m.id === value).outputCost} per 1M output tokens
          </p>
        </div>
      )}
    </div>
  );
}

function TestResult({ result }) {
  return (
    <div className={`p-3 rounded flex items-start ${
      result.success
        ? 'bg-mono-100 dark:bg-mono-850 border border-mono-300 dark:border-mono-700'
        : 'bg-mono-100 dark:bg-mono-850 border border-mono-400 dark:border-mono-600'
    }`}>
      {result.success ? (
        <Check className="w-5 h-5 mr-2 text-mono-900 dark:text-mono-100 flex-shrink-0" />
      ) : (
        <X className="w-5 h-5 mr-2 text-mono-900 dark:text-mono-100 flex-shrink-0" />
      )}
      <div>
        <p className="font-semibold text-mono-900 dark:text-mono-100">
          {result.success ? 'Connection Successful' : 'Connection Failed'}
        </p>
        <p className="text-sm text-mono-700 dark:text-mono-300">{result.message}</p>
        {result.error && (
          <p className="text-xs text-mono-600 dark:text-mono-400 mt-1 font-mono">
            {result.error}
          </p>
        )}
      </div>
    </div>
  );
}
