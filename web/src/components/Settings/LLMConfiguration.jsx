import { useState, useEffect } from 'react';
import { Bot, Key, TestTube2, DollarSign, Check, AlertTriangle, Loader2, Eye, EyeOff } from 'lucide-react';

const LLM_PROVIDERS = {
  anthropic: {
    name: 'Anthropic (Claude)',
    models: [
      { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', inputCost: 3, outputCost: 15, recommended: true },
      { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', inputCost: 15, outputCost: 75 },
      { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku', inputCost: 0.25, outputCost: 1.25 },
      { id: 'claude-3-5-haiku-20241022', name: 'Claude 3.5 Haiku', inputCost: 1, outputCost: 5 }
    ],
    requiresKey: true
  },
  openai: {
    name: 'OpenAI',
    models: [
      { id: 'gpt-4-turbo-preview', name: 'GPT-4 Turbo', inputCost: 10, outputCost: 30, recommended: true },
      { id: 'gpt-4', name: 'GPT-4', inputCost: 30, outputCost: 60 },
      { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', inputCost: 0.5, outputCost: 1.5 }
    ],
    requiresKey: true
  },
  google: {
    name: 'Google (Gemini)',
    models: [
      { id: 'gemini-1.5-pro', name: 'Gemini 1.5 Pro', inputCost: 3.5, outputCost: 10.5, recommended: true },
      { id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', inputCost: 0.35, outputCost: 1.05 },
      { id: 'gemini-pro', name: 'Gemini Pro', inputCost: 0.5, outputCost: 1.5 }
    ],
    requiresKey: true
  },
  bedrock: {
    name: 'AWS Bedrock',
    models: [
      { id: 'anthropic.claude-3-5-sonnet-20241022-v2:0', name: 'Claude 3.5 Sonnet', inputCost: 3, outputCost: 15, recommended: true },
      { id: 'anthropic.claude-3-opus-20240229-v1:0', name: 'Claude 3 Opus', inputCost: 15, outputCost: 75 },
      { id: 'anthropic.claude-3-haiku-20240307-v1:0', name: 'Claude 3 Haiku', inputCost: 0.25, outputCost: 1.25 }
    ],
    requiresKey: false,
    requiresRegion: true,
    regions: ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
  }
};

const USE_CASES = {
  query_generation: {
    label: 'Query Generation',
    description: 'Natural language to SQL conversion',
    recommendedProvider: 'anthropic',
    recommendedModel: 'claude-3-5-sonnet-20241022'
  },
  detection_engineering: {
    label: 'Detection Engineering',
    description: 'Security context understanding and rule creation',
    recommendedProvider: 'anthropic',
    recommendedModel: 'claude-3-5-sonnet-20241022'
  }
};

export default function LLMConfiguration({ userId }) {
  const [config, setConfig] = useState({
    providers: {},
    useCases: {},
    preferences: {
      maxTokens: 2000,
      temperature: 0.0
    }
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingProvider, setTestingProvider] = useState(null);
  const [testResults, setTestResults] = useState({});
  const [showApiKeys, setShowApiKeys] = useState({});
  const [error, setError] = useState(null);

  useEffect(() => {
    loadConfiguration();
  }, [userId]);

  const loadConfiguration = async () => {
    try {
      const response = await fetch(`/api/settings/llm?user_id=${userId}`);
      if (!response.ok) throw new Error('Failed to load LLM configuration');

      const data = await response.json();
      if (data.config) {
        setConfig(data.config);
      }
    } catch (err) {
      console.error('Error loading LLM configuration:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleProviderToggle = (provider) => {
    setConfig(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          enabled: !prev.providers[provider]?.enabled
        }
      }
    }));
  };

  const handleApiKeyChange = (provider, value) => {
    setConfig(prev => ({
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

  const handleModelChange = (provider, modelId) => {
    setConfig(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          selectedModel: modelId
        }
      }
    }));
  };

  const handleRegionChange = (provider, region) => {
    setConfig(prev => ({
      ...prev,
      providers: {
        ...prev.providers,
        [provider]: {
          ...prev.providers[provider],
          region: region
        }
      }
    }));
  };

  const handleUseCaseChange = (useCase, providerId, modelId) => {
    setConfig(prev => ({
      ...prev,
      useCases: {
        ...prev.useCases,
        [useCase]: { provider: providerId, model: modelId }
      }
    }));
  };

  const testConnection = async (provider) => {
    setTestingProvider(provider);
    setTestResults(prev => ({ ...prev, [provider]: null }));

    try {
      const providerConfig = config.providers[provider];

      const response = await fetch('/api/settings/llm/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          provider: provider,
          model: providerConfig?.selectedModel,
          api_key: providerConfig?.apiKey,
          region: providerConfig?.region
        })
      });

      const data = await response.json();

      if (response.ok) {
        setTestResults(prev => ({
          ...prev,
          [provider]: { success: true, message: data.message || 'Connection successful' }
        }));
      } else {
        setTestResults(prev => ({
          ...prev,
          [provider]: { success: false, message: data.error || 'Connection failed' }
        }));
      }
    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [provider]: { success: false, message: err.message }
      }));
    } finally {
      setTestingProvider(null);
    }
  };

  const saveConfiguration = async () => {
    setSaving(true);
    setError(null);

    try {
      const response = await fetch('/api/settings/llm', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          config: config
        })
      });

      if (!response.ok) throw new Error('Failed to save configuration');

      const data = await response.json();
      alert('LLM configuration saved successfully!');
    } catch (err) {
      setError(err.message);
      console.error('Error saving LLM configuration:', err);
    } finally {
      setSaving(false);
    }
  };

  const toggleShowApiKey = (provider) => {
    setShowApiKeys(prev => ({
      ...prev,
      [provider]: !prev[provider]
    }));
  };

  const getSelectedModel = (provider) => {
    const selectedModelId = config.providers[provider]?.selectedModel;
    return LLM_PROVIDERS[provider].models.find(m => m.id === selectedModelId) ||
           LLM_PROVIDERS[provider].models.find(m => m.recommended);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="w-8 h-8 animate-spin text-mono-600 dark:text-mono-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-2">
          LLM Configuration
        </h2>
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Configure Large Language Model providers for natural language query generation and detection engineering.
        </p>
      </div>

      {error && (
        <div className="p-4 bg-mono-100 dark:bg-mono-850 border border-mono-400 dark:border-mono-600 rounded-lg">
          <p className="text-sm text-mono-900 dark:text-mono-100">{error}</p>
        </div>
      )}

      {/* Provider Configurations */}
      <div className="space-y-4">
        {Object.entries(LLM_PROVIDERS).map(([providerId, providerInfo]) => {
          const providerConfig = config.providers[providerId] || {};
          const selectedModel = getSelectedModel(providerId);
          const testResult = testResults[providerId];

          return (
            <div key={providerId} className="card">
              {/* Provider Header */}
              <div className="flex items-center justify-between mb-4">
                <label className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={providerConfig.enabled || false}
                    onChange={() => handleProviderToggle(providerId)}
                    className="w-4 h-4 rounded border-mono-300 dark:border-mono-700"
                  />
                  <div>
                    <div className="font-semibold text-mono-950 dark:text-mono-50">
                      {providerInfo.name}
                    </div>
                    {providerConfig.enabled && selectedModel && (
                      <div className="text-xs text-mono-600 dark:text-mono-400 mt-0.5">
                        ${selectedModel.inputCost} / 1M input tokens, ${selectedModel.outputCost} / 1M output tokens
                      </div>
                    )}
                  </div>
                </label>
                {providerConfig.enabled && (
                  <button
                    onClick={() => testConnection(providerId)}
                    disabled={testingProvider === providerId}
                    className="btn-secondary text-sm"
                  >
                    {testingProvider === providerId ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <TestTube2 className="w-4 h-4 mr-2" />
                    )}
                    Test Connection
                  </button>
                )}
              </div>

              {/* Provider Configuration */}
              {providerConfig.enabled && (
                <div className="space-y-3 pl-7">
                  {/* API Key Input */}
                  {providerInfo.requiresKey && (
                    <div>
                      <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                        API Key
                      </label>
                      <div className="relative">
                        <input
                          type={showApiKeys[providerId] ? 'text' : 'password'}
                          value={providerConfig.apiKey || ''}
                          onChange={(e) => handleApiKeyChange(providerId, e.target.value)}
                          placeholder="Enter API key"
                          className="input pr-10"
                        />
                        <button
                          type="button"
                          onClick={() => toggleShowApiKey(providerId)}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
                        >
                          {showApiKeys[providerId] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Region Selection (for Bedrock) */}
                  {providerInfo.requiresRegion && (
                    <div>
                      <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                        AWS Region
                      </label>
                      <select
                        value={providerConfig.region || providerInfo.regions[0]}
                        onChange={(e) => handleRegionChange(providerId, e.target.value)}
                        className="input"
                      >
                        {providerInfo.regions.map(region => (
                          <option key={region} value={region}>{region}</option>
                        ))}
                      </select>
                    </div>
                  )}

                  {/* Model Selection */}
                  <div>
                    <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                      Model
                    </label>
                    <select
                      value={providerConfig.selectedModel || providerInfo.models.find(m => m.recommended)?.id}
                      onChange={(e) => handleModelChange(providerId, e.target.value)}
                      className="input"
                    >
                      {providerInfo.models.map(model => (
                        <option key={model.id} value={model.id}>
                          {model.name} {model.recommended ? '(Recommended)' : ''}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Test Result */}
                  {testResult && (
                    <div className={`p-3 rounded-lg border text-sm ${
                      testResult.success
                        ? 'bg-mono-50 dark:bg-mono-900 border-mono-300 dark:border-mono-700'
                        : 'bg-mono-100 dark:bg-mono-850 border-mono-400 dark:border-mono-600'
                    }`}>
                      <div className="flex items-start space-x-2">
                        {testResult.success ? (
                          <Check className="w-4 h-4 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
                        )}
                        <p className={testResult.success
                          ? 'text-mono-700 dark:text-mono-300'
                          : 'text-mono-900 dark:text-mono-100'
                        }>
                          {testResult.message}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Usage Preferences */}
      <div className="card">
        <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
          Usage Preferences
        </h3>
        <div className="space-y-4">
          {Object.entries(USE_CASES).map(([useCaseId, useCase]) => {
            const selectedConfig = config.useCases[useCaseId];
            const enabledProviders = Object.entries(config.providers)
              .filter(([_, cfg]) => cfg.enabled)
              .map(([id]) => id);

            return (
              <div key={useCaseId}>
                <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                  {useCase.label}
                </label>
                <div className="text-xs text-mono-600 dark:text-mono-400 mb-2">
                  {useCase.description}
                </div>
                <select
                  value={selectedConfig ? `${selectedConfig.provider}:${selectedConfig.model}` : ''}
                  onChange={(e) => {
                    const [provider, model] = e.target.value.split(':');
                    handleUseCaseChange(useCaseId, provider, model);
                  }}
                  className="input"
                  disabled={enabledProviders.length === 0}
                >
                  <option value="">Select model...</option>
                  {enabledProviders.map(providerId => {
                    const provider = LLM_PROVIDERS[providerId];
                    return provider.models.map(model => (
                      <option key={`${providerId}:${model.id}`} value={`${providerId}:${model.id}`}>
                        {provider.name} - {model.name}
                      </option>
                    ));
                  })}
                </select>
              </div>
            );
          })}

          <div className="grid grid-cols-2 gap-4 pt-2">
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Max Tokens per Request
              </label>
              <input
                type="number"
                value={config.preferences.maxTokens}
                onChange={(e) => setConfig(prev => ({
                  ...prev,
                  preferences: { ...prev.preferences, maxTokens: parseInt(e.target.value) }
                }))}
                min="100"
                max="8000"
                step="100"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-mono-900 dark:text-mono-100 mb-1">
                Temperature (0-1)
              </label>
              <input
                type="number"
                value={config.preferences.temperature}
                onChange={(e) => setConfig(prev => ({
                  ...prev,
                  preferences: { ...prev.preferences, temperature: parseFloat(e.target.value) }
                }))}
                min="0"
                max="1"
                step="0.1"
                className="input"
              />
              <div className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                0 = deterministic, 1 = creative
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={saveConfiguration}
          disabled={saving}
          className="btn-primary"
        >
          {saving ? (
            <>
              <Loader2 className="w-5 h-5 mr-2 animate-spin" />
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
