import { useState } from 'react';
import { Settings as SettingsIcon, Bot, Bell, User, Shield } from 'lucide-react';
import LLMConfiguration from '../components/Settings/LLMConfiguration';
import IntegrationSettings from '../components/Settings/IntegrationSettings';

const SETTINGS_TABS = [
  { id: 'llm', label: 'LLM Configuration', icon: Bot },
  { id: 'integrations', label: 'Alert Integrations', icon: Bell },
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'security', label: 'Security', icon: Shield }
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState('llm');
  const userId = 'user-123'; // In production, get from auth context

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-mono-900 dark:bg-mono-100 rounded-lg">
          <SettingsIcon className="w-6 h-6 text-mono-50 dark:text-mono-950" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-mono-950 dark:text-mono-50">
            Settings
          </h1>
          <p className="text-sm text-mono-600 dark:text-mono-400">
            Configure your Mantissa Log instance
          </p>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="border-b border-mono-200 dark:border-mono-800">
        <nav className="flex space-x-1">
          {SETTINGS_TABS.map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-mono-900 dark:border-mono-100 text-mono-900 dark:text-mono-100'
                    : 'border-transparent text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="pb-8">
        {activeTab === 'llm' && <LLMConfiguration userId={userId} />}
        {activeTab === 'integrations' && <IntegrationSettings userId={userId} />}
        {activeTab === 'profile' && <ProfileSettings userId={userId} />}
        {activeTab === 'security' && <SecuritySettings userId={userId} />}
      </div>
    </div>
  );
}

// Placeholder components for future implementation
function ProfileSettings({ userId }) {
  return (
    <div className="card">
      <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-4">
        Profile Settings
      </h2>
      <p className="text-sm text-mono-600 dark:text-mono-400">
        User profile configuration (coming soon)
      </p>
    </div>
  );
}

function SecuritySettings({ userId }) {
  return (
    <div className="card">
      <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-4">
        Security Settings
      </h2>
      <p className="text-sm text-mono-600 dark:text-mono-400">
        Authentication and access control (coming soon)
      </p>
    </div>
  );
}
