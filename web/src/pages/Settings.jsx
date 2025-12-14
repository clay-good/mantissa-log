import { useState } from 'react';
import { Settings as SettingsIcon, Bot, Bell, User, Shield, Mail, Key, Smartphone, Clock, LogOut, Trash2, AlertTriangle } from 'lucide-react';
import LLMConfiguration from '../components/Settings/LLMConfiguration';
import IntegrationSettings from '../components/Settings/IntegrationSettings';
import { ConfirmModal } from '../components/common/Modal';
import { useAuthStore } from '../stores/authStore';

const SETTINGS_TABS = [
  { id: 'llm', label: 'LLM Configuration', icon: Bot },
  { id: 'integrations', label: 'Alert Integrations', icon: Bell },
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'security', label: 'Security', icon: Shield }
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState('llm');
  const { user } = useAuthStore();
  const userId = user?.userId || user?.username;

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

// Profile Settings Component
function ProfileSettings({ userId }) {
  const [profile, setProfile] = useState({
    displayName: 'Security Analyst',
    email: 'analyst@example.com',
    timezone: 'America/New_York',
    notifications: {
      email: true,
      slack: true,
      criticalOnly: false
    }
  });
  const [isSaving, setIsSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState(null);

  const handleSave = async () => {
    setIsSaving(true);
    setSaveMessage(null);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));

    setIsSaving(false);
    setSaveMessage({ type: 'success', text: 'Profile updated successfully' });

    // Clear message after 3 seconds
    setTimeout(() => setSaveMessage(null), 3000);
  };

  const timezones = [
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'Europe/London',
    'Europe/Paris',
    'Asia/Tokyo',
    'Asia/Singapore',
    'Australia/Sydney',
    'UTC'
  ];

  return (
    <div className="space-y-6">
      {/* Basic Info */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
            <User className="w-5 h-5 text-mono-600 dark:text-mono-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-mono-950 dark:text-mono-50">
              Profile Information
            </h2>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Your personal account details
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="label">Display Name</label>
            <input
              type="text"
              className="input"
              value={profile.displayName}
              onChange={(e) => setProfile({ ...profile, displayName: e.target.value })}
              placeholder="Your display name"
            />
          </div>

          <div>
            <label className="label">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-mono-400" />
              <input
                type="email"
                className="input pl-10"
                value={profile.email}
                onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                placeholder="your@email.com"
              />
            </div>
          </div>

          <div>
            <label className="label">Timezone</label>
            <div className="relative">
              <Clock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-mono-400" />
              <select
                className="input pl-10 appearance-none cursor-pointer"
                value={profile.timezone}
                onChange={(e) => setProfile({ ...profile, timezone: e.target.value })}
              >
                {timezones.map(tz => (
                  <option key={tz} value={tz}>{tz}</option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Notification Preferences */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
            <Bell className="w-5 h-5 text-mono-600 dark:text-mono-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-mono-950 dark:text-mono-50">
              Notification Preferences
            </h2>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Choose how you want to receive alerts
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="flex items-center justify-between p-4 rounded-lg border border-mono-200 dark:border-mono-800 hover:bg-mono-50 dark:hover:bg-mono-850 cursor-pointer transition-colors">
            <div className="flex items-center space-x-3">
              <Mail className="w-5 h-5 text-mono-500" />
              <div>
                <p className="font-medium text-mono-900 dark:text-mono-100">Email Notifications</p>
                <p className="text-sm text-mono-500">Receive alerts via email</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={profile.notifications.email}
              onChange={(e) => setProfile({
                ...profile,
                notifications: { ...profile.notifications, email: e.target.checked }
              })}
              className="w-5 h-5 rounded border-mono-300 text-mono-900 focus:ring-mono-500"
            />
          </label>

          <label className="flex items-center justify-between p-4 rounded-lg border border-mono-200 dark:border-mono-800 hover:bg-mono-50 dark:hover:bg-mono-850 cursor-pointer transition-colors">
            <div className="flex items-center space-x-3">
              <Bell className="w-5 h-5 text-mono-500" />
              <div>
                <p className="font-medium text-mono-900 dark:text-mono-100">Slack Notifications</p>
                <p className="text-sm text-mono-500">Receive alerts via Slack</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={profile.notifications.slack}
              onChange={(e) => setProfile({
                ...profile,
                notifications: { ...profile.notifications, slack: e.target.checked }
              })}
              className="w-5 h-5 rounded border-mono-300 text-mono-900 focus:ring-mono-500"
            />
          </label>

          <label className="flex items-center justify-between p-4 rounded-lg border border-mono-200 dark:border-mono-800 hover:bg-mono-50 dark:hover:bg-mono-850 cursor-pointer transition-colors">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="w-5 h-5 text-mono-500" />
              <div>
                <p className="font-medium text-mono-900 dark:text-mono-100">Critical Alerts Only</p>
                <p className="text-sm text-mono-500">Only receive high/critical severity alerts</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={profile.notifications.criticalOnly}
              onChange={(e) => setProfile({
                ...profile,
                notifications: { ...profile.notifications, criticalOnly: e.target.checked }
              })}
              className="w-5 h-5 rounded border-mono-300 text-mono-900 focus:ring-mono-500"
            />
          </label>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex items-center justify-between">
        {saveMessage && (
          <div className={`alert-${saveMessage.type === 'success' ? 'success' : 'error'}`}>
            {saveMessage.text}
          </div>
        )}
        <div className="flex-1" />
        <button
          onClick={handleSave}
          disabled={isSaving}
          className="btn-primary"
        >
          {isSaving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  );
}

// Security Settings Component
function SecuritySettings({ userId }) {
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [password, setPassword] = useState({
    current: '',
    new: '',
    confirm: ''
  });
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [sessions] = useState([
    { id: '1', device: 'Chrome on macOS', location: 'New York, USA', lastActive: 'Now', current: true },
    { id: '2', device: 'Safari on iPhone', location: 'New York, USA', lastActive: '2 hours ago', current: false },
    { id: '3', device: 'Firefox on Windows', location: 'Chicago, USA', lastActive: '1 day ago', current: false }
  ]);

  const handlePasswordChange = () => {
    if (password.new !== password.confirm) {
      alert('Passwords do not match');
      return;
    }
    // Handle password change
    alert('Password updated successfully');
    setPassword({ current: '', new: '', confirm: '' });
  };

  const handleRevokeSession = (sessionId) => {
    // Handle session revocation
    alert(`Session ${sessionId} revoked`);
  };

  return (
    <div className="space-y-6">
      {/* Password Section */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
            <Key className="w-5 h-5 text-mono-600 dark:text-mono-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-mono-950 dark:text-mono-50">
              Password
            </h2>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Update your password regularly for better security
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="label">Current Password</label>
            <input
              type="password"
              className="input"
              value={password.current}
              onChange={(e) => setPassword({ ...password, current: e.target.value })}
              placeholder="Enter current password"
            />
          </div>
          <div>
            <label className="label">New Password</label>
            <input
              type="password"
              className="input"
              value={password.new}
              onChange={(e) => setPassword({ ...password, new: e.target.value })}
              placeholder="Enter new password"
            />
          </div>
          <div>
            <label className="label">Confirm New Password</label>
            <input
              type="password"
              className="input"
              value={password.confirm}
              onChange={(e) => setPassword({ ...password, confirm: e.target.value })}
              placeholder="Confirm new password"
            />
          </div>
        </div>

        <div className="mt-4">
          <button
            onClick={handlePasswordChange}
            disabled={!password.current || !password.new || !password.confirm}
            className="btn-primary"
          >
            Update Password
          </button>
        </div>
      </div>

      {/* Two-Factor Authentication */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
              <Smartphone className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-mono-950 dark:text-mono-50">
                Two-Factor Authentication
              </h2>
              <p className="text-sm text-mono-600 dark:text-mono-400">
                Add an extra layer of security to your account
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <span className={`badge ${mfaEnabled ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' : 'badge-default'}`}>
              {mfaEnabled ? 'Enabled' : 'Disabled'}
            </span>
            <button
              onClick={() => setMfaEnabled(!mfaEnabled)}
              className={mfaEnabled ? 'btn-secondary' : 'btn-primary'}
            >
              {mfaEnabled ? 'Disable 2FA' : 'Enable 2FA'}
            </button>
          </div>
        </div>
      </div>

      {/* Active Sessions */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
            <Shield className="w-5 h-5 text-mono-600 dark:text-mono-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-mono-950 dark:text-mono-50">
              Active Sessions
            </h2>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Manage devices where you're logged in
            </p>
          </div>
        </div>

        <div className="space-y-3">
          {sessions.map(session => (
            <div
              key={session.id}
              className="flex items-center justify-between p-4 rounded-lg border border-mono-200 dark:border-mono-800"
            >
              <div className="flex items-center space-x-3">
                <div className={`status-dot ${session.current ? 'status-dot-success' : 'status-dot-neutral'}`} />
                <div>
                  <p className="font-medium text-mono-900 dark:text-mono-100">
                    {session.device}
                    {session.current && (
                      <span className="ml-2 text-xs text-green-600 dark:text-green-400">(Current)</span>
                    )}
                  </p>
                  <p className="text-sm text-mono-500">
                    {session.location} • {session.lastActive}
                  </p>
                </div>
              </div>
              {!session.current && (
                <button
                  onClick={() => handleRevokeSession(session.id)}
                  className="btn-ghost text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20"
                >
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Danger Zone */}
      <div className="card border-red-200 dark:border-red-900">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
            <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-red-700 dark:text-red-400">
              Danger Zone
            </h2>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Irreversible actions
            </p>
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 rounded-lg border border-mono-200 dark:border-mono-800">
            <div>
              <p className="font-medium text-mono-900 dark:text-mono-100">Log out of all devices</p>
              <p className="text-sm text-mono-500">This will sign you out everywhere except here</p>
            </div>
            <button
              onClick={() => setShowLogoutModal(true)}
              className="btn-secondary flex items-center space-x-2"
            >
              <LogOut className="w-4 h-4" />
              <span>Log Out All</span>
            </button>
          </div>

          <div className="flex items-center justify-between p-4 rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/20">
            <div>
              <p className="font-medium text-red-700 dark:text-red-400">Delete account</p>
              <p className="text-sm text-mono-600 dark:text-mono-400">Permanently delete your account and all data</p>
            </div>
            <button
              onClick={() => setShowDeleteModal(true)}
              className="btn-danger flex items-center space-x-2"
            >
              <Trash2 className="w-4 h-4" />
              <span>Delete Account</span>
            </button>
          </div>
        </div>
      </div>

      {/* Confirmation Modals */}
      <ConfirmModal
        isOpen={showLogoutModal}
        onClose={() => setShowLogoutModal(false)}
        onConfirm={() => {
          // Handle logout all
          setShowLogoutModal(false);
          alert('Logged out of all devices');
        }}
        title="Log Out of All Devices"
        message="Are you sure you want to log out of all other devices? You will remain logged in on this device."
        confirmLabel="Log Out All"
        variant="warning"
      />

      <ConfirmModal
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        onConfirm={() => {
          // Handle account deletion
          setShowDeleteModal(false);
          alert('Account deletion requested');
        }}
        title="Delete Account"
        message="This action cannot be undone. All your data, including rules, alerts, and configurations will be permanently deleted."
        confirmLabel="Delete Account"
        variant="danger"
      />
    </div>
  );
}
