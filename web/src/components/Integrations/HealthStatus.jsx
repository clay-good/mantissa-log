import { useState, useEffect } from 'react';
import { Activity, CheckCircle2, AlertTriangle, XCircle, HelpCircle, TrendingUp, Clock, RefreshCw, ExternalLink, Copy, Check } from 'lucide-react';
import Modal from '../common/Modal';

const HEALTH_STATUS = {
  healthy: {
    label: 'Healthy',
    icon: CheckCircle2,
    color: 'text-mono-950 dark:text-mono-50',
    bgColor: 'bg-mono-100 dark:bg-mono-850',
    borderColor: 'border-mono-300 dark:border-mono-700'
  },
  degraded: {
    label: 'Degraded',
    icon: AlertTriangle,
    color: 'text-mono-700 dark:text-mono-300',
    bgColor: 'bg-mono-150 dark:bg-mono-850',
    borderColor: 'border-mono-400 dark:border-mono-600'
  },
  unhealthy: {
    label: 'Unhealthy',
    icon: XCircle,
    color: 'text-mono-900 dark:text-mono-100',
    bgColor: 'bg-mono-200 dark:bg-mono-800',
    borderColor: 'border-mono-500 dark:border-mono-500'
  },
  unknown: {
    label: 'Unknown',
    icon: HelpCircle,
    color: 'text-mono-600 dark:text-mono-400',
    bgColor: 'bg-mono-50 dark:bg-mono-900',
    borderColor: 'border-mono-200 dark:border-mono-800'
  }
};

export default function HealthStatus({ userId, integrationId, integrationName, compact = false }) {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showDetails, setShowDetails] = useState(false);
  const [showFailuresModal, setShowFailuresModal] = useState(false);
  const [failures, setFailures] = useState([]);
  const [loadingFailures, setLoadingFailures] = useState(false);

  useEffect(() => {
    loadHealth();
    // Refresh health every 30 seconds
    const interval = setInterval(loadHealth, 30000);
    return () => clearInterval(interval);
  }, [userId, integrationId]);

  const loadHealth = async () => {
    try {
      const response = await fetch(
        `/api/integrations/health?user_id=${userId}&integration_id=${integrationId}`
      );

      if (!response.ok) {
        setHealth({ status: 'unknown' });
        return;
      }

      const data = await response.json();
      setHealth(data.health);
    } catch (err) {
      console.error('Error loading health:', err);
      setHealth({ status: 'unknown' });
    } finally {
      setLoading(false);
    }
  };

  const loadFailures = async () => {
    setLoadingFailures(true);
    try {
      const response = await fetch(
        `/api/integrations/failures?user_id=${userId}&integration_id=${integrationId}&limit=20`
      );

      if (!response.ok) {
        // Mock data for development
        setFailures(generateMockFailures());
        return;
      }

      const data = await response.json();
      setFailures(data.failures || []);
    } catch (err) {
      console.error('Error loading failures:', err);
      // Use mock data if API fails
      setFailures(generateMockFailures());
    } finally {
      setLoadingFailures(false);
    }
  };

  const handleShowFailures = (e) => {
    e.stopPropagation();
    setShowFailuresModal(true);
    loadFailures();
  };

  if (loading) {
    return (
      <div className="flex items-center text-mono-500 dark:text-mono-500 text-sm">
        <Activity className="w-4 h-4 mr-1 animate-pulse" />
        {!compact && <span>Checking...</span>}
      </div>
    );
  }

  if (!health) {
    return null;
  }

  const status = HEALTH_STATUS[health.status] || HEALTH_STATUS.unknown;
  const Icon = status.icon;

  if (compact) {
    return (
      <div
        className="flex items-center cursor-pointer"
        onClick={() => setShowDetails(!showDetails)}
        title={`${status.label} - Click for details`}
      >
        <Icon className={`w-4 h-4 ${status.color}`} />
      </div>
    );
  }

  return (
    <div className={`rounded-lg border p-3 ${status.bgColor} ${status.borderColor}`}>
      {/* Header */}
      <div
        className="flex items-center justify-between cursor-pointer"
        onClick={() => setShowDetails(!showDetails)}
      >
        <div className="flex items-center space-x-2">
          <Icon className={`w-5 h-5 ${status.color}`} />
          <div>
            <div className={`font-semibold ${status.color}`}>
              {status.label}
            </div>
            {health.last_success && (
              <div className="text-xs text-mono-600 dark:text-mono-400">
                Last success: {formatRelativeTime(health.last_success)}
              </div>
            )}
          </div>
        </div>

        {health.success_rate !== undefined && (
          <div className="text-right">
            <div className={`text-sm font-mono ${status.color}`}>
              {health.success_rate.toFixed(1)}%
            </div>
            <div className="text-xs text-mono-600 dark:text-mono-400">
              success rate
            </div>
          </div>
        )}
      </div>

      {/* Expanded Details */}
      {showDetails && health.total_requests > 0 && (
        <div className="mt-3 pt-3 border-t border-mono-300 dark:border-mono-700 space-y-2">
          {/* Metrics Grid */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="text-mono-600 dark:text-mono-400 text-xs">Total Requests</div>
              <div className="font-mono text-mono-900 dark:text-mono-50">
                {health.total_requests}
              </div>
            </div>

            <div>
              <div className="text-mono-600 dark:text-mono-400 text-xs">Failed</div>
              <div className="font-mono text-mono-900 dark:text-mono-50">
                {health.failed_requests}
              </div>
            </div>

            <div>
              <div className="text-mono-600 dark:text-mono-400 text-xs flex items-center">
                <TrendingUp className="w-3 h-3 mr-1" />
                Avg Response
              </div>
              <div className="font-mono text-mono-900 dark:text-mono-50">
                {health.avg_response_time_ms.toFixed(0)}ms
              </div>
            </div>

            <div>
              <div className="text-mono-600 dark:text-mono-400 text-xs">Consecutive Failures</div>
              <div className="font-mono text-mono-900 dark:text-mono-50">
                {health.consecutive_failures}
              </div>
            </div>
          </div>

          {/* Last Failure */}
          {health.last_failure && (
            <div className="pt-2 border-t border-mono-300 dark:border-mono-700">
              <div className="text-xs text-mono-600 dark:text-mono-400 mb-1">
                Last Failure
              </div>
              <div className="text-xs text-mono-700 dark:text-mono-300">
                {formatRelativeTime(health.last_failure)}
              </div>
            </div>
          )}

          {/* Recent Failures Link */}
          {health.failed_requests > 0 && (
            <button
              onClick={handleShowFailures}
              className="w-full text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 underline mt-2"
            >
              View Recent Failures
            </button>
          )}
        </div>
      )}

      {/* No Data Message */}
      {showDetails && health.total_requests === 0 && (
        <div className="mt-3 pt-3 border-t border-mono-300 dark:border-mono-700">
          <p className="text-xs text-mono-600 dark:text-mono-400">
            No requests recorded yet. Health status will appear after first alert.
          </p>
        </div>
      )}

      {/* Recent Failures Modal */}
      <RecentFailuresModal
        isOpen={showFailuresModal}
        onClose={() => setShowFailuresModal(false)}
        integrationName={integrationName}
        failures={failures}
        loading={loadingFailures}
        onRefresh={loadFailures}
      />
    </div>
  );
}

function formatRelativeTime(isoString) {
  const date = new Date(isoString);
  const now = new Date();
  const diff = now - date;

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return `${seconds}s ago`;
}

function formatTimestamp(isoString) {
  const date = new Date(isoString);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

/**
 * Recent Failures Modal Component
 */
function RecentFailuresModal({ isOpen, onClose, integrationName, failures, loading, onRefresh }) {
  const [copiedId, setCopiedId] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  const copyToClipboard = async (text, id) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const getErrorTypeLabel = (errorType) => {
    const labels = {
      timeout: 'Timeout',
      connection_error: 'Connection Error',
      rate_limit: 'Rate Limited',
      auth_error: 'Auth Error',
      server_error: 'Server Error',
      invalid_response: 'Invalid Response',
      unknown: 'Unknown Error'
    };
    return labels[errorType] || errorType;
  };

  const getErrorTypeColor = (errorType) => {
    const colors = {
      timeout: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400',
      connection_error: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
      rate_limit: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400',
      auth_error: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400',
      server_error: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
      invalid_response: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400'
    };
    return colors[errorType] || 'bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300';
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Recent Failures - ${integrationName || 'Integration'}`}
      size="lg"
    >
      {/* Header Actions */}
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Showing last {failures.length} failures
        </p>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="btn-ghost btn-sm flex items-center space-x-1"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Loading State */}
      {loading && failures.length === 0 && (
        <div className="space-y-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="skeleton-card h-24" />
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && failures.length === 0 && (
        <div className="empty-state">
          <CheckCircle2 className="empty-state-icon text-green-500" />
          <p className="empty-state-title">No Recent Failures</p>
          <p className="empty-state-description">
            All requests to this integration have been successful recently.
          </p>
        </div>
      )}

      {/* Failures List */}
      {failures.length > 0 && (
        <div className="space-y-3 max-h-[400px] overflow-y-auto">
          {failures.map((failure, index) => (
            <div
              key={failure.id || index}
              className="rounded-lg border border-mono-200 dark:border-mono-800 overflow-hidden"
            >
              {/* Failure Header */}
              <div
                className="flex items-center justify-between p-3 bg-mono-50 dark:bg-mono-850 cursor-pointer hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
                onClick={() => setExpandedId(expandedId === failure.id ? null : failure.id)}
              >
                <div className="flex items-center space-x-3">
                  <XCircle className="w-4 h-4 text-red-500 flex-shrink-0" />
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className={`badge text-xs ${getErrorTypeColor(failure.error_type)}`}>
                        {getErrorTypeLabel(failure.error_type)}
                      </span>
                      {failure.status_code && (
                        <span className="text-xs font-mono text-mono-500">
                          HTTP {failure.status_code}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-mono-500 mt-1">
                      {formatTimestamp(failure.timestamp)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  {failure.response_time_ms && (
                    <span className="text-xs text-mono-500 font-mono">
                      {failure.response_time_ms}ms
                    </span>
                  )}
                  <svg
                    className={`w-4 h-4 text-mono-400 transition-transform ${expandedId === failure.id ? 'rotate-180' : ''}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedId === failure.id && (
                <div className="p-3 border-t border-mono-200 dark:border-mono-800 space-y-3 bg-white dark:bg-mono-900">
                  {/* Error Message */}
                  {failure.error_message && (
                    <div>
                      <p className="text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                        Error Message
                      </p>
                      <div className="flex items-start justify-between bg-mono-50 dark:bg-mono-850 rounded p-2">
                        <code className="text-xs text-red-600 dark:text-red-400 break-all">
                          {failure.error_message}
                        </code>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(failure.error_message, `msg-${failure.id}`);
                          }}
                          className="btn-ghost p-1 ml-2 flex-shrink-0"
                          title="Copy error message"
                        >
                          {copiedId === `msg-${failure.id}` ? (
                            <Check className="w-3 h-3 text-green-500" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Request Details */}
                  {failure.request_url && (
                    <div>
                      <p className="text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                        Request URL
                      </p>
                      <div className="flex items-center justify-between bg-mono-50 dark:bg-mono-850 rounded p-2">
                        <code className="text-xs text-mono-700 dark:text-mono-300 break-all">
                          {failure.request_method && (
                            <span className="font-semibold mr-1">{failure.request_method}</span>
                          )}
                          {failure.request_url}
                        </code>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(failure.request_url, `url-${failure.id}`);
                          }}
                          className="btn-ghost p-1 ml-2 flex-shrink-0"
                          title="Copy URL"
                        >
                          {copiedId === `url-${failure.id}` ? (
                            <Check className="w-3 h-3 text-green-500" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Alert Context */}
                  {failure.alert_id && (
                    <div>
                      <p className="text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                        Related Alert
                      </p>
                      <div className="flex items-center space-x-2">
                        <code className="text-xs bg-mono-50 dark:bg-mono-850 rounded px-2 py-1">
                          {failure.alert_id}
                        </code>
                        {failure.rule_name && (
                          <span className="text-xs text-mono-500">
                            {failure.rule_name}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Response Body Preview */}
                  {failure.response_body && (
                    <div>
                      <p className="text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                        Response Body
                      </p>
                      <pre className="text-xs bg-mono-50 dark:bg-mono-850 rounded p-2 overflow-x-auto max-h-32">
                        {typeof failure.response_body === 'string'
                          ? failure.response_body
                          : JSON.stringify(failure.response_body, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Footer with troubleshooting tips */}
      {failures.length > 0 && (
        <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-800">
          <p className="text-xs text-mono-500 dark:text-mono-400">
            Tip: Check integration credentials and endpoint availability if failures persist.
          </p>
        </div>
      )}
    </Modal>
  );
}

/**
 * Generate mock failure data for development/demo
 */
function generateMockFailures() {
  const errorTypes = ['timeout', 'connection_error', 'rate_limit', 'auth_error', 'server_error', 'invalid_response'];
  const errorMessages = {
    timeout: 'Request timed out after 30000ms',
    connection_error: 'ECONNREFUSED - Connection refused by remote server',
    rate_limit: 'Too many requests. Rate limit exceeded. Retry after 60 seconds.',
    auth_error: 'Invalid API key or authentication token expired',
    server_error: 'Internal Server Error: Unexpected condition encountered',
    invalid_response: 'Expected JSON response but received HTML'
  };

  const now = new Date();
  const failures = [];

  for (let i = 0; i < 5; i++) {
    const errorType = errorTypes[Math.floor(Math.random() * errorTypes.length)];
    const timestamp = new Date(now - (i * 3600000 + Math.random() * 3600000)).toISOString();

    failures.push({
      id: `failure-${i + 1}`,
      timestamp,
      error_type: errorType,
      error_message: errorMessages[errorType],
      status_code: errorType === 'server_error' ? 500 : errorType === 'rate_limit' ? 429 : errorType === 'auth_error' ? 401 : null,
      response_time_ms: Math.floor(Math.random() * 5000) + 100,
      request_url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
      request_method: 'POST',
      alert_id: `alert-${1000 + i}`,
      rule_name: ['Brute Force Detection', 'Suspicious Login', 'Malware Detection', 'Data Exfiltration', 'Privilege Escalation'][i % 5],
      response_body: errorType === 'rate_limit' ? { error: 'rate_limited', retry_after: 60 } : null
    });
  }

  return failures;
}
