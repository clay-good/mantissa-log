import { useState, useEffect } from 'react';
import { AlertCircle, RefreshCw, Check, Loader2, Eye, XCircle } from 'lucide-react';

export default function FailedAlertsView({ userId }) {
  const [failedAlerts, setFailedAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [retrying, setRetrying] = useState(null);
  const [stats, setStats] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    loadFailedAlerts();
    loadStats();
  }, [userId]);

  const loadFailedAlerts = async () => {
    try {
      const response = await fetch(`/api/alerts/failed?user_id=${userId}&limit=50`);
      if (!response.ok) throw new Error('Failed to load failed alerts');

      const data = await response.json();
      setFailedAlerts(data.failed_alerts || []);
    } catch (err) {
      console.error('Error loading failed alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response = await fetch(`/api/alerts/failed/stats?user_id=${userId}&hours=24`);
      if (!response.ok) return;

      const data = await response.json();
      setStats(data.stats);
    } catch (err) {
      console.error('Error loading stats:', err);
    }
  };

  const retryAlert = async (alert) => {
    setRetrying(alert.alert_id);

    try {
      const response = await fetch('/api/alerts/failed/retry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          alert_id: alert.alert_id,
          timestamp: alert.last_attempt
        })
      });

      if (!response.ok) throw new Error('Retry failed');

      // Reload alerts
      await loadFailedAlerts();
      await loadStats();
    } catch (err) {
      console.error('Error retrying alert:', err);
      alert(`Failed to retry alert: ${err.message}`);
    } finally {
      setRetrying(null);
    }
  };

  const markResolved = async (alert) => {
    try {
      const response = await fetch('/api/alerts/failed/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          alert_id: alert.alert_id,
          timestamp: alert.last_attempt,
          resolution_note: 'Manually resolved'
        })
      });

      if (!response.ok) throw new Error('Failed to mark as resolved');

      // Reload alerts
      await loadFailedAlerts();
      await loadStats();
    } catch (err) {
      console.error('Error marking resolved:', err);
      alert(`Failed to mark as resolved: ${err.message}`);
    }
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
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-mono-950 dark:text-mono-50 mb-2 flex items-center">
          <AlertCircle className="w-6 h-6 mr-2" />
          Failed Alerts
        </h2>
        <p className="text-sm text-mono-600 dark:text-mono-400">
          Alerts that failed to deliver after all retry attempts
        </p>
      </div>

      {/* Stats */}
      {stats && stats.total_failures > 0 && (
        <div className="grid grid-cols-4 gap-4">
          <div className="card">
            <div className="text-sm text-mono-600 dark:text-mono-400 mb-1">Total Failures (24h)</div>
            <div className="text-2xl font-bold text-mono-950 dark:text-mono-50 font-mono">
              {stats.total_failures}
            </div>
          </div>

          {Object.entries(stats.by_integration).slice(0, 3).map(([integration, count]) => (
            <div key={integration} className="card">
              <div className="text-sm text-mono-600 dark:text-mono-400 mb-1 capitalize">
                {integration}
              </div>
              <div className="text-2xl font-bold text-mono-950 dark:text-mono-50 font-mono">
                {count}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Failed Alerts List */}
      {failedAlerts.length === 0 ? (
        <div className="card text-center p-12">
          <Check className="w-12 h-12 text-mono-600 dark:text-mono-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-2">
            No Failed Alerts
          </h3>
          <p className="text-sm text-mono-600 dark:text-mono-400">
            All alerts are being delivered successfully
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {failedAlerts.map((alert) => (
            <div key={`${alert.alert_id}-${alert.last_attempt}`} className="card">
              {/* Alert Header */}
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-1">
                    <h3 className="font-semibold text-mono-950 dark:text-mono-50">
                      {alert.rule_name}
                    </h3>
                    <span className="px-2 py-0.5 bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-50 rounded text-xs font-mono">
                      {alert.integration_type}
                    </span>
                  </div>
                  <div className="text-sm text-mono-600 dark:text-mono-400">
                    {alert.error_message}
                  </div>
                </div>

                <div className="flex items-center space-x-2 ml-4">
                  <button
                    onClick={() => setSelectedAlert(selectedAlert?.alert_id === alert.alert_id ? null : alert)}
                    className="p-2 text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 hover:bg-mono-100 dark:hover:bg-mono-850 rounded"
                    title="View details"
                  >
                    <Eye className="w-4 h-4" />
                  </button>

                  <button
                    onClick={() => retryAlert(alert)}
                    disabled={retrying === alert.alert_id}
                    className="btn-secondary text-xs"
                  >
                    {retrying === alert.alert_id ? (
                      <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                    ) : (
                      <RefreshCw className="w-3 h-3 mr-1" />
                    )}
                    Retry
                  </button>

                  <button
                    onClick={() => markResolved(alert)}
                    className="btn-secondary text-xs"
                  >
                    <Check className="w-3 h-3 mr-1" />
                    Resolve
                  </button>
                </div>
              </div>

              {/* Alert Metadata */}
              <div className="grid grid-cols-4 gap-4 text-sm">
                <div>
                  <div className="text-mono-600 dark:text-mono-400 text-xs">Failure Reason</div>
                  <div className="text-mono-900 dark:text-mono-50 font-mono text-xs">
                    {alert.failure_reason}
                  </div>
                </div>

                <div>
                  <div className="text-mono-600 dark:text-mono-400 text-xs">Attempts</div>
                  <div className="text-mono-900 dark:text-mono-50 font-mono text-xs">
                    {alert.attempt_count}
                  </div>
                </div>

                <div>
                  <div className="text-mono-600 dark:text-mono-400 text-xs">First Attempt</div>
                  <div className="text-mono-900 dark:text-mono-50 font-mono text-xs">
                    {formatTime(alert.first_attempt)}
                  </div>
                </div>

                <div>
                  <div className="text-mono-600 dark:text-mono-400 text-xs">Last Attempt</div>
                  <div className="text-mono-900 dark:text-mono-50 font-mono text-xs">
                    {formatTime(alert.last_attempt)}
                  </div>
                </div>
              </div>

              {/* Expanded Details */}
              {selectedAlert?.alert_id === alert.alert_id && (
                <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-800">
                  <div className="space-y-3">
                    <div>
                      <div className="text-sm font-semibold text-mono-950 dark:text-mono-50 mb-2">
                        Alert Data:
                      </div>
                      <pre className="p-3 bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded text-xs font-mono text-mono-900 dark:text-mono-50 overflow-x-auto">
                        {JSON.stringify(alert.alert_data, null, 2)}
                      </pre>
                    </div>

                    <div>
                      <div className="text-sm font-semibold text-mono-950 dark:text-mono-50 mb-2">
                        Failed Payload:
                      </div>
                      <pre className="p-3 bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded text-xs font-mono text-mono-900 dark:text-mono-50 overflow-x-auto">
                        {JSON.stringify(alert.payload, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatTime(isoString) {
  const date = new Date(isoString);
  return date.toLocaleString();
}
