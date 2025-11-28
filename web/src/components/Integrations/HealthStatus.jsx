import { useState, useEffect } from 'react';
import { Activity, CheckCircle2, AlertTriangle, XCircle, HelpCircle, TrendingUp, Clock } from 'lucide-react';

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
              onClick={(e) => {
                e.stopPropagation();
                // TODO: Show recent failures modal
              }}
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
