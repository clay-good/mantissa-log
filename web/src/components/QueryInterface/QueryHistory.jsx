import { useState, useEffect } from 'react';
import {
  History,
  Clock,
  Search,
  Play,
  Copy,
  Check,
  Trash2,
  ChevronRight,
  Database,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Filter,
  Calendar,
  DollarSign,
  Star,
  StarOff
} from 'lucide-react';
import Modal from '../common/Modal';

/**
 * Query History Browser component for viewing and re-running past queries.
 */
export default function QueryHistory({ isOpen, onClose, onSelectQuery, userId }) {
  const [queries, setQueries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [sortBy, setSortBy] = useState('recent');
  const [copiedId, setCopiedId] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadHistory();
    }
  }, [isOpen, userId]);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/queries/history?user_id=${userId}&limit=50`);
      if (!response.ok) {
        // Use mock data for development
        setQueries(generateMockHistory());
        return;
      }
      const data = await response.json();
      setQueries(data.queries || []);
    } catch (err) {
      console.error('Error loading query history:', err);
      setQueries(generateMockHistory());
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async (sql, id) => {
    try {
      await navigator.clipboard.writeText(sql);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleDelete = async (queryId) => {
    try {
      await fetch(`/api/queries/${queryId}`, { method: 'DELETE' });
      setQueries(queries.filter(q => q.id !== queryId));
    } catch (err) {
      console.error('Error deleting query:', err);
    }
  };

  const handleToggleFavorite = async (queryId) => {
    const query = queries.find(q => q.id === queryId);
    if (!query) return;

    // Optimistically update UI
    setQueries(queries.map(q =>
      q.id === queryId ? { ...q, favorite: !q.favorite } : q
    ));

    try {
      await fetch(`/api/queries/${queryId}/favorite`, {
        method: 'POST',
        body: JSON.stringify({ favorite: !query.favorite })
      });
    } catch (err) {
      // Revert on error
      setQueries(queries.map(q =>
        q.id === queryId ? { ...q, favorite: query.favorite } : q
      ));
    }
  };

  const filteredQueries = queries
    .filter(q => {
      // Text search
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchesNl = q.natural_language?.toLowerCase().includes(term);
        const matchesSql = q.sql?.toLowerCase().includes(term);
        if (!matchesNl && !matchesSql) return false;
      }

      // Status filter
      if (filterStatus !== 'all') {
        if (filterStatus === 'favorites' && !q.favorite) return false;
        if (filterStatus === 'succeeded' && q.status !== 'SUCCEEDED') return false;
        if (filterStatus === 'failed' && q.status !== 'FAILED') return false;
      }

      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'recent') {
        return new Date(b.timestamp) - new Date(a.timestamp);
      }
      if (sortBy === 'cost') {
        return (b.cost_usd || 0) - (a.cost_usd || 0);
      }
      if (sortBy === 'data') {
        return (b.data_scanned_bytes || 0) - (a.data_scanned_bytes || 0);
      }
      return 0;
    });

  const getStatusIcon = (status) => {
    switch (status) {
      case 'SUCCEEDED':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      case 'FAILED':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'RUNNING':
        return <div className="w-4 h-4 border-2 border-mono-500 border-t-transparent rounded-full animate-spin" />;
      default:
        return <AlertCircle className="w-4 h-4 text-mono-400" />;
    }
  };

  const formatTimestamp = (isoString) => {
    const date = new Date(isoString);
    const now = new Date();
    const diff = now - date;

    // Less than 24 hours, show relative time
    if (diff < 86400000) {
      const hours = Math.floor(diff / 3600000);
      const minutes = Math.floor((diff % 3600000) / 60000);
      if (hours > 0) return `${hours}h ago`;
      if (minutes > 0) return `${minutes}m ago`;
      return 'Just now';
    }

    // Otherwise show date
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
      bytes /= 1024;
      i++;
    }
    return `${bytes.toFixed(1)} ${units[i]}`;
  };

  const formatCost = (cost) => {
    if (!cost) return '$0.00';
    return `$${cost.toFixed(4)}`;
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Query History"
      size="xl"
    >
      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-mono-400" />
          <input
            type="text"
            placeholder="Search queries..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input pl-10"
          />
        </div>

        <div className="flex gap-2">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="input w-auto"
          >
            <option value="all">All Status</option>
            <option value="favorites">Favorites</option>
            <option value="succeeded">Succeeded</option>
            <option value="failed">Failed</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="input w-auto"
          >
            <option value="recent">Most Recent</option>
            <option value="cost">Highest Cost</option>
            <option value="data">Most Data</option>
          </select>
        </div>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-3 gap-4 mb-4 p-3 bg-mono-50 dark:bg-mono-850 rounded-lg">
        <div className="text-center">
          <p className="text-xs text-mono-500">Total Queries</p>
          <p className="text-lg font-semibold text-mono-900 dark:text-mono-100">
            {queries.length}
          </p>
        </div>
        <div className="text-center border-x border-mono-200 dark:border-mono-700">
          <p className="text-xs text-mono-500">Data Scanned</p>
          <p className="text-lg font-semibold text-mono-900 dark:text-mono-100">
            {formatBytes(queries.reduce((sum, q) => sum + (q.data_scanned_bytes || 0), 0))}
          </p>
        </div>
        <div className="text-center">
          <p className="text-xs text-mono-500">Total Cost</p>
          <p className="text-lg font-semibold text-mono-900 dark:text-mono-100">
            {formatCost(queries.reduce((sum, q) => sum + (q.cost_usd || 0), 0))}
          </p>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} className="skeleton-card h-20" />
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && filteredQueries.length === 0 && (
        <div className="empty-state py-8">
          <History className="empty-state-icon" />
          <p className="empty-state-title">
            {searchTerm || filterStatus !== 'all' ? 'No Matching Queries' : 'No Query History'}
          </p>
          <p className="empty-state-description">
            {searchTerm || filterStatus !== 'all'
              ? 'Try adjusting your search or filters.'
              : 'Your query history will appear here once you run some queries.'}
          </p>
        </div>
      )}

      {/* Query List */}
      {!loading && filteredQueries.length > 0 && (
        <div className="space-y-2 max-h-[400px] overflow-y-auto">
          {filteredQueries.map((query) => (
            <div
              key={query.id}
              className="border border-mono-200 dark:border-mono-800 rounded-lg overflow-hidden"
            >
              {/* Query Header */}
              <div
                className="flex items-center justify-between p-3 bg-white dark:bg-mono-900 cursor-pointer hover:bg-mono-50 dark:hover:bg-mono-850 transition-colors"
                onClick={() => setExpandedId(expandedId === query.id ? null : query.id)}
              >
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  {getStatusIcon(query.status)}
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-mono-900 dark:text-mono-100 truncate">
                      {query.natural_language || 'Manual SQL Query'}
                    </p>
                    <div className="flex items-center space-x-3 text-xs text-mono-500 mt-0.5">
                      <span className="flex items-center">
                        <Clock className="w-3 h-3 mr-1" />
                        {formatTimestamp(query.timestamp)}
                      </span>
                      {query.data_scanned_bytes && (
                        <span className="flex items-center">
                          <Database className="w-3 h-3 mr-1" />
                          {formatBytes(query.data_scanned_bytes)}
                        </span>
                      )}
                      {query.cost_usd && (
                        <span className="flex items-center">
                          <DollarSign className="w-3 h-3 mr-1" />
                          {formatCost(query.cost_usd)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-1 ml-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleFavorite(query.id);
                    }}
                    className="btn-ghost p-2"
                    title={query.favorite ? 'Remove from favorites' : 'Add to favorites'}
                  >
                    {query.favorite ? (
                      <Star className="w-4 h-4 text-amber-500 fill-amber-500" />
                    ) : (
                      <StarOff className="w-4 h-4 text-mono-400" />
                    )}
                  </button>
                  <ChevronRight className={`w-4 h-4 text-mono-400 transition-transform ${expandedId === query.id ? 'rotate-90' : ''}`} />
                </div>
              </div>

              {/* Expanded Details */}
              {expandedId === query.id && (
                <div className="p-3 border-t border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-850 space-y-3">
                  {/* SQL */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-xs font-medium text-mono-600 dark:text-mono-400">
                        SQL Query
                      </p>
                      <button
                        onClick={() => handleCopy(query.sql, query.id)}
                        className="btn-ghost p-1"
                        title="Copy SQL"
                      >
                        {copiedId === query.id ? (
                          <Check className="w-3 h-3 text-green-500" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                    <pre className="text-xs bg-white dark:bg-mono-900 rounded p-2 overflow-x-auto max-h-32 font-mono text-mono-700 dark:text-mono-300">
                      {query.sql}
                    </pre>
                  </div>

                  {/* Error Message (if failed) */}
                  {query.status === 'FAILED' && query.error && (
                    <div className="alert-error text-xs">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />
                      <span>{query.error}</span>
                    </div>
                  )}

                  {/* Execution Stats */}
                  {query.status === 'SUCCEEDED' && (
                    <div className="grid grid-cols-3 gap-3 text-xs">
                      <div>
                        <p className="text-mono-500">Execution Time</p>
                        <p className="font-mono text-mono-900 dark:text-mono-100">
                          {query.execution_time_ms ? `${(query.execution_time_ms / 1000).toFixed(2)}s` : '-'}
                        </p>
                      </div>
                      <div>
                        <p className="text-mono-500">Rows Returned</p>
                        <p className="font-mono text-mono-900 dark:text-mono-100">
                          {query.row_count?.toLocaleString() || '-'}
                        </p>
                      </div>
                      <div>
                        <p className="text-mono-500">Query Cost</p>
                        <p className="font-mono text-mono-900 dark:text-mono-100">
                          {formatCost(query.cost_usd)}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center justify-between pt-2 border-t border-mono-200 dark:border-mono-700">
                    <button
                      onClick={() => handleDelete(query.id)}
                      className="btn-ghost text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 btn-sm flex items-center space-x-1"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>Delete</span>
                    </button>
                    <button
                      onClick={() => {
                        onSelectQuery(query);
                        onClose();
                      }}
                      className="btn-primary btn-sm flex items-center space-x-1"
                    >
                      <Play className="w-3 h-3" />
                      <span>Run Again</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Keyboard Shortcut Hint */}
      <div className="mt-4 pt-4 border-t border-mono-200 dark:border-mono-800">
        <p className="text-xs text-mono-500 text-center">
          Tip: Press <kbd className="px-1.5 py-0.5 bg-mono-100 dark:bg-mono-800 rounded text-mono-700 dark:text-mono-300">Ctrl+H</kbd> to open query history
        </p>
      </div>
    </Modal>
  );
}

/**
 * Generate mock query history for development/demo
 */
function generateMockHistory() {
  const queries = [
    {
      natural_language: 'Show me failed login attempts in the last 24 hours',
      sql: "SELECT timestamp, source_ip, user, event_type, status\nFROM cloudtrail_logs\nWHERE event_type = 'ConsoleLogin'\n  AND status = 'Failure'\n  AND timestamp > current_timestamp - interval '24' hour\nORDER BY timestamp DESC\nLIMIT 100",
      status: 'SUCCEEDED',
      favorite: true
    },
    {
      natural_language: 'Find all S3 bucket policy changes this week',
      sql: "SELECT timestamp, user, bucket_name, event_name, request_parameters\nFROM cloudtrail_logs\nWHERE event_source = 's3.amazonaws.com'\n  AND event_name LIKE '%BucketPolicy%'\n  AND timestamp > current_timestamp - interval '7' day\nORDER BY timestamp DESC",
      status: 'SUCCEEDED',
      favorite: false
    },
    {
      natural_language: 'List IAM users with admin permissions',
      sql: "SELECT user_name, policy_name, attached_policies\nFROM iam_users\nWHERE attached_policies LIKE '%AdministratorAccess%'\n  OR policy_name LIKE '%Admin%'",
      status: 'FAILED',
      error: 'Table iam_users does not exist',
      favorite: false
    },
    {
      natural_language: 'Show unusual outbound network traffic',
      sql: "SELECT timestamp, source_ip, destination_ip, bytes_sent, protocol\nFROM vpc_flow_logs\nWHERE bytes_sent > 1000000000\n  AND action = 'ACCEPT'\n  AND timestamp > current_timestamp - interval '24' hour\nORDER BY bytes_sent DESC\nLIMIT 50",
      status: 'SUCCEEDED',
      favorite: true
    },
    {
      natural_language: 'Find security group changes',
      sql: "SELECT timestamp, user, event_name, security_group_id, ip_permissions\nFROM cloudtrail_logs\nWHERE event_name IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress')\n  AND timestamp > current_timestamp - interval '30' day\nORDER BY timestamp DESC",
      status: 'SUCCEEDED',
      favorite: false
    }
  ];

  const now = new Date();
  return queries.map((q, i) => ({
    id: `query-${i + 1}`,
    ...q,
    timestamp: new Date(now - (i * 3600000 * (i + 1))).toISOString(),
    data_scanned_bytes: Math.floor(Math.random() * 500000000) + 10000000,
    execution_time_ms: Math.floor(Math.random() * 30000) + 500,
    row_count: q.status === 'SUCCEEDED' ? Math.floor(Math.random() * 500) + 1 : 0,
    cost_usd: (Math.random() * 0.05) + 0.001
  }));
}
