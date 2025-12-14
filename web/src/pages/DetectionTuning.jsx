import { useState, useEffect } from 'react';
import {
  Settings2,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ThumbsUp,
  ThumbsDown,
  Zap,
  BarChart3,
  Filter,
  RefreshCw,
  ChevronRight,
  Lightbulb,
  Target,
  Activity,
  Eye,
  EyeOff,
  LineChart
} from 'lucide-react';
import Modal from '../components/common/Modal';
import { useAuthStore } from '../stores/authStore';
import { MetricsChart } from '../components/DetectionMetrics';

/**
 * Detection Tuning Dashboard
 * Provides insights into detection rule performance and optimization suggestions.
 */
export default function DetectionTuning() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRule, setSelectedRule] = useState(null);
  const [filterBy, setFilterBy] = useState('all');
  const [sortBy, setSortBy] = useState('fp_rate');
  const [showOptimizations, setShowOptimizations] = useState(false);
  const [optimizations, setOptimizations] = useState([]);
  const [showMetricsChart, setShowMetricsChart] = useState(true);
  const { user } = useAuthStore();
  const userId = user?.userId || user?.username;

  useEffect(() => {
    loadRuleMetrics();
  }, []);

  const loadRuleMetrics = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/detection/metrics?period=week`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token') || ''}`,
          'Content-Type': 'application/json'
        }
      });
      if (!response.ok) {
        // Use mock data in development or if API unavailable
        setRules(generateMockMetrics());
        return;
      }
      const data = await response.json();
      setRules(data.rules || []);
    } catch (err) {
      console.error('Error loading metrics:', err);
      setRules(generateMockMetrics());
    } finally {
      setLoading(false);
    }
  };

  const loadOptimizations = async (ruleId) => {
    try {
      const response = await fetch(`/api/detection/optimizations?rule_id=${ruleId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token') || ''}`,
          'Content-Type': 'application/json'
        }
      });
      if (!response.ok) {
        setOptimizations(generateMockOptimizations(ruleId));
        return;
      }
      const data = await response.json();
      setOptimizations(data.optimizations || []);
    } catch (err) {
      setOptimizations(generateMockOptimizations(ruleId));
    }
  };

  const handleViewOptimizations = (rule) => {
    setSelectedRule(rule);
    loadOptimizations(rule.id);
    setShowOptimizations(true);
  };

  const handleApplyOptimization = async (optimizationId) => {
    // In production, call API to apply optimization
    alert(`Applying optimization ${optimizationId}. This would update the rule query.`);
    setShowOptimizations(false);
  };

  const filteredRules = rules
    .filter(r => {
      if (filterBy === 'high_fp') return r.fp_rate > 20;
      if (filterBy === 'zero_alerts') return r.total_alerts === 0 && r.enabled;
      if (filterBy === 'needs_tuning') return r.fp_rate > 10 || (r.total_alerts === 0 && r.enabled);
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'fp_rate') return b.fp_rate - a.fp_rate;
      if (sortBy === 'alerts') return b.total_alerts - a.total_alerts;
      if (sortBy === 'accuracy') return a.accuracy - b.accuracy;
      if (sortBy === 'name') return a.name.localeCompare(b.name);
      return 0;
    });

  // Calculate summary stats
  const stats = {
    totalRules: rules.length,
    avgFpRate: rules.length > 0
      ? (rules.reduce((sum, r) => sum + r.fp_rate, 0) / rules.length).toFixed(1)
      : 0,
    needsTuning: rules.filter(r => r.fp_rate > 10 || (r.total_alerts === 0 && r.enabled)).length,
    highPerformance: rules.filter(r => r.accuracy >= 90).length
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-mono-900 dark:bg-mono-100 rounded-lg">
            <Settings2 className="w-6 h-6 text-mono-50 dark:text-mono-950" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
              Detection Tuning
            </h1>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Optimize detection rules for better accuracy
            </p>
          </div>
        </div>
        <button
          onClick={loadRuleMetrics}
          disabled={loading}
          className="btn-secondary flex items-center space-x-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
              <Target className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Total Rules</p>
              <p className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {stats.totalRules}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-amber-100 dark:bg-amber-900/30 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Avg FP Rate</p>
              <p className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {stats.avgFpRate}%
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
              <Zap className="w-5 h-5 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Needs Tuning</p>
              <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                {stats.needsTuning}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
              <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">High Performance</p>
              <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                {stats.highPerformance}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Time Series Chart */}
      {showMetricsChart && (
        <div className="relative">
          <button
            onClick={() => setShowMetricsChart(false)}
            className="absolute top-4 right-4 z-10 p-1 rounded hover:bg-mono-200 dark:hover:bg-mono-700 text-mono-500"
            title="Hide chart"
          >
            <EyeOff className="w-4 h-4" />
          </button>
          <MetricsChart period="day" limit={30} height={200} />
        </div>
      )}

      {!showMetricsChart && (
        <button
          onClick={() => setShowMetricsChart(true)}
          className="flex items-center space-x-2 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
        >
          <LineChart className="w-4 h-4" />
          <span>Show metrics chart</span>
        </button>
      )}

      {/* Filters and Controls */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <div className="flex items-center space-x-2">
            <Filter className="w-4 h-4 text-mono-500" />
            <span className="text-sm text-mono-600 dark:text-mono-400">Filter:</span>
            <div className="flex gap-2">
              {[
                { value: 'all', label: 'All Rules' },
                { value: 'needs_tuning', label: 'Needs Tuning' },
                { value: 'high_fp', label: 'High FP Rate' },
                { value: 'zero_alerts', label: 'Zero Alerts' }
              ].map(({ value, label }) => (
                <button
                  key={value}
                  onClick={() => setFilterBy(value)}
                  className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                    filterBy === value
                      ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-900'
                      : 'bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300 hover:bg-mono-200 dark:hover:bg-mono-700'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-sm text-mono-600 dark:text-mono-400">Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="input w-auto"
            >
              <option value="fp_rate">FP Rate (High to Low)</option>
              <option value="alerts">Alert Count</option>
              <option value="accuracy">Accuracy</option>
              <option value="name">Name</option>
            </select>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="card p-0">
        {loading ? (
          <div className="p-6 space-y-3">
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} className="skeleton-card h-16" />
            ))}
          </div>
        ) : filteredRules.length === 0 ? (
          <div className="empty-state py-12">
            <Target className="empty-state-icon" />
            <p className="empty-state-title">No Rules Found</p>
            <p className="empty-state-description">
              {filterBy !== 'all'
                ? 'Try changing your filter settings.'
                : 'Create detection rules to see their performance metrics here.'}
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Status</th>
                  <th>Total Alerts</th>
                  <th>FP Rate</th>
                  <th>Accuracy</th>
                  <th>Last Alert</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map(rule => (
                  <RuleMetricRow
                    key={rule.id}
                    rule={rule}
                    onViewOptimizations={handleViewOptimizations}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Tuning Tips */}
      <div className="card bg-gradient-to-r from-mono-50 to-mono-100 dark:from-mono-900 dark:to-mono-850 border-mono-200 dark:border-mono-700">
        <div className="flex items-start space-x-3">
          <div className="p-2 bg-mono-200 dark:bg-mono-800 rounded-lg">
            <Lightbulb className="w-5 h-5 text-mono-600 dark:text-mono-400" />
          </div>
          <div>
            <h3 className="font-semibold text-mono-900 dark:text-mono-100">Tuning Best Practices</h3>
            <ul className="mt-2 text-sm text-mono-600 dark:text-mono-400 space-y-1">
              <li>- Rules with FP rate above 20% should be tuned or disabled</li>
              <li>- Zero-alert rules may have incorrect queries or missing log sources</li>
              <li>- Review false positives weekly to identify patterns for suppression</li>
              <li>- Use the optimization suggestions to automatically improve queries</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Optimization Modal */}
      <OptimizationModal
        isOpen={showOptimizations}
        onClose={() => setShowOptimizations(false)}
        rule={selectedRule}
        optimizations={optimizations}
        onApply={handleApplyOptimization}
      />
    </div>
  );
}

/**
 * Individual rule metric row component
 */
function RuleMetricRow({ rule, onViewOptimizations }) {
  const getFpRateColor = (rate) => {
    if (rate >= 30) return 'text-red-600 dark:text-red-400';
    if (rate >= 15) return 'text-amber-600 dark:text-amber-400';
    return 'text-green-600 dark:text-green-400';
  };

  const getAccuracyColor = (accuracy) => {
    if (accuracy >= 90) return 'text-green-600 dark:text-green-400';
    if (accuracy >= 70) return 'text-amber-600 dark:text-amber-400';
    return 'text-red-600 dark:text-red-400';
  };

  const formatTimestamp = (isoString) => {
    if (!isoString) return 'Never';
    const date = new Date(isoString);
    const now = new Date();
    const diff = now - date;
    const days = Math.floor(diff / 86400000);
    if (days > 30) return 'Over 30 days';
    if (days > 0) return `${days}d ago`;
    const hours = Math.floor(diff / 3600000);
    if (hours > 0) return `${hours}h ago`;
    return 'Recently';
  };

  const needsTuning = rule.fp_rate > 10 || (rule.total_alerts === 0 && rule.enabled);

  return (
    <tr className={needsTuning ? 'bg-amber-50/50 dark:bg-amber-900/10' : ''}>
      <td>
        <div className="flex items-center space-x-3">
          <div className={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-mono-400'}`} />
          <div>
            <p className="font-medium text-mono-900 dark:text-mono-100">{rule.name}</p>
            <p className="text-xs text-mono-500">{rule.severity} severity</p>
          </div>
        </div>
      </td>
      <td>
        <span className={`badge ${rule.enabled ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' : 'badge-default'}`}>
          {rule.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </td>
      <td>
        <div className="flex items-center space-x-2">
          <span className="font-mono text-mono-900 dark:text-mono-100">{rule.total_alerts}</span>
          {rule.alert_trend === 'up' && <TrendingUp className="w-3 h-3 text-green-500" />}
          {rule.alert_trend === 'down' && <TrendingDown className="w-3 h-3 text-red-500" />}
        </div>
      </td>
      <td>
        <div className="flex items-center space-x-2">
          <span className={`font-mono ${getFpRateColor(rule.fp_rate)}`}>
            {rule.fp_rate.toFixed(1)}%
          </span>
          <div className="w-16 h-2 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                rule.fp_rate >= 30 ? 'bg-red-500' :
                rule.fp_rate >= 15 ? 'bg-amber-500' : 'bg-green-500'
              }`}
              style={{ width: `${Math.min(rule.fp_rate, 100)}%` }}
            />
          </div>
        </div>
      </td>
      <td>
        <span className={`font-mono ${getAccuracyColor(rule.accuracy)}`}>
          {rule.accuracy.toFixed(0)}%
        </span>
      </td>
      <td>
        <span className="text-sm text-mono-600 dark:text-mono-400">
          {formatTimestamp(rule.last_alert)}
        </span>
      </td>
      <td>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => onViewOptimizations(rule)}
            className="btn-ghost btn-sm flex items-center space-x-1"
            title="View optimization suggestions"
          >
            <Zap className="w-3 h-3" />
            <span>Tune</span>
          </button>
        </div>
      </td>
    </tr>
  );
}

/**
 * Optimization suggestions modal
 */
function OptimizationModal({ isOpen, onClose, rule, optimizations, onApply }) {
  if (!rule) return null;

  const getOptimizationTypeIcon = (type) => {
    switch (type) {
      case 'add_filter':
        return <Filter className="w-4 h-4 text-blue-500" />;
      case 'adjust_threshold':
        return <BarChart3 className="w-4 h-4 text-purple-500" />;
      case 'add_exclusion':
        return <EyeOff className="w-4 h-4 text-amber-500" />;
      case 'fix_query':
        return <Zap className="w-4 h-4 text-red-500" />;
      default:
        return <Lightbulb className="w-4 h-4 text-mono-500" />;
    }
  };

  const getImpactColor = (impact) => {
    if (impact === 'high') return 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400';
    if (impact === 'medium') return 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400';
    return 'bg-mono-100 dark:bg-mono-800 text-mono-700 dark:text-mono-300';
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Optimize: ${rule.name}`}
      size="lg"
    >
      {/* Rule Summary */}
      <div className="mb-4 p-4 bg-mono-50 dark:bg-mono-850 rounded-lg">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="text-xs text-mono-500">FP Rate</p>
            <p className={`text-lg font-bold ${rule.fp_rate > 15 ? 'text-red-600' : 'text-green-600'}`}>
              {rule.fp_rate.toFixed(1)}%
            </p>
          </div>
          <div>
            <p className="text-xs text-mono-500">Accuracy</p>
            <p className={`text-lg font-bold ${rule.accuracy < 80 ? 'text-amber-600' : 'text-green-600'}`}>
              {rule.accuracy.toFixed(0)}%
            </p>
          </div>
          <div>
            <p className="text-xs text-mono-500">Total Alerts</p>
            <p className="text-lg font-bold text-mono-900 dark:text-mono-100">
              {rule.total_alerts}
            </p>
          </div>
        </div>
      </div>

      {/* Optimization Suggestions */}
      {optimizations.length === 0 ? (
        <div className="empty-state py-8">
          <CheckCircle2 className="empty-state-icon text-green-500" />
          <p className="empty-state-title">No Optimizations Needed</p>
          <p className="empty-state-description">
            This rule is performing well and doesn't require tuning at this time.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-mono-600 dark:text-mono-400">
            {optimizations.length} suggested optimization{optimizations.length > 1 ? 's' : ''}
          </p>

          {optimizations.map((opt, index) => (
            <div
              key={opt.id || index}
              className="border border-mono-200 dark:border-mono-800 rounded-lg overflow-hidden"
            >
              <div className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {getOptimizationTypeIcon(opt.type)}
                    <span className="font-medium text-mono-900 dark:text-mono-100">
                      {opt.title}
                    </span>
                  </div>
                  <span className={`badge text-xs ${getImpactColor(opt.impact)}`}>
                    {opt.impact} impact
                  </span>
                </div>

                <p className="text-sm text-mono-600 dark:text-mono-400 mb-3">
                  {opt.description}
                </p>

                {opt.estimated_reduction && (
                  <p className="text-xs text-green-600 dark:text-green-400 mb-3">
                    Estimated FP reduction: {opt.estimated_reduction}%
                  </p>
                )}

                {opt.query_change && (
                  <div className="mb-3">
                    <p className="text-xs font-medium text-mono-600 dark:text-mono-400 mb-1">
                      Query Change:
                    </p>
                    <pre className="text-xs bg-mono-100 dark:bg-mono-800 rounded p-2 overflow-x-auto">
                      {opt.query_change}
                    </pre>
                  </div>
                )}

                <div className="flex items-center justify-end space-x-2 pt-2 border-t border-mono-200 dark:border-mono-800">
                  <button className="btn-ghost btn-sm">
                    Dismiss
                  </button>
                  <button
                    onClick={() => onApply(opt.id)}
                    className="btn-primary btn-sm"
                  >
                    Apply Change
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

/**
 * Generate mock rule metrics for development/demo
 */
function generateMockMetrics() {
  const rules = [
    { name: 'Brute Force Login Detection', severity: 'high', fp_rate: 35.2, accuracy: 64.8 },
    { name: 'Suspicious S3 Access Pattern', severity: 'medium', fp_rate: 8.5, accuracy: 91.5 },
    { name: 'IAM Policy Change Detection', severity: 'critical', fp_rate: 2.1, accuracy: 97.9 },
    { name: 'Unusual Outbound Traffic', severity: 'high', fp_rate: 45.0, accuracy: 55.0 },
    { name: 'Failed SSH Authentication', severity: 'medium', fp_rate: 18.3, accuracy: 81.7 },
    { name: 'Root Account Usage', severity: 'critical', fp_rate: 0.5, accuracy: 99.5 },
    { name: 'Security Group Modification', severity: 'high', fp_rate: 12.8, accuracy: 87.2 },
    { name: 'CloudTrail Disabled', severity: 'critical', fp_rate: 0, accuracy: 100, total_alerts: 0 },
    { name: 'Data Exfiltration Attempt', severity: 'critical', fp_rate: 22.5, accuracy: 77.5 },
    { name: 'Privilege Escalation', severity: 'high', fp_rate: 5.2, accuracy: 94.8 }
  ];

  const now = new Date();
  return rules.map((r, i) => ({
    id: `rule-${i + 1}`,
    ...r,
    enabled: i !== 7, // CloudTrail rule disabled for demo
    total_alerts: r.total_alerts ?? Math.floor(Math.random() * 200) + 10,
    true_positives: Math.floor(Math.random() * 100) + 5,
    false_positives: Math.floor(Math.random() * 50),
    alert_trend: ['up', 'down', 'stable'][Math.floor(Math.random() * 3)],
    last_alert: i === 7 ? null : new Date(now - Math.random() * 7 * 86400000).toISOString()
  }));
}

/**
 * Generate mock optimization suggestions
 */
function generateMockOptimizations(ruleId) {
  const optimizations = [
    {
      id: 'opt-1',
      type: 'add_filter',
      title: 'Add Service Account Filter',
      description: 'Exclude known service accounts that frequently trigger false positives.',
      impact: 'high',
      estimated_reduction: 25,
      query_change: "AND user NOT IN ('svc-monitoring', 'svc-backup', 'automation-bot')"
    },
    {
      id: 'opt-2',
      type: 'adjust_threshold',
      title: 'Increase Threshold',
      description: 'Current threshold of 3 attempts is too sensitive. Recommend increasing to 5.',
      impact: 'medium',
      estimated_reduction: 15,
      query_change: 'HAVING COUNT(*) >= 5  -- was: >= 3'
    },
    {
      id: 'opt-3',
      type: 'add_exclusion',
      title: 'Exclude Internal IP Ranges',
      description: 'Add exclusion for internal corporate IP ranges that are frequently flagged.',
      impact: 'medium',
      estimated_reduction: 10,
      query_change: "AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%'"
    }
  ];

  // Randomly return 0-3 optimizations
  const count = Math.floor(Math.random() * 4);
  return optimizations.slice(0, count);
}
