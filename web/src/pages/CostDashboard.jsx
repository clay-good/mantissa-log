import { useState, useEffect } from 'react';
import {
  DollarSign,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  RefreshCw,
  Calendar,
  Database,
  Zap,
  Activity,
  PieChart,
  BarChart3,
  Download,
  Filter,
  ChevronDown,
  ChevronUp,
  Info
} from 'lucide-react';
import { useAuthStore } from '../stores/authStore';

/**
 * Cost Dashboard - Comprehensive cost tracking and analytics for detection rules
 */
export default function CostDashboard() {
  const [loading, setLoading] = useState(true);
  const [costData, setCostData] = useState(null);
  const [timeRange, setTimeRange] = useState(30);
  const [sortBy, setSortBy] = useState('cost');
  const [expandedRules, setExpandedRules] = useState(new Set());
  const { user } = useAuthStore();
  const userId = user?.userId || user?.username;

  useEffect(() => {
    loadCostData();
  }, [timeRange]);

  const loadCostData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/cost/dashboard?user_id=${userId}&days=${timeRange}`);
      if (!response.ok) {
        // Use mock data for development
        setCostData(generateMockCostData(timeRange));
        return;
      }
      const data = await response.json();
      setCostData(data);
    } catch (err) {
      console.error('Error loading cost data:', err);
      setCostData(generateMockCostData(timeRange));
    } finally {
      setLoading(false);
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
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

  const toggleRuleExpand = (ruleId) => {
    const newExpanded = new Set(expandedRules);
    if (newExpanded.has(ruleId)) {
      newExpanded.delete(ruleId);
    } else {
      newExpanded.add(ruleId);
    }
    setExpandedRules(newExpanded);
  };

  const getSortedRules = () => {
    if (!costData?.rules) return [];
    return [...costData.rules].sort((a, b) => {
      if (sortBy === 'cost') return b.total_cost - a.total_cost;
      if (sortBy === 'data') return b.data_scanned - a.data_scanned;
      if (sortBy === 'executions') return b.executions - a.executions;
      if (sortBy === 'name') return a.name.localeCompare(b.name);
      return 0;
    });
  };

  const exportReport = () => {
    if (!costData) return;

    const report = {
      generated_at: new Date().toISOString(),
      time_range_days: timeRange,
      summary: costData.summary,
      rules: costData.rules
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cost-report-${timeRange}d-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="skeleton h-8 w-48 mb-2" />
            <div className="skeleton h-4 w-64" />
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <div key={i} className="skeleton-card h-24" />)}
        </div>
        <div className="skeleton-card h-96" />
      </div>
    );
  }

  const summary = costData?.summary || {};
  const dailyTrend = costData?.daily_trend || [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-mono-900 dark:bg-mono-100 rounded-lg">
            <DollarSign className="w-6 h-6 text-mono-50 dark:text-mono-950" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
              Cost Dashboard
            </h1>
            <p className="text-sm text-mono-600 dark:text-mono-400">
              Track and optimize detection rule costs
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(parseInt(e.target.value))}
            className="input w-auto"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={60}>Last 60 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button
            onClick={exportReport}
            className="btn-secondary flex items-center space-x-2"
          >
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
          <button
            onClick={loadCostData}
            disabled={loading}
            className="btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
              <DollarSign className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Total Cost</p>
              <p className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {formatCurrency(summary.total_cost || 0)}
              </p>
              <p className="text-xs text-mono-500">{timeRange} day total</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
              <Calendar className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Projected Monthly</p>
              <p className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {formatCurrency(summary.projected_monthly || 0)}
              </p>
              <div className="flex items-center text-xs">
                {summary.trend > 0 ? (
                  <>
                    <TrendingUp className="w-3 h-3 text-red-500 mr-1" />
                    <span className="text-red-600">+{summary.trend}%</span>
                  </>
                ) : (
                  <>
                    <TrendingDown className="w-3 h-3 text-green-500 mr-1" />
                    <span className="text-green-600">{summary.trend}%</span>
                  </>
                )}
                <span className="text-mono-400 ml-1">vs last period</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
              <Database className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Data Scanned</p>
              <p className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {formatBytes(summary.total_data_scanned || 0)}
              </p>
              <p className="text-xs text-mono-500">{timeRange} day total</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-mono-100 dark:bg-mono-800 rounded-lg">
              <Zap className="w-5 h-5 text-mono-600 dark:text-mono-400" />
            </div>
            <div>
              <p className="text-xs text-mono-500">Total Executions</p>
              <p className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                {(summary.total_executions || 0).toLocaleString()}
              </p>
              <p className="text-xs text-mono-500">
                {((summary.total_executions || 0) / timeRange).toFixed(0)}/day avg
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Cost Trend Chart */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
            Daily Cost Trend
          </h3>
          <div className="flex items-center space-x-2 text-xs text-mono-500">
            <div className="flex items-center">
              <div className="w-3 h-3 bg-mono-600 rounded mr-1" />
              <span>Query Cost</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 bg-mono-400 rounded mr-1" />
              <span>Lambda Cost</span>
            </div>
          </div>
        </div>

        <div className="h-48 flex items-end space-x-1">
          {dailyTrend.map((day, index) => {
            const maxCost = Math.max(...dailyTrend.map(d => d.query_cost + d.lambda_cost));
            const queryHeight = maxCost > 0 ? (day.query_cost / maxCost) * 100 : 0;
            const lambdaHeight = maxCost > 0 ? (day.lambda_cost / maxCost) * 100 : 0;

            return (
              <div
                key={index}
                className="flex-1 flex flex-col items-center justify-end group relative"
              >
                <div className="w-full flex flex-col">
                  <div
                    className="w-full bg-mono-400 rounded-t transition-all duration-200 group-hover:bg-mono-500"
                    style={{ height: `${lambdaHeight}%`, minHeight: lambdaHeight > 0 ? '2px' : '0' }}
                  />
                  <div
                    className="w-full bg-mono-600 rounded-b transition-all duration-200 group-hover:bg-mono-700"
                    style={{ height: `${queryHeight}%`, minHeight: queryHeight > 0 ? '2px' : '0' }}
                  />
                </div>

                {/* Tooltip */}
                <div className="absolute bottom-full mb-2 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                  <div className="bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-900 text-xs rounded px-2 py-1 whitespace-nowrap">
                    <p className="font-medium">{day.date}</p>
                    <p>Query: {formatCurrency(day.query_cost)}</p>
                    <p>Lambda: {formatCurrency(day.lambda_cost)}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex justify-between mt-2 text-xs text-mono-500">
          <span>{dailyTrend[0]?.date}</span>
          <span>{dailyTrend[dailyTrend.length - 1]?.date}</span>
        </div>
      </div>

      {/* Cost by Rule */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
            Cost by Detection Rule
          </h3>
          <div className="flex items-center space-x-2">
            <span className="text-sm text-mono-500">Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="input w-auto text-sm"
            >
              <option value="cost">Highest Cost</option>
              <option value="data">Most Data</option>
              <option value="executions">Most Executions</option>
              <option value="name">Name</option>
            </select>
          </div>
        </div>

        <div className="space-y-2">
          {getSortedRules().map((rule) => {
            const isExpanded = expandedRules.has(rule.id);
            const costPercentage = summary.total_cost > 0
              ? (rule.total_cost / summary.total_cost) * 100
              : 0;

            return (
              <div
                key={rule.id}
                className="border border-mono-200 dark:border-mono-800 rounded-lg overflow-hidden"
              >
                {/* Rule Header */}
                <div
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-mono-50 dark:hover:bg-mono-850 transition-colors"
                  onClick={() => toggleRuleExpand(rule.id)}
                >
                  <div className="flex items-center space-x-4 flex-1">
                    <div className={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-mono-400'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-mono-900 dark:text-mono-100 truncate">
                        {rule.name}
                      </p>
                      <div className="flex items-center space-x-3 text-xs text-mono-500 mt-0.5">
                        <span>{rule.executions.toLocaleString()} executions</span>
                        <span>{formatBytes(rule.data_scanned)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    {/* Cost bar */}
                    <div className="w-32 hidden sm:block">
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="text-mono-500">{costPercentage.toFixed(1)}%</span>
                      </div>
                      <div className="h-2 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-mono-600 dark:bg-mono-400 rounded-full"
                          style={{ width: `${costPercentage}%` }}
                        />
                      </div>
                    </div>

                    <div className="text-right min-w-[80px]">
                      <p className="font-mono font-semibold text-mono-900 dark:text-mono-100">
                        {formatCurrency(rule.total_cost)}
                      </p>
                    </div>

                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-mono-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-mono-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-2 border-t border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-850">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div>
                        <p className="text-xs text-mono-500 mb-1">Query Cost</p>
                        <p className="font-mono text-sm text-mono-900 dark:text-mono-100">
                          {formatCurrency(rule.query_cost)}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-mono-500 mb-1">Lambda Cost</p>
                        <p className="font-mono text-sm text-mono-900 dark:text-mono-100">
                          {formatCurrency(rule.lambda_cost)}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-mono-500 mb-1">Avg Cost/Execution</p>
                        <p className="font-mono text-sm text-mono-900 dark:text-mono-100">
                          {formatCurrency(rule.executions > 0 ? rule.total_cost / rule.executions : 0)}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-mono-500 mb-1">Avg Data/Execution</p>
                        <p className="font-mono text-sm text-mono-900 dark:text-mono-100">
                          {formatBytes(rule.executions > 0 ? rule.data_scanned / rule.executions : 0)}
                        </p>
                      </div>
                    </div>

                    {/* Cost optimization hint */}
                    {rule.optimization_hint && (
                      <div className="mt-3 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                        <div className="flex items-start space-x-2">
                          <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" />
                          <div>
                            <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
                              Optimization Opportunity
                            </p>
                            <p className="text-xs text-amber-700 dark:text-amber-300 mt-0.5">
                              {rule.optimization_hint}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Cost Breakdown by Service */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
            Cost by Service
          </h3>
          <div className="space-y-3">
            {[
              { name: 'Athena Queries', cost: summary.athena_cost || 0, icon: Database },
              { name: 'Lambda Functions', cost: summary.lambda_cost || 0, icon: Zap },
              { name: 'CloudWatch', cost: summary.cloudwatch_cost || 0, icon: Activity },
              { name: 'S3 Storage', cost: summary.s3_cost || 0, icon: Database }
            ].map((service) => {
              const percentage = summary.total_cost > 0
                ? (service.cost / summary.total_cost) * 100
                : 0;

              return (
                <div key={service.name} className="flex items-center space-x-3">
                  <service.icon className="w-4 h-4 text-mono-500" />
                  <div className="flex-1">
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-mono-700 dark:text-mono-300">{service.name}</span>
                      <span className="font-mono text-mono-900 dark:text-mono-100">
                        {formatCurrency(service.cost)}
                      </span>
                    </div>
                    <div className="h-2 bg-mono-200 dark:bg-mono-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-mono-600 dark:bg-mono-400 rounded-full transition-all duration-300"
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
            Cost Saving Tips
          </h3>
          <div className="space-y-3">
            <div className="p-3 bg-mono-50 dark:bg-mono-850 rounded-lg">
              <div className="flex items-start space-x-2">
                <Info className="w-4 h-4 text-mono-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-mono-700 dark:text-mono-300">
                    Partition your queries
                  </p>
                  <p className="text-xs text-mono-500 mt-0.5">
                    Use time-based partitions to reduce data scanned
                  </p>
                </div>
              </div>
            </div>
            <div className="p-3 bg-mono-50 dark:bg-mono-850 rounded-lg">
              <div className="flex items-start space-x-2">
                <Info className="w-4 h-4 text-mono-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-mono-700 dark:text-mono-300">
                    Use columnar format
                  </p>
                  <p className="text-xs text-mono-500 mt-0.5">
                    Convert logs to Parquet for 30-90% cost reduction
                  </p>
                </div>
              </div>
            </div>
            <div className="p-3 bg-mono-50 dark:bg-mono-850 rounded-lg">
              <div className="flex items-start space-x-2">
                <Info className="w-4 h-4 text-mono-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-mono-700 dark:text-mono-300">
                    Optimize query frequency
                  </p>
                  <p className="text-xs text-mono-500 mt-0.5">
                    Low-priority rules can run less frequently
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Note */}
      <div className="alert-info">
        <Info className="w-4 h-4 flex-shrink-0" />
        <span className="text-sm">
          Cost data is updated hourly. Athena charges $5 per TB of data scanned.
          Lambda charges vary by memory allocation and execution time.
        </span>
      </div>
    </div>
  );
}

/**
 * Generate mock cost data for development/demo
 */
function generateMockCostData(days) {
  const rules = [
    { name: 'Brute Force Login Detection', enabled: true },
    { name: 'Suspicious S3 Access Pattern', enabled: true },
    { name: 'IAM Policy Change Detection', enabled: true },
    { name: 'Unusual Outbound Traffic', enabled: true },
    { name: 'Failed SSH Authentication', enabled: false },
    { name: 'Root Account Usage', enabled: true },
    { name: 'Security Group Modification', enabled: true }
  ];

  const ruleData = rules.map((rule, index) => {
    const executions = Math.floor(Math.random() * 1000) + 100;
    const dataScanned = (Math.random() * 50 + 5) * 1024 * 1024 * 1024; // GB in bytes
    const queryCost = (dataScanned / (1024 * 1024 * 1024 * 1024)) * 5; // $5 per TB
    const lambdaCost = executions * 0.0001 * (Math.random() + 0.5);

    return {
      id: `rule-${index + 1}`,
      ...rule,
      executions,
      data_scanned: dataScanned,
      query_cost: queryCost,
      lambda_cost: lambdaCost,
      total_cost: queryCost + lambdaCost,
      optimization_hint: index === 0 ? 'Consider adding time partition filter to reduce data scanned by 60%' :
                         index === 3 ? 'This rule scans full VPC flow logs. Add destination port filter.' : null
    };
  });

  const totalCost = ruleData.reduce((sum, r) => sum + r.total_cost, 0);
  const totalData = ruleData.reduce((sum, r) => sum + r.data_scanned, 0);
  const totalExecutions = ruleData.reduce((sum, r) => sum + r.executions, 0);

  // Generate daily trend
  const dailyTrend = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const variation = 0.8 + Math.random() * 0.4;
    const dailyCost = (totalCost / days) * variation;

    dailyTrend.push({
      date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      query_cost: dailyCost * 0.7,
      lambda_cost: dailyCost * 0.3
    });
  }

  return {
    summary: {
      total_cost: totalCost,
      projected_monthly: totalCost * (30 / days),
      total_data_scanned: totalData,
      total_executions: totalExecutions,
      trend: Math.floor(Math.random() * 20) - 10,
      athena_cost: totalCost * 0.65,
      lambda_cost: totalCost * 0.25,
      cloudwatch_cost: totalCost * 0.07,
      s3_cost: totalCost * 0.03
    },
    rules: ruleData,
    daily_trend: dailyTrend
  };
}
