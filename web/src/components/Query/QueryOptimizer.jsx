import { useState } from 'react';
import { Zap, CheckCircle, AlertCircle, Info, ArrowRight } from 'lucide-react';

export default function QueryOptimizer({ queryString, onApplyOptimization }) {
  const [suggestions, setSuggestions] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzQuery = async () => {
    setLoading(true);

    try {
      const response = await fetch('/api/cost/optimize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: queryString })
      });

      if (!response.ok) {
        throw new Error('Failed to analyze query');
      }

      const data = await response.json();
      setSuggestions(data);
    } catch (err) {
      console.error('Error analyzing query:', err);
    } finally {
      setLoading(false);
    }
  };

  if (!queryString) {
    return null;
  }

  return (
    <div className="space-y-4">
      <button
        onClick={analyzeQuery}
        disabled={loading}
        className="btn-secondary w-full"
      >
        <Zap className="w-4 h-4 mr-2" />
        {loading ? 'Analyzing Query...' : 'Optimize for Cost'}
      </button>

      {suggestions && (
        <div className="space-y-3">
          {/* Summary */}
          <div className="card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold text-mono-950 dark:text-mono-50">
                Optimization Analysis
              </h3>
              <span className={`px-2 py-1 rounded text-xs font-mono ${getScoreBadgeClass(suggestions.total_suggestions)}`}>
                {suggestions.total_suggestions === 0 ? 'Optimized' : `${suggestions.total_suggestions} issue${suggestions.total_suggestions > 1 ? 's' : ''}`}
              </span>
            </div>

            {suggestions.total_suggestions === 0 ? (
              <div className="flex items-center text-mono-700 dark:text-mono-300">
                <CheckCircle className="w-5 h-5 mr-2" />
                <span className="text-sm">Query is well optimized for cost</span>
              </div>
            ) : (
              <div className="text-sm text-mono-700 dark:text-mono-300">
                {suggestions.estimated_improvement}
              </div>
            )}
          </div>

          {/* Suggestions */}
          {suggestions.suggestions && suggestions.suggestions.length > 0 && (
            <div className="space-y-2">
              {suggestions.suggestions.map((suggestion, index) => (
                <OptimizationSuggestion
                  key={index}
                  suggestion={suggestion}
                  onApply={() => onApplyOptimization && onApplyOptimization(suggestion)}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function OptimizationSuggestion({ suggestion, onApply }) {
  const [expanded, setExpanded] = useState(false);

  const severityConfig = {
    high: {
      icon: AlertCircle,
      color: 'text-mono-900 dark:text-mono-100',
      bgColor: 'bg-mono-100 dark:bg-mono-850',
      borderColor: 'border-mono-400 dark:border-mono-600'
    },
    medium: {
      icon: Info,
      color: 'text-mono-700 dark:text-mono-300',
      bgColor: 'bg-mono-50 dark:bg-mono-900',
      borderColor: 'border-mono-300 dark:border-mono-700'
    },
    low: {
      icon: Info,
      color: 'text-mono-600 dark:text-mono-400',
      bgColor: 'bg-mono-50 dark:bg-mono-950',
      borderColor: 'border-mono-200 dark:border-mono-800'
    }
  };

  const config = severityConfig[suggestion.severity] || severityConfig.low;
  const Icon = config.icon;

  return (
    <div className={`card border-l-4 ${config.borderColor}`}>
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start flex-1">
            <Icon className={`w-5 h-5 mr-3 mt-0.5 flex-shrink-0 ${config.color}`} />
            <div className="flex-1">
              <h4 className="font-semibold text-mono-950 dark:text-mono-50 mb-1">
                {suggestion.message}
              </h4>
              {suggestion.potential_savings && (
                <p className="text-xs text-mono-600 dark:text-mono-400 mb-2">
                  Potential savings: {suggestion.potential_savings}
                </p>
              )}

              {expanded && (
                <div className="mt-3 space-y-3">
                  {suggestion.example && (
                    <div>
                      <div className="text-xs font-semibold text-mono-700 dark:text-mono-300 mb-1">
                        Example:
                      </div>
                      <pre className="p-2 bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded text-xs font-mono text-mono-900 dark:text-mono-50 overflow-x-auto">
                        {suggestion.example}
                      </pre>
                    </div>
                  )}

                  {onApply && (
                    <button
                      onClick={onApply}
                      className="btn-secondary text-xs"
                    >
                      <ArrowRight className="w-3 h-3 mr-1" />
                      Apply This Optimization
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>

          <button
            onClick={() => setExpanded(!expanded)}
            className="ml-2 text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 text-xs"
          >
            {expanded ? 'Less' : 'More'}
          </button>
        </div>
      </div>
    </div>
  );
}

function getScoreBadgeClass(issueCount) {
  if (issueCount === 0) {
    return 'bg-mono-200 dark:bg-mono-800 text-mono-950 dark:text-mono-50';
  } else if (issueCount <= 2) {
    return 'bg-mono-150 dark:bg-mono-850 text-mono-900 dark:text-mono-100';
  } else {
    return 'bg-mono-300 dark:bg-mono-700 text-mono-950 dark:text-mono-50';
  }
}
