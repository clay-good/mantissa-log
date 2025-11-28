import { useState, useEffect } from 'react';
import { DollarSign, TrendingUp, AlertCircle } from 'lucide-react';

export default function InlineCostEstimate({ queryString, userId, compact = false }) {
  const [estimate, setEstimate] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (queryString && queryString.length > 20) {
      // Debounce cost estimation
      const timer = setTimeout(() => {
        estimateCost();
      }, 500);

      return () => clearTimeout(timer);
    }
  }, [queryString]);

  const estimateCost = async () => {
    setLoading(true);

    try {
      const response = await fetch('/api/cost/estimate-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          query: queryString
        })
      });

      if (!response.ok) {
        throw new Error('Failed to estimate cost');
      }

      const data = await response.json();
      setEstimate(data.estimate);
    } catch (err) {
      console.error('Error estimating cost:', err);
      setEstimate(null);
    } finally {
      setLoading(false);
    }
  };

  if (!estimate && !loading) {
    return null;
  }

  if (compact) {
    return (
      <div className="inline-flex items-center text-xs text-mono-600 dark:text-mono-400">
        <DollarSign className="w-3 h-3 mr-1" />
        {loading ? (
          <span>Estimating...</span>
        ) : (
          <>
            <span className="font-mono">${estimate.cost_usd.toFixed(4)}</span>
            <span className="mx-1">•</span>
            <span>{estimate.data_scanned_mb.toFixed(0)} MB</span>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between p-3 bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded">
      <div className="flex items-center space-x-4">
        <div className="flex items-center">
          <DollarSign className="w-4 h-4 mr-2 text-mono-600 dark:text-mono-400" />
          <div>
            <div className="text-xs text-mono-600 dark:text-mono-400">
              Estimated Cost
            </div>
            {loading ? (
              <div className="text-sm text-mono-500 dark:text-mono-500 animate-pulse">
                Calculating...
              </div>
            ) : (
              <div className="text-sm font-mono text-mono-900 dark:text-mono-50">
                ${estimate.cost_usd.toFixed(6)}
              </div>
            )}
          </div>
        </div>

        {!loading && estimate && (
          <>
            <div className="flex items-center">
              <TrendingUp className="w-4 h-4 mr-2 text-mono-600 dark:text-mono-400" />
              <div>
                <div className="text-xs text-mono-600 dark:text-mono-400">
                  Data Scanned
                </div>
                <div className="text-sm font-mono text-mono-900 dark:text-mono-50">
                  {estimate.data_scanned_mb.toFixed(0)} MB
                </div>
              </div>
            </div>

            {estimate.warnings && estimate.warnings.length > 0 && (
              <div className="flex items-center">
                <AlertCircle className="w-4 h-4 mr-2 text-mono-700 dark:text-mono-300" />
                <div>
                  <div className="text-xs text-mono-700 dark:text-mono-300">
                    {estimate.warnings.length} optimization{estimate.warnings.length > 1 ? 's' : ''} available
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {!loading && estimate && estimate.cost_usd > 0.01 && (
        <div className="text-xs text-mono-600 dark:text-mono-400">
          <AlertCircle className="w-3 h-3 inline mr-1" />
          High cost query
        </div>
      )}
    </div>
  );
}
