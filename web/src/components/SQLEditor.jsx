import { useState, useEffect, useRef } from 'react';
import { Code, RotateCcw, Check, AlertTriangle, DollarSign, Loader2 } from 'lucide-react';

export default function SQLEditor({
  initialSql,
  aiGeneratedSql,
  onSqlChange,
  onExecute,
  showCostEstimate = true,
  readOnly = false
}) {
  const [sql, setSql] = useState(initialSql || '');
  const [originalSql, setOriginalSql] = useState(aiGeneratedSql || initialSql || '');
  const [warnings, setWarnings] = useState([]);
  const [costEstimate, setCostEstimate] = useState(null);
  const [estimatingCost, setEstimatingCost] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const textareaRef = useRef(null);
  const debounceTimerRef = useRef(null);

  // Update SQL when initialSql changes
  useEffect(() => {
    if (initialSql) {
      setSql(initialSql);
      if (!originalSql) {
        setOriginalSql(initialSql);
      }
    }
  }, [initialSql]);

  // Update AI-generated SQL reference
  useEffect(() => {
    if (aiGeneratedSql) {
      setOriginalSql(aiGeneratedSql);
    }
  }, [aiGeneratedSql]);

  // Validate and estimate cost on SQL changes
  useEffect(() => {
    if (sql !== initialSql) {
      setHasChanges(true);
    } else {
      setHasChanges(false);
    }

    // Debounce validation and cost estimation
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    debounceTimerRef.current = setTimeout(() => {
      validateSQL(sql);
      if (showCostEstimate && sql.trim()) {
        estimateCost(sql);
      }
    }, 500);

    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, [sql]);

  const validateSQL = (sqlText) => {
    const validationWarnings = [];

    if (!sqlText.trim()) {
      return;
    }

    const sqlUpper = sqlText.toUpperCase();

    // Check for SELECT statement
    if (!sqlUpper.includes('SELECT')) {
      validationWarnings.push({
        type: 'error',
        message: 'Query must contain a SELECT statement'
      });
    }

    // Check for FROM clause
    if (!sqlUpper.includes('FROM')) {
      validationWarnings.push({
        type: 'error',
        message: 'Query must contain a FROM clause'
      });
    }

    // Warn about SELECT *
    if (sqlUpper.includes('SELECT *')) {
      validationWarnings.push({
        type: 'warning',
        message: 'Using SELECT * scans all columns and increases cost. Consider selecting only needed columns.'
      });
    }

    // Warn about missing WHERE clause
    if (!sqlUpper.includes('WHERE')) {
      validationWarnings.push({
        type: 'warning',
        message: 'No WHERE clause detected. Query will scan entire table and may be expensive.'
      });
    }

    // Warn about missing partition filters
    const hasDateFilter = /WHERE.*\b(dt|date|year|month|day)\b/i.test(sqlText);
    if (!hasDateFilter && sqlUpper.includes('FROM')) {
      validationWarnings.push({
        type: 'warning',
        message: 'Consider adding partition filters (e.g., WHERE dt >= DATE_SUB(CURRENT_DATE, 7)) to reduce costs.'
      });
    }

    // Warn about missing LIMIT
    if (!sqlUpper.includes('LIMIT')) {
      validationWarnings.push({
        type: 'info',
        message: 'Consider adding a LIMIT clause to restrict result size.'
      });
    }

    setWarnings(validationWarnings);
  };

  const estimateCost = async (sqlText) => {
    if (!sqlText.trim()) return;

    setEstimatingCost(true);

    try {
      // Estimate data scanned based on query characteristics
      const estimate = estimateDataScanned(sqlText);

      // Could also call API for more accurate estimation
      // const response = await fetch('/api/cost/estimate-query', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ sql: sqlText })
      // });
      // const data = await response.json();

      setCostEstimate(estimate);
    } catch (err) {
      console.error('Failed to estimate cost:', err);
    } finally {
      setEstimatingCost(false);
    }
  };

  const estimateDataScanned = (sqlText) => {
    const sqlUpper = sqlText.toUpperCase();

    // Base estimate
    let estimatedGB = 1.0;

    // Adjust based on query characteristics
    if (sqlUpper.includes('SELECT *')) {
      estimatedGB *= 2.0; // Double for full table scan
    }

    if (!sqlUpper.includes('WHERE')) {
      estimatedGB *= 10.0; // 10x for no filtering
    }

    // Reduce if has date filter
    if (/WHERE.*\b(dt|date)\b.*[<>=]/i.test(sqlText)) {
      const daysMatch = sqlText.match(/(\d+)\s*(day|hour)/i);
      if (daysMatch) {
        const days = parseInt(daysMatch[1]);
        if (days <= 1) estimatedGB *= 0.01;
        else if (days <= 7) estimatedGB *= 0.1;
        else if (days <= 30) estimatedGB *= 0.3;
      } else {
        estimatedGB *= 0.5;
      }
    }

    // Has LIMIT
    if (sqlUpper.includes('LIMIT')) {
      estimatedGB *= 0.8;
    }

    const costPerTB = 5.00;
    const costPerGB = costPerTB / 1024;
    const estimatedCost = estimatedGB * costPerGB;

    return {
      estimatedGB: Math.max(0.001, estimatedGB).toFixed(3),
      estimatedCost: Math.max(0.00001, estimatedCost).toFixed(5),
      confidence: sqlUpper.includes('WHERE') ? 'medium' : 'low'
    };
  };

  const handleSqlChange = (e) => {
    const newSql = e.target.value;
    setSql(newSql);
    if (onSqlChange) {
      onSqlChange(newSql);
    }
  };

  const handleRevert = () => {
    setSql(originalSql);
    setHasChanges(false);
    if (onSqlChange) {
      onSqlChange(originalSql);
    }
  };

  const handleExecute = () => {
    if (onExecute) {
      onExecute(sql);
    }
  };

  const getSyntaxHighlightedSQL = (sqlText) => {
    // Simple syntax highlighting using regex
    const keywords = /\b(SELECT|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING|LIMIT|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AS|DISTINCT|COUNT|SUM|AVG|MAX|MIN|CASE|WHEN|THEN|ELSE|END|IN|NOT|NULL|IS|BETWEEN|LIKE)\b/gi;
    const strings = /'([^']*)'/g;
    const numbers = /\b(\d+)\b/g;
    const comments = /(--[^\n]*)/g;

    return sqlText
      .replace(keywords, '<span class="sql-keyword">$1</span>')
      .replace(strings, '<span class="sql-string">\'$1\'</span>')
      .replace(numbers, '<span class="sql-number">$1</span>')
      .replace(comments, '<span class="sql-comment">$1</span>');
  };

  return (
    <div className="space-y-3">
      {/* Editor Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Code className="w-4 h-4 text-mono-600 dark:text-mono-400" />
          <span className="text-sm font-medium text-mono-900 dark:text-mono-100">
            SQL Query
          </span>
          {hasChanges && !readOnly && (
            <span className="text-xs text-mono-600 dark:text-mono-400">
              (Modified)
            </span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          {hasChanges && !readOnly && originalSql && (
            <button
              onClick={handleRevert}
              className="text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 flex items-center space-x-1 transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Revert to AI-generated</span>
            </button>
          )}
        </div>
      </div>

      {/* SQL Editor */}
      <div className="relative">
        <textarea
          ref={textareaRef}
          value={sql}
          onChange={handleSqlChange}
          readOnly={readOnly}
          className="input font-mono text-sm min-h-32 resize-y"
          placeholder="Enter SQL query or generate one with natural language..."
          spellCheck="false"
        />
      </div>

      {/* Warnings */}
      {warnings.length > 0 && (
        <div className="space-y-2">
          {warnings.map((warning, index) => (
            <div
              key={index}
              className={`p-3 rounded-lg border text-sm ${
                warning.type === 'error'
                  ? 'bg-mono-100 dark:bg-mono-850 border-mono-400 dark:border-mono-600'
                  : warning.type === 'warning'
                  ? 'bg-mono-50 dark:bg-mono-900 border-mono-300 dark:border-mono-700'
                  : 'bg-mono-50 dark:bg-mono-900 border-mono-200 dark:border-mono-800'
              }`}
            >
              <div className="flex items-start space-x-2">
                {warning.type === 'error' ? (
                  <AlertTriangle className="w-4 h-4 text-mono-900 dark:text-mono-100 flex-shrink-0 mt-0.5" />
                ) : warning.type === 'warning' ? (
                  <AlertTriangle className="w-4 h-4 text-mono-700 dark:text-mono-300 flex-shrink-0 mt-0.5" />
                ) : (
                  <Check className="w-4 h-4 text-mono-600 dark:text-mono-400 flex-shrink-0 mt-0.5" />
                )}
                <div className="flex-1">
                  <p className={`${
                    warning.type === 'error'
                      ? 'text-mono-900 dark:text-mono-100'
                      : warning.type === 'warning'
                      ? 'text-mono-700 dark:text-mono-300'
                      : 'text-mono-600 dark:text-mono-400'
                  }`}>
                    {warning.message}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Cost Estimate */}
      {showCostEstimate && sql.trim() && (
        <div className="p-3 bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded-lg">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <DollarSign className="w-4 h-4 text-mono-600 dark:text-mono-400" />
              <span className="text-sm font-medium text-mono-900 dark:text-mono-100">
                Estimated Cost
              </span>
            </div>
            {estimatingCost ? (
              <Loader2 className="w-4 h-4 animate-spin text-mono-600 dark:text-mono-400" />
            ) : costEstimate ? (
              <div className="text-right">
                <div className="text-sm font-semibold text-mono-900 dark:text-mono-100">
                  ${costEstimate.estimatedCost} per execution
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400">
                  ~{costEstimate.estimatedGB} GB scanned ({costEstimate.confidence} confidence)
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Execute Button */}
      {onExecute && !readOnly && (
        <button
          onClick={handleExecute}
          disabled={!sql.trim() || warnings.some(w => w.type === 'error')}
          className="btn-primary w-full"
        >
          Execute Query
        </button>
      )}

      {/* SQL Reference */}
      <details className="text-xs text-mono-600 dark:text-mono-400">
        <summary className="cursor-pointer hover:text-mono-900 dark:hover:text-mono-100 transition-colors">
          SQL Reference
        </summary>
        <div className="mt-2 space-y-2 p-3 bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded">
          <div>
            <strong>Common Tables:</strong>
            <ul className="list-disc list-inside ml-2 mt-1">
              <li>cloudtrail_logs - AWS API calls</li>
              <li>vpc_flow_logs - Network traffic</li>
              <li>s3_access_logs - S3 bucket access</li>
              <li>lambda_logs - Lambda function logs</li>
            </ul>
          </div>
          <div>
            <strong>Partition Filters (reduce cost):</strong>
            <ul className="list-disc list-inside ml-2 mt-1">
              <li>WHERE dt &gt;= DATE_SUB(CURRENT_DATE, 7)</li>
              <li>WHERE year = '2024' AND month = '11'</li>
            </ul>
          </div>
          <div>
            <strong>Example:</strong>
            <pre className="mt-1 p-2 bg-mono-100 dark:bg-mono-850 rounded text-xs font-mono overflow-x-auto">
{`SELECT eventName, userIdentity.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE dt >= DATE_SUB(CURRENT_DATE, 1)
  AND eventName = 'ConsoleLogin'
LIMIT 100`}
            </pre>
          </div>
        </div>
      </details>
    </div>
  );
}
