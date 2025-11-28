import { useState } from 'react';
import { Search, Code2, Save, Settings } from 'lucide-react';
import SQLEditor from './SQLEditor';
import ConversationalInterface from './ConversationalInterface';
import DetectionRuleWizardV3 from './DetectionRuleWizardV3';

export default function EnhancedQueryInterface({ userId }) {
  const [mode, setMode] = useState('natural'); // 'natural' or 'sql'
  const [currentQuery, setCurrentQuery] = useState('');
  const [currentSql, setSql] = useState('');
  const [aiGeneratedSql, setAiGeneratedSql] = useState('');
  const [queryResults, setQueryResults] = useState(null);
  const [showWizard, setShowWizard] = useState(false);

  const handleNaturalLanguageQuery = async (naturalLanguage) => {
    try {
      // Generate SQL from natural language
      const response = await fetch('/api/nlp/generate-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_message: naturalLanguage,
          user_id: userId
        })
      });

      if (!response.ok) throw new Error('Failed to generate query');

      const data = await response.json();
      const { sql, explanation } = data;

      setCurrentQuery(naturalLanguage);
      setSql(sql);
      setAiGeneratedSql(sql);

      // Execute the query
      await executeQuery(sql);

      return { sql, explanation };
    } catch (err) {
      console.error('Error generating query:', err);
      throw err;
    }
  };

  const executeQuery = async (sql) => {
    try {
      const response = await fetch('/api/query/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: sql,
          database: 'mantissa_log'
        })
      });

      if (!response.ok) throw new Error('Failed to execute query');

      const results = await response.json();
      setQueryResults(results);

      return results;
    } catch (err) {
      console.error('Error executing query:', err);
      throw err;
    }
  };

  const handleSqlChange = (newSql) => {
    setSql(newSql);
  };

  const handleSqlExecute = async (sql) => {
    await executeQuery(sql);
  };

  const handleSaveAsDetection = () => {
    if (!currentSql) {
      alert('Please execute a query first');
      return;
    }
    setShowWizard(true);
  };

  const handleCreateDetection = async (detectionConfig) => {
    try {
      const response = await fetch('/api/detections/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          name: detectionConfig.ruleName,
          description: detectionConfig.description,
          query: detectionConfig.query,
          severity: detectionConfig.severity,
          threshold: {
            type: 'count',
            value: detectionConfig.threshold
          },
          schedule_expression: detectionConfig.schedule,
          alert_destinations: detectionConfig.alertDestinations || [],
          enabled: true
        })
      });

      if (!response.ok) throw new Error('Failed to create detection');

      const data = await response.json();

      // Schedule the detection
      await fetch('/api/detections/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          rule_id: data.rule_id,
          schedule_expression: detectionConfig.schedule
        })
      });

      alert(`Detection rule "${detectionConfig.ruleName}" created successfully!`);
    } catch (err) {
      console.error('Error creating detection:', err);
      throw err;
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header with Mode Toggle */}
      <div className="bg-white dark:bg-mono-900 border-b border-mono-200 dark:border-mono-800 p-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-mono-950 dark:text-mono-50">
            Query Interface
          </h1>
          <div className="flex items-center space-x-2">
            <div className="inline-flex rounded-lg border border-mono-200 dark:border-mono-800 p-1">
              <button
                onClick={() => setMode('natural')}
                className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                  mode === 'natural'
                    ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                    : 'text-mono-700 dark:text-mono-300 hover:text-mono-900 dark:hover:text-mono-100'
                }`}
              >
                <Search className="w-4 h-4 inline mr-2" />
                Natural Language
              </button>
              <button
                onClick={() => setMode('sql')}
                className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                  mode === 'sql'
                    ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                    : 'text-mono-700 dark:text-mono-300 hover:text-mono-900 dark:hover:text-mono-100'
                }`}
              >
                <Code2 className="w-4 h-4 inline mr-2" />
                SQL Editor
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-hidden">
        {mode === 'natural' ? (
          <ConversationalInterface
            userId={userId}
            onQueryExecute={executeQuery}
            onDetectionCreate={handleCreateDetection}
          />
        ) : (
          <div className="h-full overflow-y-auto">
            <div className="max-w-5xl mx-auto p-6 space-y-6">
              {/* SQL Editor Section */}
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
                    SQL Query Editor
                  </h2>
                  {currentSql && queryResults && (
                    <button
                      onClick={handleSaveAsDetection}
                      className="btn-secondary text-sm"
                    >
                      <Save className="w-4 h-4 mr-2" />
                      Save as Detection
                    </button>
                  )}
                </div>

                {currentQuery && (
                  <div className="mb-4 p-3 bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded-lg">
                    <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                      Generated from:
                    </div>
                    <div className="text-sm text-mono-900 dark:text-mono-100">
                      "{currentQuery}"
                    </div>
                  </div>
                )}

                <SQLEditor
                  initialSql={currentSql}
                  aiGeneratedSql={aiGeneratedSql}
                  onSqlChange={handleSqlChange}
                  onExecute={handleSqlExecute}
                  showCostEstimate={true}
                />
              </div>

              {/* Query Results */}
              {queryResults && (
                <div className="card">
                  <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-4">
                    Query Results
                  </h3>

                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div>
                      <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                        Results
                      </div>
                      <div className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                        {queryResults.results?.length || 0}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                        Data Scanned
                      </div>
                      <div className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                        {((queryResults.statistics?.data_scanned_bytes || 0) / (1024 * 1024)).toFixed(2)} MB
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-mono-600 dark:text-mono-400 uppercase mb-1">
                        Execution Time
                      </div>
                      <div className="text-2xl font-bold text-mono-900 dark:text-mono-100">
                        {((queryResults.statistics?.execution_time_ms || 0) / 1000).toFixed(2)}s
                      </div>
                    </div>
                  </div>

                  {queryResults.results && queryResults.results.length > 0 && (
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead className="bg-mono-100 dark:bg-mono-850 border-b border-mono-200 dark:border-mono-800">
                          <tr>
                            {Object.keys(queryResults.results[0]).map((key) => (
                              <th
                                key={key}
                                className="px-4 py-3 text-left font-semibold text-mono-900 dark:text-mono-100"
                              >
                                {key}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {queryResults.results.slice(0, 50).map((row, index) => (
                            <tr
                              key={index}
                              className="border-b border-mono-200 dark:border-mono-800 hover:bg-mono-50 dark:hover:bg-mono-900"
                            >
                              {Object.values(row).map((value, colIndex) => (
                                <td
                                  key={colIndex}
                                  className="px-4 py-3 text-mono-700 dark:text-mono-300"
                                >
                                  {typeof value === 'object'
                                    ? JSON.stringify(value)
                                    : String(value)}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {queryResults.results.length > 50 && (
                        <div className="text-xs text-mono-600 dark:text-mono-400 text-center py-3">
                          Showing first 50 of {queryResults.results.length} results
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Detection Rule Wizard Modal */}
      {showWizard && (
        <DetectionRuleWizardV3
          query={currentSql}
          queryStats={{
            data_scanned_bytes: queryResults?.statistics?.data_scanned_bytes || 0,
            execution_time_ms: queryResults?.statistics?.execution_time_ms || 0,
            result_count: queryResults?.results?.length || 0
          }}
          integrations={[]} // Would be fetched from API
          onSave={async (config) => {
            await handleCreateDetection(config);
            setShowWizard(false);
          }}
          onClose={() => setShowWizard(false)}
        />
      )}
    </div>
  );
}
