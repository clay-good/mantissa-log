import { useState, useEffect, useRef } from 'react';
import { Send, Bot, Loader2, RotateCcw, History } from 'lucide-react';
import ConversationHistory from './ConversationHistory';

export default function ConversationalInterface({ userId, onQueryExecute, onDetectionCreate }) {
  const [session Id, setSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [context, setContext] = useState({});
  const messagesEndRef = useRef(null);

  // Create session on mount
  useEffect(() => {
    createSession();
  }, [userId]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const createSession = async () => {
    try {
      const response = await fetch('/api/conversation/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId })
      });

      if (!response.ok) throw new Error('Failed to create session');

      const data = await response.json();
      setSessionId(data.session_id);
    } catch (err) {
      setError('Failed to start conversation session');
      console.error(err);
    }
  };

  const resetSession = async () => {
    setMessages([]);
    setContext({});
    await createSession();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!input.trim() || !sessionId) return;

    const userMessage = input.trim();
    setInput('');
    setLoading(true);
    setError(null);

    // Add user message to UI immediately
    const userMsg = {
      role: 'user',
      content: userMessage,
      timestamp: new Date().toISOString()
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      // Add user message to session
      await fetch('/api/conversation/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.dumps({
          session_id: sessionId,
          role: 'user',
          content: userMessage
        })
      });

      // Parse intent and extract entities
      const parseResponse = await fetch('/api/nlp/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.dumps({
          user_message: userMessage,
          session_id: sessionId,
          context: context
        })
      });

      if (!parseResponse.ok) throw new Error('Failed to parse message');

      const parsed = await parseResponse.json();
      const { intent, entities, is_followup } = parsed;

      let assistantResponse = '';
      let metadata = {};

      // Handle different intents
      if (intent === 'query' || intent === 'refine_query') {
        // Generate and execute query
        const queryResponse = await fetch('/api/nlp/generate-query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.dumps({
            user_message: userMessage,
            session_id: sessionId,
            is_followup: is_followup,
            context: context
          })
        });

        if (!queryResponse.ok) throw new Error('Failed to generate query');

        const queryData = await queryResponse.json();
        const { sql, explanation } = queryData;

        // Execute query
        if (onQueryExecute) {
          const results = await onQueryExecute(sql);

          assistantResponse = `${explanation}\n\nFound ${results.count} results.`;
          metadata = {
            sql: sql,
            results: results,
            data_scanned_bytes: results.statistics?.data_scanned_bytes
          };

          // Update context
          setContext(prev => ({
            ...prev,
            current_query: userMessage,
            current_sql: sql,
            last_results: {
              count: results.count,
              execution_time_ms: results.statistics?.execution_time_ms,
              data_scanned_bytes: results.statistics?.data_scanned_bytes
            }
          }));
        }
      } else if (intent === 'create_detection') {
        // Create detection rule
        const detectionConfig = {
          query: context.current_sql,
          name: entities.name || `Detection from ${new Date().toLocaleString()}`,
          severity: entities.severity || 'medium',
          schedule: entities.schedule || 'rate(5 minutes)',
          threshold: entities.threshold || 1
        };

        if (onDetectionCreate) {
          await onDetectionCreate(detectionConfig);
          assistantResponse = `Created detection rule "${detectionConfig.name}" with ${detectionConfig.severity} severity, running ${detectionConfig.schedule}.`;
        }

        // Update context
        setContext(prev => ({
          ...prev,
          pending_action: null,
          detection_config: {}
        }));
      } else if (intent === 'configure_alert') {
        // Configure alert routing
        const integration = entities.integration;

        assistantResponse = `I'll help you configure ${integration} alerts. `;

        if (!context.current_sql) {
          assistantResponse += 'First, let me know what you want to detect by asking a query.';
        } else if (context.pending_action !== 'create_detection') {
          assistantResponse += 'Would you like to save this query as a detection rule first?';
          setContext(prev => ({
            ...prev,
            pending_action: 'create_detection'
          }));
        } else {
          assistantResponse += `Adding ${integration} to alert destinations.`;
          setContext(prev => ({
            ...prev,
            mentioned_integrations: [
              ...(prev.mentioned_integrations || []),
              integration
            ]
          }));
        }
      } else if (intent === 'show_results') {
        // Show previous results
        if (context.last_results) {
          assistantResponse = `The last query returned ${context.last_results.count} results and scanned ${(context.last_results.data_scanned_bytes / (1024 * 1024)).toFixed(2)} MB of data.`;
          metadata = {
            sql: context.current_sql,
            results_summary: context.last_results
          };
        } else {
          assistantResponse = 'No previous results to show. Please run a query first.';
        }
      } else if (intent === 'explain') {
        // Explain query or results
        if (context.current_sql) {
          assistantResponse = `This query searches for events in your logs. The SQL generated was:\n\n\`\`\`sql\n${context.current_sql}\n\`\`\``;
          metadata = { sql: context.current_sql };
        } else {
          assistantResponse = 'I haven't generated a query yet. Ask me to search for something in your logs.';
        }
      } else {
        // Unknown intent
        assistantResponse = 'I'm not sure what you want to do. You can:\n- Ask questions about your logs\n- Create detection rules from queries\n- Configure alert destinations';
      }

      // Add assistant message to session
      await fetch('/api/conversation/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.dumps({
          session_id: sessionId,
          role: 'assistant',
          content: assistantResponse,
          metadata: metadata
        })
      });

      // Add to UI
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: assistantResponse,
        timestamp: new Date().toISOString(),
        metadata: metadata
      }]);

      // Update session context
      if (Object.keys(context).length > 0) {
        await fetch(`/api/conversation/context/${sessionId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.dumps({ context: context })
        });
      }

    } catch (err) {
      setError(err.message);
      console.error('Error processing message:', err);

      // Add error message
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Sorry, I encountered an error: ${err.message}`,
        timestamp: new Date().toISOString(),
        metadata: { error: true }
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-white dark:bg-mono-900">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-mono-200 dark:border-mono-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-mono-900 dark:bg-mono-100 rounded-lg">
            <Bot className="w-5 h-5 text-mono-50 dark:text-mono-950" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
              Conversational Query Interface
            </h2>
            <p className="text-xs text-mono-600 dark:text-mono-400">
              Ask questions in natural language
            </p>
          </div>
        </div>
        <button
          onClick={resetSession}
          className="btn-secondary text-sm"
          disabled={loading}
        >
          <RotateCcw className="w-4 h-4 mr-2" />
          New Session
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Bot className="w-16 h-16 text-mono-300 dark:text-mono-700 mb-4" />
            <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100 mb-2">
              Start a Conversation
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 max-w-md mb-6">
              Ask questions about your logs, create detection rules, and configure alerts all through natural conversation.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-2xl">
              <button
                onClick={() => setInput('Show me failed login attempts in the last 24 hours')}
                className="text-left p-3 bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg hover:border-mono-400 dark:hover:border-mono-600 transition-colors"
              >
                <div className="font-medium text-sm text-mono-900 dark:text-mono-100 mb-1">
                  Search logs
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400">
                  "Show me failed login attempts"
                </div>
              </button>
              <button
                onClick={() => setInput('Create a detection to run every hour')}
                className="text-left p-3 bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg hover:border-mono-400 dark:hover:border-mono-600 transition-colors"
              >
                <div className="font-medium text-sm text-mono-900 dark:text-mono-100 mb-1">
                  Create detection
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400">
                  "Create a detection to run every hour"
                </div>
              </button>
              <button
                onClick={() => setInput('Send alerts to Slack')}
                className="text-left p-3 bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg hover:border-mono-400 dark:hover:border-mono-600 transition-colors"
              >
                <div className="font-medium text-sm text-mono-900 dark:text-mono-100 mb-1">
                  Configure alerts
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400">
                  "Send alerts to Slack"
                </div>
              </button>
              <button
                onClick={() => setInput('Explain what this query does')}
                className="text-left p-3 bg-mono-50 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg hover:border-mono-400 dark:hover:border-mono-600 transition-colors"
              >
                <div className="font-medium text-sm text-mono-900 dark:text-mono-100 mb-1">
                  Get help
                </div>
                <div className="text-xs text-mono-600 dark:text-mono-400">
                  "Explain what this query does"
                </div>
              </button>
            </div>
          </div>
        ) : (
          <ConversationHistory
            messages={messages}
            onMessageClick={(msg) => {
              if (msg.metadata?.sql) {
                console.log('SQL:', msg.metadata.sql);
              }
            }}
          />
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Error Display */}
      {error && (
        <div className="px-4 py-2 bg-mono-100 dark:bg-mono-850 border-t border-mono-300 dark:border-mono-700">
          <p className="text-sm text-mono-900 dark:text-mono-100">{error}</p>
        </div>
      )}

      {/* Input */}
      <form onSubmit={handleSubmit} className="p-4 border-t border-mono-200 dark:border-mono-800">
        <div className="flex items-center space-x-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a question or give a command..."
            className="input flex-1"
            disabled={loading || !sessionId}
          />
          <button
            type="submit"
            className="btn-primary"
            disabled={loading || !input.trim() || !sessionId}
          >
            {loading ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <Send className="w-5 h-5" />
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
