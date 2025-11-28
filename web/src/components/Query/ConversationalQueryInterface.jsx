import { useState, useEffect, useRef } from 'react';
import { Send, MessageSquare, Sparkles, History, X, RotateCcw } from 'lucide-react';

export default function ConversationalQueryInterface({ userId, onQueryExecute }) {
  const [sessionId, setSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionSummary, setSessionSummary] = useState('');
  const messagesEndRef = useRef(null);

  useEffect(() => {
    // Create new session on mount
    createNewSession();
  }, [userId]);

  useEffect(() => {
    // Scroll to bottom when messages change
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const createNewSession = async () => {
    try {
      const response = await fetch('/api/conversation/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId })
      });

      if (!response.ok) {
        throw new Error('Failed to create session');
      }

      const data = await response.json();
      setSessionId(data.session_id);
      setMessages([]);
      setSessionSummary('');
    } catch (err) {
      console.error('Error creating session:', err);
    }
  };

  const sendMessage = async () => {
    if (!inputValue.trim() || !sessionId) return;

    const userMessage = inputValue.trim();
    setInputValue('');

    // Add user message to UI immediately
    setMessages(prev => [...prev, {
      role: 'user',
      content: userMessage,
      timestamp: new Date().toISOString()
    }]);

    setLoading(true);

    try {
      const response = await fetch('/api/conversation/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          session_id: sessionId,
          message: userMessage
        })
      });

      if (!response.ok) {
        throw new Error('Query failed');
      }

      const data = await response.json();

      // Add assistant response
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.response,
        timestamp: new Date().toISOString(),
        sql: data.sql,
        results: data.results,
        result_count: data.result_count,
        cost: data.cost,
        is_follow_up: data.is_follow_up
      }]);

      // Update session summary
      if (data.session_summary) {
        setSessionSummary(data.session_summary);
      }

      // Notify parent of query execution
      if (onQueryExecute && data.sql) {
        onQueryExecute({
          sql: data.sql,
          results: data.results,
          result_count: data.result_count
        });
      }

    } catch (err) {
      console.error('Error sending message:', err);

      // Add error message
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Sorry, I encountered an error processing your request. Please try again.',
        timestamp: new Date().toISOString(),
        error: true
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-mono-200 dark:border-mono-800">
        <div className="flex items-center">
          <MessageSquare className="w-5 h-5 mr-2 text-mono-600 dark:text-mono-400" />
          <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
            Conversational Query
          </h2>
        </div>

        <div className="flex items-center space-x-2">
          {sessionSummary && (
            <div className="text-xs text-mono-600 dark:text-mono-400 max-w-md truncate">
              {sessionSummary}
            </div>
          )}

          <button
            onClick={createNewSession}
            className="p-2 text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 hover:bg-mono-100 dark:hover:bg-mono-850 rounded"
            title="Start new conversation"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Sparkles className="w-12 h-12 text-mono-400 dark:text-mono-600 mb-4" />
            <h3 className="text-lg font-semibold text-mono-950 dark:text-mono-50 mb-2">
              Start a Conversation
            </h3>
            <p className="text-sm text-mono-600 dark:text-mono-400 max-w-md">
              Ask questions about your logs in natural language. I'll remember the context
              and you can refine your queries with follow-up questions.
            </p>

            <div className="mt-6 space-y-2">
              <p className="text-xs font-semibold text-mono-700 dark:text-mono-300 mb-2">
                Try asking:
              </p>
              {[
                "Show me failed login attempts in the last hour",
                "Filter to only admin users",
                "Group by source IP and count failures",
                "Show me the top 10 IPs"
              ].map((example, index) => (
                <button
                  key={index}
                  onClick={() => setInputValue(example)}
                  className="block w-full text-left px-3 py-2 text-sm bg-mono-50 dark:bg-mono-900 hover:bg-mono-100 dark:hover:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded text-mono-700 dark:text-mono-300"
                >
                  "{example}"
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {messages.map((message, index) => (
              <Message
                key={index}
                message={message}
                isLast={index === messages.length - 1}
              />
            ))}
            {loading && (
              <div className="flex items-center text-mono-600 dark:text-mono-400">
                <div className="animate-pulse flex space-x-2">
                  <div className="w-2 h-2 bg-mono-600 dark:bg-mono-400 rounded-full"></div>
                  <div className="w-2 h-2 bg-mono-600 dark:bg-mono-400 rounded-full"></div>
                  <div className="w-2 h-2 bg-mono-600 dark:bg-mono-400 rounded-full"></div>
                </div>
                <span className="ml-3 text-sm">Thinking...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </>
        )}
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-mono-200 dark:border-mono-800">
        <div className="flex space-x-2">
          <textarea
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask a question or refine the previous query..."
            rows={2}
            disabled={loading || !sessionId}
            className="flex-1 px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded text-mono-900 dark:text-mono-50 placeholder-mono-500 dark:placeholder-mono-500 focus:outline-none focus:ring-2 focus:ring-mono-400 dark:focus:ring-mono-600 resize-none"
          />
          <button
            onClick={sendMessage}
            disabled={!inputValue.trim() || loading || !sessionId}
            className="px-4 py-2 bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950 rounded hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>

        <div className="mt-2 text-xs text-mono-600 dark:text-mono-400">
          Press Enter to send, Shift+Enter for new line
        </div>
      </div>
    </div>
  );
}

function Message({ message, isLast }) {
  const [showSQL, setShowSQL] = useState(false);
  const [showResults, setShowResults] = useState(false);

  const isUser = message.role === 'user';

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div className={`max-w-3xl ${isUser ? 'ml-12' : 'mr-12'}`}>
        {/* Message bubble */}
        <div
          className={`rounded-lg p-3 ${
            isUser
              ? 'bg-mono-900 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
              : message.error
              ? 'bg-mono-200 dark:bg-mono-800 text-mono-900 dark:text-mono-100 border border-mono-400 dark:border-mono-600'
              : 'bg-mono-100 dark:bg-mono-850 text-mono-900 dark:text-mono-50'
          }`}
        >
          {/* Follow-up indicator */}
          {!isUser && message.is_follow_up && (
            <div className="flex items-center text-xs text-mono-600 dark:text-mono-400 mb-2">
              <History className="w-3 h-3 mr-1" />
              <span>Follow-up query</span>
            </div>
          )}

          {/* Message content */}
          <div className="text-sm whitespace-pre-wrap">{message.content}</div>

          {/* SQL and Results (for assistant messages) */}
          {!isUser && message.sql && (
            <div className="mt-3 space-y-2">
              {/* SQL Toggle */}
              <button
                onClick={() => setShowSQL(!showSQL)}
                className="text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 underline"
              >
                {showSQL ? 'Hide SQL' : 'Show SQL'}
              </button>

              {showSQL && (
                <pre className="p-2 bg-mono-50 dark:bg-mono-900 border border-mono-200 dark:border-mono-800 rounded text-xs font-mono text-mono-900 dark:text-mono-50 overflow-x-auto">
                  {message.sql}
                </pre>
              )}

              {/* Results info */}
              {message.result_count !== undefined && (
                <div className="flex items-center justify-between text-xs text-mono-600 dark:text-mono-400">
                  <span>{message.result_count} rows returned</span>
                  {message.cost && (
                    <span>${message.cost.toFixed(6)} cost</span>
                  )}
                </div>
              )}

              {/* Results Toggle */}
              {message.results && message.results.length > 0 && (
                <>
                  <button
                    onClick={() => setShowResults(!showResults)}
                    className="text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 underline"
                  >
                    {showResults ? 'Hide Results' : 'Show Results Preview'}
                  </button>

                  {showResults && (
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-xs border border-mono-200 dark:border-mono-800">
                        <thead>
                          <tr className="bg-mono-100 dark:bg-mono-850">
                            {Object.keys(message.results[0]).map((key) => (
                              <th
                                key={key}
                                className="px-2 py-1 text-left font-semibold text-mono-900 dark:text-mono-50 border-b border-mono-200 dark:border-mono-800"
                              >
                                {key}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {message.results.slice(0, 5).map((row, idx) => (
                            <tr
                              key={idx}
                              className="border-b border-mono-200 dark:border-mono-800"
                            >
                              {Object.values(row).map((value, vidx) => (
                                <td
                                  key={vidx}
                                  className="px-2 py-1 text-mono-700 dark:text-mono-300 font-mono"
                                >
                                  {String(value)}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {message.results.length > 5 && (
                        <div className="text-xs text-mono-600 dark:text-mono-400 mt-1">
                          Showing 5 of {message.results.length} rows
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {/* Timestamp */}
        <div className={`mt-1 text-xs text-mono-500 dark:text-mono-500 ${isUser ? 'text-right' : 'text-left'}`}>
          {new Date(message.timestamp).toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
}
