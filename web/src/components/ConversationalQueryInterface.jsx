import { useState, useEffect } from 'react';
import { Send, RotateCcw, Trash2 } from 'lucide-react';
import ConversationHistory from './ConversationHistory';
import CostProjection from './CostProjection';

export default function ConversationalQueryInterface() {
  const [question, setQuestion] = useState('');
  const [sessionId, setSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [currentSQL, setCurrentSQL] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!question.trim() || loading) return;

    setLoading(true);

    try {
      // Add user message optimistically
      const userMessage = {
        role: 'user',
        content: question,
        timestamp: new Date().toISOString()
      };
      setMessages(prev => [...prev, userMessage]);

      // Call API with conversation context
      const response = await fetch('/api/conversational-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question,
          sessionId,
          userId: 'current-user' // TODO: Get from auth context
        })
      });

      const data = await response.json();

      // Update session ID if new
      if (data.sessionId && !sessionId) {
        setSessionId(data.sessionId);
      }

      // Add assistant response
      const assistantMessage = {
        role: 'assistant',
        content: data.explanation,
        timestamp: new Date().toISOString(),
        metadata: {
          sql: data.sql,
          warnings: data.warnings || []
        }
      };
      setMessages(prev => [...prev, assistantMessage]);
      setCurrentSQL(data.sql);

      // Clear input
      setQuestion('');

    } catch (error) {
      console.error('Error generating query:', error);
      // Add error message
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Sorry, I encountered an error processing your request.',
        timestamp: new Date().toISOString(),
        metadata: { warnings: [error.message] }
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleNewConversation = () => {
    if (window.confirm('Start a new conversation? This will clear the current conversation history.')) {
      setSessionId(null);
      setMessages([]);
      setCurrentSQL(null);
      setQuestion('');
    }
  };

  const handleClearHistory = () => {
    if (window.confirm('Clear conversation history? This cannot be undone.')) {
      setMessages([]);
    }
  };

  const handleMessageClick = (message) => {
    if (message.metadata?.sql) {
      setCurrentSQL(message.metadata.sql);
    }
  };

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-mono-950 dark:text-mono-50 mb-2">
              Conversational Query
            </h1>
            <p className="text-mono-600 dark:text-mono-400">
              Ask questions about your logs in natural language. Context is preserved across messages.
            </p>
          </div>

          {messages.length > 0 && (
            <div className="flex space-x-2">
              <button
                onClick={handleClearHistory}
                className="btn-secondary text-sm flex items-center space-x-1"
              >
                <Trash2 className="w-4 h-4" />
                <span className="hidden sm:inline">Clear History</span>
              </button>
              <button
                onClick={handleNewConversation}
                className="btn-secondary text-sm flex items-center space-x-1"
              >
                <RotateCcw className="w-4 h-4" />
                <span className="hidden sm:inline">New Conversation</span>
              </button>
            </div>
          )}
        </div>

        {sessionId && (
          <div className="mt-3 inline-flex items-center px-3 py-1 bg-mono-100 dark:bg-mono-850 border border-mono-200 dark:border-mono-800 rounded-lg">
            <div className="w-2 h-2 bg-mono-900 dark:bg-mono-100 rounded-full mr-2 animate-pulse"></div>
            <span className="text-xs text-mono-700 dark:text-mono-300">
              Session active
            </span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Conversation Area */}
        <div className="lg:col-span-2 space-y-6">
          {/* Conversation History */}
          {messages.length > 0 && (
            <div className="card max-h-[500px] overflow-y-auto">
              <ConversationHistory
                messages={messages}
                onMessageClick={handleMessageClick}
              />
            </div>
          )}

          {/* Input Area */}
          <div className="card">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="label">
                  {messages.length === 0 ? 'Ask a question' : 'Follow-up question'}
                </label>
                <div className="relative">
                  <textarea
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder={
                      messages.length === 0
                        ? "e.g., Show me all failed login attempts in the last hour"
                        : "e.g., And filter by user admin"
                    }
                    rows={3}
                    className="input resize-none pr-12"
                    disabled={loading}
                  />
                  <button
                    type="submit"
                    disabled={!question.trim() || loading}
                    className="absolute bottom-2 right-2 p-2 rounded-lg bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 disabled:opacity-30 hover:bg-mono-800 dark:hover:bg-mono-200 transition-colors"
                  >
                    {loading ? (
                      <div className="w-5 h-5 border-2 border-mono-200 dark:border-mono-800 border-t-mono-50 dark:border-t-mono-950 rounded-full animate-spin" />
                    ) : (
                      <Send className="w-5 h-5" />
                    )}
                  </button>
                </div>
              </div>

              {messages.length > 0 && (
                <div className="bg-mono-50 dark:bg-mono-850 rounded-lg p-3 border border-mono-200 dark:border-mono-800">
                  <p className="text-xs text-mono-700 dark:text-mono-300">
                    <span className="font-medium">Context-aware:</span> I remember our conversation. You can ask follow-up questions like "and show the top 5" or "filter by today only".
                  </p>
                </div>
              )}
            </form>
          </div>

          {/* Current SQL Display */}
          {currentSQL && (
            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold text-mono-900 dark:text-mono-100">
                  Generated SQL Query
                </h3>
                <button
                  onClick={() => navigator.clipboard.writeText(currentSQL)}
                  className="text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 underline"
                >
                  Copy
                </button>
              </div>
              <pre className="bg-mono-950 dark:bg-mono-900 text-mono-100 dark:text-mono-200 p-4 rounded-lg overflow-x-auto text-sm font-mono border border-mono-800">
                {currentSQL}
              </pre>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="lg:col-span-1 space-y-6">
          {/* Quick Examples */}
          <div className="card">
            <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
              Example Questions
            </h3>
            <div className="space-y-2">
              {[
                'Show me failed login attempts',
                'What are the most common API calls?',
                'Find suspicious network traffic',
                'Show GuardDuty high severity findings'
              ].map((example, idx) => (
                <button
                  key={idx}
                  onClick={() => setQuestion(example)}
                  className="w-full text-left p-2 rounded-lg text-sm text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors border border-transparent hover:border-mono-200 dark:hover:border-mono-800"
                >
                  {example}
                </button>
              ))}
            </div>
          </div>

          {/* Follow-up Examples */}
          {messages.length > 0 && (
            <div className="card">
              <h3 className="font-semibold text-mono-900 dark:text-mono-100 mb-3">
                Try Follow-ups
              </h3>
              <div className="space-y-2">
                {[
                  'Show only the top 10 results',
                  'Filter by last 24 hours',
                  'Group by user',
                  'Order by count descending'
                ].map((example, idx) => (
                  <button
                    key={idx}
                    onClick={() => setQuestion(example)}
                    className="w-full text-left p-2 rounded-lg text-sm text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors border border-transparent hover:border-mono-200 dark:hover:border-mono-800"
                  >
                    {example}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
