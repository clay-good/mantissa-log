import { User, Bot, Clock, Code } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

export default function ConversationHistory({ messages, onMessageClick }) {
  if (!messages || messages.length === 0) {
    return (
      <div className="text-center py-12">
        <Bot className="w-12 h-12 mx-auto text-mono-400 dark:text-mono-600 mb-3" />
        <p className="text-sm text-mono-600 dark:text-mono-400">
          No conversation history yet
        </p>
        <p className="text-xs text-mono-500 dark:text-mono-500 mt-1">
          Ask a question to start a conversation
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {messages.map((message, index) => (
        <div
          key={index}
          className={`flex items-start space-x-3 animate-slide-up ${
            message.role === 'user' ? 'flex-row' : 'flex-row'
          }`}
        >
          {/* Avatar */}
          <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${
            message.role === 'user'
              ? 'bg-mono-200 dark:bg-mono-800'
              : 'bg-mono-900 dark:bg-mono-100'
          }`}>
            {message.role === 'user' ? (
              <User className="w-4 h-4 text-mono-700 dark:text-mono-300" />
            ) : (
              <Bot className="w-4 h-4 text-mono-50 dark:text-mono-950" />
            )}
          </div>

          {/* Message Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2 mb-1">
              <span className="text-sm font-medium text-mono-900 dark:text-mono-100">
                {message.role === 'user' ? 'You' : 'Assistant'}
              </span>
              {message.timestamp && (
                <span className="text-xs text-mono-500 dark:text-mono-500 flex items-center">
                  <Clock className="w-3 h-3 mr-1" />
                  {formatDistanceToNow(new Date(message.timestamp), { addSuffix: true })}
                </span>
              )}
            </div>

            {/* Message Text */}
            <div className={`text-sm rounded-lg p-3 ${
              message.role === 'user'
                ? 'bg-mono-100 dark:bg-mono-850 text-mono-900 dark:text-mono-100'
                : 'bg-white dark:bg-mono-900 border border-mono-200 dark:border-mono-800 text-mono-800 dark:text-mono-200'
            }`}>
              <p className="whitespace-pre-wrap">{message.content}</p>
            </div>

            {/* Message Metadata (SQL, Results, etc.) */}
            {message.metadata && message.metadata.sql && (
              <div className="mt-2">
                <button
                  onClick={() => onMessageClick && onMessageClick(message)}
                  className="group inline-flex items-center space-x-1 text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100 transition-colors"
                >
                  <Code className="w-3 h-3" />
                  <span className="underline decoration-mono-400 dark:decoration-mono-600 group-hover:decoration-mono-900 dark:group-hover:decoration-mono-100">
                    View SQL Query
                  </span>
                </button>
              </div>
            )}

            {message.metadata && message.metadata.warnings && message.metadata.warnings.length > 0 && (
              <div className="mt-2 p-2 bg-mono-150 dark:bg-mono-850 border border-mono-300 dark:border-mono-700 rounded text-xs">
                <p className="font-medium text-mono-800 dark:text-mono-200 mb-1">Warnings:</p>
                <ul className="list-disc list-inside text-mono-700 dark:text-mono-300 space-y-0.5">
                  {message.metadata.warnings.map((warning, idx) => (
                    <li key={idx}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
