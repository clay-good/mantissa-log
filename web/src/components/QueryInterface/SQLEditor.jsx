import { useState, useRef, useEffect } from 'react'
import { ClipboardIcon, CheckIcon, PencilIcon, ArrowUturnLeftIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

// SQL keywords for syntax highlighting
const SQL_KEYWORDS = [
  'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'AS', 'JOIN', 'LEFT', 'RIGHT',
  'INNER', 'OUTER', 'ON', 'GROUP', 'BY', 'HAVING', 'ORDER', 'ASC', 'DESC', 'LIMIT',
  'OFFSET', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MAX', 'MIN', 'CASE', 'WHEN', 'THEN',
  'ELSE', 'END', 'CAST', 'LIKE', 'BETWEEN', 'IS', 'NULL', 'TRUE', 'FALSE', 'WITH',
  'UNION', 'INTERSECT', 'EXCEPT', 'EXISTS', 'ANY', 'ALL', 'INTERVAL'
]

const SQL_FUNCTIONS = [
  'CURRENT_TIMESTAMP', 'CURRENT_DATE', 'NOW', 'DATE', 'TIMESTAMP', 'SUBSTRING',
  'LOWER', 'UPPER', 'TRIM', 'LTRIM', 'RTRIM', 'LENGTH', 'COALESCE', 'NULLIF',
  'EXTRACT', 'DATE_TRUNC', 'DATE_ADD', 'DATE_SUB', 'REGEXP_LIKE', 'REGEXP_REPLACE'
]

function escapeHtml(text) {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

function highlightSQL(sql) {
  if (!sql) return ''

  // SECURITY: Escape HTML entities first to prevent XSS
  let highlighted = escapeHtml(sql)

  // Highlight strings (single and double quotes)
  highlighted = highlighted.replace(
    /('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/g,
    '<span class="text-green-400">$1</span>'
  )

  // Highlight numbers
  highlighted = highlighted.replace(
    /\b(\d+\.?\d*)\b/g,
    '<span class="text-yellow-400">$1</span>'
  )

  // Highlight SQL keywords
  SQL_KEYWORDS.forEach(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi')
    highlighted = highlighted.replace(
      regex,
      `<span class="text-purple-400 font-semibold">${keyword}</span>`
    )
  })

  // Highlight SQL functions
  SQL_FUNCTIONS.forEach(func => {
    const regex = new RegExp(`\\b${func}\\b`, 'gi')
    highlighted = highlighted.replace(
      regex,
      `<span class="text-blue-400">${func}</span>`
    )
  })

  // Highlight comments
  highlighted = highlighted.replace(
    /(--[^\n]*)/g,
    '<span class="text-gray-500 italic">$1</span>'
  )

  return highlighted
}

export default function SQLEditor({ sql, warnings = [], onEdit, onRevert }) {
  const [copied, setCopied] = useState(false)
  const [isEditing, setIsEditing] = useState(false)
  const [editedSql, setEditedSql] = useState(sql)
  const [validationErrors, setValidationErrors] = useState([])
  const textareaRef = useRef(null)

  useEffect(() => {
    setEditedSql(sql)
  }, [sql])

  const handleCopy = async () => {
    await navigator.clipboard.writeText(sql)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const validateSQL = (sqlText) => {
    const errors = []

    // Basic SQL validation
    if (!sqlText.trim().toUpperCase().startsWith('SELECT')) {
      errors.push('Query must start with SELECT')
    }

    if (!sqlText.toUpperCase().includes('FROM')) {
      errors.push('Query must include FROM clause')
    }

    // Check for potentially dangerous operations
    if (/DROP\s+TABLE|DELETE\s+FROM|TRUNCATE|ALTER\s+TABLE/i.test(sqlText)) {
      errors.push('Dangerous operations (DROP, DELETE, TRUNCATE, ALTER) are not allowed')
    }

    // Check for balanced parentheses
    const openParens = (sqlText.match(/\(/g) || []).length
    const closeParens = (sqlText.match(/\)/g) || []).length
    if (openParens !== closeParens) {
      errors.push('Unbalanced parentheses')
    }

    return errors
  }

  const handleSave = () => {
    const errors = validateSQL(editedSql)
    if (errors.length > 0) {
      setValidationErrors(errors)
      return
    }

    setValidationErrors([])
    onEdit(editedSql)
    setIsEditing(false)
  }

  const handleCancel = () => {
    setEditedSql(sql)
    setValidationErrors([])
    setIsEditing(false)
  }

  const handleRevert = () => {
    if (onRevert) {
      onRevert()
      setEditedSql(sql)
      setValidationErrors([])
      setIsEditing(false)
    }
  }

  const handleEdit = () => {
    setIsEditing(true)
    setTimeout(() => {
      if (textareaRef.current) {
        textareaRef.current.focus()
      }
    }, 0)
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-mono-900 dark:text-mono-100">
          {isEditing ? 'Edit SQL Query' : 'Generated SQL'}
        </h3>
        <div className="flex gap-2">
          {!isEditing && (
            <>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
              >
                {copied ? (
                  <>
                    <CheckIcon className="h-4 w-4" />
                    Copied
                  </>
                ) : (
                  <>
                    <ClipboardIcon className="h-4 w-4" />
                    Copy
                  </>
                )}
              </button>
              {onEdit && (
                <button
                  onClick={handleEdit}
                  className="flex items-center gap-1 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
                >
                  <PencilIcon className="h-4 w-4" />
                  Edit
                </button>
              )}
              {onRevert && editedSql !== sql && (
                <button
                  onClick={handleRevert}
                  className="flex items-center gap-1 text-sm text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
                >
                  <ArrowUturnLeftIcon className="h-4 w-4" />
                  Revert to Original
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 p-3">
          {warnings.map((warning, index) => (
            <p key={index} className="text-sm text-yellow-800 dark:text-yellow-200">
              ⚠ {warning}
            </p>
          ))}
        </div>
      )}

      {validationErrors.length > 0 && (
        <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3 space-y-1">
          {validationErrors.map((error, index) => (
            <p key={index} className="text-sm text-red-800 dark:text-red-200">
              ✕ {error}
            </p>
          ))}
        </div>
      )}

      {isEditing ? (
        <div className="space-y-2">
          <div className="relative">
            <textarea
              ref={textareaRef}
              value={editedSql}
              onChange={(e) => setEditedSql(e.target.value)}
              className="w-full rounded-lg border border-mono-300 dark:border-mono-700 bg-mono-950 dark:bg-mono-900 text-mono-50 font-mono text-sm p-4 focus:outline-none focus:ring-2 focus:ring-mono-500 dark:focus:ring-mono-400 resize-y"
              rows={12}
              spellCheck={false}
            />
          </div>
          <div className="flex items-center justify-between">
            <p className="text-xs text-mono-600 dark:text-mono-400">
              Use caution when editing SQL. Only SELECT queries are allowed.
            </p>
            <div className="flex gap-2">
              <button onClick={handleCancel} className="btn btn-secondary text-sm">
                Cancel
              </button>
              <button onClick={handleSave} className="btn btn-primary text-sm">
                Save Changes
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="relative group">
          <pre className="overflow-x-auto rounded-lg bg-mono-950 dark:bg-mono-900 border border-mono-800 dark:border-mono-850 p-4">
            <code
              className="font-mono text-sm text-mono-50"
              dangerouslySetInnerHTML={{ __html: highlightSQL(sql) }}
            />
          </pre>
        </div>
      )}
    </div>
  )
}
