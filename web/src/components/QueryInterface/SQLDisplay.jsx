import { useState } from 'react'
import { ClipboardIcon, CheckIcon, PencilIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

export default function SQLDisplay({ sql, warnings = [], onEdit }) {
  const [copied, setCopied] = useState(false)
  const [isEditing, setIsEditing] = useState(false)
  const [editedSql, setEditedSql] = useState(sql)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(sql)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleSave = () => {
    onEdit(editedSql)
    setIsEditing(false)
  }

  const handleCancel = () => {
    setEditedSql(sql)
    setIsEditing(false)
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-700">Generated SQL</h3>
        <div className="flex gap-2">
          {!isEditing && (
            <>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-900"
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
                  onClick={() => setIsEditing(true)}
                  className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-900"
                >
                  <PencilIcon className="h-4 w-4" />
                  Edit
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="rounded-lg bg-yellow-50 p-3">
          {warnings.map((warning, index) => (
            <p key={index} className="text-sm text-yellow-800">
              {warning}
            </p>
          ))}
        </div>
      )}

      {isEditing ? (
        <div className="space-y-2">
          <textarea
            value={editedSql}
            onChange={(e) => setEditedSql(e.target.value)}
            className="input font-mono text-sm"
            rows={10}
          />
          <div className="flex gap-2">
            <button onClick={handleSave} className="btn btn-primary text-sm">
              Save
            </button>
            <button onClick={handleCancel} className="btn btn-secondary text-sm">
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <pre className="overflow-x-auto rounded-lg bg-gray-900 p-4">
          <code className="font-mono text-sm text-green-400">{sql}</code>
        </pre>
      )}
    </div>
  )
}
