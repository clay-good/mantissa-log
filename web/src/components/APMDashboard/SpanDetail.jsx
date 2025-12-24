import { useState } from 'react'
import clsx from 'clsx'
import {
  XMarkIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  ClockIcon,
  ServerIcon,
  TagIcon,
  LinkIcon,
  BoltIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

/**
 * Span Detail Panel
 *
 * Shows detailed information about a selected span in the trace viewer.
 */

function formatDuration(ms) {
  if (ms === null || ms === undefined) return '-'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${Math.round(ms)}ms`
}

function formatTimestamp(ts) {
  if (!ts) return '-'
  const date = new Date(ts)
  return date.toLocaleString() + '.' + String(date.getMilliseconds()).padStart(3, '0')
}

function getStatusColor(status) {
  if (status === 'error') return 'text-red-500'
  if (status === 'ok') return 'text-green-500'
  return 'text-mono-500'
}

function getKindLabel(kind) {
  const kinds = {
    client: 'Client',
    server: 'Server',
    producer: 'Producer',
    consumer: 'Consumer',
    internal: 'Internal',
  }
  return kinds[kind] || kind || 'Unknown'
}

export default function SpanDetail({ span, traceStart, onClose, onCopyId, copiedId }) {
  const [expandedSections, setExpandedSections] = useState({
    basic: true,
    attributes: true,
    events: false,
    resource: false,
    links: false,
  })

  if (!span) return null

  const toggleSection = (section) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }))
  }

  const handleCopy = async (text, id) => {
    try {
      await navigator.clipboard.writeText(text)
      if (onCopyId) {
        onCopyId(id)
      }
      toast.success('Copied')
    } catch {
      toast.error('Failed to copy')
    }
  }

  const spanDuration = span.duration_ms ||
    (span.end_time && span.start_time
      ? new Date(span.end_time).getTime() - new Date(span.start_time).getTime()
      : null)

  const relativeStart = traceStart && span.start_time
    ? new Date(span.start_time).getTime() - traceStart
    : null

  // Parse attributes if they're a string
  const attributes = typeof span.attributes === 'string'
    ? JSON.parse(span.attributes || '{}')
    : span.attributes || {}

  // Parse events if they're a string
  const events = typeof span.events === 'string'
    ? JSON.parse(span.events || '[]')
    : span.events || []

  // Parse resource if it's a string
  const resource = typeof span.resource === 'string'
    ? JSON.parse(span.resource || '{}')
    : span.resource || {}

  // Parse links if they're a string
  const links = typeof span.links === 'string'
    ? JSON.parse(span.links || '[]')
    : span.links || []

  return (
    <div className="w-[400px] border-l border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-900 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-950">
        <h3 className="text-sm font-semibold text-mono-900 dark:text-mono-100 truncate">
          {span.operation_name}
        </h3>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-mono-100 dark:hover:bg-mono-800"
        >
          <XMarkIcon className="h-4 w-4 text-mono-500" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {/* Basic Info Section */}
        <Section
          title="Basic Info"
          icon={ClockIcon}
          expanded={expandedSections.basic}
          onToggle={() => toggleSection('basic')}
        >
          <div className="space-y-3">
            <InfoRow label="Service" value={span.service_name} />
            <InfoRow label="Operation" value={span.operation_name} />
            <InfoRow
              label="Status"
              value={
                <span className={clsx('font-medium capitalize', getStatusColor(span.status))}>
                  {span.status || 'unknown'}
                </span>
              }
            />
            <InfoRow label="Kind" value={getKindLabel(span.kind)} />
            <InfoRow label="Duration" value={formatDuration(spanDuration)} />
            {relativeStart !== null && (
              <InfoRow label="Started at" value={`+${formatDuration(relativeStart)}`} />
            )}
            <InfoRow label="Start Time" value={formatTimestamp(span.start_time)} mono />
            <InfoRow label="End Time" value={formatTimestamp(span.end_time)} mono />

            {/* IDs with copy buttons */}
            <div className="pt-2 border-t border-mono-200 dark:border-mono-800">
              <IdRow
                label="Trace ID"
                value={span.trace_id}
                copied={copiedId === span.trace_id}
                onCopy={() => handleCopy(span.trace_id, span.trace_id)}
              />
              <IdRow
                label="Span ID"
                value={span.span_id}
                copied={copiedId === span.span_id}
                onCopy={() => handleCopy(span.span_id, span.span_id)}
              />
              {span.parent_span_id && (
                <IdRow
                  label="Parent ID"
                  value={span.parent_span_id}
                  copied={copiedId === span.parent_span_id}
                  onCopy={() => handleCopy(span.parent_span_id, span.parent_span_id)}
                />
              )}
            </div>
          </div>
        </Section>

        {/* Attributes Section */}
        <Section
          title={`Attributes (${Object.keys(attributes).length})`}
          icon={TagIcon}
          expanded={expandedSections.attributes}
          onToggle={() => toggleSection('attributes')}
        >
          {Object.keys(attributes).length > 0 ? (
            <div className="space-y-1">
              {Object.entries(attributes).map(([key, value]) => (
                <div key={key} className="flex justify-between items-start py-1">
                  <span className="text-xs text-mono-500 truncate max-w-[140px]" title={key}>
                    {key}
                  </span>
                  <span
                    className="text-xs font-mono text-mono-700 dark:text-mono-300 text-right truncate max-w-[200px]"
                    title={String(value)}
                  >
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-mono-500">No attributes</p>
          )}
        </Section>

        {/* Events Section */}
        <Section
          title={`Events (${events.length})`}
          icon={BoltIcon}
          expanded={expandedSections.events}
          onToggle={() => toggleSection('events')}
        >
          {events.length > 0 ? (
            <div className="space-y-2">
              {events.map((event, idx) => (
                <div key={idx} className="p-2 bg-mono-100 dark:bg-mono-800 rounded">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-mono-900 dark:text-mono-100">
                      {event.name}
                    </span>
                    <span className="text-[10px] text-mono-500">
                      {formatTimestamp(event.timestamp)}
                    </span>
                  </div>
                  {event.attributes && Object.keys(event.attributes).length > 0 && (
                    <div className="mt-1 space-y-0.5">
                      {Object.entries(event.attributes).slice(0, 5).map(([k, v]) => (
                        <div key={k} className="text-[10px] text-mono-500">
                          <span className="text-mono-400">{k}:</span>{' '}
                          <span className="text-mono-600 dark:text-mono-400">
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))}
                      {Object.keys(event.attributes).length > 5 && (
                        <span className="text-[10px] text-mono-400">
                          +{Object.keys(event.attributes).length - 5} more
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-mono-500">No events</p>
          )}
        </Section>

        {/* Resource Section */}
        <Section
          title="Resource"
          icon={ServerIcon}
          expanded={expandedSections.resource}
          onToggle={() => toggleSection('resource')}
        >
          {Object.keys(resource).length > 0 ? (
            <div className="space-y-1">
              {Object.entries(resource).map(([key, value]) => (
                <div key={key} className="flex justify-between items-start py-1">
                  <span className="text-xs text-mono-500 truncate max-w-[140px]" title={key}>
                    {key}
                  </span>
                  <span
                    className="text-xs font-mono text-mono-700 dark:text-mono-300 text-right truncate max-w-[200px]"
                    title={String(value)}
                  >
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-mono-500">No resource attributes</p>
          )}
        </Section>

        {/* Links Section */}
        <Section
          title={`Links (${links.length})`}
          icon={LinkIcon}
          expanded={expandedSections.links}
          onToggle={() => toggleSection('links')}
        >
          {links.length > 0 ? (
            <div className="space-y-2">
              {links.map((link, idx) => (
                <div key={idx} className="p-2 bg-mono-100 dark:bg-mono-800 rounded">
                  <IdRow
                    label="Trace"
                    value={link.trace_id}
                    copied={copiedId === link.trace_id}
                    onCopy={() => handleCopy(link.trace_id, link.trace_id)}
                    small
                  />
                  <IdRow
                    label="Span"
                    value={link.span_id}
                    copied={copiedId === link.span_id}
                    onCopy={() => handleCopy(link.span_id, link.span_id)}
                    small
                  />
                  {link.attributes && Object.keys(link.attributes).length > 0 && (
                    <div className="mt-1 pt-1 border-t border-mono-200 dark:border-mono-700">
                      {Object.entries(link.attributes).slice(0, 3).map(([k, v]) => (
                        <div key={k} className="text-[10px] text-mono-500">
                          {k}: {String(v)}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-mono-500">No linked spans</p>
          )}
        </Section>
      </div>
    </div>
  )
}

function Section({ title, icon: Icon, expanded, onToggle, children }) {
  return (
    <div className="border-b border-mono-200 dark:border-mono-800">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-4 py-2 hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
      >
        {expanded ? (
          <ChevronDownIcon className="h-3 w-3 text-mono-500" />
        ) : (
          <ChevronRightIcon className="h-3 w-3 text-mono-500" />
        )}
        <Icon className="h-4 w-4 text-mono-400" />
        <span className="text-xs font-medium text-mono-700 dark:text-mono-300">
          {title}
        </span>
      </button>
      {expanded && (
        <div className="px-4 pb-3">
          {children}
        </div>
      )}
    </div>
  )
}

function InfoRow({ label, value, mono = false }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-xs text-mono-500">{label}</span>
      <span className={clsx(
        'text-xs text-mono-700 dark:text-mono-300',
        mono && 'font-mono'
      )}>
        {value}
      </span>
    </div>
  )
}

function IdRow({ label, value, copied, onCopy, small = false }) {
  if (!value) return null

  return (
    <div className={clsx('flex items-center justify-between', small ? 'py-0.5' : 'py-1')}>
      <span className={clsx('text-mono-500', small ? 'text-[10px]' : 'text-xs')}>
        {label}
      </span>
      <div className="flex items-center gap-1">
        <code className={clsx(
          'font-mono text-mono-600 dark:text-mono-400',
          small ? 'text-[10px]' : 'text-xs'
        )}>
          {value.substring(0, 16)}...
        </code>
        <button
          onClick={onCopy}
          className="p-0.5 rounded hover:bg-mono-200 dark:hover:bg-mono-700"
          title={`Copy ${label}`}
        >
          {copied ? (
            <CheckIcon className={clsx('text-green-500', small ? 'h-3 w-3' : 'h-3.5 w-3.5')} />
          ) : (
            <ClipboardDocumentIcon className={clsx('text-mono-400', small ? 'h-3 w-3' : 'h-3.5 w-3.5')} />
          )}
        </button>
      </div>
    </div>
  )
}
