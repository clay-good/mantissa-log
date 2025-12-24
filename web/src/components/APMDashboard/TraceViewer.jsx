import { useState, useMemo, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  XMarkIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  ExclamationTriangleIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  MinusIcon,
  PlusIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

import { getTrace, buildTraceTree, flattenTraceTree } from '../../services/apmApi'
import SpanDetail from './SpanDetail'

/**
 * Trace Viewer Component
 *
 * Displays a trace as a waterfall/timeline visualization showing all spans
 * with their hierarchical relationships and timing.
 */

function formatDuration(ms) {
  if (ms === null || ms === undefined) return '-'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${Math.round(ms)}ms`
}

function getSpanColor(status, kind) {
  if (status === 'error') return 'bg-red-500'
  if (kind === 'client') return 'bg-blue-500'
  if (kind === 'server') return 'bg-green-500'
  if (kind === 'producer') return 'bg-purple-500'
  if (kind === 'consumer') return 'bg-orange-500'
  return 'bg-mono-400'
}

function getSpanBorderColor(status, kind) {
  if (status === 'error') return 'border-red-600'
  if (kind === 'client') return 'border-blue-600'
  if (kind === 'server') return 'border-green-600'
  if (kind === 'producer') return 'border-purple-600'
  if (kind === 'consumer') return 'border-orange-600'
  return 'border-mono-500'
}

export default function TraceViewer({ traceId, onClose }) {
  const [selectedSpan, setSelectedSpan] = useState(null)
  const [collapsedSpans, setCollapsedSpans] = useState(new Set())
  const [zoom, setZoom] = useState(1)
  const [copiedId, setCopiedId] = useState(null)
  const timelineRef = useRef(null)

  // Fetch trace data
  const {
    data: traceData,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['trace', traceId],
    queryFn: () => getTrace(traceId),
    enabled: !!traceId,
  })

  // Build trace tree and flatten for rendering
  const { flatSpans, traceStart, traceEnd, totalDuration } = useMemo(() => {
    if (!traceData?.spans || traceData.spans.length === 0) {
      return { flatSpans: [], traceStart: 0, traceEnd: 0, totalDuration: 0 }
    }

    const tree = buildTraceTree(traceData.spans)
    const flat = flattenTraceTree(tree)

    // Calculate trace time bounds
    let minStart = Infinity
    let maxEnd = -Infinity
    traceData.spans.forEach((span) => {
      const start = new Date(span.start_time).getTime()
      const end = new Date(span.end_time).getTime()
      minStart = Math.min(minStart, start)
      maxEnd = Math.max(maxEnd, end)
    })

    return {
      flatSpans: flat,
      traceStart: minStart,
      traceEnd: maxEnd,
      totalDuration: maxEnd - minStart,
    }
  }, [traceData])

  // Filter out collapsed spans
  const visibleSpans = useMemo(() => {
    if (collapsedSpans.size === 0) return flatSpans

    const visible = []
    const hiddenParents = new Set()

    flatSpans.forEach((span) => {
      // Check if any ancestor is collapsed
      let isHidden = false
      let current = span
      while (current && current.parent_span_id) {
        if (collapsedSpans.has(current.parent_span_id)) {
          isHidden = true
          break
        }
        // Find parent span
        current = flatSpans.find((s) => s.span_id === current.parent_span_id)
      }

      if (!isHidden) {
        visible.push(span)
      }
    })

    return visible
  }, [flatSpans, collapsedSpans])

  const toggleCollapse = (spanId) => {
    setCollapsedSpans((prev) => {
      const next = new Set(prev)
      if (next.has(spanId)) {
        next.delete(spanId)
      } else {
        next.add(spanId)
      }
      return next
    })
  }

  const handleCopyId = async (id, e) => {
    e?.stopPropagation()
    try {
      await navigator.clipboard.writeText(id)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
      toast.success('Copied')
    } catch {
      toast.error('Failed to copy')
    }
  }

  const handleZoomIn = () => setZoom((z) => Math.min(4, z * 1.5))
  const handleZoomOut = () => setZoom((z) => Math.max(0.25, z / 1.5))
  const handleResetZoom = () => setZoom(1)

  // Generate time ruler marks
  const timeMarks = useMemo(() => {
    if (totalDuration === 0) return []
    const marks = []
    const numMarks = 10
    const interval = totalDuration / numMarks
    for (let i = 0; i <= numMarks; i++) {
      marks.push({
        position: (i / numMarks) * 100,
        label: formatDuration(i * interval),
      })
    }
    return marks
  }, [totalDuration])

  if (!traceId) return null

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-mono-950/50" onClick={onClose} />

      {/* Panel */}
      <div className="relative ml-auto w-full max-w-5xl bg-white dark:bg-mono-950 shadow-xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-mono-200 dark:border-mono-800">
          <div className="flex items-center gap-4">
            <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
              Trace Viewer
            </h2>
            <div className="flex items-center gap-2">
              <code className="text-sm font-mono text-mono-600 dark:text-mono-400">
                {traceId.substring(0, 16)}...
              </code>
              <button
                onClick={(e) => handleCopyId(traceId, e)}
                className="p-1 rounded hover:bg-mono-200 dark:hover:bg-mono-700"
                title="Copy trace ID"
              >
                {copiedId === traceId ? (
                  <CheckIcon className="h-4 w-4 text-green-500" />
                ) : (
                  <ClipboardDocumentIcon className="h-4 w-4 text-mono-400" />
                )}
              </button>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Zoom controls */}
            <div className="flex items-center gap-1 mr-4">
              <button
                onClick={handleZoomOut}
                className="p-1.5 rounded hover:bg-mono-100 dark:hover:bg-mono-800"
                title="Zoom out"
              >
                <MinusIcon className="h-4 w-4 text-mono-600 dark:text-mono-400" />
              </button>
              <button
                onClick={handleResetZoom}
                className="px-2 py-1 text-xs text-mono-600 dark:text-mono-400 hover:text-mono-900 dark:hover:text-mono-100"
              >
                {Math.round(zoom * 100)}%
              </button>
              <button
                onClick={handleZoomIn}
                className="p-1.5 rounded hover:bg-mono-100 dark:hover:bg-mono-800"
                title="Zoom in"
              >
                <PlusIcon className="h-4 w-4 text-mono-600 dark:text-mono-400" />
              </button>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-mono-100 dark:hover:bg-mono-800"
            >
              <XMarkIcon className="h-5 w-5 text-mono-500" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden flex">
          {/* Waterfall */}
          <div className="flex-1 overflow-auto" ref={timelineRef}>
            {isLoading ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <div className="animate-spin h-8 w-8 border-2 border-mono-300 border-t-mono-900 dark:border-mono-600 dark:border-t-mono-100 rounded-full mx-auto"></div>
                  <p className="mt-4 text-mono-600 dark:text-mono-400">Loading trace...</p>
                </div>
              </div>
            ) : error ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center text-red-500">
                  <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4" />
                  <p className="font-medium">Failed to load trace</p>
                  <p className="text-sm mt-1">{error.message}</p>
                </div>
              </div>
            ) : visibleSpans.length === 0 ? (
              <div className="flex items-center justify-center h-full text-mono-500">
                <p>No spans found in this trace</p>
              </div>
            ) : (
              <div className="min-w-max">
                {/* Time Ruler */}
                <div className="sticky top-0 z-10 bg-mono-50 dark:bg-mono-900 border-b border-mono-200 dark:border-mono-800 px-4 py-2">
                  <div className="flex">
                    <div className="w-[300px] shrink-0"></div>
                    <div
                      className="flex-1 relative h-6"
                      style={{ minWidth: `${800 * zoom}px` }}
                    >
                      {timeMarks.map((mark) => (
                        <div
                          key={mark.position}
                          className="absolute top-0 h-full flex flex-col items-center"
                          style={{ left: `${mark.position}%` }}
                        >
                          <div className="h-2 w-px bg-mono-300 dark:bg-mono-600"></div>
                          <span className="text-[10px] text-mono-500">{mark.label}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Spans */}
                <div className="p-4">
                  {visibleSpans.map((span) => {
                    const spanStart = new Date(span.start_time).getTime()
                    const spanDuration = span.duration_ms || (new Date(span.end_time).getTime() - spanStart)
                    const offsetPercent = totalDuration > 0 ? ((spanStart - traceStart) / totalDuration) * 100 : 0
                    const widthPercent = totalDuration > 0 ? (spanDuration / totalDuration) * 100 : 0
                    const isCollapsed = collapsedSpans.has(span.span_id)
                    const isSelected = selectedSpan?.span_id === span.span_id

                    return (
                      <div
                        key={span.span_id}
                        className={clsx(
                          'flex items-center py-1 hover:bg-mono-50 dark:hover:bg-mono-900 rounded cursor-pointer transition-colors',
                          isSelected && 'bg-mono-100 dark:bg-mono-800'
                        )}
                        onClick={() => setSelectedSpan(span)}
                      >
                        {/* Label section */}
                        <div
                          className="w-[300px] shrink-0 flex items-center gap-1 px-2"
                          style={{ paddingLeft: `${8 + span.depth * 16}px` }}
                        >
                          {span.hasChildren && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                toggleCollapse(span.span_id)
                              }}
                              className="p-0.5 rounded hover:bg-mono-200 dark:hover:bg-mono-700"
                            >
                              {isCollapsed ? (
                                <ChevronRightIcon className="h-3 w-3 text-mono-500" />
                              ) : (
                                <ChevronDownIcon className="h-3 w-3 text-mono-500" />
                              )}
                            </button>
                          )}
                          <div
                            className={clsx(
                              'w-2 h-2 rounded-full shrink-0',
                              getSpanColor(span.status, span.kind)
                            )}
                          />
                          <span className="text-xs font-medium text-mono-700 dark:text-mono-300 truncate">
                            {span.service_name}
                          </span>
                          <span className="text-xs text-mono-500 truncate">
                            {span.operation_name}
                          </span>
                        </div>

                        {/* Timeline section */}
                        <div
                          className="flex-1 relative h-6"
                          style={{ minWidth: `${800 * zoom}px` }}
                        >
                          {/* Span bar */}
                          <div
                            className={clsx(
                              'absolute top-1 h-4 rounded-sm border-l-2',
                              getSpanColor(span.status, span.kind),
                              getSpanBorderColor(span.status, span.kind),
                              span.isOrphan && 'opacity-60'
                            )}
                            style={{
                              left: `${offsetPercent}%`,
                              width: `${Math.max(widthPercent, 0.5)}%`,
                            }}
                            title={`${span.operation_name}: ${formatDuration(spanDuration)}`}
                          >
                            {widthPercent > 5 && (
                              <span className="absolute inset-0 flex items-center px-1 text-[10px] text-white truncate">
                                {formatDuration(spanDuration)}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>

                {/* Summary */}
                <div className="px-4 py-3 border-t border-mono-200 dark:border-mono-800 text-xs text-mono-500">
                  <span>{visibleSpans.length} spans</span>
                  <span className="mx-2">|</span>
                  <span>Total duration: {formatDuration(totalDuration)}</span>
                  {traceData?.services && (
                    <>
                      <span className="mx-2">|</span>
                      <span>{traceData.services.length} services</span>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Span Detail Panel */}
          {selectedSpan && (
            <SpanDetail
              span={selectedSpan}
              traceStart={traceStart}
              onClose={() => setSelectedSpan(null)}
              onCopyId={handleCopyId}
              copiedId={copiedId}
            />
          )}
        </div>
      </div>
    </div>
  )
}
