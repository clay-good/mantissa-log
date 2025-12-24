import { useEffect, useRef, useCallback } from 'react'
import clsx from 'clsx'
import {
  ExclamationTriangleIcon,
  ArrowsPointingOutIcon,
  ArrowsPointingInIcon,
  MapIcon,
} from '@heroicons/react/24/outline'

/**
 * Service Map Visualization
 *
 * Renders an interactive service dependency graph using Canvas.
 * Shows services as nodes and their communication patterns as edges.
 *
 * Note: For production use, consider using Cytoscape.js or D3.js for more
 * advanced features. This implementation provides a lightweight alternative.
 */

// Node status colors based on error rate
const getNodeColor = (errorRate, isDark) => {
  if (errorRate >= 0.1) return isDark ? '#ef4444' : '#dc2626' // Red - high errors
  if (errorRate >= 0.05) return isDark ? '#f59e0b' : '#d97706' // Yellow - some errors
  return isDark ? '#22c55e' : '#16a34a' // Green - healthy
}

const getNodeBorderColor = (errorRate, isDark) => {
  if (errorRate >= 0.1) return isDark ? '#fca5a5' : '#f87171'
  if (errorRate >= 0.05) return isDark ? '#fcd34d' : '#fbbf24'
  return isDark ? '#86efac' : '#4ade80'
}

export default function ServiceMap({ data, isLoading, error, onServiceSelect }) {
  const canvasRef = useRef(null)
  const containerRef = useRef(null)
  const nodesRef = useRef([])
  const edgesRef = useRef([])
  const scaleRef = useRef(1)
  const offsetRef = useRef({ x: 0, y: 0 })
  const isDraggingRef = useRef(false)
  const lastMouseRef = useRef({ x: 0, y: 0 })

  // Parse Cytoscape format data into nodes and edges
  const parseData = useCallback(() => {
    if (!data?.elements) return { nodes: [], edges: [] }

    const nodes = []
    const edges = []

    // Parse nodes
    data.elements
      .filter((el) => !el.data.source)
      .forEach((el) => {
        nodes.push({
          id: el.data.id,
          label: el.data.label || el.data.id,
          errorRate: el.data.error_rate || 0,
          requestCount: el.data.request_count || 0,
          avgLatency: el.data.avg_latency_ms || 0,
          x: 0,
          y: 0,
          radius: 30,
        })
      })

    // Parse edges
    data.elements
      .filter((el) => el.data.source)
      .forEach((el) => {
        edges.push({
          source: el.data.source,
          target: el.data.target,
          callCount: el.data.call_count || 0,
          errorCount: el.data.error_count || 0,
          avgLatency: el.data.avg_latency_ms || 0,
        })
      })

    return { nodes, edges }
  }, [data])

  // Calculate node positions using force-directed layout
  const calculateLayout = useCallback((nodes, edges, width, height) => {
    if (nodes.length === 0) return nodes

    // Initialize random positions
    nodes.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / nodes.length
      const radius = Math.min(width, height) * 0.3
      node.x = width / 2 + radius * Math.cos(angle)
      node.y = height / 2 + radius * Math.sin(angle)
    })

    // Simple force-directed layout iterations
    const iterations = 50
    const k = Math.sqrt((width * height) / nodes.length) * 0.5

    for (let iter = 0; iter < iterations; iter++) {
      const forces = nodes.map(() => ({ fx: 0, fy: 0 }))

      // Repulsive forces between all nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x
          const dy = nodes[j].y - nodes[i].y
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          const force = (k * k) / dist

          forces[i].fx -= (dx / dist) * force
          forces[i].fy -= (dy / dist) * force
          forces[j].fx += (dx / dist) * force
          forces[j].fy += (dy / dist) * force
        }
      }

      // Attractive forces along edges
      edges.forEach((edge) => {
        const sourceIdx = nodes.findIndex((n) => n.id === edge.source)
        const targetIdx = nodes.findIndex((n) => n.id === edge.target)
        if (sourceIdx === -1 || targetIdx === -1) return

        const dx = nodes[targetIdx].x - nodes[sourceIdx].x
        const dy = nodes[targetIdx].y - nodes[sourceIdx].y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (dist * dist) / k

        forces[sourceIdx].fx += (dx / dist) * force * 0.1
        forces[sourceIdx].fy += (dy / dist) * force * 0.1
        forces[targetIdx].fx -= (dx / dist) * force * 0.1
        forces[targetIdx].fy -= (dy / dist) * force * 0.1
      })

      // Apply forces with damping
      const damping = 0.8 * (1 - iter / iterations)
      nodes.forEach((node, i) => {
        node.x += forces[i].fx * damping
        node.y += forces[i].fy * damping

        // Keep within bounds
        const padding = 60
        node.x = Math.max(padding, Math.min(width - padding, node.x))
        node.y = Math.max(padding, Math.min(height - padding, node.y))
      })
    }

    return nodes
  }, [])

  // Draw the service map on canvas
  const draw = useCallback(() => {
    const canvas = canvasRef.current
    const container = containerRef.current
    if (!canvas || !container) return

    const ctx = canvas.getContext('2d')
    const { width, height } = container.getBoundingClientRect()

    // Set canvas size
    canvas.width = width * window.devicePixelRatio
    canvas.height = height * window.devicePixelRatio
    canvas.style.width = `${width}px`
    canvas.style.height = `${height}px`
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio)

    // Clear canvas
    const isDark = document.documentElement.classList.contains('dark')
    ctx.fillStyle = isDark ? '#0a0a0a' : '#fafafa'
    ctx.fillRect(0, 0, width, height)

    // Apply transformations
    ctx.save()
    ctx.translate(offsetRef.current.x, offsetRef.current.y)
    ctx.scale(scaleRef.current, scaleRef.current)

    const nodes = nodesRef.current
    const edges = edgesRef.current

    // Draw edges
    edges.forEach((edge) => {
      const source = nodes.find((n) => n.id === edge.source)
      const target = nodes.find((n) => n.id === edge.target)
      if (!source || !target) return

      // Calculate line from edge of source to edge of target
      const dx = target.x - source.x
      const dy = target.y - source.y
      const dist = Math.sqrt(dx * dx + dy * dy)
      if (dist === 0) return

      const startX = source.x + (dx / dist) * source.radius
      const startY = source.y + (dy / dist) * source.radius
      const endX = target.x - (dx / dist) * target.radius
      const endY = target.y - (dy / dist) * target.radius

      // Draw line
      const hasErrors = edge.errorCount > 0
      ctx.strokeStyle = hasErrors
        ? isDark
          ? '#ef4444'
          : '#dc2626'
        : isDark
          ? '#525252'
          : '#a3a3a3'
      ctx.lineWidth = Math.max(1, Math.min(5, Math.log10(edge.callCount + 1)))
      ctx.beginPath()
      ctx.moveTo(startX, startY)
      ctx.lineTo(endX, endY)
      ctx.stroke()

      // Draw arrow head
      const arrowSize = 8
      const angle = Math.atan2(endY - startY, endX - startX)
      ctx.fillStyle = ctx.strokeStyle
      ctx.beginPath()
      ctx.moveTo(endX, endY)
      ctx.lineTo(
        endX - arrowSize * Math.cos(angle - Math.PI / 6),
        endY - arrowSize * Math.sin(angle - Math.PI / 6)
      )
      ctx.lineTo(
        endX - arrowSize * Math.cos(angle + Math.PI / 6),
        endY - arrowSize * Math.sin(angle + Math.PI / 6)
      )
      ctx.closePath()
      ctx.fill()

      // Draw call count label
      const midX = (startX + endX) / 2
      const midY = (startY + endY) / 2
      ctx.fillStyle = isDark ? '#a3a3a3' : '#525252'
      ctx.font = '10px Inter, system-ui, sans-serif'
      ctx.textAlign = 'center'
      ctx.fillText(`${edge.callCount}`, midX, midY - 5)
    })

    // Draw nodes
    nodes.forEach((node) => {
      // Node circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI)
      ctx.fillStyle = getNodeColor(node.errorRate, isDark)
      ctx.fill()
      ctx.strokeStyle = getNodeBorderColor(node.errorRate, isDark)
      ctx.lineWidth = 3
      ctx.stroke()

      // Node label
      ctx.fillStyle = isDark ? '#fafafa' : '#0a0a0a'
      ctx.font = 'bold 12px Inter, system-ui, sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'

      // Truncate long labels
      let label = node.label
      if (label.length > 15) {
        label = label.substring(0, 12) + '...'
      }
      ctx.fillText(label, node.x, node.y)

      // Latency label below node
      ctx.font = '10px Inter, system-ui, sans-serif'
      ctx.fillStyle = isDark ? '#a3a3a3' : '#525252'
      ctx.fillText(`${Math.round(node.avgLatency)}ms`, node.x, node.y + node.radius + 12)
    })

    ctx.restore()
  }, [])

  // Initialize and update layout when data changes
  useEffect(() => {
    if (!data || !containerRef.current) return

    const { nodes, edges } = parseData()
    const { width, height } = containerRef.current.getBoundingClientRect()

    nodesRef.current = calculateLayout(nodes, edges, width, height)
    edgesRef.current = edges

    draw()
  }, [data, parseData, calculateLayout, draw])

  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      if (!containerRef.current || nodesRef.current.length === 0) return
      draw()
    }

    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [draw])

  // Handle mouse events for panning and clicking
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const handleMouseDown = (e) => {
      isDraggingRef.current = true
      lastMouseRef.current = { x: e.clientX, y: e.clientY }
    }

    const handleMouseMove = (e) => {
      if (!isDraggingRef.current) return
      const dx = e.clientX - lastMouseRef.current.x
      const dy = e.clientY - lastMouseRef.current.y
      offsetRef.current.x += dx
      offsetRef.current.y += dy
      lastMouseRef.current = { x: e.clientX, y: e.clientY }
      draw()
    }

    const handleMouseUp = () => {
      isDraggingRef.current = false
    }

    const handleClick = (e) => {
      const rect = canvas.getBoundingClientRect()
      const x = (e.clientX - rect.left - offsetRef.current.x) / scaleRef.current
      const y = (e.clientY - rect.top - offsetRef.current.y) / scaleRef.current

      // Check if click is on a node
      const clickedNode = nodesRef.current.find((node) => {
        const dx = x - node.x
        const dy = y - node.y
        return Math.sqrt(dx * dx + dy * dy) <= node.radius
      })

      if (clickedNode && onServiceSelect) {
        onServiceSelect(clickedNode.id)
      }
    }

    const handleWheel = (e) => {
      e.preventDefault()
      const scaleFactor = e.deltaY > 0 ? 0.9 : 1.1
      scaleRef.current = Math.max(0.5, Math.min(3, scaleRef.current * scaleFactor))
      draw()
    }

    canvas.addEventListener('mousedown', handleMouseDown)
    canvas.addEventListener('mousemove', handleMouseMove)
    canvas.addEventListener('mouseup', handleMouseUp)
    canvas.addEventListener('mouseleave', handleMouseUp)
    canvas.addEventListener('click', handleClick)
    canvas.addEventListener('wheel', handleWheel, { passive: false })

    return () => {
      canvas.removeEventListener('mousedown', handleMouseDown)
      canvas.removeEventListener('mousemove', handleMouseMove)
      canvas.removeEventListener('mouseup', handleMouseUp)
      canvas.removeEventListener('mouseleave', handleMouseUp)
      canvas.removeEventListener('click', handleClick)
      canvas.removeEventListener('wheel', handleWheel)
    }
  }, [draw, onServiceSelect])

  // Zoom controls
  const handleZoomIn = () => {
    scaleRef.current = Math.min(3, scaleRef.current * 1.2)
    draw()
  }

  const handleZoomOut = () => {
    scaleRef.current = Math.max(0.5, scaleRef.current / 1.2)
    draw()
  }

  const handleResetView = () => {
    scaleRef.current = 1
    offsetRef.current = { x: 0, y: 0 }
    draw()
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="animate-spin h-8 w-8 border-2 border-mono-300 border-t-mono-900 dark:border-mono-600 dark:border-t-mono-100 rounded-full mx-auto"></div>
          <p className="mt-4 text-mono-600 dark:text-mono-400">Loading service map...</p>
        </div>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center text-red-500">
          <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4" />
          <p className="font-medium">Failed to load service map</p>
          <p className="text-sm mt-1">{error.message}</p>
        </div>
      </div>
    )
  }

  // Empty state
  if (!data?.elements || data.elements.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-mono-500">
        <div className="text-center">
          <MapIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p className="text-lg font-medium">No service data</p>
          <p className="text-sm mt-1">No traces found in the selected time range</p>
        </div>
      </div>
    )
  }

  return (
    <div ref={containerRef} className="relative h-full w-full">
      <canvas ref={canvasRef} className="absolute inset-0 cursor-grab active:cursor-grabbing" />

      {/* Zoom Controls */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-1 bg-white dark:bg-mono-900 rounded-lg shadow-lg border border-mono-200 dark:border-mono-700">
        <button
          onClick={handleZoomIn}
          className="p-2 hover:bg-mono-100 dark:hover:bg-mono-800 rounded-t-lg transition-colors"
          title="Zoom in"
        >
          <ArrowsPointingOutIcon className="h-5 w-5 text-mono-600 dark:text-mono-400" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-2 hover:bg-mono-100 dark:hover:bg-mono-800 transition-colors"
          title="Zoom out"
        >
          <ArrowsPointingInIcon className="h-5 w-5 text-mono-600 dark:text-mono-400" />
        </button>
        <button
          onClick={handleResetView}
          className="p-2 hover:bg-mono-100 dark:hover:bg-mono-800 rounded-b-lg transition-colors text-xs font-medium text-mono-600 dark:text-mono-400"
          title="Reset view"
        >
          Reset
        </button>
      </div>

      {/* Legend */}
      <div className="absolute top-4 left-4 bg-white dark:bg-mono-900 rounded-lg shadow-lg border border-mono-200 dark:border-mono-700 p-3">
        <p className="text-xs font-medium text-mono-700 dark:text-mono-300 mb-2">Health Status</p>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="text-xs text-mono-600 dark:text-mono-400">Healthy (&lt;5% errors)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <span className="text-xs text-mono-600 dark:text-mono-400">Degraded (5-10% errors)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <span className="text-xs text-mono-600 dark:text-mono-400">Errors (&gt;10% errors)</span>
          </div>
        </div>
        <p className="text-xs text-mono-500 mt-2">Click a service for details</p>
      </div>
    </div>
  )
}
