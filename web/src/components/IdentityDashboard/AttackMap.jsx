import { useState, useMemo } from 'react'
import clsx from 'clsx'
import {
  aggregateByLocation,
  calculateMarkerSize,
  latLonToSvg,
} from '../../utils/geoTransform'
import AttackMapLegend from './AttackMapLegend'
import AttackMapFilters from './AttackMapFilters'
import TopAttackSources from './TopAttackSources'
import { GlobeAltIcon } from '@heroicons/react/24/outline'

const SEVERITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#22C55E',
}

// Simplified world map paths (continents outline)
const WORLD_MAP_PATH = `
  M 155 95 Q 165 85, 175 90 L 185 88 Q 195 82, 210 85 L 230 80 Q 250 78, 270 82 L 295 78
  Q 320 75, 340 80 L 360 85 Q 375 88, 385 95 L 390 105 Q 392 115, 388 125 L 380 140
  Q 370 155, 355 165 L 340 175 Q 320 185, 295 188 L 270 190 Q 245 192, 220 188 L 195 182
  Q 175 175, 160 165 L 150 155 Q 142 140, 145 125 L 150 110 Q 152 100, 155 95 Z
  M 475 70 Q 490 65, 510 68 L 545 65 Q 575 62, 600 68 L 635 72 Q 670 78, 695 88 L 715 100
  Q 725 115, 720 135 L 710 155 Q 695 175, 670 185 L 640 192 Q 610 198, 575 195 L 540 188
  Q 510 180, 485 168 L 465 155 Q 450 138, 455 118 L 462 95 Q 468 80, 475 70 Z
  M 560 195 Q 580 188, 605 192 L 640 198 Q 670 205, 690 218 L 705 235 Q 715 255, 708 275
  L 695 295 Q 675 315, 645 325 L 610 330 Q 575 332, 545 325 L 515 315 Q 490 300, 482 278
  L 478 255 Q 480 235, 495 220 L 520 205 Q 540 195, 560 195 Z
  M 180 195 Q 200 185, 225 188 L 255 192 Q 285 198, 305 212 L 320 230 Q 332 252, 325 275
  L 312 298 Q 292 320, 262 332 L 228 340 Q 195 345, 165 338 L 138 328 Q 115 312, 110 288
  L 108 262 Q 112 238, 128 218 L 150 200 Q 165 192, 180 195 Z
  M 680 285 Q 705 275, 735 280 L 768 288 Q 795 298, 810 318 L 820 342 Q 825 368, 815 392
  L 798 415 Q 775 435, 742 442 L 708 445 Q 672 445, 645 432 L 625 415 Q 608 392, 612 365
  L 622 338 Q 638 310, 660 295 L 680 285 Z
`

// Organization headquarters location (configurable)
const ORG_LOCATION = { lat: 37.7749, lon: -122.4194, name: 'HQ (San Francisco)' }

function AttackMarker({ location, size, color, isActive, onHover, onClick }) {
  return (
    <g
      className="cursor-pointer"
      onMouseEnter={() => onHover(location)}
      onMouseLeave={() => onHover(null)}
      onClick={() => onClick(location)}
    >
      {/* Pulse animation for active attacks */}
      {isActive && (
        <circle
          cx={location.x}
          cy={location.y}
          r={size + 4}
          fill={color}
          opacity="0.3"
          className="animate-ping"
        />
      )}
      {/* Main marker */}
      <circle
        cx={location.x}
        cy={location.y}
        r={size}
        fill={color}
        stroke="white"
        strokeWidth="1.5"
        className="transition-all duration-200 hover:opacity-80"
      />
      {/* Attack count label for larger markers */}
      {size >= 10 && (
        <text
          x={location.x}
          y={location.y + 1}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="white"
          fontSize="8"
          fontWeight="bold"
        >
          {location.count > 99 ? '99+' : location.count}
        </text>
      )}
    </g>
  )
}

function AttackLine({ from, to, color, isActive }) {
  return (
    <line
      x1={from.x}
      y1={from.y}
      x2={to.x}
      y2={to.y}
      stroke={color}
      strokeWidth={isActive ? 2 : 1}
      strokeDasharray={isActive ? '4,2' : '2,2'}
      opacity={0.5}
      className={isActive ? 'animate-pulse' : ''}
    />
  )
}

function TooltipContent({ location }) {
  if (!location) return null

  return (
    <div className="bg-mono-900 text-white px-3 py-2 rounded-lg shadow-lg text-xs max-w-xs">
      <div className="font-semibold text-sm mb-1">{location.name}</div>
      <div className="space-y-1">
        <div className="flex justify-between gap-4">
          <span className="text-mono-400">Attacks:</span>
          <span className="font-medium">{location.count}</span>
        </div>
        <div className="flex justify-between gap-4">
          <span className="text-mono-400">Unique IPs:</span>
          <span className="font-medium">{location.ips?.length || 0}</span>
        </div>
        <div className="flex justify-between gap-4">
          <span className="text-mono-400">Max Severity:</span>
          <span
            className="font-medium capitalize"
            style={{ color: SEVERITY_COLORS[location.maxSeverity] }}
          >
            {location.maxSeverity}
          </span>
        </div>
        {location.attackTypes?.length > 0 && (
          <div className="mt-1 pt-1 border-t border-mono-700">
            <span className="text-mono-400">Types: </span>
            <span>{location.attackTypes.slice(0, 3).join(', ')}</span>
          </div>
        )}
      </div>
    </div>
  )
}

export default function AttackMap({ attacks, onLocationClick, className }) {
  const [filters, setFilters] = useState({
    timeRange: '24h',
    severity: 'all',
    attackType: 'all',
    provider: 'all',
  })
  const [hoveredLocation, setHoveredLocation] = useState(null)
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 })

  const viewport = { width: 800, height: 400 }

  // Filter attacks
  const filteredAttacks = useMemo(() => {
    if (!attacks) return []

    return attacks.filter((attack) => {
      if (filters.severity !== 'all' && attack.severity !== filters.severity) {
        return false
      }
      if (filters.attackType !== 'all' && attack.attack_type !== filters.attackType) {
        return false
      }
      if (filters.provider !== 'all' && attack.provider !== filters.provider) {
        return false
      }
      // Time range filtering would be applied here based on attack.timestamp
      return true
    })
  }, [attacks, filters])

  // Aggregate by location
  const locationData = useMemo(() => {
    const aggregated = aggregateByLocation(filteredAttacks)
    const maxCount = Math.max(...aggregated.map((l) => l.count), 1)

    return aggregated.map((loc) => ({
      ...loc,
      ...latLonToSvg(loc.lat, loc.lon, viewport),
      size: calculateMarkerSize(loc.count, maxCount),
      color: SEVERITY_COLORS[loc.maxSeverity] || SEVERITY_COLORS.medium,
      isActive: loc.severity.critical > 0 || loc.severity.high > 0,
    }))
  }, [filteredAttacks, viewport])

  // Organization HQ position
  const orgPosition = latLonToSvg(ORG_LOCATION.lat, ORG_LOCATION.lon, viewport)

  const handleMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setTooltipPosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    })
  }

  const handleBlockSource = (source) => {
    if (window.confirm(`Block all attacks from ${source.name}?`)) {
      console.log('Blocking source:', source)
    }
  }

  if (!attacks || attacks.length === 0) {
    return (
      <div
        className={clsx(
          'rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-8',
          className
        )}
      >
        <div className="text-center text-mono-500 dark:text-mono-400">
          <GlobeAltIcon className="mx-auto h-12 w-12 text-mono-400" />
          <p className="mt-2">No attack data available</p>
        </div>
      </div>
    )
  }

  return (
    <div className={clsx('space-y-4', className)}>
      {/* Filters */}
      <AttackMapFilters filters={filters} onFilterChange={setFilters} />

      {/* Map Container */}
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 overflow-hidden">
        <div className="border-b border-mono-200 dark:border-mono-800 px-4 py-3">
          <h3 className="text-lg font-semibold text-mono-900 dark:text-mono-100">
            Attack Source Map
          </h3>
          <p className="text-sm text-mono-500 dark:text-mono-400">
            {locationData.length} location{locationData.length !== 1 ? 's' : ''} •{' '}
            {filteredAttacks.length} attack{filteredAttacks.length !== 1 ? 's' : ''}
          </p>
        </div>

        <div
          className="relative bg-mono-100 dark:bg-mono-800"
          onMouseMove={handleMouseMove}
        >
          <svg
            viewBox={`0 0 ${viewport.width} ${viewport.height}`}
            className="w-full h-auto"
            style={{ minHeight: '300px', maxHeight: '400px' }}
          >
            {/* Background */}
            <rect
              width={viewport.width}
              height={viewport.height}
              fill="currentColor"
              className="text-mono-100 dark:text-mono-800"
            />

            {/* World map outline */}
            <path
              d={WORLD_MAP_PATH}
              fill="currentColor"
              className="text-mono-200 dark:text-mono-700"
              stroke="currentColor"
              strokeWidth="0.5"
            />

            {/* Attack lines to HQ */}
            {locationData.map((loc, i) => (
              <AttackLine
                key={`line-${i}`}
                from={loc}
                to={orgPosition}
                color={loc.color}
                isActive={loc.isActive}
              />
            ))}

            {/* HQ marker */}
            <g>
              <circle
                cx={orgPosition.x}
                cy={orgPosition.y}
                r="8"
                fill="#6366F1"
                stroke="white"
                strokeWidth="2"
              />
              <text
                x={orgPosition.x}
                y={orgPosition.y + 20}
                textAnchor="middle"
                fill="currentColor"
                className="text-mono-600 dark:text-mono-400"
                fontSize="10"
              >
                HQ
              </text>
            </g>

            {/* Attack markers */}
            {locationData.map((loc, i) => (
              <AttackMarker
                key={`marker-${i}`}
                location={loc}
                size={loc.size}
                color={loc.color}
                isActive={loc.isActive}
                onHover={setHoveredLocation}
                onClick={onLocationClick}
              />
            ))}
          </svg>

          {/* Legend */}
          <AttackMapLegend className="absolute bottom-4 left-4 max-w-xs" />

          {/* Tooltip */}
          {hoveredLocation && (
            <div
              className="absolute pointer-events-none z-10"
              style={{
                left: tooltipPosition.x + 10,
                top: tooltipPosition.y - 10,
                transform: tooltipPosition.x > viewport.width / 2 ? 'translateX(-100%)' : 'none',
              }}
            >
              <TooltipContent location={hoveredLocation} />
            </div>
          )}
        </div>
      </div>

      {/* Top Attack Sources Table */}
      <TopAttackSources sources={locationData} onBlockSource={handleBlockSource} />
    </div>
  )
}
