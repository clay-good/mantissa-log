import clsx from 'clsx'

const SEVERITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#22C55E',
}

const SIZE_SCALE = [
  { label: '1-10', size: 6 },
  { label: '11-50', size: 10 },
  { label: '51-100', size: 14 },
  { label: '100+', size: 18 },
]

const ATTACK_TYPES = [
  { type: 'brute_force', label: 'Brute Force', icon: '🔓' },
  { type: 'credential_stuffing', label: 'Credential Stuffing', icon: '🔑' },
  { type: 'password_spray', label: 'Password Spray', icon: '💨' },
  { type: 'impossible_travel', label: 'Impossible Travel', icon: '✈️' },
  { type: 'mfa_fatigue', label: 'MFA Fatigue', icon: '📱' },
]

export default function AttackMapLegend({ className }) {
  return (
    <div
      className={clsx(
        'bg-white/95 dark:bg-mono-900/95 backdrop-blur-sm rounded-lg border border-mono-200 dark:border-mono-700 p-3 text-xs',
        className
      )}
    >
      {/* Severity Colors */}
      <div className="mb-3">
        <h4 className="font-medium text-mono-700 dark:text-mono-300 mb-2">Severity</h4>
        <div className="flex flex-wrap gap-2">
          {Object.entries(SEVERITY_COLORS).map(([severity, color]) => (
            <div key={severity} className="flex items-center gap-1">
              <div
                className="h-3 w-3 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="text-mono-600 dark:text-mono-400 capitalize">{severity}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Size Scale */}
      <div className="mb-3">
        <h4 className="font-medium text-mono-700 dark:text-mono-300 mb-2">Attack Volume</h4>
        <div className="flex items-end gap-3">
          {SIZE_SCALE.map((item) => (
            <div key={item.label} className="flex flex-col items-center gap-1">
              <div
                className="rounded-full bg-mono-400"
                style={{ width: item.size, height: item.size }}
              />
              <span className="text-mono-500 dark:text-mono-400">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Attack Types (condensed) */}
      <div>
        <h4 className="font-medium text-mono-700 dark:text-mono-300 mb-2">Attack Types</h4>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {ATTACK_TYPES.map((item) => (
            <div key={item.type} className="flex items-center gap-1">
              <span>{item.icon}</span>
              <span className="text-mono-600 dark:text-mono-400">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
