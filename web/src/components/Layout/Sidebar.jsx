import { NavLink } from 'react-router-dom'
import {
  HomeIcon,
  MagnifyingGlassIcon,
  ShieldCheckIcon,
  BellAlertIcon,
  Cog6ToothIcon,
  AdjustmentsHorizontalIcon,
  CurrencyDollarIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'

const navigation = [
  { name: 'Dashboard', to: '/', icon: HomeIcon },
  { name: 'Query', to: '/query', icon: MagnifyingGlassIcon },
  { name: 'Rules', to: '/rules', icon: ShieldCheckIcon },
  { name: 'Tuning', to: '/tuning', icon: AdjustmentsHorizontalIcon },
  { name: 'Alerts', to: '/alerts', icon: BellAlertIcon },
  { name: 'Costs', to: '/costs', icon: CurrencyDollarIcon },
  { name: 'Settings', to: '/settings', icon: Cog6ToothIcon },
]

export default function Sidebar() {
  return (
    <div className="flex w-64 flex-col bg-white dark:bg-mono-950 border-r border-mono-200 dark:border-mono-800 transition-colors">
      <div className="flex h-16 items-center px-6 border-b border-mono-200 dark:border-mono-800">
        <h1 className="text-xl font-bold text-mono-950 dark:text-mono-50">Mantissa Log</h1>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              clsx(
                'group flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200',
                isActive
                  ? 'bg-mono-950 dark:bg-mono-100 text-mono-50 dark:text-mono-950'
                  : 'text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 hover:text-mono-950 dark:hover:text-mono-50'
              )
            }
          >
            <item.icon className="mr-3 h-5 w-5" aria-hidden="true" />
            {item.name}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-mono-200 dark:border-mono-800 p-4">
        <p className="text-xs text-mono-600 dark:text-mono-400">
          Separate the Signal from the Noise
        </p>
      </div>
    </div>
  )
}
