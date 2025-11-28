import { NavLink } from 'react-router-dom'
import {
  HomeIcon,
  MagnifyingGlassIcon,
  ShieldCheckIcon,
  BellAlertIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'

const navigation = [
  { name: 'Dashboard', to: '/', icon: HomeIcon },
  { name: 'Query', to: '/query', icon: MagnifyingGlassIcon },
  { name: 'Rules', to: '/rules', icon: ShieldCheckIcon },
  { name: 'Alerts', to: '/alerts', icon: BellAlertIcon },
  { name: 'Settings', to: '/settings', icon: Cog6ToothIcon },
]

export default function Sidebar() {
  return (
    <div className="flex w-64 flex-col bg-gray-900">
      <div className="flex h-16 items-center px-6">
        <h1 className="text-xl font-bold text-white">Mantissa Log</h1>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              clsx(
                'group flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-gray-800 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              )
            }
          >
            <item.icon className="mr-3 h-5 w-5" aria-hidden="true" />
            {item.name}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-gray-800 p-4">
        <p className="text-xs text-gray-400">
          Separate the Signal from the Noise
        </p>
      </div>
    </div>
  )
}
