import { Menu } from '@headlessui/react'
import { UserCircleIcon, ArrowRightOnRectangleIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '../../stores/authStore'
import ThemeToggle from '../common/ThemeToggle'
import clsx from 'clsx'

export default function Header() {
  const { user, logout } = useAuthStore()

  return (
    <header className="flex h-16 items-center justify-between border-b border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-950 px-6 transition-colors">
      <div className="flex items-center">
        <h2 className="text-lg font-semibold text-mono-950 dark:text-mono-50">
          {/* Page title will be added by individual pages */}
        </h2>
      </div>
      <div className="flex items-center gap-4">
        <ThemeToggle />
        <Menu as="div" className="relative">
          <Menu.Button className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors">
            <UserCircleIcon className="h-6 w-6" />
            <span>{user?.username || 'User'}</span>
          </Menu.Button>
          <Menu.Items className="absolute right-0 mt-2 w-48 origin-top-right rounded-lg bg-white dark:bg-mono-900 shadow-lg border border-mono-200 dark:border-mono-800 focus:outline-none animate-scale-in">
            <Menu.Item>
              {({ active }) => (
                <button
                  onClick={logout}
                  className={clsx(
                    'flex w-full items-center gap-2 px-4 py-2 text-sm text-mono-900 dark:text-mono-100 rounded-lg transition-colors',
                    active ? 'bg-mono-100 dark:bg-mono-850' : ''
                  )}
                >
                  <ArrowRightOnRectangleIcon className="h-5 w-5" />
                  Sign out
                </button>
              )}
            </Menu.Item>
          </Menu.Items>
        </Menu>
      </div>
    </header>
  )
}
