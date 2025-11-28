import { Menu } from '@headlessui/react'
import { UserCircleIcon, ArrowRightOnRectangleIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '../../stores/authStore'
import clsx from 'clsx'

export default function Header() {
  const { user, logout } = useAuthStore()

  return (
    <header className="flex h-16 items-center justify-between border-b border-gray-200 bg-white px-6">
      <div className="flex items-center">
        <h2 className="text-lg font-semibold text-gray-900">
          {/* Page title will be added by individual pages */}
        </h2>
      </div>
      <div className="flex items-center gap-4">
        <Menu as="div" className="relative">
          <Menu.Button className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100">
            <UserCircleIcon className="h-6 w-6" />
            <span>{user?.username || 'User'}</span>
          </Menu.Button>
          <Menu.Items className="absolute right-0 mt-2 w-48 origin-top-right rounded-lg bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none">
            <Menu.Item>
              {({ active }) => (
                <button
                  onClick={logout}
                  className={clsx(
                    'flex w-full items-center gap-2 px-4 py-2 text-sm',
                    active ? 'bg-gray-100' : ''
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
