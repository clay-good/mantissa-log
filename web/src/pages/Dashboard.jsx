export default function Dashboard() {
  return (
    <div className="p-6">
      <h1 className="mb-6 text-2xl font-bold text-mono-950 dark:text-mono-50">Dashboard</h1>
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Active Alerts</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">12</p>
        </div>
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Detection Rules</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">45</p>
        </div>
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Events Today</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">1.2M</p>
        </div>
        <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 transition-colors hover:shadow-md">
          <h3 className="text-sm font-medium text-mono-600 dark:text-mono-400">Queries Run</h3>
          <p className="mt-2 text-3xl font-bold text-mono-950 dark:text-mono-50">89</p>
        </div>
      </div>
    </div>
  )
}
