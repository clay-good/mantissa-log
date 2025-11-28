export default function Dashboard() {
  return (
    <div>
      <h1 className="mb-6">Dashboard</h1>
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <h3 className="text-sm font-medium text-gray-500">Active Alerts</h3>
          <p className="mt-2 text-3xl font-bold text-gray-900">12</p>
        </div>
        <div className="card">
          <h3 className="text-sm font-medium text-gray-500">Detection Rules</h3>
          <p className="mt-2 text-3xl font-bold text-gray-900">45</p>
        </div>
        <div className="card">
          <h3 className="text-sm font-medium text-gray-500">Events Today</h3>
          <p className="mt-2 text-3xl font-bold text-gray-900">1.2M</p>
        </div>
        <div className="card">
          <h3 className="text-sm font-medium text-gray-500">Queries Run</h3>
          <p className="mt-2 text-3xl font-bold text-gray-900">89</p>
        </div>
      </div>
    </div>
  )
}
