import { Routes, Route } from 'react-router-dom'
import LogSourceHealthDashboard from '../components/LogSourceHealth/LogSourceHealthDashboard'
import LogSourceHealthDetail from '../components/LogSourceHealth/LogSourceHealthDetail'

export default function LogSourceHealth() {
  return (
    <Routes>
      <Route index element={<LogSourceHealthDashboard />} />
      <Route path=":sourceType" element={<LogSourceHealthDetail />} />
    </Routes>
  )
}
