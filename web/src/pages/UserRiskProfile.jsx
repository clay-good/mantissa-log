import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getUserRiskProfile, getUserTimeline } from '../services/identityApi'
import UserRiskHeader from '../components/UserRisk/UserRiskHeader'
import ActivityTimeline from '../components/UserRisk/ActivityTimeline'
import RiskFactorsPanel from '../components/UserRisk/RiskFactorsPanel'
import BaselineComparisonPanel from '../components/UserRisk/BaselineComparisonPanel'
import UserContextPanel from '../components/UserRisk/UserContextPanel'
import RelatedAlertsPanel from '../components/UserRisk/RelatedAlertsPanel'
import { ArrowLeftIcon } from '@heroicons/react/24/outline'

export default function UserRiskProfile() {
  const { userEmail } = useParams()
  const [profile, setProfile] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [timelineFilters, setTimelineFilters] = useState({
    eventTypes: [],
    timeRange: '7d',
    riskLevel: 'all',
  })

  useEffect(() => {
    if (!userEmail) return

    setIsLoading(true)
    setError(null)

    Promise.all([
      getUserRiskProfile(userEmail),
      getUserTimeline(userEmail, timelineFilters),
    ])
      .then(([profileData, timelineData]) => {
        setProfile(profileData)
        setTimeline(timelineData)
      })
      .catch((err) => {
        setError(err.message)
      })
      .finally(() => {
        setIsLoading(false)
      })
  }, [userEmail, timelineFilters])

  const handleFilterChange = (newFilters) => {
    setTimelineFilters((prev) => ({ ...prev, ...newFilters }))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary-600 border-t-transparent" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-8">
        <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-6 text-center">
          <p className="text-red-600 dark:text-red-400">{error}</p>
          <Link
            to="/identity"
            className="mt-4 inline-flex items-center gap-2 text-sm font-medium text-primary-600 hover:text-primary-700"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back to Identity Dashboard
          </Link>
        </div>
      </div>
    )
  }

  if (!profile) {
    return (
      <div className="p-8">
        <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 p-6 text-center">
          <p className="text-mono-600 dark:text-mono-400">User not found: {userEmail}</p>
          <Link
            to="/identity"
            className="mt-4 inline-flex items-center gap-2 text-sm font-medium text-primary-600 hover:text-primary-700"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back to Identity Dashboard
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-mono-50 dark:bg-mono-950">
      {/* Back navigation */}
      <div className="border-b border-mono-200 dark:border-mono-800 bg-white dark:bg-mono-900 px-6 py-3">
        <Link
          to="/identity"
          className="inline-flex items-center gap-2 text-sm font-medium text-mono-600 hover:text-mono-900 dark:text-mono-400 dark:hover:text-mono-100"
        >
          <ArrowLeftIcon className="h-4 w-4" />
          Back to Identity Dashboard
        </Link>
      </div>

      {/* User Header */}
      <UserRiskHeader user={profile} />

      {/* Main Content */}
      <div className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Activity Timeline */}
          <div className="lg:col-span-2 space-y-6">
            <ActivityTimeline
              events={timeline}
              filters={timelineFilters}
              onFilterChange={handleFilterChange}
            />
          </div>

          {/* Right Column - Details Panels */}
          <div className="space-y-6">
            <RiskFactorsPanel factors={profile.risk_factors} />
            <BaselineComparisonPanel baseline={profile.baseline} current={profile.current_behavior} />
            <UserContextPanel user={profile} />
            <RelatedAlertsPanel alerts={profile.related_alerts} userId={profile.user_email} />
          </div>
        </div>
      </div>
    </div>
  )
}
