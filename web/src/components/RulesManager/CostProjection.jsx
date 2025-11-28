import { useState, useEffect } from 'react'
import { CurrencyDollarIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

const SCHEDULE_EXECUTIONS = {
  'rate(5 minutes)': 8640,
  'rate(15 minutes)': 2880,
  'rate(30 minutes)': 1440,
  'rate(1 hour)': 720,
  'rate(6 hours)': 120,
  'rate(12 hours)': 60,
  'rate(1 day)': 30,
}

const LAMBDA_PRICING = {
  per_gb_second: 0.0000166667,
  requests_per_million: 0.20,
}

const ATHENA_PRICING = {
  per_tb_scanned: 5.0,
}

const DYNAMODB_PRICING = {
  per_million_writes: 1.25,
}

export default function CostProjection({
  dataScannedBytes,
  executionTimeMs,
  lambdaMemoryMB,
  schedule
}) {
  const [costBreakdown, setCostBreakdown] = useState(null)
  const [showDetails, setShowDetails] = useState(false)

  useEffect(() => {
    if (!dataScannedBytes || !executionTimeMs || !schedule) {
      return
    }

    const executionsPerMonth = SCHEDULE_EXECUTIONS[schedule] || 0
    const dataScannedMB = dataScannedBytes / (1024 * 1024)
    const dataScannedGB = dataScannedMB / 1024
    const dataScannedTB = dataScannedGB / 1024

    // Athena cost: data scanned * executions * price per TB
    const athenaCost = dataScannedTB * executionsPerMonth * ATHENA_PRICING.per_tb_scanned

    // Lambda cost
    const executionTimeSec = executionTimeMs / 1000
    const lambdaMemoryGB = lambdaMemoryMB / 1024
    const gbSeconds = lambdaMemoryGB * executionTimeSec * executionsPerMonth
    const lambdaComputeCost = gbSeconds * LAMBDA_PRICING.per_gb_second
    const lambdaRequestCost = (executionsPerMonth / 1000000) * LAMBDA_PRICING.requests_per_million

    // DynamoDB cost (state tracking writes)
    const dynamoWriteCost = (executionsPerMonth / 1000000) * DYNAMODB_PRICING.per_million_writes

    const totalCost = athenaCost + lambdaComputeCost + lambdaRequestCost + dynamoWriteCost

    setCostBreakdown({
      athena: athenaCost,
      lambdaCompute: lambdaComputeCost,
      lambdaRequests: lambdaRequestCost,
      dynamodb: dynamoWriteCost,
      total: totalCost,
      executionsPerMonth,
      dataScannedMB,
    })
  }, [dataScannedBytes, executionTimeMs, lambdaMemoryMB, schedule])

  if (!costBreakdown) {
    return (
      <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-mono-50 dark:bg-mono-900 p-4">
        <div className="flex items-center gap-2 text-mono-600 dark:text-mono-400">
          <CurrencyDollarIcon className="h-5 w-5" />
          <span className="text-sm">Cost projection calculating...</span>
        </div>
      </div>
    )
  }

  const isHighCost = costBreakdown.total > 50
  const isMediumCost = costBreakdown.total > 10 && costBreakdown.total <= 50

  return (
    <div className="rounded-lg border border-mono-200 dark:border-mono-800 bg-gradient-to-br from-mono-50 to-mono-100 dark:from-mono-900 dark:to-mono-850 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CurrencyDollarIcon className="h-5 w-5 text-mono-600 dark:text-mono-400" />
          <span className="text-sm font-medium text-mono-950 dark:text-mono-50">
            Projected Monthly Cost
          </span>
        </div>
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="text-xs text-mono-600 dark:text-mono-400 hover:text-mono-950 dark:hover:text-mono-50 transition-colors"
        >
          {showDetails ? 'Hide' : 'Show'} details
        </button>
      </div>

      <div className="mt-3">
        <div className={clsx(
          'inline-flex items-baseline gap-1',
          isHighCost && 'text-red-600 dark:text-red-400',
          isMediumCost && 'text-yellow-600 dark:text-yellow-400',
          !isHighCost && !isMediumCost && 'text-green-600 dark:text-green-400'
        )}>
          <span className="text-3xl font-bold">
            ${costBreakdown.total.toFixed(2)}
          </span>
          <span className="text-sm font-medium">/month</span>
        </div>

        {isHighCost && (
          <div className="mt-2 flex items-start gap-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3">
            <ExclamationTriangleIcon className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0" />
            <div className="text-sm text-red-800 dark:text-red-300">
              <p className="font-medium">High cost warning</p>
              <p className="mt-1 text-xs">
                Consider reducing execution frequency or optimizing the query to scan less data.
              </p>
            </div>
          </div>
        )}

        {isMediumCost && (
          <div className="mt-2 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 p-2">
            <p className="text-xs text-yellow-800 dark:text-yellow-300">
              Moderate cost. Monitor usage and optimize if needed.
            </p>
          </div>
        )}
      </div>

      {showDetails && (
        <div className="mt-4 space-y-2 border-t border-mono-200 dark:border-mono-800 pt-4">
          <div className="text-xs font-medium text-mono-600 dark:text-mono-400">
            Cost Breakdown
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between text-sm">
              <span className="text-mono-700 dark:text-mono-300">
                Query Execution (Athena)
              </span>
              <span className="font-mono text-mono-950 dark:text-mono-50">
                ${costBreakdown.athena.toFixed(4)}
              </span>
            </div>
            <div className="text-xs text-mono-500 dark:text-mono-500 pl-3">
              {costBreakdown.dataScannedMB.toFixed(2)} MB/query × {costBreakdown.executionsPerMonth.toLocaleString()} executions
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-mono-700 dark:text-mono-300">
                Lambda Compute
              </span>
              <span className="font-mono text-mono-950 dark:text-mono-50">
                ${costBreakdown.lambdaCompute.toFixed(4)}
              </span>
            </div>
            <div className="text-xs text-mono-500 dark:text-mono-500 pl-3">
              {executionTimeMs}ms @ {lambdaMemoryMB}MB × {costBreakdown.executionsPerMonth.toLocaleString()} executions
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-mono-700 dark:text-mono-300">
                Lambda Requests
              </span>
              <span className="font-mono text-mono-950 dark:text-mono-50">
                ${costBreakdown.lambdaRequests.toFixed(4)}
              </span>
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-mono-700 dark:text-mono-300">
                State Storage (DynamoDB)
              </span>
              <span className="font-mono text-mono-950 dark:text-mono-50">
                ${costBreakdown.dynamodb.toFixed(4)}
              </span>
            </div>
          </div>

          <div className="border-t border-mono-200 dark:border-mono-800 pt-2 mt-2">
            <div className="flex justify-between text-sm font-medium">
              <span className="text-mono-950 dark:text-mono-50">Total</span>
              <span className="font-mono text-mono-950 dark:text-mono-50">
                ${costBreakdown.total.toFixed(2)}/month
              </span>
            </div>
          </div>

          <div className="mt-3 rounded-lg bg-mono-100 dark:bg-mono-850 p-3">
            <p className="text-xs text-mono-700 dark:text-mono-300">
              <span className="font-medium">Tip:</span> Reduce costs by using partition pruning,
              limiting time ranges, or reducing execution frequency.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
