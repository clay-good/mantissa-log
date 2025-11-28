import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';

/**
 * Fetch cost projection for a detection rule
 */
export function useCostProjection({
  queryMetrics,
  schedule,
  lambdaMemoryMb = 512,
  estimatedAlertsPerMonth = 10,
  alertDestinations = [],
  enabled = true
}) {
  return useQuery({
    queryKey: ['costProjection', queryMetrics, schedule, lambdaMemoryMb, alertDestinations],
    queryFn: async () => {
      const response = await api.post('/cost-estimate', {
        queryMetrics,
        schedule,
        lambdaMemoryMb,
        estimatedAlertsPerMonth,
        alertDestinations
      });
      return response.data;
    },
    enabled: enabled && !!queryMetrics && !!schedule,
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: 1,
  });
}

/**
 * Calculate cost projection client-side (fallback if API unavailable)
 */
export function calculateCostClientSide({
  dataScannedBytes,
  executionTimeMs,
  schedule,
  alertCount = 10
}) {
  // Parse schedule to get executions per month
  const executionsPerMonth = parseSchedule(schedule);

  // Athena cost: $5 per TB
  const dataScannedTB = dataScannedBytes / (1024 ** 4);
  const queryCost = dataScannedTB * executionsPerMonth * 5.0;

  // Lambda cost (approximate)
  const lambdaCost = (executionTimeMs / 1000) * (512 / 1024) * executionsPerMonth * 0.0000166667;

  // DynamoDB cost
  const storageCost = executionsPerMonth * 0.00000125;

  // Total
  const totalCost = queryCost + lambdaCost + storageCost;

  return {
    total_monthly_cost: totalCost,
    breakdown: {
      query_execution: {
        cost: queryCost,
        data_scanned_mb: dataScannedBytes / (1024 ** 2),
        runs_per_month: executionsPerMonth
      },
      lambda_execution: {
        cost: lambdaCost,
        executions: executionsPerMonth
      },
      state_storage: {
        cost: storageCost,
        write_requests: executionsPerMonth
      },
      alert_delivery: {
        cost: 0
      }
    },
    notes: ['Client-side estimate', 'Actual costs may vary']
  };
}

function parseSchedule(schedule) {
  const lower = schedule.toLowerCase();

  if (lower.includes('5 minutes')) return 8640;
  if (lower.includes('15 minutes')) return 2880;
  if (lower.includes('30 minutes')) return 1440;
  if (lower.includes('1 hour')) return 720;
  if (lower.includes('6 hours')) return 120;
  if (lower.includes('12 hours')) return 60;
  if (lower.includes('1 day')) return 30;

  // Default: 5 minutes
  return 8640;
}
