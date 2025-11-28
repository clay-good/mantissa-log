import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../lib/api';

/**
 * Fetch all integrations for the current user
 */
export function useIntegrations() {
  return useQuery({
    queryKey: ['integrations'],
    queryFn: async () => {
      const response = await api.get('/integrations');
      return response.data;
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

/**
 * Fetch a specific integration by ID
 */
export function useIntegration(integrationId) {
  return useQuery({
    queryKey: ['integrations', integrationId],
    queryFn: async () => {
      const response = await api.get(`/integrations/${integrationId}`);
      return response.data;
    },
    enabled: !!integrationId,
  });
}

/**
 * Create or update an integration
 */
export function useSaveIntegration() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (integrationData) => {
      const response = await api.post('/integrations', integrationData);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });
}

/**
 * Test an integration connection
 */
export function useTestIntegration() {
  return useMutation({
    mutationFn: async (integrationId) => {
      const response = await api.post(`/integrations/${integrationId}/test`);
      return response.data;
    },
  });
}

/**
 * Delete an integration
 */
export function useDeleteIntegration() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (integrationId) => {
      const response = await api.delete(`/integrations/${integrationId}`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });
}

/**
 * Get integration status for UI indicators
 */
export function useIntegrationStatus() {
  return useQuery({
    queryKey: ['integrations', 'status'],
    queryFn: async () => {
      const response = await api.get('/integrations/status');
      return response.data;
    },
    staleTime: 60 * 1000, // 1 minute
    refetchInterval: 60 * 1000, // Refresh every minute
  });
}

/**
 * Get default integrations structure (mock data for development)
 */
export function useDefaultIntegrations() {
  return {
    data: [
      {
        id: 'slack',
        name: 'Slack',
        description: 'Send alerts to Slack channels',
        type: 'slack',
        configured: false,
        status: 'not_configured',
      },
      {
        id: 'email',
        name: 'Email',
        description: 'Send alerts via email',
        type: 'email',
        configured: false,
        status: 'not_configured',
      },
      {
        id: 'jira',
        name: 'Jira',
        description: 'Create Jira tickets for security findings',
        type: 'jira',
        configured: false,
        status: 'not_configured',
      },
      {
        id: 'pagerduty',
        name: 'PagerDuty',
        description: 'Trigger PagerDuty incidents for critical alerts',
        type: 'pagerduty',
        configured: false,
        status: 'not_configured',
      },
    ],
    isLoading: false,
    error: null,
  };
}
