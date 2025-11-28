import { CheckCircle, XCircle, AlertTriangle, ExternalLink } from 'lucide-react';

export default function IntegrationStatus({ integrations, onConfigure }) {
  const getStatusIcon = (status) => {
    switch (status) {
      case 'configured':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-600" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-yellow-600" />;
      default:
        return <XCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'configured':
        return <span className="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded">Configured</span>;
      case 'error':
        return <span className="px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded">Error</span>;
      case 'warning':
        return <span className="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded">Needs Attention</span>;
      default:
        return <span className="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 rounded">Not Configured</span>;
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      <div className="px-4 py-3 border-b border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900">Alert Integrations</h3>
        <p className="text-sm text-gray-500 mt-1">Configure destinations for security alerts</p>
      </div>

      <div className="divide-y divide-gray-200">
        {integrations.map(integration => (
          <div key={integration.id} className="px-4 py-4 hover:bg-gray-50 transition">
            <div className="flex items-start justify-between">
              <div className="flex items-start space-x-3 flex-1">
                <div className="mt-1">
                  {getStatusIcon(integration.status)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2">
                    <h4 className="text-sm font-medium text-gray-900">{integration.name}</h4>
                    {getStatusBadge(integration.status)}
                  </div>
                  <p className="text-sm text-gray-500 mt-1">{integration.description}</p>

                  {integration.status === 'configured' && integration.details && (
                    <div className="mt-2 text-xs text-gray-600">
                      {integration.type === 'slack' && integration.details.channel && (
                        <span>Channel: #{integration.details.channel}</span>
                      )}
                      {integration.type === 'jira' && integration.details.project && (
                        <span>Project: {integration.details.project}</span>
                      )}
                      {integration.type === 'email' && integration.details.recipients && (
                        <span>{integration.details.recipients.length} recipient(s)</span>
                      )}
                      {integration.type === 'pagerduty' && integration.details.service && (
                        <span>Service: {integration.details.service}</span>
                      )}
                    </div>
                  )}

                  {integration.status === 'error' && integration.error && (
                    <div className="mt-2 text-xs text-red-600">
                      {integration.error}
                    </div>
                  )}

                  {integration.lastTested && (
                    <div className="mt-2 text-xs text-gray-500">
                      Last tested: {new Date(integration.lastTested).toLocaleString()}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center space-x-2 ml-4">
                {integration.status === 'configured' && integration.testUrl && (
                  <button
                    onClick={() => window.open(integration.testUrl, '_blank')}
                    className="text-sm text-blue-600 hover:text-blue-800 flex items-center"
                  >
                    Test
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </button>
                )}
                <button
                  onClick={() => onConfigure(integration)}
                  className="px-3 py-1 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  {integration.status === 'configured' ? 'Edit' : 'Configure'}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
