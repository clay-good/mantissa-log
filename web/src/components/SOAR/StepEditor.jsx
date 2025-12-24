import clsx from 'clsx'

const ACTION_TYPES = [
  { value: 'isolate_host', label: 'Isolate Host', category: 'Endpoint' },
  { value: 'quarantine_file', label: 'Quarantine File', category: 'Endpoint' },
  { value: 'block_ip', label: 'Block IP', category: 'Network' },
  { value: 'disable_user', label: 'Disable User', category: 'Identity' },
  { value: 'reset_password', label: 'Reset Password', category: 'Identity' },
  { value: 'revoke_sessions', label: 'Revoke Sessions', category: 'Identity' },
  { value: 'notify', label: 'Send Notification', category: 'Communication' },
  { value: 'create_ticket', label: 'Create Ticket', category: 'Communication' },
  { value: 'query', label: 'Run Query', category: 'Investigation' },
  { value: 'webhook', label: 'Call Webhook', category: 'Custom' },
  { value: 'custom', label: 'Custom Action', category: 'Custom' },
]

const PROVIDERS = {
  isolate_host: ['crowdstrike', 'defender', 'sentinelone', 'carbon_black'],
  quarantine_file: ['crowdstrike', 'defender', 'sentinelone'],
  block_ip: ['paloalto', 'fortinet', 'cisco', 'aws_nacl'],
  disable_user: ['okta', 'azure_ad', 'google_workspace', 'jumpcloud'],
  reset_password: ['okta', 'azure_ad', 'google_workspace'],
  revoke_sessions: ['okta', 'azure_ad'],
  notify: ['slack', 'teams', 'email', 'pagerduty'],
  create_ticket: ['jira', 'servicenow', 'zendesk'],
  query: ['athena', 'splunk', 'elastic'],
  webhook: [],
  custom: [],
}

const PARAMETER_SCHEMAS = {
  notify: {
    slack: ['channel', 'message'],
    teams: ['channel', 'message'],
    email: ['to', 'subject', 'body'],
    pagerduty: ['service_key', 'description', 'severity'],
  },
  create_ticket: {
    jira: ['project', 'summary', 'description', 'priority', 'assignee'],
    servicenow: ['table', 'short_description', 'description', 'urgency'],
  },
  block_ip: {
    paloalto: ['address_group'],
    aws_nacl: ['nacl_id', 'rule_number'],
  },
  query: {
    athena: ['database', 'query', 'output_location'],
    splunk: ['search', 'earliest_time', 'latest_time'],
  },
  webhook: {
    default: ['url', 'method', 'headers', 'body'],
  },
}

export default function StepEditor({ step, allSteps, onChange }) {
  const handleChange = (field, value) => {
    onChange({ [field]: value })
  }

  const handleParameterChange = (key, value) => {
    onChange({
      parameters: {
        ...step.parameters,
        [key]: value,
      },
    })
  }

  const availableProviders = PROVIDERS[step.action_type] || []
  const parameterSchema =
    PARAMETER_SCHEMAS[step.action_type]?.[step.provider] ||
    PARAMETER_SCHEMAS[step.action_type]?.default ||
    []

  const otherSteps = allSteps.filter((s) => s.id !== step.id)

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">
            Step Name
          </label>
          <input
            type="text"
            value={step.name}
            onChange={(e) => handleChange('name', e.target.value)}
            placeholder="Enter step name"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Action Type
          </label>
          <select
            value={step.action_type}
            onChange={(e) => {
              handleChange('action_type', e.target.value)
              handleChange('provider', '')
              handleChange('parameters', {})
            }}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            {Object.entries(
              ACTION_TYPES.reduce((acc, action) => {
                if (!acc[action.category]) acc[action.category] = []
                acc[action.category].push(action)
                return acc
              }, {})
            ).map(([category, actions]) => (
              <optgroup key={category} label={category}>
                {actions.map((action) => (
                  <option key={action.value} value={action.value}>
                    {action.label}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>

        {availableProviders.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Provider
            </label>
            <select
              value={step.provider || ''}
              onChange={(e) => {
                handleChange('provider', e.target.value)
                handleChange('parameters', {})
              }}
              className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
            >
              <option value="">Select provider...</option>
              {availableProviders.map((provider) => (
                <option key={provider} value={provider}>
                  {provider.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="col-span-2">
          <label className="block text-sm font-medium text-gray-700">
            Condition (Jinja2)
          </label>
          <input
            type="text"
            value={step.condition || ''}
            onChange={(e) => handleChange('condition', e.target.value)}
            placeholder="{{ alert.severity == 'critical' }}"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <p className="mt-1 text-xs text-gray-500">
            Optional. If provided, step only runs when condition is true.
          </p>
        </div>
      </div>

      {(step.provider || step.action_type === 'webhook' || step.action_type === 'custom') && (
        <div>
          <label className="mb-2 block text-sm font-medium text-gray-700">
            Parameters
          </label>
          <div className="space-y-2 rounded-lg border border-gray-200 p-3">
            {step.action_type === 'webhook' || step.action_type === 'custom' ? (
              <>
                <div>
                  <label className="block text-xs font-medium text-gray-600">
                    URL
                  </label>
                  <input
                    type="text"
                    value={step.parameters?.url || ''}
                    onChange={(e) => handleParameterChange('url', e.target.value)}
                    placeholder="https://api.example.com/webhook"
                    className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-primary-500 focus:outline-none"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-xs font-medium text-gray-600">
                      Method
                    </label>
                    <select
                      value={step.parameters?.method || 'POST'}
                      onChange={(e) => handleParameterChange('method', e.target.value)}
                      className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-primary-500 focus:outline-none"
                    >
                      <option value="GET">GET</option>
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                      <option value="DELETE">DELETE</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600">
                    Body (JSON or Jinja2 template)
                  </label>
                  <textarea
                    value={step.parameters?.body || ''}
                    onChange={(e) => handleParameterChange('body', e.target.value)}
                    placeholder='{"alert_id": "{{ alert.id }}"}'
                    rows={3}
                    className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm focus:border-primary-500 focus:outline-none"
                  />
                </div>
              </>
            ) : (
              parameterSchema.map((param) => (
                <div key={param}>
                  <label className="block text-xs font-medium text-gray-600">
                    {param.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                  </label>
                  {param === 'message' || param === 'body' || param === 'description' ? (
                    <textarea
                      value={step.parameters?.[param] || ''}
                      onChange={(e) => handleParameterChange(param, e.target.value)}
                      placeholder={`{{ alert.title }}`}
                      rows={2}
                      className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-primary-500 focus:outline-none"
                    />
                  ) : (
                    <input
                      type="text"
                      value={step.parameters?.[param] || ''}
                      onChange={(e) => handleParameterChange(param, e.target.value)}
                      placeholder={`{{ context.${param} }}`}
                      className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-primary-500 focus:outline-none"
                    />
                  )}
                </div>
              ))
            )}
            <p className="text-xs text-gray-500">
              Use Jinja2 templates for dynamic values. Available variables: alert,
              context, previous_step
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">
            On Success
          </label>
          <select
            value={step.on_success || ''}
            onChange={(e) => handleChange('on_success', e.target.value || null)}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">Continue to next step</option>
            <option value="end">End playbook</option>
            {otherSteps.map((s) => (
              <option key={s.id} value={s.id}>
                Jump to: {s.name}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            On Failure
          </label>
          <select
            value={step.on_failure || ''}
            onChange={(e) => handleChange('on_failure', e.target.value || null)}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">Fail playbook</option>
            <option value="continue">Continue to next step</option>
            <option value="end">End playbook (success)</option>
            {otherSteps.map((s) => (
              <option key={s.id} value={s.id}>
                Jump to: {s.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">
            Timeout (seconds)
          </label>
          <input
            type="number"
            value={step.timeout_seconds || 300}
            onChange={(e) => handleChange('timeout_seconds', parseInt(e.target.value))}
            min={10}
            max={3600}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Retry Count
          </label>
          <input
            type="number"
            value={step.retry_count || 0}
            onChange={(e) => handleChange('retry_count', parseInt(e.target.value))}
            min={0}
            max={5}
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
        </div>

        <div className="flex items-end">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={step.requires_approval || false}
              onChange={(e) => handleChange('requires_approval', e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
            />
            <span className="text-sm text-gray-700">Requires Approval</span>
          </label>
        </div>
      </div>

      {step.requires_approval && (
        <div>
          <label className="block text-sm font-medium text-gray-700">
            Approver Roles
          </label>
          <input
            type="text"
            value={step.approval_roles?.join(', ') || ''}
            onChange={(e) =>
              handleChange(
                'approval_roles',
                e.target.value.split(',').map((r) => r.trim()).filter(Boolean)
              )
            }
            placeholder="admin, security-analyst"
            className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <p className="mt-1 text-xs text-gray-500">
            Comma-separated list of roles that can approve this step
          </p>
        </div>
      )}
    </div>
  )
}
