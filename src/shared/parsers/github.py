"""
GitHub Enterprise Audit Log Parser with ECS Normalization

Normalizes GitHub Enterprise audit log events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports:
- GitHub Enterprise Cloud
- GitHub Enterprise Server
- Organization-level audit logs
- Repository-level events
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class GitHubParser(BaseParser):
    """Parser for GitHub Enterprise audit log events with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "github"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse GitHub audit log event and normalize to ECS.

        Args:
            raw_event: Raw GitHub audit log event

        Returns:
            Normalized event in ECS format
        """
        # Extract core fields
        timestamp = raw_event.get('@timestamp', 0)
        action = raw_event.get('action', '')
        actor = raw_event.get('actor', '')
        actor_location = raw_event.get('actor_location', {})
        user_agent = raw_event.get('user_agent', '')

        # Extract organization/enterprise
        org = raw_event.get('org', '')
        business = raw_event.get('business', '')

        # Extract repository information
        repo = raw_event.get('repo', '')

        # Extract additional context
        created_at = raw_event.get('created_at', 0)
        document_id = raw_event.get('_document_id', '')

        # Extract user information
        user = raw_event.get('user', '')
        actor_id = raw_event.get('actor_id', 0)

        # Extract IP and location
        actor_ip = actor_location.get('country_code', '')  # GitHub doesn't always expose IP
        country_code = actor_location.get('country_code', '')

        # Categorize event
        ecs_category = self._categorize_event(action)
        ecs_type = self._get_event_type(action)
        ecs_outcome = self._get_outcome(raw_event)

        # Build ECS-normalized event
        normalized = {
            # ECS Core Fields
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ecs_category,
                'type': ecs_type,
                'action': action,
                'outcome': ecs_outcome,
                'created': self._parse_timestamp(created_at) if created_at else None,
                'id': document_id,
                'provider': 'github',
                'module': 'audit'
            },

            # User fields
            'user': {
                'name': actor or user,
                'id': str(actor_id) if actor_id else None
            },

            # Source fields (location information)
            'source': {
                'geo': {
                    'country_iso_code': country_code
                } if country_code else None
            },

            # User agent fields
            'user_agent': {
                'original': user_agent
            } if user_agent else None,

            # Organization fields
            'organization': {
                'name': org or business
            } if org or business else None,

            # Related fields
            'related': {
                'user': [actor, user] if actor or user else []
            },

            # GitHub-specific fields
            'github': {
                'action': action,
                'actor': actor,
                'actor_id': actor_id,
                'actor_location': actor_location,
                'org': org,
                'business': business,
                'repo': repo,
                'created_at': created_at,
                'document_id': document_id,
                'user': user,
                'user_agent': user_agent,

                # Additional contextual fields
                'team': raw_event.get('team', ''),
                'permission': raw_event.get('permission', ''),
                'visibility': raw_event.get('visibility', ''),
                'public': raw_event.get('public', None),

                # OAuth application fields
                'oauth_application_id': raw_event.get('oauth_application_id', 0),
                'application': raw_event.get('application', ''),

                # Transport protocol fields
                'transport_protocol': raw_event.get('transport_protocol', 0),
                'transport_protocol_name': raw_event.get('transport_protocol_name', ''),

                # Data fields
                'data': raw_event.get('data', {}),

                # Programmatic access fields
                'programmatic_access_type': raw_event.get('programmatic_access_type', ''),
                'token_scopes': raw_event.get('token_scopes', ''),

                # Repository fields
                'repo_id': raw_event.get('repo_id', 0),
                'repository': raw_event.get('repository', ''),
                'repository_public': raw_event.get('repository_public', None),

                # Issue/PR fields
                'issue': raw_event.get('issue', ''),
                'pull_request': raw_event.get('pull_request', ''),

                # Branch protection fields
                'branch': raw_event.get('branch', ''),
                'protected_branch': raw_event.get('protected_branch', ''),

                # Workflow fields
                'workflow': raw_event.get('workflow', ''),
                'workflow_id': raw_event.get('workflow_id', 0),
                'workflow_run_id': raw_event.get('workflow_run_id', 0),

                # External identity fields
                'external_identity_nameid': raw_event.get('external_identity_nameid', ''),
                'external_identity_username': raw_event.get('external_identity_username', ''),

                # Hook fields
                'hook_id': raw_event.get('hook_id', 0),
                'events': raw_event.get('events', []),
                'active': raw_event.get('active', None),

                # Deployment fields
                'deployment_id': raw_event.get('deployment_id', 0),
                'environment': raw_event.get('environment', ''),

                # Billing fields
                'previous_plan_name': raw_event.get('previous_plan_name', ''),
                'plan_name': raw_event.get('plan_name', '')
            },

            # Preserve raw event
            '_raw': raw_event
        }

        # Clean None values
        return self._remove_none_values(normalized)

    def _categorize_event(self, action: str) -> List[str]:
        """Categorize event based on action"""
        categories = []

        action_lower = action.lower()

        # Authentication and authorization
        if any(x in action_lower for x in ['oauth', 'token', 'credential', 'ssh', 'gpg', 'personal_access_token']):
            categories.append('authentication')

        # IAM operations
        if any(x in action_lower for x in ['member', 'team', 'permission', 'role', 'collaborator', 'invite']):
            categories.append('iam')

        # Configuration changes
        if any(x in action_lower for x in ['create', 'update', 'destroy', 'rename', 'transfer', 'enable', 'disable']):
            categories.append('configuration')

        # Repository/file operations
        if any(x in action_lower for x in ['repo', 'git', 'commit', 'push', 'pull', 'clone', 'download']):
            categories.append('file')

        # Web operations
        if any(x in action_lower for x in ['hook', 'webhook', 'integration', 'app']):
            categories.append('web')

        # Package operations
        if any(x in action_lower for x in ['package', 'release', 'artifact']):
            categories.append('package')

        return categories if categories else ['session']

    def _get_event_type(self, action: str) -> List[str]:
        """Determine ECS event.type based on action"""
        types = []

        action_lower = action.lower()

        if any(x in action_lower for x in ['create', 'add', 'register', 'install']):
            types.append('creation')
        if any(x in action_lower for x in ['update', 'modify', 'edit', 'change', 'rename']):
            types.append('change')
        if any(x in action_lower for x in ['destroy', 'delete', 'remove', 'uninstall']):
            types.append('deletion')
        if any(x in action_lower for x in ['access', 'download', 'clone', 'fetch']):
            types.append('access')
        if any(x in action_lower for x in ['enable', 'activate', 'start']):
            types.append('start')
        if any(x in action_lower for x in ['disable', 'deactivate', 'stop']):
            types.append('end')
        if any(x in action_lower for x in ['deny', 'block', 'reject']):
            types.append('denied')
        if any(x in action_lower for x in ['approve', 'accept']):
            types.append('allowed')

        return types if types else ['info']

    def _get_outcome(self, event: Dict[str, Any]) -> str:
        """Determine ECS outcome from event data"""
        # GitHub audit logs don't typically include explicit success/failure
        # Most logged events represent successful actions
        # Failures are usually in the action name (e.g., "failed_login")
        action = event.get('action', '').lower()

        if 'fail' in action or 'error' in action or 'deny' in action or 'reject' in action:
            return 'failure'

        return 'success'

    def _parse_timestamp(self, timestamp: Any) -> Optional[str]:
        """Parse and validate timestamp (can be Unix milliseconds or ISO 8601)"""
        if not timestamp:
            return None

        try:
            # GitHub uses Unix timestamp in milliseconds
            if isinstance(timestamp, int):
                dt = datetime.fromtimestamp(timestamp / 1000, tz=None)
                return dt.isoformat() + 'Z'

            # ISO 8601 string
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.isoformat() + 'Z'

            return None
        except (ValueError, OSError):
            return None

    def _remove_none_values(self, data: Any) -> Any:
        """Recursively remove None values from dict"""
        if isinstance(data, dict):
            return {
                k: self._remove_none_values(v)
                for k, v in data.items()
                if v is not None and v != {} and v != []
            }
        elif isinstance(data, list):
            return [self._remove_none_values(item) for item in data if item is not None]
        else:
            return data

    def validate(self, event: Dict[str, Any]) -> bool:
        """
        Validate that event has required GitHub audit log fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['@timestamp', 'action']

        for field in required_fields:
            if field not in event:
                return False

        # Must have either actor or user
        if 'actor' not in event and 'user' not in event:
            return False

        return True
