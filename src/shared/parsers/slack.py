"""
Slack Audit Logs Parser with ECS Normalization

Normalizes Slack Enterprise Grid audit log events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class SlackParser(BaseParser):
    """Parser for Slack Enterprise Grid audit logs with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "slack"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Slack audit log event and normalize to ECS.

        Args:
            raw_event: Raw Slack audit log event

        Returns:
            Normalized event in ECS format
        """
        # Extract core fields
        event_id = raw_event.get('id', '')
        action = raw_event.get('action', '')
        date_create = raw_event.get('date_create', 0)

        # Extract actor (user) information
        actor = raw_event.get('actor', {})
        actor_type = actor.get('type', '')
        actor_user = actor.get('user', {})
        user_id = actor_user.get('id', '')
        user_email = actor_user.get('email', '')
        user_name = actor_user.get('name', '')

        # Extract context information
        context = raw_event.get('context', {})
        ua = context.get('ua', '')
        ip_address = context.get('ip_address', '')
        location = context.get('location', {})
        session_id = context.get('session_id', '')

        # Extract entity information
        entity = raw_event.get('entity', {})
        entity_type = entity.get('type', '')
        entity_id = entity.get('id', '')

        # Extract details
        details = raw_event.get('details', {})

        # Categorize event
        ecs_category = self._categorize_event(action)
        ecs_type = self._get_event_type(action)
        ecs_outcome = self._determine_outcome(details)

        # Build ECS-normalized event
        normalized = {
            # ECS Core Fields
            '@timestamp': self._parse_timestamp(date_create),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ecs_category,
                'type': ecs_type,
                'action': action,
                'outcome': ecs_outcome,
                'created': self._parse_timestamp(date_create),
                'id': event_id,
                'provider': 'slack',
                'module': 'audit'
            },

            # User fields (actor)
            'user': {
                'id': user_id,
                'email': user_email,
                'name': user_name
            },

            # Source fields (client IP)
            'source': {
                'ip': ip_address,
                'geo': {
                    'country_name': location.get('country', ''),
                    'region_name': location.get('region', ''),
                    'city_name': location.get('city', '')
                }
            },

            # User agent
            'user_agent': {
                'original': ua
            },

            # Related fields
            'related': {
                'ip': [ip_address] if ip_address else [],
                'user': [user_id, user_email, user_name] if user_id or user_email or user_name else []
            },

            # Slack-specific fields
            'slack': {
                'id': event_id,
                'action': action,
                'date_create': date_create,
                'actor': {
                    'type': actor_type,
                    'user': {
                        'id': user_id,
                        'email': user_email,
                        'name': user_name,
                        'team': actor_user.get('team', '')
                    }
                },
                'context': {
                    'ua': ua,
                    'ip_address': ip_address,
                    'location': location,
                    'session_id': session_id,
                    'app': context.get('app', {}),
                    'device_id': context.get('device_id', '')
                },
                'entity': {
                    'type': entity_type,
                    'id': entity_id,
                    'name': entity.get('name', ''),
                    'domain': entity.get('domain', ''),
                    'privacy': entity.get('privacy', ''),
                    'app': entity.get('app', {})
                },
                'details': details
            },

            # Preserve raw event
            '_raw': raw_event
        }

        # Clean None values
        return self._remove_none_values(normalized)

    def _categorize_event(self, action: str) -> List[str]:
        """Categorize event based on Slack action"""
        categories = []

        action_lower = action.lower()

        # Authentication events
        if any(x in action_lower for x in ['signin', 'signout', 'login', 'logout', 'session']):
            categories.append('authentication')

        # User/team management
        if any(x in action_lower for x in ['user_', 'member_', 'team_']):
            categories.append('iam')

        # File operations
        if any(x in action_lower for x in ['file_', 'download', 'upload', 'share']):
            categories.append('file')

        # Configuration changes
        if any(x in action_lower for x in ['workspace_', 'app_', 'channel_', 'permissions_']):
            categories.append('configuration')

        # Data access
        if any(x in action_lower for x in ['export', 'compliance_export']):
            categories.append('file')

        return categories if categories else ['session']

    def _get_event_type(self, action: str) -> List[str]:
        """Determine ECS event.type based on Slack action"""
        types = []

        action_lower = action.lower()

        if any(x in action_lower for x in ['created', 'added', 'invited']):
            types.append('creation')
        if any(x in action_lower for x in ['changed', 'updated', 'modified']):
            types.append('change')
        if any(x in action_lower for x in ['deleted', 'removed', 'revoked']):
            types.append('deletion')
        if any(x in action_lower for x in ['login', 'signin']):
            types.append('start')
        if any(x in action_lower for x in ['logout', 'signout']):
            types.append('end')
        if any(x in action_lower for x in ['download', 'export', 'shared', 'accessed']):
            types.append('access')
        if any(x in action_lower for x in ['approved', 'allowed']):
            types.append('allowed')
        if any(x in action_lower for x in ['denied', 'rejected', 'failed']):
            types.append('denied')

        return types if types else ['info']

    def _determine_outcome(self, details: Dict[str, Any]) -> str:
        """Determine outcome from event details"""
        # Check for failure indicators
        if details.get('is_failure', False):
            return 'failure'
        if details.get('is_denied', False):
            return 'failure'

        # Check for success indicators
        if details.get('is_success', True):
            return 'success'

        return 'unknown'

    def _parse_timestamp(self, timestamp: int) -> str:
        """Parse Unix timestamp to ISO 8601"""
        if not timestamp:
            return datetime.utcnow().isoformat() + 'Z'

        try:
            dt = datetime.fromtimestamp(timestamp, tz=None)
            return dt.isoformat() + 'Z'
        except (ValueError, OSError):
            return datetime.utcnow().isoformat() + 'Z'

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
        Validate that event has required Slack fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['id', 'action', 'date_create', 'actor']

        for field in required_fields:
            if field not in event:
                return False

        # Validate actor structure
        if not isinstance(event.get('actor'), dict):
            return False

        return True
