"""
Google Workspace Reports Parser with ECS Normalization

Normalizes Google Workspace Admin SDK Reports API events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class GoogleWorkspaceParser(BaseParser):
    """Parser for Google Workspace Reports API events with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "google_workspace"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Google Workspace Reports event and normalize to ECS.

        Args:
            raw_event: Raw event from Google Workspace Reports API

        Returns:
            Normalized event in ECS format
        """
        # Extract core fields
        event_id = raw_event.get('id', {})
        event_time = event_id.get('time', '')
        unique_qualifier = event_id.get('uniqueQualifier', '')
        application_name = event_id.get('applicationName', '')
        customer_id = event_id.get('customerId', '')

        # Extract actor (user) information
        actor = raw_event.get('actor', {})
        actor_email = actor.get('email', '')
        actor_profile_id = actor.get('profileId', '')
        caller_type = actor.get('callerType', '')

        # Extract IP address
        ip_address = raw_event.get('ipAddress', '')

        # Extract events (activities)
        events = raw_event.get('events', [])
        event_names = [e.get('name', '') for e in events]
        event_types = [e.get('type', '') for e in events]
        parameters = self._extract_parameters(events)

        # Extract ownership information
        ownership_domain = raw_event.get('ownershipDomain', '')

        # Categorize event
        ecs_category = self._categorize_event(application_name, event_names)
        ecs_type = self._get_event_type(event_names, event_types)
        ecs_action = self._get_primary_action(event_names)

        # Determine outcome
        ecs_outcome = self._determine_outcome(parameters)

        # Build ECS-normalized event
        normalized = {
            # ECS Core Fields
            '@timestamp': self._parse_timestamp(event_time),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ecs_category,
                'type': ecs_type,
                'action': ecs_action,
                'outcome': ecs_outcome,
                'created': self._parse_timestamp(event_time),
                'id': unique_qualifier,
                'provider': 'google_workspace',
                'module': application_name
            },

            # User fields (actor)
            'user': {
                'email': actor_email,
                'id': actor_profile_id,
                'name': actor_email.split('@')[0] if '@' in actor_email else actor_email
            },

            # Source fields (client IP)
            'source': {
                'ip': ip_address
            },

            # Organization fields
            'organization': {
                'id': customer_id,
                'name': ownership_domain
            },

            # Related fields
            'related': {
                'ip': [ip_address] if ip_address else [],
                'user': [actor_email, actor_profile_id] if actor_email or actor_profile_id else []
            },

            # Google Workspace-specific fields
            'google_workspace': {
                'kind': raw_event.get('kind', ''),
                'id': {
                    'time': event_time,
                    'unique_qualifier': unique_qualifier,
                    'application_name': application_name,
                    'customer_id': customer_id
                },
                'actor': {
                    'email': actor_email,
                    'profile_id': actor_profile_id,
                    'caller_type': caller_type
                },
                'ownership_domain': ownership_domain,
                'events': self._normalize_events(events),
                'org_unit_path': raw_event.get('orgUnitPath', ''),
                'etag': raw_event.get('etag', '')
            },

            # Preserve raw event
            '_raw': raw_event
        }

        # Clean None values
        return self._remove_none_values(normalized)

    def _extract_parameters(self, events: List[Dict]) -> Dict[str, Any]:
        """Extract and flatten parameters from all events"""
        all_params = {}

        for event in events:
            params = event.get('parameters', [])
            for param in params:
                name = param.get('name', '')
                value = param.get('value')
                multi_value = param.get('multiValue')
                int_value = param.get('intValue')
                bool_value = param.get('boolValue')

                # Use first non-None value
                param_value = value or multi_value or int_value or bool_value
                if param_value is not None:
                    all_params[name] = param_value

        return all_params

    def _normalize_events(self, events: List[Dict]) -> List[Dict]:
        """Normalize event details"""
        normalized_events = []

        for event in events:
            normalized_event = {
                'name': event.get('name', ''),
                'type': event.get('type', ''),
                'parameters': {}
            }

            # Extract parameters
            params = event.get('parameters', [])
            for param in params:
                name = param.get('name', '')
                value = (
                    param.get('value') or
                    param.get('multiValue') or
                    param.get('intValue') or
                    param.get('boolValue')
                )
                if value is not None:
                    normalized_event['parameters'][name] = value

            normalized_events.append(normalized_event)

        return normalized_events

    def _categorize_event(self, application_name: str, event_names: List[str]) -> List[str]:
        """Categorize event based on application and event names"""
        categories = []

        # Authentication events
        if application_name == 'login' or any('login' in name.lower() for name in event_names):
            categories.append('authentication')

        # User/group management
        if application_name in ['admin', 'groups']:
            categories.append('iam')

        # File/data access
        if application_name == 'drive':
            categories.append('file')

        # Configuration changes
        if any(name in ['CHANGE_APPLICATION_SETTING', 'CREATE_APPLICATION_SETTING', 'DELETE_APPLICATION_SETTING'] for name in event_names):
            categories.append('configuration')

        # Token/credential events
        if application_name == 'token':
            categories.append('authentication')

        return categories if categories else ['session']

    def _get_event_type(self, event_names: List[str], event_types: List[str]) -> List[str]:
        """Determine ECS event.type based on event names and types"""
        types = []

        for name, type_val in zip(event_names, event_types):
            name_lower = name.lower()

            if 'create' in name_lower or type_val == 'CREATE':
                types.append('creation')
            if 'update' in name_lower or 'modify' in name_lower or 'change' in name_lower:
                types.append('change')
            if 'delete' in name_lower or 'remove' in name_lower:
                types.append('deletion')
            if 'login' in name_lower or 'signin' in name_lower:
                types.append('start')
            if 'logout' in name_lower or 'signout' in name_lower:
                types.append('end')
            if 'download' in name_lower or 'view' in name_lower or 'access' in name_lower:
                types.append('access')
            if 'grant' in name_lower or 'allow' in name_lower:
                types.append('allowed')
            if 'deny' in name_lower or 'block' in name_lower or 'revoke' in name_lower:
                types.append('denied')

        return list(set(types)) if types else ['info']

    def _get_primary_action(self, event_names: List[str]) -> str:
        """Get primary action from event names"""
        if not event_names:
            return 'unknown'
        # Use first event name as primary action
        return event_names[0]

    def _determine_outcome(self, parameters: Dict[str, Any]) -> str:
        """Determine outcome from event parameters"""
        # Check for common failure indicators
        if parameters.get('login_failure_type'):
            return 'failure'
        if parameters.get('login_challenge_status') == 'Challenge Failed':
            return 'failure'
        if parameters.get('is_suspicious', False):
            return 'failure'

        # Check for success indicators
        if parameters.get('login_type'):
            return 'success'

        return 'unknown'

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate RFC 3339 timestamp"""
        if not timestamp_str:
            return datetime.utcnow().isoformat() + 'Z'

        # Google uses RFC 3339 format
        try:
            # Handle both Z and +00:00 timezone formats
            if timestamp_str.endswith('Z'):
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp_str)
            return dt.isoformat() + 'Z'
        except ValueError:
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
        Validate that event has required Google Workspace fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['id', 'actor', 'events']

        for field in required_fields:
            if field not in event:
                return False

        # Validate id structure
        if not isinstance(event.get('id'), dict):
            return False

        id_required = ['time', 'uniqueQualifier', 'applicationName']
        for field in id_required:
            if field not in event['id']:
                return False

        return True
