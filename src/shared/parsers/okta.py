"""
Okta Log Parser with ECS Normalization

Normalizes Okta System Log events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class OktaParser(BaseParser):
    """Parser for Okta System Log events with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "okta"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Okta System Log event and normalize to ECS.

        Args:
            raw_event: Raw Okta event from System Log API

        Returns:
            Normalized event in ECS format
        """
        # Extract core fields
        event_type = raw_event.get('eventType', '')
        display_message = raw_event.get('displayMessage', '')
        severity = raw_event.get('severity', 'INFO')
        published = raw_event.get('published', '')

        # Extract actor (user) information
        actor = raw_event.get('actor', {})
        user_name = actor.get('alternateId', '')  # Usually email
        user_id = actor.get('id', '')
        user_display_name = actor.get('displayName', '')

        # Extract client information
        client = raw_event.get('client', {})
        source_ip = client.get('ipAddress', '')
        user_agent = client.get('userAgent', {}).get('rawUserAgent', '')
        device = client.get('device', 'Unknown')
        geo = client.get('geographicalContext', {})

        # Extract target resources
        target = raw_event.get('target', [])
        target_resources = self._extract_targets(target)

        # Extract authentication context
        auth_context = raw_event.get('authenticationContext', {})
        auth_provider = auth_context.get('authenticationProvider', '')
        external_session_id = auth_context.get('externalSessionId', '')

        # Extract outcome
        outcome = raw_event.get('outcome', {})
        result = outcome.get('result', '')
        reason = outcome.get('reason', '')

        # Map Okta severity to ECS severity
        ecs_severity = self._map_severity(severity)

        # Map Okta result to ECS outcome
        ecs_outcome = self._map_outcome(result)

        # Build ECS-normalized event
        normalized = {
            # ECS Core Fields
            '@timestamp': self._parse_timestamp(published),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': self._categorize_event(event_type),
                'type': self._get_event_type(event_type),
                'action': event_type,
                'outcome': ecs_outcome,
                'severity': ecs_severity,
                'created': self._parse_timestamp(published),
                'id': raw_event.get('uuid', ''),
                'provider': 'okta',
                'reason': reason
            },

            # Message
            'message': display_message,

            # User fields
            'user': {
                'name': user_name,
                'id': user_id,
                'full_name': user_display_name,
                'email': user_name if '@' in user_name else None
            },

            # Source fields (client)
            'source': {
                'ip': source_ip,
                'geo': {
                    'city_name': geo.get('city', ''),
                    'country_name': geo.get('country', ''),
                    'region_name': geo.get('state', ''),
                    'postal_code': geo.get('postalCode', ''),
                    'location': {
                        'lat': geo.get('geolocation', {}).get('lat'),
                        'lon': geo.get('geolocation', {}).get('lon')
                    }
                }
            },

            # User agent
            'user_agent': {
                'original': user_agent
            },

            # Related fields
            'related': {
                'ip': [source_ip] if source_ip else [],
                'user': [user_name, user_id] if user_name or user_id else []
            },

            # Okta-specific fields
            'okta': {
                'event_type': event_type,
                'display_message': display_message,
                'severity': severity,
                'transaction': {
                    'id': raw_event.get('transaction', {}).get('id', ''),
                    'type': raw_event.get('transaction', {}).get('type', '')
                },
                'debug_context': raw_event.get('debugContext', {}),
                'authentication_context': {
                    'authentication_provider': auth_provider,
                    'authentication_step': auth_context.get('authenticationStep', 0),
                    'credential_provider': auth_context.get('credentialProvider', ''),
                    'credential_type': auth_context.get('credentialType', ''),
                    'external_session_id': external_session_id,
                    'issuer': auth_context.get('issuer', {})
                },
                'security_context': raw_event.get('securityContext', {}),
                'client': {
                    'device': device,
                    'id': client.get('id', ''),
                    'zone': client.get('zone', '')
                },
                'target': target_resources,
                'outcome': {
                    'result': result,
                    'reason': reason
                },
                'request': {
                    'ip_chain': raw_event.get('request', {}).get('ipChain', [])
                }
            },

            # Preserve raw event
            '_raw': raw_event
        }

        # Clean None values
        return self._remove_none_values(normalized)

    def _extract_targets(self, targets: List[Dict]) -> List[Dict]:
        """Extract and normalize target resources"""
        normalized_targets = []

        for target in targets:
            normalized_target = {
                'id': target.get('id', ''),
                'type': target.get('type', ''),
                'alternate_id': target.get('alternateId', ''),
                'display_name': target.get('displayName', ''),
                'details': target.get('detailEntry', {})
            }
            normalized_targets.append(normalized_target)

        return normalized_targets

    def _map_severity(self, okta_severity: str) -> int:
        """
        Map Okta severity to ECS numeric severity (0-100).

        Okta severities: INFO, WARN, ERROR
        """
        severity_mapping = {
            'INFO': 20,
            'WARN': 50,
            'ERROR': 80
        }
        return severity_mapping.get(okta_severity, 20)

    def _map_outcome(self, okta_result: str) -> str:
        """Map Okta result to ECS outcome"""
        if okta_result in ('SUCCESS', 'ALLOW'):
            return 'success'
        elif okta_result in ('FAILURE', 'DENY'):
            return 'failure'
        else:
            return 'unknown'

    def _categorize_event(self, event_type: str) -> List[str]:
        """Categorize event based on Okta event type"""
        categories = []

        # Authentication events
        if 'user.session' in event_type.lower() or 'user.authentication' in event_type.lower():
            categories.append('authentication')

        # User management
        if 'user.' in event_type.lower() and any(x in event_type.lower() for x in ['create', 'update', 'delete', 'deactivate']):
            categories.append('iam')

        # Application events
        if 'application.' in event_type.lower():
            categories.append('configuration')

        # Policy events
        if 'policy.' in event_type.lower():
            categories.append('configuration')

        # Group management
        if 'group.' in event_type.lower():
            categories.append('iam')

        # Admin actions
        if 'system.' in event_type.lower() or 'admin.' in event_type.lower():
            categories.append('configuration')

        return categories if categories else ['session']

    def _get_event_type(self, event_type: str) -> List[str]:
        """Determine ECS event.type based on Okta event"""
        types = []

        lower_event = event_type.lower()

        if 'create' in lower_event:
            types.append('creation')
        if 'update' in lower_event or 'modify' in lower_event:
            types.append('change')
        if 'delete' in lower_event or 'remove' in lower_event:
            types.append('deletion')
        if 'login' in lower_event or 'authentication' in lower_event:
            types.append('start')
        if 'logout' in lower_event:
            types.append('end')
        if 'deny' in lower_event or 'block' in lower_event:
            types.append('denied')
        if 'allow' in lower_event or 'grant' in lower_event:
            types.append('allowed')

        return types if types else ['info']

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate ISO 8601 timestamp"""
        if not timestamp_str:
            return datetime.utcnow().isoformat() + 'Z'

        # Okta uses ISO 8601 format, ensure it's valid
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
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
        Validate that event has required Okta fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['uuid', 'published', 'eventType', 'actor']

        for field in required_fields:
            if field not in event:
                return False

        return True
