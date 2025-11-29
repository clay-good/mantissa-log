"""
Duo Security Log Parser with ECS Normalization

Normalizes Duo authentication logs to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports Duo Admin API logs including:
- Authentication logs (MFA attempts, push notifications, bypass codes)
- Administrator activity logs
- Telephony logs (phone call and SMS events)
- Trust monitor events
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from .base import BaseParser


class DuoParser(BaseParser):
    """Parser for Duo Security logs with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "duo"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Duo log event and normalize to ECS.

        Args:
            raw_event: Raw Duo event

        Returns:
            Normalized event in ECS format
        """
        # Determine event type and parse accordingly
        if 'txid' in raw_event and 'factor' in raw_event:
            return self._parse_auth_log(raw_event)
        elif 'action' in raw_event and 'object' in raw_event:
            return self._parse_admin_log(raw_event)
        elif 'credits' in raw_event or 'phone' in raw_event:
            return self._parse_telephony_log(raw_event)
        else:
            return self._parse_generic_log(raw_event)

    def _parse_auth_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Duo authentication log event"""
        # Extract core fields
        txid = raw_event.get('txid', '')
        timestamp = raw_event.get('timestamp', 0)
        username = raw_event.get('user', {}).get('name', '')
        user_key = raw_event.get('user', {}).get('key', '')

        # Authentication details
        factor = raw_event.get('factor', '')
        result = raw_event.get('result', '')
        reason = raw_event.get('reason', '')
        event_type = raw_event.get('event_type', '')

        # Access device info
        access_device = raw_event.get('access_device', {})
        access_ip = access_device.get('ip', '')
        access_location = access_device.get('location', {})
        access_browser = access_device.get('browser', '')
        access_os = access_device.get('os', '')

        # Auth device info (the 2FA device used)
        auth_device = raw_event.get('auth_device', {})
        device_name = auth_device.get('name', '')
        device_ip = auth_device.get('ip', '')
        device_location = auth_device.get('location', {})

        # Application info
        application = raw_event.get('application', {})
        app_name = application.get('name', '')
        app_key = application.get('key', '')

        # Determine outcome
        ecs_outcome = 'success' if result == 'SUCCESS' else 'failure'

        # Build ECS-normalized event
        normalized = {
            '@timestamp': self._unix_to_iso(timestamp),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ['authentication'],
                'type': ['info'] if result == 'SUCCESS' else ['denied'],
                'action': f'mfa_{factor.lower()}' if factor else 'mfa_attempt',
                'outcome': ecs_outcome,
                'reason': reason,
                'id': txid,
                'provider': 'duo',
                'module': 'authentication'
            },

            # User fields
            'user': {
                'name': username,
                'id': user_key,
                'email': raw_event.get('user', {}).get('email', '')
            },

            # Source fields (where the auth request came from)
            'source': {
                'ip': access_ip,
                'geo': {
                    'city_name': access_location.get('city', ''),
                    'region_name': access_location.get('state', ''),
                    'country_iso_code': access_location.get('country', '')
                }
            },

            # User agent
            'user_agent': {
                'name': access_browser,
                'os': {
                    'name': access_os,
                    'version': access_device.get('os_version', '')
                },
                'original': raw_event.get('access_device', {}).get('browser_version', '')
            },

            # Related fields
            'related': {
                'ip': [ip for ip in [access_ip, device_ip] if ip],
                'user': [username, user_key] if username else []
            },

            # Duo-specific fields
            'duo': {
                'txid': txid,
                'event_type': event_type,
                'result': result,
                'reason': reason,
                'factor': factor,
                'integration': app_name,
                'integration_key': app_key,
                'user': {
                    'name': username,
                    'key': user_key,
                    'groups': raw_event.get('user', {}).get('groups', [])
                },
                'access_device': {
                    'ip': access_ip,
                    'hostname': access_device.get('hostname', ''),
                    'browser': access_browser,
                    'browser_version': access_device.get('browser_version', ''),
                    'os': access_os,
                    'os_version': access_device.get('os_version', ''),
                    'flash_version': access_device.get('flash_version', ''),
                    'java_version': access_device.get('java_version', ''),
                    'is_encryption_enabled': access_device.get('is_encryption_enabled'),
                    'is_firewall_enabled': access_device.get('is_firewall_enabled'),
                    'is_password_set': access_device.get('is_password_set'),
                    'location': access_location
                },
                'auth_device': {
                    'name': device_name,
                    'ip': device_ip,
                    'type': auth_device.get('type', ''),
                    'location': device_location
                },
                'application': {
                    'name': app_name,
                    'key': app_key
                },
                'alias': raw_event.get('alias', ''),
                'email': raw_event.get('email', ''),
                'isotimestamp': raw_event.get('isotimestamp', ''),
                'new_enrollment': raw_event.get('new_enrollment', False),
                'trusted_endpoint_status': raw_event.get('trusted_endpoint_status', '')
            },

            # Preserve raw event
            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_admin_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Duo administrator activity log event"""
        timestamp = raw_event.get('timestamp', 0)
        action = raw_event.get('action', '')
        obj = raw_event.get('object', '')
        username = raw_event.get('username', '')
        description = raw_event.get('description', {})

        # Determine event type based on action
        ecs_type = ['admin']
        if 'delete' in action.lower():
            ecs_type.append('deletion')
        elif 'create' in action.lower() or 'add' in action.lower():
            ecs_type.append('creation')
        elif 'update' in action.lower() or 'change' in action.lower():
            ecs_type.append('change')

        normalized = {
            '@timestamp': self._unix_to_iso(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['iam', 'configuration'],
                'type': ecs_type,
                'action': action,
                'outcome': 'success',
                'provider': 'duo',
                'module': 'admin'
            },

            'user': {
                'name': username
            },

            'duo': {
                'action': action,
                'object': obj,
                'description': description,
                'admin_name': username,
                'isotimestamp': raw_event.get('isotimestamp', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_telephony_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Duo telephony log event"""
        timestamp = raw_event.get('timestamp', 0)
        phone = raw_event.get('phone', '')
        telephony_type = raw_event.get('type', '')
        context = raw_event.get('context', '')
        credits = raw_event.get('credits', 0)

        normalized = {
            '@timestamp': self._unix_to_iso(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['authentication'],
                'type': ['info'],
                'action': f'telephony_{telephony_type.lower()}' if telephony_type else 'telephony',
                'outcome': 'success',
                'provider': 'duo',
                'module': 'telephony'
            },

            'duo': {
                'phone': phone,
                'telephony_type': telephony_type,
                'context': context,
                'credits': credits,
                'isotimestamp': raw_event.get('isotimestamp', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic Duo log event"""
        timestamp = raw_event.get('timestamp', 0)

        normalized = {
            '@timestamp': self._unix_to_iso(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['iam'],
                'type': ['info'],
                'provider': 'duo',
                'module': 'generic'
            },

            'duo': raw_event,

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _unix_to_iso(self, timestamp: int) -> str:
        """Convert Unix timestamp to ISO 8601"""
        if not timestamp:
            return datetime.now(timezone.utc).isoformat()

        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OSError):
            return datetime.now(timezone.utc).isoformat()

    def _remove_none_values(self, data: Any) -> Any:
        """Recursively remove None values from dict"""
        if isinstance(data, dict):
            return {
                k: self._remove_none_values(v)
                for k, v in data.items()
                if v is not None and v != {} and v != [] and v != ''
            }
        elif isinstance(data, list):
            return [self._remove_none_values(item) for item in data if item is not None]
        else:
            return data

    def validate(self, event: Dict[str, Any]) -> bool:
        """
        Validate that event has required Duo fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # At minimum, need a timestamp
        if 'timestamp' not in event:
            return False

        # Check for auth log structure
        if 'txid' in event:
            return 'factor' in event or 'result' in event

        # Check for admin log structure
        if 'action' in event:
            return 'object' in event or 'username' in event

        # Check for telephony log structure
        if 'phone' in event or 'credits' in event:
            return True

        return True  # Accept unknown structures
