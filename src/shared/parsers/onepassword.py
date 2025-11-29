"""
1Password Events API Log Parser with ECS Normalization

Normalizes 1Password Business/Enterprise audit events to Elastic Common Schema
(ECS) format for unified detection and analysis.

Supports 1Password event types including:
- Sign-in Events (user authentication, MFA)
- Vault Events (access, creation, modification)
- Item Events (access, creation, modification, sharing)
- User Events (provisioning, deprovisioning)
- Group Events (membership changes)
- Secret Events (secret access, rotation)
- Audit Events (admin actions, settings changes)
- Service Account Events (API access)

Reference:
- https://developer.1password.com/docs/events-api/
- https://developer.1password.com/docs/events-api/reference/
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


class BaseParser:
    """Base parser class for ECS normalization"""

    def __init__(self):
        self.source_type = "generic"


class OnePasswordParser(BaseParser):
    """Parser for 1Password Events API with ECS normalization"""

    # 1Password action to ECS category mapping
    ACTION_CATEGORY_MAP = {
        # Sign-in Events
        'signin': ['authentication'],
        'signout': ['authentication'],
        'mfa_challenge': ['authentication'],
        'mfa_verify': ['authentication'],
        'sso_signin': ['authentication'],
        'recovery_signin': ['authentication'],

        # Vault Events
        'vault_create': ['configuration'],
        'vault_delete': ['configuration'],
        'vault_update': ['configuration'],
        'vault_access': ['database'],
        'vault_share': ['configuration'],
        'vault_unshare': ['configuration'],

        # Item Events
        'item_create': ['database'],
        'item_update': ['database'],
        'item_delete': ['database'],
        'item_access': ['database'],
        'item_copy': ['database'],
        'item_move': ['database'],
        'item_share': ['database'],
        'item_unshare': ['database'],
        'item_export': ['database'],
        'item_import': ['database'],
        'item_restore': ['database'],
        'item_archive': ['database'],
        'item_usage': ['database'],

        # User Events
        'user_create': ['iam'],
        'user_delete': ['iam'],
        'user_update': ['iam'],
        'user_suspend': ['iam'],
        'user_reactivate': ['iam'],
        'user_invite': ['iam'],
        'user_confirm': ['iam'],
        'user_recover': ['iam'],
        'user_provision': ['iam'],
        'user_deprovision': ['iam'],

        # Group Events
        'group_create': ['iam'],
        'group_delete': ['iam'],
        'group_update': ['iam'],
        'group_member_add': ['iam'],
        'group_member_remove': ['iam'],
        'group_grant_access': ['iam'],
        'group_revoke_access': ['iam'],

        # Secret/Credential Events
        'secret_access': ['database'],
        'secret_reveal': ['database'],
        'secret_copy': ['database'],
        'credential_autofill': ['database'],
        'password_reveal': ['database'],
        'password_copy': ['database'],
        'totp_copy': ['database'],
        'totp_reveal': ['database'],

        # Admin/Settings Events
        'settings_update': ['configuration'],
        'policy_create': ['configuration'],
        'policy_update': ['configuration'],
        'policy_delete': ['configuration'],
        'billing_update': ['configuration'],
        'integration_enable': ['configuration'],
        'integration_disable': ['configuration'],
        'scim_provision': ['iam'],
        'scim_deprovision': ['iam'],

        # Service Account Events
        'service_account_create': ['iam'],
        'service_account_delete': ['iam'],
        'service_account_update': ['iam'],
        'service_account_token_create': ['iam'],
        'service_account_token_revoke': ['iam'],
        'api_access': ['web'],

        # Security Events
        'firewall_allow': ['network'],
        'firewall_deny': ['network'],
        'security_alert': ['intrusion_detection'],
        'suspicious_activity': ['intrusion_detection'],
        'breach_report_view': ['database'],
        'watchtower_alert': ['intrusion_detection'],
    }

    # Actions that indicate sensitive operations
    SENSITIVE_ACTIONS = {
        'secret_reveal', 'password_reveal', 'password_copy',
        'item_export', 'vault_delete', 'user_delete',
        'service_account_token_create', 'breach_report_view',
        'recovery_signin', 'settings_update', 'policy_delete'
    }

    # Actions related to sharing
    SHARING_ACTIONS = {
        'vault_share', 'vault_unshare', 'item_share', 'item_unshare',
        'group_grant_access', 'group_revoke_access'
    }

    def __init__(self):
        super().__init__()
        self.source_type = "onepassword"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse 1Password event and normalize to ECS.

        Args:
            raw_event: Raw 1Password event from Events API

        Returns:
            Normalized event in ECS format
        """
        # Handle different event formats
        if 'action' in raw_event:
            return self._parse_events_api(raw_event)
        elif 'event_type' in raw_event:
            return self._parse_legacy_event(raw_event)
        else:
            return self._parse_generic_event(raw_event)

    def _parse_events_api(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse 1Password Events API format"""
        action = raw_event.get('action', '')
        timestamp = raw_event.get('timestamp', '')

        # Extract actor (user performing the action)
        actor = raw_event.get('actor', {})
        actor_uuid = actor.get('uuid', '')
        actor_email = actor.get('email', '')
        actor_name = actor.get('name', '')

        # Extract target information
        target = raw_event.get('target', raw_event.get('object', {}))
        target_type = target.get('type', '')
        target_uuid = target.get('uuid', '')
        target_name = target.get('name', target.get('title', ''))

        # Extract vault information if present
        vault = raw_event.get('vault', target if target_type == 'vault' else {})
        vault_uuid = vault.get('uuid', '')
        vault_name = vault.get('name', '')

        # Extract item information if present
        item = raw_event.get('item', target if target_type == 'item' else {})
        item_uuid = item.get('uuid', '')
        item_title = item.get('title', item.get('name', ''))
        item_category = item.get('category', '')

        # Extract client/session information
        session = raw_event.get('session', {})
        client = raw_event.get('client', session.get('client', {}))
        client_app_name = client.get('app_name', client.get('name', ''))
        client_app_version = client.get('app_version', client.get('version', ''))
        client_platform = client.get('platform', client.get('os', ''))

        # Extract location information
        location = raw_event.get('location', session.get('location', {}))
        source_ip = location.get('ip', raw_event.get('ip', session.get('ip', '')))
        country = location.get('country', '')
        region = location.get('region', '')
        city = location.get('city', '')

        # Determine ECS categorization
        ecs_categories = self.ACTION_CATEGORY_MAP.get(action, ['database'])

        # Determine event type
        ecs_types = self._get_event_type(action)

        # Determine outcome
        ecs_outcome = self._determine_outcome(raw_event)

        # Build message
        message = self._build_message(action, actor_email or actor_name, target_name, target_type)

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': ecs_types,
                'action': action,
                'outcome': ecs_outcome,
                'provider': '1password',
                'module': self._get_module(action),
                'id': raw_event.get('uuid', raw_event.get('id', ''))
            },

            'message': message,

            'user': {
                'id': actor_uuid,
                'name': actor_name,
                'email': actor_email,
                'target': {
                    'id': target_uuid if target_type in ('user', 'member') else None,
                    'name': target_name if target_type in ('user', 'member') else None
                } if target_type in ('user', 'member') else None
            },

            'source': {
                'ip': source_ip,
                'geo': {
                    'country_iso_code': country,
                    'region_name': region,
                    'city_name': city
                } if country or region or city else None
            } if source_ip else None,

            'user_agent': {
                'name': client_app_name,
                'version': client_app_version,
                'os': {
                    'name': client_platform
                }
            } if client_app_name else None,

            'related': self._build_related(
                actor_email, actor_name, actor_uuid,
                target_name, target_uuid, source_ip
            ),

            'onepassword': {
                'action': action,
                'uuid': raw_event.get('uuid', ''),
                'actor': {
                    'uuid': actor_uuid,
                    'email': actor_email,
                    'name': actor_name,
                    'type': actor.get('type', '')
                } if actor else None,
                'vault': {
                    'uuid': vault_uuid,
                    'name': vault_name
                } if vault_uuid else None,
                'item': {
                    'uuid': item_uuid,
                    'title': item_title,
                    'category': item_category
                } if item_uuid else None,
                'target': {
                    'type': target_type,
                    'uuid': target_uuid,
                    'name': target_name
                } if target else None,
                'session': {
                    'uuid': session.get('uuid', ''),
                    'login_time': session.get('login_time', ''),
                    'device_uuid': session.get('device_uuid', '')
                } if session else None,
                'client': {
                    'app_name': client_app_name,
                    'app_version': client_app_version,
                    'platform': client_platform,
                    'os_version': client.get('os_version', '')
                } if client else None,
                'location': {
                    'country': country,
                    'region': region,
                    'city': city,
                    'ip': source_ip
                } if location or source_ip else None,
                'aux_info': raw_event.get('aux_info', {}),
                'is_sensitive': action in self.SENSITIVE_ACTIONS,
                'is_sharing': action in self.SHARING_ACTIONS
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_legacy_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse legacy 1Password event format"""
        event_type = raw_event.get('event_type', '')
        timestamp = raw_event.get('timestamp', raw_event.get('time', ''))

        # Map legacy event type to action
        action = self._map_legacy_event_type(event_type)

        # Extract user info
        user_email = raw_event.get('user_email', raw_event.get('email', ''))
        user_uuid = raw_event.get('user_uuid', raw_event.get('user_id', ''))
        user_name = raw_event.get('user_name', raw_event.get('name', ''))

        # Extract source info
        source_ip = raw_event.get('ip_address', raw_event.get('ip', ''))

        ecs_categories = self.ACTION_CATEGORY_MAP.get(action, ['database'])
        ecs_types = self._get_event_type(action)

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': ecs_types,
                'action': action,
                'outcome': 'success',
                'provider': '1password',
                'module': 'legacy'
            },

            'user': {
                'id': user_uuid,
                'name': user_name,
                'email': user_email
            },

            'source': {
                'ip': source_ip
            } if source_ip else None,

            'related': {
                'ip': [source_ip] if source_ip else [],
                'user': [u for u in [user_email, user_name, user_uuid] if u]
            },

            'onepassword': {
                'action': action,
                'event_type': event_type,
                'legacy_format': True
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic/unknown 1Password event format"""
        timestamp = (
            raw_event.get('timestamp') or
            raw_event.get('time') or
            raw_event.get('created_at') or
            ''
        )

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['database'],
                'type': ['info'],
                'action': 'unknown',
                'outcome': 'unknown',
                'provider': '1password',
                'module': 'generic'
            },

            'onepassword': {
                'event_data': raw_event
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _get_event_type(self, action: str) -> List[str]:
        """Determine ECS event.type based on action"""
        types = []

        if not action:
            return ['info']

        lower_action = action.lower()

        if 'signin' in lower_action or 'login' in lower_action:
            types.append('start')
        elif 'signout' in lower_action or 'logout' in lower_action:
            types.append('end')
        elif 'create' in lower_action or 'add' in lower_action or 'invite' in lower_action:
            types.append('creation')
        elif 'delete' in lower_action or 'remove' in lower_action or 'revoke' in lower_action:
            types.append('deletion')
        elif 'update' in lower_action or 'change' in lower_action:
            types.append('change')
        elif 'access' in lower_action or 'reveal' in lower_action or 'copy' in lower_action:
            types.append('access')
        elif 'share' in lower_action or 'grant' in lower_action:
            types.append('allowed')
        elif 'unshare' in lower_action or 'deny' in lower_action:
            types.append('denied')
        elif 'suspend' in lower_action or 'deprovision' in lower_action:
            types.append('deletion')
        elif 'reactivate' in lower_action or 'provision' in lower_action:
            types.append('creation')
        elif 'mfa' in lower_action or 'verify' in lower_action:
            types.append('info')
        elif 'export' in lower_action:
            types.append('access')
        elif 'import' in lower_action:
            types.append('creation')
        else:
            types.append('info')

        return types

    def _get_module(self, action: str) -> str:
        """Determine module based on action"""
        if not action:
            return 'unknown'

        lower_action = action.lower()

        if 'signin' in lower_action or 'signout' in lower_action or 'mfa' in lower_action or 'sso' in lower_action:
            return 'authentication'
        elif 'vault' in lower_action:
            return 'vault'
        elif 'item' in lower_action or 'secret' in lower_action or 'password' in lower_action or 'credential' in lower_action or 'totp' in lower_action:
            return 'item'
        elif 'user' in lower_action or 'member' in lower_action:
            return 'user'
        elif 'group' in lower_action:
            return 'group'
        elif 'service_account' in lower_action or 'api' in lower_action:
            return 'service_account'
        elif 'policy' in lower_action or 'settings' in lower_action or 'integration' in lower_action:
            return 'admin'
        elif 'scim' in lower_action:
            return 'scim'
        elif 'firewall' in lower_action or 'security' in lower_action or 'watchtower' in lower_action:
            return 'security'
        else:
            return 'general'

    def _determine_outcome(self, raw_event: Dict[str, Any]) -> str:
        """Determine ECS outcome from event data"""
        # Check explicit outcome/result fields
        outcome = raw_event.get('outcome', raw_event.get('result', ''))
        if outcome:
            lower_outcome = outcome.lower()
            if lower_outcome in ('success', 'succeeded', 'allowed', 'ok'):
                return 'success'
            elif lower_outcome in ('failure', 'failed', 'denied', 'blocked'):
                return 'failure'

        # Check action for deny/block indicators
        action = raw_event.get('action', '')
        if 'deny' in action.lower() or 'block' in action.lower() or 'fail' in action.lower():
            return 'failure'

        # Check for error field
        if raw_event.get('error') or raw_event.get('error_message'):
            return 'failure'

        # Default to success for most events
        return 'success'

    def _build_message(self, action: str, actor: str, target: str, target_type: str) -> str:
        """Build human-readable event message"""
        if not action:
            return "1Password event"

        # Format action for readability
        readable_action = action.replace('_', ' ')

        parts = []
        if actor:
            parts.append(f"{actor}")

        parts.append(readable_action)

        if target and target_type:
            parts.append(f"{target_type} '{target}'")
        elif target:
            parts.append(f"'{target}'")

        return ' '.join(parts)

    def _build_related(
        self,
        actor_email: str,
        actor_name: str,
        actor_uuid: str,
        target_name: str,
        target_uuid: str,
        source_ip: str
    ) -> Dict[str, Any]:
        """Build related fields for correlation"""
        related = {
            'ip': [],
            'user': []
        }

        if source_ip:
            related['ip'].append(source_ip)

        for user in [actor_email, actor_name, actor_uuid]:
            if user and user not in related['user']:
                related['user'].append(user)

        # Only add target as user if it's a user-type target
        if target_name and target_name not in related['user']:
            # Could be a vault or item name, so be selective
            pass

        if target_uuid and target_uuid not in related['user']:
            related['user'].append(target_uuid)

        # Remove empty lists
        return {k: v for k, v in related.items() if v}

    def _map_legacy_event_type(self, event_type: str) -> str:
        """Map legacy event type to standard action"""
        mapping = {
            'sign_in': 'signin',
            'sign_out': 'signout',
            'vault_created': 'vault_create',
            'vault_deleted': 'vault_delete',
            'item_created': 'item_create',
            'item_updated': 'item_update',
            'item_deleted': 'item_delete',
            'item_accessed': 'item_access',
            'user_created': 'user_create',
            'user_deleted': 'user_delete',
            'user_invited': 'user_invite',
            'group_created': 'group_create',
            'group_deleted': 'group_delete',
        }
        return mapping.get(event_type, event_type)

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate timestamp"""
        if not timestamp_str:
            return datetime.now(timezone.utc).isoformat()

        # Handle various 1Password timestamp formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

        # Try ISO format parsing
        try:
            if timestamp_str.endswith('Z'):
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp_str)
            return dt.isoformat()
        except ValueError:
            pass

        # Try Unix timestamp
        try:
            ts = float(timestamp_str)
            if ts > 1e12:  # Milliseconds
                ts = ts / 1000
            return datetime.fromtimestamp(ts, timezone.utc).isoformat()
        except (ValueError, TypeError, OSError):
            pass

        return datetime.now(timezone.utc).isoformat()

    def _remove_none_values(self, data: Any) -> Any:
        """Recursively remove None/empty values from dict"""
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
        Validate that event has required 1Password fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # Events API format
        if 'action' in event:
            return True

        # Legacy format
        if 'event_type' in event:
            return True

        # Has timestamp (minimal requirement)
        if 'timestamp' in event or 'time' in event or 'created_at' in event:
            return True

        return False
