"""
Jamf Pro Log Parser with ECS Normalization

Normalizes Jamf Pro audit logs, device management events, and security events
to Elastic Common Schema (ECS) format for unified detection and analysis.

Supports Jamf Pro event types including:
- Computer Events (enrollment, check-in, inventory)
- Mobile Device Events (enrollment, check-in, commands)
- User Events (authentication, LDAP sync)
- Policy Events (execution, triggers)
- Configuration Profile Events (installation, removal)
- Application Events (installation, blocking)
- Security Events (FileVault, Gatekeeper, XProtect)
- Audit Logs (admin actions, API access)
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


class BaseParser:
    """Base parser class for ECS normalization"""

    def __init__(self):
        self.source_type = "generic"


class JamfParser(BaseParser):
    """Parser for Jamf Pro events with ECS normalization"""

    # Jamf event type to ECS category mapping
    EVENT_TYPE_CATEGORY_MAP = {
        # Computer Events
        'ComputerAdded': ['host', 'configuration'],
        'ComputerCheckIn': ['host'],
        'ComputerInventoryCompleted': ['host', 'configuration'],
        'ComputerPolicyFinished': ['process', 'configuration'],
        'ComputerPushCapabilityChanged': ['host', 'configuration'],
        'ComputerEnrolled': ['host', 'configuration'],
        'ComputerUnenrolled': ['host', 'configuration'],

        # Mobile Device Events
        'MobileDeviceCheckIn': ['host'],
        'MobileDeviceCommandCompleted': ['process'],
        'MobileDeviceEnrolled': ['host', 'configuration'],
        'MobileDeviceUnenrolled': ['host', 'configuration'],
        'MobileDevicePushSent': ['process'],

        # User Events
        'JSSLogin': ['authentication'],
        'JSSLogout': ['authentication'],
        'SSOAuthentication': ['authentication'],
        'LDAPUserSync': ['iam'],
        'LDAPGroupSync': ['iam'],

        # Policy Events
        'PolicyTriggered': ['process'],
        'PolicyCompleted': ['process'],
        'PolicyFailed': ['process'],

        # Configuration Profile Events
        'ConfigurationProfileInstalled': ['configuration'],
        'ConfigurationProfileRemoved': ['configuration'],
        'ConfigurationProfileFailed': ['configuration'],

        # Application Events
        'AppInstalled': ['package'],
        'AppRemoved': ['package'],
        'AppBlocked': ['intrusion_detection'],
        'AppUpdated': ['package'],
        'PatchInstalled': ['package'],
        'PatchFailed': ['package'],

        # Security Events
        'FileVaultEnabled': ['configuration'],
        'FileVaultDisabled': ['configuration'],
        'FileVaultKeyEscrowed': ['configuration'],
        'GatekeeperStatus': ['configuration'],
        'XProtectVersion': ['configuration'],
        'FirewallEnabled': ['configuration'],
        'FirewallDisabled': ['configuration'],
        'MalwareDetected': ['malware'],
        'ThreatPrevented': ['intrusion_detection'],

        # Audit Events
        'AuditLogEntry': ['configuration'],
        'APIAccess': ['web'],
        'WebhookSent': ['network'],
        'SmartGroupUpdated': ['configuration'],
        'ScriptExecuted': ['process'],

        # Extension Attribute Events
        'ExtensionAttributeUpdated': ['configuration'],

        # Prestage Events
        'PrestageEnrollment': ['host', 'configuration'],
        'AutomatedDeviceEnrollment': ['host', 'configuration'],

        # Self Service Events
        'SelfServiceBookmarkClicked': ['web'],
        'SelfServicePolicyCompleted': ['process'],
    }

    # Event types that indicate security-relevant actions
    SECURITY_EVENT_TYPES = {
        'FileVaultEnabled', 'FileVaultDisabled', 'FileVaultKeyEscrowed',
        'GatekeeperStatus', 'FirewallEnabled', 'FirewallDisabled',
        'MalwareDetected', 'ThreatPrevented', 'AppBlocked',
        'ComputerUnenrolled', 'MobileDeviceUnenrolled',
        'ConfigurationProfileRemoved', 'JSSLogin', 'SSOAuthentication'
    }

    # Admin action types
    ADMIN_ACTIONS = {
        'Create', 'Update', 'Delete', 'View', 'Flush',
        'SendCommand', 'Deploy', 'Assign', 'Unassign'
    }

    def __init__(self):
        super().__init__()
        self.source_type = "jamf"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Jamf Pro event and normalize to ECS.

        Args:
            raw_event: Raw Jamf Pro event

        Returns:
            Normalized event in ECS format
        """
        # Determine event type and parse accordingly
        if 'webhook' in raw_event:
            return self._parse_webhook_event(raw_event)
        elif 'event' in raw_event:
            return self._parse_event_notification(raw_event)
        elif 'computer' in raw_event or 'Computer' in raw_event:
            return self._parse_computer_event(raw_event)
        elif 'mobileDevice' in raw_event or 'MobileDevice' in raw_event:
            return self._parse_mobile_device_event(raw_event)
        elif 'auditEvent' in raw_event or 'audit_event' in raw_event:
            return self._parse_audit_event(raw_event)
        elif 'policy' in raw_event or 'Policy' in raw_event:
            return self._parse_policy_event(raw_event)
        else:
            return self._parse_generic_event(raw_event)

    def _parse_webhook_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jamf Pro webhook notification"""
        webhook = raw_event.get('webhook', {})
        event_data = raw_event.get('event', {})

        event_type = webhook.get('webhookEvent', event_data.get('eventType', 'unknown'))
        timestamp = raw_event.get('eventTimestamp', webhook.get('eventTimestamp', ''))

        # Extract device info if present
        device_info = self._extract_device_info(event_data)
        user_info = self._extract_user_info(event_data)

        # Determine ECS categorization
        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['host'])

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': self._format_action(event_type),
                'outcome': self._determine_outcome(event_data),
                'provider': 'jamf',
                'module': 'webhook',
                'id': str(webhook.get('id', ''))
            },

            'message': webhook.get('name', event_type),

            'host': device_info,
            'user': user_info,

            'related': self._build_related(device_info, user_info),

            'jamf': {
                'event_type': event_type,
                'webhook': {
                    'id': webhook.get('id'),
                    'name': webhook.get('name'),
                    'enabled': webhook.get('enabled')
                },
                'event_data': event_data
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_event_notification(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jamf Pro event notification format"""
        event = raw_event.get('event', {})
        event_type = event.get('eventType', event.get('type', 'unknown'))
        timestamp = event.get('timestamp', event.get('dateTime', ''))

        # Extract device and user info
        device_info = self._extract_device_info(event)
        user_info = self._extract_user_info(event)

        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['host'])

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': self._format_action(event_type),
                'outcome': self._determine_outcome(event),
                'provider': 'jamf',
                'module': event_type.lower() if event_type else 'event'
            },

            'message': event.get('description', event.get('message', '')),

            'host': device_info,
            'user': user_info,

            'related': self._build_related(device_info, user_info),

            'jamf': {
                'event_type': event_type,
                'event_id': event.get('id'),
                'trigger': event.get('trigger'),
                'status': event.get('status'),
                'details': event
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_computer_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jamf Pro computer event"""
        computer = raw_event.get('computer', raw_event.get('Computer', {}))
        general = computer.get('general', computer.get('General', {}))
        hardware = computer.get('hardware', computer.get('Hardware', {}))
        security = computer.get('security', computer.get('Security', {}))

        event_type = raw_event.get('eventType', 'ComputerCheckIn')
        timestamp = general.get('last_contact_time', general.get('lastContactTime',
                    general.get('report_date', '')))

        # Build host information
        host_info = {
            'id': str(computer.get('id', general.get('id', ''))),
            'name': general.get('name', general.get('computer_name', '')),
            'hostname': general.get('name', general.get('computer_name', '')),
            'mac': [hardware.get('mac_address', hardware.get('macAddress', ''))],
            'ip': [general.get('ip_address', general.get('ipAddress', ''))],
            'os': {
                'name': 'macOS',
                'version': hardware.get('os_version', hardware.get('osVersion', '')),
                'full': f"macOS {hardware.get('os_version', hardware.get('osVersion', ''))}"
            },
            'architecture': hardware.get('processor_architecture', '')
        }

        # Extract user info
        user_info = {
            'name': general.get('last_reported_username', general.get('username', '')),
            'email': general.get('email_address', '')
        }

        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['host'])

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': self._format_action(event_type),
                'outcome': 'success',
                'provider': 'jamf',
                'module': 'computer'
            },

            'host': host_info,
            'user': user_info,

            'related': self._build_related(host_info, user_info),

            'jamf': {
                'event_type': event_type,
                'computer': {
                    'id': computer.get('id'),
                    'udid': general.get('udid'),
                    'serial_number': general.get('serial_number', hardware.get('serialNumber', '')),
                    'management_status': general.get('remote_management', {}).get('managed', False),
                    'supervised': general.get('supervised', False),
                    'mdm_capable': general.get('mdm_capable', False),
                    'enrolled_via_dep': general.get('enrolled_via_dep', False),
                    'site': general.get('site', {}).get('name', ''),
                    'building': general.get('building', ''),
                    'department': general.get('department', '')
                },
                'hardware': {
                    'model': hardware.get('model', ''),
                    'model_identifier': hardware.get('model_identifier', ''),
                    'processor_type': hardware.get('processor_type', ''),
                    'processor_speed': hardware.get('processor_speed_mhz', 0),
                    'total_ram_mb': hardware.get('total_ram_mb', 0),
                    'sip_status': hardware.get('sip_status', '')
                },
                'security': {
                    'filevault_enabled': security.get('filevault_enabled', False),
                    'filevault_status': security.get('filevault_status', ''),
                    'gatekeeper_status': security.get('gatekeeper_status', ''),
                    'xprotect_version': security.get('xprotect_version', ''),
                    'firewall_enabled': security.get('firewall_enabled', False),
                    'external_boot_level': security.get('external_boot_level', ''),
                    'secure_boot_level': security.get('secure_boot_level', ''),
                    'activation_lock_enabled': security.get('activation_lock_enabled', False)
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_mobile_device_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jamf Pro mobile device event"""
        device = raw_event.get('mobileDevice', raw_event.get('MobileDevice', {}))
        general = device.get('general', device.get('General', {}))
        security = device.get('security', device.get('Security', {}))

        event_type = raw_event.get('eventType', 'MobileDeviceCheckIn')
        timestamp = general.get('last_inventory_update', general.get('lastInventoryUpdate', ''))

        # Determine if iOS or iPadOS
        os_name = 'iOS'
        if general.get('model', '').lower().startswith('ipad'):
            os_name = 'iPadOS'

        # Build host information
        host_info = {
            'id': str(device.get('id', general.get('id', ''))),
            'name': general.get('name', general.get('device_name', '')),
            'hostname': general.get('name', general.get('device_name', '')),
            'mac': [general.get('wifi_mac_address', general.get('wifiMacAddress', ''))],
            'ip': [general.get('ip_address', general.get('ipAddress', ''))],
            'os': {
                'name': os_name,
                'version': general.get('os_version', general.get('osVersion', '')),
                'full': f"{os_name} {general.get('os_version', general.get('osVersion', ''))}"
            }
        }

        # Extract user info
        user_info = {
            'name': general.get('username', ''),
            'email': general.get('email_address', '')
        }

        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['host'])

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': self._format_action(event_type),
                'outcome': 'success',
                'provider': 'jamf',
                'module': 'mobile_device'
            },

            'host': host_info,
            'user': user_info,

            'related': self._build_related(host_info, user_info),

            'jamf': {
                'event_type': event_type,
                'mobile_device': {
                    'id': device.get('id'),
                    'udid': general.get('udid'),
                    'serial_number': general.get('serial_number', ''),
                    'phone_number': general.get('phone_number', ''),
                    'managed': general.get('managed', False),
                    'supervised': general.get('supervised', False),
                    'device_ownership_level': general.get('device_ownership_level', ''),
                    'enrolled_via_automated_device_enrollment': general.get('enrolled_via_automated_device_enrollment', False),
                    'site': general.get('site', {}).get('name', ''),
                    'model': general.get('model', ''),
                    'model_identifier': general.get('model_identifier', ''),
                    'model_display': general.get('model_display', '')
                },
                'security': {
                    'data_protection': security.get('data_protection', False),
                    'passcode_present': security.get('passcode_present', False),
                    'passcode_compliant': security.get('passcode_compliant', False),
                    'hardware_encryption': security.get('hardware_encryption', 0),
                    'activation_lock_enabled': security.get('activation_lock_enabled', False),
                    'jailbreak_detected': security.get('jailbreak_detected', 'Unknown'),
                    'lost_mode_enabled': security.get('lost_mode_enabled', False),
                    'lost_mode_enforced': security.get('lost_mode_enforced', False)
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_audit_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jamf Pro audit log event"""
        audit = raw_event.get('auditEvent', raw_event.get('audit_event', raw_event))

        event_type = audit.get('object_type', audit.get('objectType', 'AuditLogEntry'))
        action = audit.get('action', audit.get('event', ''))
        timestamp = audit.get('date_time', audit.get('dateTime', audit.get('timestamp', '')))

        # Extract user info
        user_info = {
            'name': audit.get('username', audit.get('user', '')),
            'id': str(audit.get('user_id', audit.get('userId', '')))
        }

        # Extract source IP if available
        source_ip = audit.get('ip_address', audit.get('ipAddress',
                   audit.get('source_ip', '')))

        ecs_categories = ['configuration', 'iam']
        if action.lower() in ('view', 'read', 'get'):
            ecs_categories = ['configuration']

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_audit_event_type(action),
                'action': self._format_action(f"{event_type}_{action}"),
                'outcome': 'success',
                'provider': 'jamf',
                'module': 'audit'
            },

            'message': audit.get('details', audit.get('description', '')),

            'user': user_info,

            'source': {
                'ip': source_ip
            } if source_ip else None,

            'related': {
                'ip': [source_ip] if source_ip else [],
                'user': [u for u in [user_info.get('name'), user_info.get('id')] if u]
            },

            'jamf': {
                'event_type': 'AuditLogEntry',
                'audit': {
                    'id': audit.get('id'),
                    'action': action,
                    'object_type': event_type,
                    'object_id': audit.get('object_id', audit.get('objectId')),
                    'object_name': audit.get('object_name', audit.get('objectName', '')),
                    'details': audit.get('details', ''),
                    'note': audit.get('note', audit.get('notes', ''))
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_policy_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jamf Pro policy event"""
        policy = raw_event.get('policy', raw_event.get('Policy', {}))
        general = policy.get('general', policy.get('General', {}))

        event_type = raw_event.get('eventType', 'PolicyCompleted')
        timestamp = raw_event.get('timestamp', raw_event.get('date_time', ''))

        # Extract target device info
        device = raw_event.get('computer', raw_event.get('target', {}))
        host_info = self._extract_device_info(device) if device else {}

        # Extract user info
        user_info = self._extract_user_info(raw_event)

        # Determine outcome
        status = raw_event.get('status', general.get('status', 'completed'))
        outcome = 'success' if status.lower() in ('completed', 'success') else 'failure'

        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['process', 'configuration'])

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': self._format_action(event_type),
                'outcome': outcome,
                'reason': raw_event.get('error', raw_event.get('message', '')) if outcome == 'failure' else None,
                'provider': 'jamf',
                'module': 'policy'
            },

            'message': general.get('name', ''),

            'host': host_info if host_info else None,
            'user': user_info if user_info else None,

            'related': self._build_related(host_info, user_info),

            'jamf': {
                'event_type': event_type,
                'policy': {
                    'id': policy.get('id', general.get('id')),
                    'name': general.get('name', ''),
                    'enabled': general.get('enabled', True),
                    'trigger': general.get('trigger', raw_event.get('trigger', '')),
                    'frequency': general.get('frequency', ''),
                    'category': general.get('category', {}).get('name', ''),
                    'site': general.get('site', {}).get('name', ''),
                    'self_service': general.get('self_service', False)
                },
                'execution': {
                    'status': status,
                    'duration_ms': raw_event.get('duration', raw_event.get('execution_time')),
                    'exit_code': raw_event.get('exit_code', raw_event.get('exitCode'))
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic Jamf Pro event format"""
        event_type = raw_event.get('eventType', raw_event.get('type', 'unknown'))
        timestamp = (
            raw_event.get('timestamp') or
            raw_event.get('dateTime') or
            raw_event.get('date_time') or
            raw_event.get('eventTimestamp') or
            ''
        )

        # Try to extract device and user info
        device_info = self._extract_device_info(raw_event)
        user_info = self._extract_user_info(raw_event)

        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['host'])

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': self._format_action(event_type),
                'outcome': self._determine_outcome(raw_event),
                'provider': 'jamf',
                'module': 'generic'
            },

            'message': raw_event.get('description', raw_event.get('message', '')),

            'host': device_info if device_info else None,
            'user': user_info if user_info else None,

            'related': self._build_related(device_info, user_info),

            'jamf': {
                'event_type': event_type,
                'event_data': raw_event
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _extract_device_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract device information from event data"""
        device_info = {}

        # Check various possible locations for device info
        computer = data.get('computer', data.get('Computer', {}))
        mobile = data.get('mobileDevice', data.get('MobileDevice', {}))
        target = data.get('target', {})

        device = computer or mobile or target
        if not device:
            # Try direct fields
            device = data

        general = device.get('general', device.get('General', device))

        device_id = str(device.get('id', general.get('id', '')))
        name = general.get('name', general.get('computer_name',
               general.get('device_name', data.get('deviceName', ''))))
        serial = general.get('serial_number', general.get('serialNumber', ''))
        udid = general.get('udid', general.get('UDID', ''))

        if device_id or name or serial:
            device_info = {
                'id': device_id,
                'name': name,
                'hostname': name
            }

            if serial:
                device_info['serial_number'] = serial
            if udid:
                device_info['udid'] = udid

            # Extract IP if available
            ip = general.get('ip_address', general.get('ipAddress', ''))
            if ip:
                device_info['ip'] = [ip]

            # Extract MAC if available
            mac = general.get('mac_address', general.get('macAddress',
                  general.get('wifi_mac_address', '')))
            if mac:
                device_info['mac'] = [mac]

        return device_info

    def _extract_user_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user information from event data"""
        user_info = {}

        # Check various possible locations for user info
        username = (
            data.get('username') or
            data.get('userName') or
            data.get('user') or
            data.get('last_reported_username') or
            data.get('general', {}).get('username') or
            data.get('general', {}).get('last_reported_username') or
            ''
        )

        user_id = str(data.get('user_id', data.get('userId', '')))
        email = data.get('email', data.get('email_address',
                data.get('general', {}).get('email_address', '')))

        if username or user_id or email:
            user_info = {
                'name': username,
                'id': user_id,
                'email': email
            }

        return user_info

    def _build_related(self, host_info: Dict[str, Any],
                       user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build related fields for correlation"""
        related = {
            'ip': [],
            'user': [],
            'hosts': []
        }

        if host_info:
            if host_info.get('ip'):
                related['ip'].extend(host_info['ip'])
            if host_info.get('name'):
                related['hosts'].append(host_info['name'])
            if host_info.get('id'):
                related['hosts'].append(host_info['id'])

        if user_info:
            if user_info.get('name'):
                related['user'].append(user_info['name'])
            if user_info.get('id'):
                related['user'].append(user_info['id'])
            if user_info.get('email'):
                related['user'].append(user_info['email'])

        # Remove duplicates and empty lists
        related = {k: list(set(v)) for k, v in related.items() if v}

        return related if related else {}

    def _get_event_type(self, event_type: str) -> List[str]:
        """Determine ECS event.type based on Jamf event type"""
        types = []

        lower_event = event_type.lower() if event_type else ''

        if 'login' in lower_event or 'authentication' in lower_event:
            types.append('start')
        elif 'logout' in lower_event:
            types.append('end')
        elif 'enrolled' in lower_event or 'added' in lower_event:
            types.append('creation')
        elif 'unenrolled' in lower_event or 'removed' in lower_event:
            types.append('deletion')
        elif 'installed' in lower_event:
            types.append('installation')
        elif 'updated' in lower_event or 'changed' in lower_event:
            types.append('change')
        elif 'completed' in lower_event or 'finished' in lower_event:
            types.append('end')
        elif 'triggered' in lower_event or 'started' in lower_event:
            types.append('start')
        elif 'failed' in lower_event or 'blocked' in lower_event:
            types.append('denied')
        elif 'detected' in lower_event:
            types.append('indicator')
        elif 'check' in lower_event:
            types.append('info')
        else:
            types.append('info')

        return types

    def _get_audit_event_type(self, action: str) -> List[str]:
        """Determine ECS event.type for audit actions"""
        types = []

        lower_action = action.lower() if action else ''

        if any(x in lower_action for x in ['create', 'add', 'enable']):
            types.append('creation')
        elif any(x in lower_action for x in ['update', 'change', 'modify', 'edit']):
            types.append('change')
        elif any(x in lower_action for x in ['delete', 'remove', 'disable']):
            types.append('deletion')
        elif any(x in lower_action for x in ['view', 'read', 'get', 'list']):
            types.append('access')
        elif any(x in lower_action for x in ['assign', 'grant']):
            types.append('allowed')
        elif any(x in lower_action for x in ['unassign', 'revoke']):
            types.append('denied')
        elif 'deploy' in lower_action or 'send' in lower_action:
            types.append('start')
        else:
            types.append('info')

        return types

    def _format_action(self, event_type: str) -> str:
        """Format event type as action string"""
        if not event_type:
            return 'unknown'

        # Convert CamelCase to snake_case
        import re
        action = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', event_type)
        action = re.sub('([a-z0-9])([A-Z])', r'\1_\2', action)
        return action.lower()

    def _determine_outcome(self, data: Dict[str, Any]) -> str:
        """Determine ECS outcome from event data"""
        # Check explicit status/success fields
        status = data.get('status', data.get('Status', ''))
        if status:
            lower_status = status.lower()
            if lower_status in ('success', 'completed', 'ok', 'true'):
                return 'success'
            elif lower_status in ('failed', 'failure', 'error', 'blocked', 'false'):
                return 'failure'

        # Check success boolean
        if 'success' in data:
            return 'success' if data['success'] else 'failure'

        # Check error presence
        if data.get('error') or data.get('errorMessage'):
            return 'failure'

        return 'success'

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate timestamp"""
        if not timestamp_str:
            return datetime.now(timezone.utc).isoformat()

        # Handle various Jamf timestamp formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%m/%d/%Y %H:%M:%S',
            '%m/%d/%y %I:%M:%S %p',
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
        Validate that event has required Jamf Pro fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # Webhook format
        if 'webhook' in event:
            return True

        # Event notification format
        if 'event' in event:
            return True

        # Computer event format
        if 'computer' in event or 'Computer' in event:
            return True

        # Mobile device format
        if 'mobileDevice' in event or 'MobileDevice' in event:
            return True

        # Audit event format
        if 'auditEvent' in event or 'audit_event' in event:
            return True

        # Policy event format
        if 'policy' in event or 'Policy' in event:
            return True

        # Generic - need some identifying field
        if 'eventType' in event or 'type' in event:
            return True

        return False
