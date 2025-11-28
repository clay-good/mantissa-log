"""
CrowdStrike Falcon Parser with ECS Normalization

Normalizes CrowdStrike Falcon Event Streams events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports:
- DetectionSummaryEvent (malware, suspicious behavior)
- IncidentSummaryEvent (incidents and investigations)
- AuditEvent (admin activity, policy changes)
- UserActivityAuditEvent (user authentication events)
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class CrowdStrikeParser(BaseParser):
    """Parser for CrowdStrike Falcon Event Streams with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "crowdstrike"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CrowdStrike event and normalize to ECS.

        Args:
            raw_event: Raw event from CrowdStrike Event Streams API

        Returns:
            Normalized event in ECS format
        """
        # Extract metadata
        metadata = raw_event.get('metadata', {})
        event_type = metadata.get('eventType', '')
        event_creation_time = metadata.get('eventCreationTime', 0)
        customer_id_string = metadata.get('customerIDString', '')
        offset = metadata.get('offset', 0)

        # Parse event based on type
        if event_type == 'DetectionSummaryEvent':
            return self._parse_detection_event(raw_event, metadata)
        elif event_type == 'IncidentSummaryEvent':
            return self._parse_incident_event(raw_event, metadata)
        elif event_type == 'AuditEvent':
            return self._parse_audit_event(raw_event, metadata)
        elif event_type == 'UserActivityAuditEvent':
            return self._parse_user_activity_event(raw_event, metadata)
        else:
            # Generic parsing for unknown event types
            return self._parse_generic_event(raw_event, metadata)

    def _parse_detection_event(self, raw_event: Dict, metadata: Dict) -> Dict:
        """Parse DetectionSummaryEvent (malware, suspicious behavior)"""
        event_data = raw_event.get('event', {})

        # Extract detection details
        detection_id = event_data.get('DetectionId', '')
        severity = event_data.get('SeverityName', 'Unknown')
        tactic = event_data.get('Tactic', '')
        technique = event_data.get('Technique', '')
        pattern_disposition_description = event_data.get('PatternDispositionDescription', '')

        # Extract host information
        computer_name = event_data.get('ComputerName', '')
        host_name = event_data.get('HostName', '')
        mac_address = event_data.get('MacAddress', '')
        local_ip = event_data.get('LocalIP', '')

        # Extract user information
        user_name = event_data.get('UserName', '')
        user_id = event_data.get('UserId', '')

        # Extract file/process information
        file_name = event_data.get('FileName', '')
        file_path = event_data.get('FilePath', '')
        command_line = event_data.get('CommandLine', '')
        md5 = event_data.get('MD5String', '')
        sha256 = event_data.get('SHA256String', '')

        # Map severity to ECS
        ecs_severity = self._map_detection_severity(severity)

        # Determine outcome
        ecs_outcome = 'success' if pattern_disposition_description else 'unknown'

        normalized = {
            '@timestamp': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'alert',
                'category': ['malware', 'intrusion_detection'],
                'type': ['info'],
                'action': tactic or 'detection',
                'outcome': ecs_outcome,
                'severity': ecs_severity,
                'created': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
                'id': detection_id,
                'provider': 'crowdstrike',
                'module': 'falcon',
                'reason': pattern_disposition_description
            },

            'host': {
                'name': host_name or computer_name,
                'hostname': host_name or computer_name,
                'mac': [mac_address] if mac_address else [],
                'ip': [local_ip] if local_ip else []
            },

            'user': {
                'name': user_name,
                'id': user_id
            },

            'file': {
                'name': file_name,
                'path': file_path,
                'hash': {
                    'md5': md5,
                    'sha256': sha256
                }
            },

            'process': {
                'command_line': command_line
            },

            'threat': {
                'tactic': {
                    'name': [tactic] if tactic else []
                },
                'technique': {
                    'name': [technique] if technique else []
                }
            },

            'crowdstrike': {
                'metadata': metadata,
                'detection': {
                    'id': detection_id,
                    'severity': severity,
                    'tactic': tactic,
                    'technique': technique,
                    'pattern_disposition': pattern_disposition_description,
                    'confidence': event_data.get('Confidence', 0),
                    'objective': event_data.get('Objective', ''),
                    'scenario': event_data.get('Scenario', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_incident_event(self, raw_event: Dict, metadata: Dict) -> Dict:
        """Parse IncidentSummaryEvent"""
        event_data = raw_event.get('event', {})

        incident_id = event_data.get('IncidentId', '')
        state = event_data.get('State', '')
        status = event_data.get('Status', '')
        fine_score = event_data.get('FineScore', 0)

        normalized = {
            '@timestamp': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'alert',
                'category': ['intrusion_detection'],
                'type': ['info'],
                'action': 'incident',
                'outcome': 'unknown',
                'severity': self._map_incident_score(fine_score),
                'created': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
                'id': incident_id,
                'provider': 'crowdstrike',
                'module': 'falcon'
            },

            'crowdstrike': {
                'metadata': metadata,
                'incident': {
                    'id': incident_id,
                    'state': state,
                    'status': status,
                    'fine_score': fine_score,
                    'start_time': event_data.get('StartTime', ''),
                    'end_time': event_data.get('EndTime', ''),
                    'hosts': event_data.get('HostIds', []),
                    'users': event_data.get('UserIds', [])
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_audit_event(self, raw_event: Dict, metadata: Dict) -> Dict:
        """Parse AuditEvent (admin activity)"""
        event_data = raw_event.get('event', {})

        user_id = event_data.get('UserId', '')
        user_name = event_data.get('UserName', '')
        operation_name = event_data.get('OperationName', '')
        service_name = event_data.get('ServiceName', '')
        success = event_data.get('Success', False)
        audit_key_values = event_data.get('AuditKeyValues', [])

        normalized = {
            '@timestamp': self._parse_timestamp_ms(event_data.get('UTCTimestamp', 0)),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['iam', 'configuration'],
                'type': [self._get_audit_event_type(operation_name)],
                'action': operation_name,
                'outcome': 'success' if success else 'failure',
                'created': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
                'provider': 'crowdstrike',
                'module': service_name or 'falcon'
            },

            'user': {
                'id': user_id,
                'name': user_name
            },

            'crowdstrike': {
                'metadata': metadata,
                'audit': {
                    'operation_name': operation_name,
                    'service_name': service_name,
                    'success': success,
                    'audit_key_values': self._parse_audit_key_values(audit_key_values)
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_user_activity_event(self, raw_event: Dict, metadata: Dict) -> Dict:
        """Parse UserActivityAuditEvent (authentication)"""
        event_data = raw_event.get('event', {})

        user_id = event_data.get('UserId', '')
        user_name = event_data.get('UserName', '')
        operation_name = event_data.get('OperationName', '')
        success = event_data.get('Success', False)
        user_ip = event_data.get('UserIp', '')

        normalized = {
            '@timestamp': self._parse_timestamp_ms(event_data.get('UTCTimestamp', 0)),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['authentication'],
                'type': [self._get_user_activity_type(operation_name)],
                'action': operation_name,
                'outcome': 'success' if success else 'failure',
                'created': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
                'provider': 'crowdstrike',
                'module': 'falcon'
            },

            'user': {
                'id': user_id,
                'name': user_name
            },

            'source': {
                'ip': user_ip
            },

            'crowdstrike': {
                'metadata': metadata,
                'user_activity': {
                    'operation_name': operation_name,
                    'success': success,
                    'user_ip': user_ip
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_event(self, raw_event: Dict, metadata: Dict) -> Dict:
        """Parse unknown event types"""
        event_type = metadata.get('eventType', 'unknown')

        normalized = {
            '@timestamp': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['session'],
                'type': ['info'],
                'action': event_type,
                'created': self._parse_timestamp_ms(metadata.get('eventCreationTime', 0)),
                'provider': 'crowdstrike',
                'module': 'falcon'
            },

            'crowdstrike': {
                'metadata': metadata,
                'event': raw_event.get('event', {})
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _map_detection_severity(self, severity: str) -> int:
        """Map CrowdStrike severity to ECS numeric severity"""
        severity_mapping = {
            'Critical': 100,
            'High': 80,
            'Medium': 50,
            'Low': 20,
            'Informational': 10
        }
        return severity_mapping.get(severity, 50)

    def _map_incident_score(self, score: int) -> int:
        """Map incident fine score to ECS severity"""
        if score >= 80:
            return 100  # Critical
        elif score >= 60:
            return 80   # High
        elif score >= 40:
            return 50   # Medium
        elif score >= 20:
            return 20   # Low
        else:
            return 10   # Informational

    def _get_audit_event_type(self, operation_name: str) -> str:
        """Determine ECS event type from audit operation"""
        operation_lower = operation_name.lower()

        if 'create' in operation_lower or 'add' in operation_lower:
            return 'creation'
        elif 'update' in operation_lower or 'modify' in operation_lower or 'change' in operation_lower:
            return 'change'
        elif 'delete' in operation_lower or 'remove' in operation_lower:
            return 'deletion'
        else:
            return 'admin'

    def _get_user_activity_type(self, operation_name: str) -> str:
        """Determine ECS event type from user activity"""
        operation_lower = operation_name.lower()

        if 'login' in operation_lower or 'signin' in operation_lower:
            return 'start'
        elif 'logout' in operation_lower or 'signout' in operation_lower:
            return 'end'
        else:
            return 'info'

    def _parse_audit_key_values(self, audit_key_values: List[Dict]) -> Dict:
        """Convert audit key-value pairs to dict"""
        result = {}
        for item in audit_key_values:
            key = item.get('Key', '')
            value = item.get('ValueString', '')
            if key and value:
                result[key] = value
        return result

    def _parse_timestamp_ms(self, timestamp_ms: int) -> str:
        """Parse timestamp from milliseconds since epoch"""
        if not timestamp_ms:
            return datetime.utcnow().isoformat() + 'Z'

        try:
            dt = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=None)
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
        Validate that event has required CrowdStrike fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['metadata', 'event']

        for field in required_fields:
            if field not in event:
                return False

        # Validate metadata structure
        metadata = event.get('metadata', {})
        if not isinstance(metadata, dict):
            return False

        metadata_required = ['eventType', 'eventCreationTime']
        for field in metadata_required:
            if field not in metadata:
                return False

        return True
