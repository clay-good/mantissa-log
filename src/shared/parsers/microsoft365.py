"""
Microsoft 365 Management Activity Parser with ECS Normalization

Normalizes Microsoft 365 Management Activity API events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports:
- Azure Active Directory
- Exchange Online
- SharePoint Online
- Microsoft Teams
- DLP events
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class Microsoft365Parser(BaseParser):
    """Parser for Microsoft 365 Management Activity API events with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "microsoft365"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Microsoft 365 event and normalize to ECS.

        Args:
            raw_event: Raw Microsoft 365 Management Activity event

        Returns:
            Normalized event in ECS format
        """
        # Extract core fields
        record_type = raw_event.get('RecordType', 0)
        operation = raw_event.get('Operation', '')
        workload = raw_event.get('Workload', '')
        creation_time = raw_event.get('CreationTime', '')
        id_field = raw_event.get('Id', '')

        # Extract user information
        user_id = raw_event.get('UserId', '')
        user_type = raw_event.get('UserType', 0)

        # Extract client IP
        client_ip = raw_event.get('ClientIP', '')

        # Extract organization and tenant
        organization_id = raw_event.get('OrganizationId', '')
        user_key = raw_event.get('UserKey', '')

        # Extract result status
        result_status = raw_event.get('ResultStatus', '')

        # Categorize event
        ecs_category = self._categorize_event(record_type, workload, operation)
        ecs_type = self._get_event_type(operation)
        ecs_outcome = self._map_result_status(result_status)

        # Build ECS-normalized event
        normalized = {
            # ECS Core Fields
            '@timestamp': self._parse_timestamp(creation_time),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ecs_category,
                'type': ecs_type,
                'action': operation,
                'outcome': ecs_outcome,
                'created': self._parse_timestamp(creation_time),
                'id': id_field,
                'provider': 'microsoft365',
                'module': workload.lower() if workload else 'unknown'
            },

            # User fields
            'user': {
                'id': user_key or user_id,
                'email': user_id if '@' in user_id else None,
                'name': user_id.split('@')[0] if '@' in user_id else user_id
            },

            # Source fields
            'source': {
                'ip': client_ip
            },

            # Organization fields
            'organization': {
                'id': organization_id
            },

            # Related fields
            'related': {
                'ip': [client_ip] if client_ip else [],
                'user': [user_id, user_key] if user_id or user_key else []
            },

            # Microsoft 365-specific fields
            'microsoft365': {
                'record_type': record_type,
                'record_type_name': self._get_record_type_name(record_type),
                'operation': operation,
                'workload': workload,
                'creation_time': creation_time,
                'user_id': user_id,
                'user_type': user_type,
                'user_key': user_key,
                'organization_id': organization_id,
                'result_status': result_status,
                'object_id': raw_event.get('ObjectId', ''),
                'item_type': raw_event.get('ItemType', ''),
                'site_url': raw_event.get('SiteUrl', ''),
                'source_file_name': raw_event.get('SourceFileName', ''),
                'source_relative_url': raw_event.get('SourceRelativeUrl', ''),
                'extended_properties': raw_event.get('ExtendedProperties', []),
                'parameters': raw_event.get('Parameters', []),
                'app_id': raw_event.get('AppId', ''),
                'application_id': raw_event.get('ApplicationId', ''),
                'azure_ad_app_id': raw_event.get('AzureActiveDirectoryEventType', 0)
            },

            # Preserve raw event
            '_raw': raw_event
        }

        # Clean None values
        return self._remove_none_values(normalized)

    def _categorize_event(self, record_type: int, workload: str, operation: str) -> List[str]:
        """Categorize event based on record type and workload"""
        categories = []

        workload_lower = workload.lower()
        operation_lower = operation.lower()

        # Azure AD events
        if workload_lower == 'azureactivedirectory' or record_type in [15, 8]:
            categories.append('authentication')
            if any(x in operation_lower for x in ['user', 'group', 'role']):
                categories.append('iam')

        # Exchange events
        if workload_lower == 'exchange' or record_type in [2, 3, 4]:
            categories.append('email')
            if 'mailbox' in operation_lower:
                categories.append('file')

        # SharePoint events
        if workload_lower == 'sharepoint' or record_type in [4, 6]:
            categories.append('file')

        # DLP events
        if workload_lower == 'dlp' or record_type == 28:
            categories.append('file')
            categories.append('intrusion_detection')

        # Configuration changes
        if any(x in operation_lower for x in ['new-', 'set-', 'remove-', 'update']):
            categories.append('configuration')

        return categories if categories else ['session']

    def _get_event_type(self, operation: str) -> List[str]:
        """Determine ECS event.type based on operation"""
        types = []

        operation_lower = operation.lower()

        if any(x in operation_lower for x in ['new-', 'add', 'create']):
            types.append('creation')
        if any(x in operation_lower for x in ['set-', 'update', 'modify', 'change']):
            types.append('change')
        if any(x in operation_lower for x in ['remove-', 'delete']):
            types.append('deletion')
        if any(x in operation_lower for x in ['userloggedin', 'login', 'signin']):
            types.append('start')
        if any(x in operation_lower for x in ['logout', 'signout']):
            types.append('end')
        if any(x in operation_lower for x in ['access', 'download', 'fileaccessed']):
            types.append('access')
        if any(x in operation_lower for x in ['denied', 'failed']):
            types.append('denied')

        return types if types else ['info']

    def _map_result_status(self, result_status: str) -> str:
        """Map result status to ECS outcome"""
        if not result_status:
            return 'unknown'

        status_lower = result_status.lower()

        if status_lower in ['success', 'succeeded', 'partiallyprocessed']:
            return 'success'
        elif status_lower in ['failed', 'failure']:
            return 'failure'
        else:
            return 'unknown'

    def _get_record_type_name(self, record_type: int) -> str:
        """Map record type number to name"""
        record_type_map = {
            1: 'ExchangeAdmin',
            2: 'ExchangeItem',
            3: 'ExchangeItemGroup',
            4: 'SharePoint',
            6: 'SharePointFileOperation',
            8: 'AzureActiveDirectory',
            9: 'AzureActiveDirectoryAccountLogon',
            10: 'DataCenterSecurityCmdlet',
            11: 'ComplianceDLPSharePoint',
            13: 'ComplianceDLPExchange',
            14: 'SharePointSharingOperation',
            15: 'AzureActiveDirectoryStsLogon',
            18: 'SecurityComplianceCenterEOPCmdlet',
            20: 'PowerBIAudit',
            21: 'CRM',
            22: 'Yammer',
            23: 'SkypeForBusinessCmdlets',
            24: 'Discovery',
            25: 'MicrosoftTeams',
            28: 'ThreatIntelligence',
            30: 'MicrosoftFlow',
            32: 'MicrosoftStream',
            35: 'ComplianceDLPSharePointClassification',
            36: 'ThreatFinder',
            38: 'Project',
            40: 'SecurityComplianceAlerts',
            41: 'ThreatIntelligenceUrl',
            47: 'ThreatIntelligenceAtpContent',
            52: 'AirInvestigation',
            54: 'SecurityComplianceInsights',
            64: 'MicrosoftTeamsAdmin',
            68: 'DataInsightsRestApiAudit',
            72: 'ThreatIntelligenceIntelProfiles',
            73: 'MyAnalyticsSettings',
            82: 'SecurityComplianceRBAC',
            91: 'MicrosoftTeamsShifts'
        }
        return record_type_map.get(record_type, f'Unknown_{record_type}')

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate ISO 8601 timestamp"""
        if not timestamp_str:
            return datetime.utcnow().isoformat() + 'Z'

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
        Validate that event has required Microsoft 365 fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['RecordType', 'CreationTime', 'Id', 'Operation', 'Workload']

        for field in required_fields:
            if field not in event:
                return False

        return True
