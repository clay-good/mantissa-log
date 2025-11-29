"""
Salesforce Log Parser with ECS Normalization

Normalizes Salesforce EventLogFile and Login History events to Elastic Common
Schema (ECS) format for unified detection and analysis across all log sources.

Supports Salesforce log types including:
- Login History (authentication events)
- Logout History
- API Event Logs (REST, SOAP, Bulk API)
- Report Export logs
- Setup Audit Trail (admin configuration changes)
- URI Event logs (page views, actions)
- Apex Execution logs
- Console Event logs
- Lightning Error logs
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


class BaseParser:
    """Base parser class for ECS normalization"""

    def __init__(self):
        self.source_type = "generic"


class SalesforceParser(BaseParser):
    """Parser for Salesforce Event Log File and Login History with ECS normalization"""

    # Salesforce event type to ECS category mapping
    EVENT_TYPE_CATEGORY_MAP = {
        'Login': ['authentication'],
        'Logout': ['authentication'],
        'LoginAs': ['authentication', 'iam'],
        'API': ['web'],
        'RestApi': ['web'],
        'ApexExecution': ['process'],
        'ApexTrigger': ['process'],
        'ApexSoap': ['web'],
        'ApexRest': ['web'],
        'BulkApi': ['web', 'file'],
        'Report': ['file'],
        'ReportExport': ['file'],
        'Dashboard': ['web'],
        'Document': ['file'],
        'ContentTransfer': ['file'],
        'ContentDistribution': ['file'],
        'LightningError': ['web'],
        'LightningInteraction': ['web'],
        'LightningPageView': ['web'],
        'LightningPerformance': ['web'],
        'URI': ['web'],
        'Sites': ['web'],
        'VisualforceRequest': ['web'],
        'WaveChange': ['configuration'],
        'WaveInteraction': ['web'],
        'SetupAuditTrail': ['configuration', 'iam'],
        'PermissionSetAssignment': ['iam'],
        'PermissionSetLicense': ['iam'],
        'PackageInstall': ['package'],
        'Sandbox': ['configuration'],
        'Console': ['web'],
        'TimeBasedWorkflow': ['process'],
        'ApexCallout': ['network'],
        'AsyncReportRun': ['process'],
        'ConcurrentLongRunningApexLimit': ['process'],
        'CorsViolation': ['network'],
        'ExternalCrossOrgCallout': ['network'],
        'ExternalODataCallout': ['network'],
        'FlowExecution': ['process'],
        'InsecureExternalAssets': ['network'],
        'KnowledgeArticleView': ['web'],
        'MetadataApiOperation': ['configuration'],
        'MultiBlockReport': ['file'],
        'NamedCredential': ['authentication'],
        'OneCommerceUsage': ['web'],
        'PlatformEncryption': ['configuration'],
        'QueuedExecution': ['process'],
        'Search': ['web'],
        'SearchClick': ['web'],
        'TransactionSecurity': ['intrusion_detection'],
    }

    # Login status to outcome mapping
    LOGIN_STATUS_MAP = {
        'Success': 'success',
        'Invalid Password': 'failure',
        'User Lockout': 'failure',
        'Invalid Credentials': 'failure',
        'Failed: Invalid Password': 'failure',
        'Failed': 'failure',
        'Pending': 'unknown',
    }

    def __init__(self):
        super().__init__()
        self.source_type = "salesforce"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Salesforce event and normalize to ECS.

        Args:
            raw_event: Raw Salesforce event (EventLogFile or Login History)

        Returns:
            Normalized event in ECS format
        """
        # Determine event type and parse accordingly
        if 'EventType' in raw_event:
            # EventLogFile format
            return self._parse_event_log(raw_event)
        elif 'LoginType' in raw_event or 'Status' in raw_event:
            # Login History format
            return self._parse_login_event(raw_event)
        elif 'Action' in raw_event and 'Section' in raw_event:
            # Setup Audit Trail format
            return self._parse_audit_trail(raw_event)
        else:
            return self._parse_generic_event(raw_event)

    def _parse_event_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Salesforce EventLogFile format"""
        event_type = raw_event.get('EventType', '')
        timestamp = raw_event.get('TIMESTAMP_DERIVED', raw_event.get('TIMESTAMP', ''))
        user_id = raw_event.get('USER_ID', raw_event.get('UserId', ''))
        username = raw_event.get('USER_NAME', raw_event.get('Username', ''))
        source_ip = raw_event.get('CLIENT_IP', raw_event.get('SourceIp', ''))
        session_id = raw_event.get('SESSION_KEY', raw_event.get('SessionId', ''))

        # Extract request details
        uri = raw_event.get('URI', raw_event.get('REQUEST_URL', ''))
        method = raw_event.get('METHOD', raw_event.get('HTTP_METHOD', ''))
        status_code = raw_event.get('STATUS_CODE', raw_event.get('HttpStatusCode', ''))
        request_id = raw_event.get('REQUEST_ID', '')

        # Extract API details
        api_type = raw_event.get('API_TYPE', '')
        api_version = raw_event.get('API_VERSION', '')

        # Extract performance metrics
        cpu_time = raw_event.get('CPU_TIME', raw_event.get('CpuTime', 0))
        db_time = raw_event.get('DB_TOTAL_TIME', raw_event.get('DbTotalTime', 0))
        run_time = raw_event.get('RUN_TIME', raw_event.get('RunTime', 0))
        rows_processed = raw_event.get('ROWS_PROCESSED', raw_event.get('RowsProcessed', 0))

        # Determine ECS categorization
        ecs_categories = self.EVENT_TYPE_CATEGORY_MAP.get(event_type, ['web'])

        # Determine outcome from status code
        ecs_outcome = self._determine_outcome(status_code, raw_event)

        # Extract user agent
        user_agent = raw_event.get('USER_AGENT', raw_event.get('Browser', ''))

        # Build ECS-normalized event
        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type(event_type),
                'action': event_type.lower(),
                'outcome': ecs_outcome,
                'duration': run_time * 1000000 if run_time else None,  # Convert ms to ns
                'id': request_id,
                'provider': 'salesforce',
                'module': event_type.lower()
            },

            'user': {
                'id': user_id,
                'name': username,
                'email': username if '@' in str(username) else None
            },

            'source': {
                'ip': source_ip
            },

            'url': {
                'path': uri,
                'original': uri
            },

            'http': {
                'request': {
                    'method': method
                },
                'response': {
                    'status_code': int(status_code) if status_code and str(status_code).isdigit() else None
                }
            },

            'user_agent': {
                'original': user_agent
            },

            'related': {
                'ip': [source_ip] if source_ip else [],
                'user': [u for u in [username, user_id] if u]
            },

            'salesforce': {
                'event_type': event_type,
                'request_id': request_id,
                'session_key': session_id,
                'api': {
                    'type': api_type,
                    'version': api_version
                },
                'performance': {
                    'cpu_time': cpu_time,
                    'db_time': db_time,
                    'run_time': run_time,
                    'rows_processed': rows_processed
                },
                'organization_id': raw_event.get('ORGANIZATION_ID', raw_event.get('OrganizationId', '')),
                'entity_name': raw_event.get('ENTITY_NAME', ''),
                'query': raw_event.get('SOQL_QUERIES', raw_event.get('Query', '')),
                'rows_returned': raw_event.get('NUMBER_SOQL_QUERIES', 0),
                'success': raw_event.get('SUCCESS', raw_event.get('IsSuccess', True)),
                'login_key': raw_event.get('LOGIN_KEY', ''),
                'user_type': raw_event.get('USER_TYPE', ''),
                'request_status': raw_event.get('REQUEST_STATUS', ''),
                'client_name': raw_event.get('CLIENT_NAME', ''),
                'connected_app_id': raw_event.get('CONNECTED_APP_ID', ''),
                'login_type': raw_event.get('LOGIN_TYPE', ''),
                'login_status': raw_event.get('LOGIN_STATUS', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_login_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Salesforce Login History format"""
        timestamp = raw_event.get('LoginTime', raw_event.get('CreatedDate', ''))
        user_id = raw_event.get('UserId', '')
        username = raw_event.get('Username', '')
        source_ip = raw_event.get('SourceIp', raw_event.get('ClientIp', ''))
        login_type = raw_event.get('LoginType', '')
        status = raw_event.get('Status', 'Success')
        platform = raw_event.get('Platform', '')
        browser = raw_event.get('Browser', '')
        application = raw_event.get('Application', '')
        login_geo_id = raw_event.get('LoginGeoId', '')

        # Determine outcome from status
        ecs_outcome = self.LOGIN_STATUS_MAP.get(status, 'unknown')

        # Determine if this is a login failure
        is_failure = ecs_outcome == 'failure'

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['authentication'],
                'type': ['start'] if ecs_outcome == 'success' else ['info'],
                'action': 'user_login',
                'outcome': ecs_outcome,
                'reason': status if is_failure else None,
                'provider': 'salesforce',
                'module': 'login'
            },

            'user': {
                'id': user_id,
                'name': username,
                'email': username if '@' in str(username) else None
            },

            'source': {
                'ip': source_ip
            },

            'user_agent': {
                'name': browser,
                'os': {
                    'name': platform
                }
            },

            'related': {
                'ip': [source_ip] if source_ip else [],
                'user': [u for u in [username, user_id] if u]
            },

            'salesforce': {
                'login': {
                    'type': login_type,
                    'status': status,
                    'platform': platform,
                    'browser': browser,
                    'application': application,
                    'geo_id': login_geo_id,
                    'api_type': raw_event.get('ApiType', ''),
                    'api_version': raw_event.get('ApiVersion', ''),
                    'authentication_service_id': raw_event.get('AuthenticationServiceId', ''),
                    'cipher_suite': raw_event.get('CipherSuite', ''),
                    'country_iso': raw_event.get('CountryIso', ''),
                    'login_url': raw_event.get('LoginUrl', ''),
                    'tls_protocol': raw_event.get('TlsProtocol', ''),
                    'options_is_get': raw_event.get('OptionsIsGet', False),
                    'options_is_post': raw_event.get('OptionsIsPost', False)
                },
                'organization_id': raw_event.get('OrganizationId', ''),
                'user_type': raw_event.get('UserType', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_audit_trail(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Salesforce Setup Audit Trail format"""
        timestamp = raw_event.get('CreatedDate', '')
        created_by_id = raw_event.get('CreatedById', '')
        created_by_name = raw_event.get('CreatedByName', raw_event.get('CreatedBy', {}).get('Name', ''))
        action = raw_event.get('Action', '')
        section = raw_event.get('Section', '')
        display = raw_event.get('Display', '')
        delegate_user = raw_event.get('DelegateUser', '')
        responsible_namespace = raw_event.get('ResponsibleNamespacePrefix', '')

        # Determine event type based on action
        ecs_types = self._get_audit_event_type(action)

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['configuration', 'iam'],
                'type': ecs_types,
                'action': action.lower().replace(' ', '_') if action else 'setup_change',
                'outcome': 'success',
                'provider': 'salesforce',
                'module': 'setup_audit_trail'
            },

            'message': display,

            'user': {
                'id': created_by_id,
                'name': created_by_name
            },

            'related': {
                'user': [u for u in [created_by_name, created_by_id, delegate_user] if u]
            },

            'salesforce': {
                'audit_trail': {
                    'action': action,
                    'section': section,
                    'display': display,
                    'delegate_user': delegate_user,
                    'responsible_namespace': responsible_namespace
                },
                'id': raw_event.get('Id', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic Salesforce event format"""
        timestamp = (
            raw_event.get('TIMESTAMP_DERIVED') or
            raw_event.get('TIMESTAMP') or
            raw_event.get('CreatedDate') or
            raw_event.get('LoginTime') or
            ''
        )

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['web'],
                'type': ['info'],
                'action': 'salesforce_event',
                'outcome': 'unknown',
                'provider': 'salesforce',
                'module': 'generic'
            },

            'salesforce': raw_event,

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _determine_outcome(self, status_code: Any, raw_event: Dict[str, Any]) -> str:
        """Determine ECS outcome from status code or event fields"""
        # Check explicit success field
        if 'SUCCESS' in raw_event:
            return 'success' if raw_event['SUCCESS'] else 'failure'
        if 'IsSuccess' in raw_event:
            return 'success' if raw_event['IsSuccess'] else 'failure'

        # Check status code
        if status_code:
            try:
                code = int(status_code)
                if 200 <= code < 300:
                    return 'success'
                elif 400 <= code < 600:
                    return 'failure'
            except (ValueError, TypeError):
                pass

        # Check request status
        request_status = raw_event.get('REQUEST_STATUS', '')
        if request_status:
            if request_status.upper() in ('S', 'SUCCESS'):
                return 'success'
            elif request_status.upper() in ('F', 'FAILURE', 'E', 'ERROR'):
                return 'failure'

        return 'unknown'

    def _get_event_type(self, event_type: str) -> List[str]:
        """Determine ECS event.type based on Salesforce event type"""
        types = []

        lower_event = event_type.lower()

        if 'login' in lower_event:
            types.append('start')
        elif 'logout' in lower_event:
            types.append('end')
        elif any(x in lower_event for x in ['create', 'insert', 'add']):
            types.append('creation')
        elif any(x in lower_event for x in ['update', 'modify', 'change', 'edit']):
            types.append('change')
        elif any(x in lower_event for x in ['delete', 'remove']):
            types.append('deletion')
        elif 'export' in lower_event:
            types.append('access')
        elif 'api' in lower_event or 'request' in lower_event:
            types.append('access')
        elif 'error' in lower_event:
            types.append('error')
        else:
            types.append('info')

        return types

    def _get_audit_event_type(self, action: str) -> List[str]:
        """Determine ECS event.type for audit trail actions"""
        types = []

        lower_action = action.lower() if action else ''

        if any(x in lower_action for x in ['created', 'added', 'inserted', 'enabled']):
            types.append('creation')
        elif any(x in lower_action for x in ['changed', 'modified', 'updated', 'edited']):
            types.append('change')
        elif any(x in lower_action for x in ['deleted', 'removed', 'disabled']):
            types.append('deletion')
        elif any(x in lower_action for x in ['granted', 'assigned']):
            types.append('allowed')
        elif any(x in lower_action for x in ['revoked', 'unassigned']):
            types.append('denied')
        else:
            types.append('change')

        return types

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate timestamp"""
        if not timestamp_str:
            return datetime.now(timezone.utc).isoformat()

        # Handle various Salesforce timestamp formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S',
            '%Y%m%d%H%M%S.%f',  # EventLogFile format
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
        Validate that event has required Salesforce fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # EventLogFile format
        if 'EventType' in event:
            return True

        # Login History format
        if 'LoginType' in event or 'Status' in event:
            return 'UserId' in event or 'Username' in event

        # Setup Audit Trail format
        if 'Action' in event and 'Section' in event:
            return True

        # Generic - need at least a timestamp
        if any(k in event for k in ['TIMESTAMP', 'TIMESTAMP_DERIVED', 'CreatedDate', 'LoginTime']):
            return True

        return False
