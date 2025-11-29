"""
Snowflake Log Parser with ECS Normalization

Normalizes Snowflake audit and access logs to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports Snowflake log types from ACCOUNT_USAGE schema:
- LOGIN_HISTORY (authentication events)
- QUERY_HISTORY (data access and query execution)
- ACCESS_HISTORY (object-level access tracking)
- SESSIONS (session lifecycle events)
- GRANTS_TO_USERS (permission changes)
- GRANTS_TO_ROLES (role-based access control)
- WAREHOUSE_EVENTS_HISTORY (warehouse operations)
- COPY_HISTORY (data loading operations)
- DATA_TRANSFER_HISTORY (data export/replication)
- POLICY_REFERENCES (security policy usage)
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from .base import BaseParser


class SnowflakeParser(BaseParser):
    """Parser for Snowflake audit logs with ECS normalization"""

    # Query type to ECS category mapping
    QUERY_TYPE_CATEGORY_MAP = {
        'SELECT': ['database'],
        'INSERT': ['database'],
        'UPDATE': ['database'],
        'DELETE': ['database'],
        'MERGE': ['database'],
        'CREATE': ['database', 'configuration'],
        'ALTER': ['database', 'configuration'],
        'DROP': ['database', 'configuration'],
        'GRANT': ['iam'],
        'REVOKE': ['iam'],
        'COPY': ['file', 'database'],
        'PUT': ['file'],
        'GET': ['file'],
        'LIST': ['file'],
        'REMOVE': ['file'],
        'CALL': ['process'],
        'DESCRIBE': ['database'],
        'SHOW': ['database'],
        'USE': ['database'],
        'EXPLAIN': ['database'],
        'SET': ['configuration'],
        'UNSET': ['configuration'],
    }

    # Login error codes to outcomes
    LOGIN_ERROR_MAP = {
        '': 'success',
        None: 'success',
        'INCORRECT_USERNAME_PASSWORD': 'failure',
        'USER_LOCKED_OUT': 'failure',
        'INVALID_CONNECTION_STRING': 'failure',
        'IP_ADDRESS_NOT_ALLOWED': 'failure',
        'CLIENT_IP_BLOCKED': 'failure',
        'INVALID_CLIENT_TYPE': 'failure',
        'DISABLED_USER_ACCOUNT': 'failure',
        'EXPIRED_PASSWORD': 'failure',
        'MFA_REQUIRED': 'failure',
        'OAUTH_INVALID_TOKEN': 'failure',
        'SAML_INVALID_ASSERTION': 'failure',
    }

    def __init__(self):
        super().__init__()
        self.source_type = "snowflake"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Snowflake event and normalize to ECS.

        Args:
            raw_event: Raw Snowflake event from ACCOUNT_USAGE views

        Returns:
            Normalized event in ECS format
        """
        # Determine event type based on available fields
        if 'EVENT_TYPE' in raw_event and raw_event.get('EVENT_TYPE') == 'LOGIN':
            return self._parse_login_history(raw_event)
        elif 'IS_SUCCESS' in raw_event and 'LOGIN_EVENT_TYPE' in raw_event:
            return self._parse_login_history(raw_event)
        elif 'QUERY_ID' in raw_event and 'QUERY_TEXT' in raw_event:
            return self._parse_query_history(raw_event)
        elif 'QUERY_ID' in raw_event and 'DIRECT_OBJECTS_ACCESSED' in raw_event:
            return self._parse_access_history(raw_event)
        elif 'SESSION_ID' in raw_event and 'CREATED_ON' in raw_event:
            return self._parse_session_event(raw_event)
        elif 'GRANTEE_NAME' in raw_event and 'PRIVILEGE' in raw_event:
            return self._parse_grant_event(raw_event)
        elif 'WAREHOUSE_NAME' in raw_event and 'EVENT_TYPE' in raw_event:
            return self._parse_warehouse_event(raw_event)
        elif 'FILE_NAME' in raw_event and 'STAGE_LOCATION' in raw_event:
            return self._parse_copy_history(raw_event)
        elif 'SOURCE_CLOUD' in raw_event or 'TARGET_CLOUD' in raw_event:
            return self._parse_data_transfer(raw_event)
        else:
            return self._parse_generic_event(raw_event)

    def _parse_login_history(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake LOGIN_HISTORY event"""
        timestamp = raw_event.get('EVENT_TIMESTAMP', raw_event.get('LOGIN_EVENT_TIMESTAMP', ''))
        user_name = raw_event.get('USER_NAME', '')
        client_ip = raw_event.get('CLIENT_IP', '')
        reported_client_type = raw_event.get('REPORTED_CLIENT_TYPE', '')
        reported_client_version = raw_event.get('REPORTED_CLIENT_VERSION', '')
        first_auth_factor = raw_event.get('FIRST_AUTHENTICATION_FACTOR', '')
        second_auth_factor = raw_event.get('SECOND_AUTHENTICATION_FACTOR', '')
        is_success = raw_event.get('IS_SUCCESS', 'YES')
        error_code = raw_event.get('ERROR_CODE', '')
        error_message = raw_event.get('ERROR_MESSAGE', '')

        # Determine outcome
        ecs_outcome = 'success' if is_success == 'YES' else 'failure'
        if error_code and error_code in self.LOGIN_ERROR_MAP:
            ecs_outcome = self.LOGIN_ERROR_MAP[error_code]

        # Build ECS-normalized event
        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['authentication'],
                'type': ['start'] if ecs_outcome == 'success' else ['info'],
                'action': 'user_login',
                'outcome': ecs_outcome,
                'reason': error_message if ecs_outcome == 'failure' else None,
                'provider': 'snowflake',
                'module': 'login_history'
            },

            'user': {
                'name': user_name
            },

            'source': {
                'ip': client_ip
            },

            'user_agent': {
                'name': reported_client_type,
                'version': reported_client_version
            },

            'related': {
                'ip': [client_ip] if client_ip else [],
                'user': [user_name] if user_name else []
            },

            'snowflake': {
                'event_id': raw_event.get('EVENT_ID', ''),
                'event_type': raw_event.get('EVENT_TYPE', raw_event.get('LOGIN_EVENT_TYPE', '')),
                'login': {
                    'is_success': is_success,
                    'error_code': error_code,
                    'error_message': error_message,
                    'first_auth_factor': first_auth_factor,
                    'second_auth_factor': second_auth_factor,
                    'client_type': reported_client_type,
                    'client_version': reported_client_version,
                    'connection_id': raw_event.get('CONNECTION_ID', ''),
                    'session_id': raw_event.get('SESSION_ID', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_query_history(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake QUERY_HISTORY event"""
        timestamp = raw_event.get('START_TIME', raw_event.get('END_TIME', ''))
        query_id = raw_event.get('QUERY_ID', '')
        query_text = raw_event.get('QUERY_TEXT', '')
        query_type = raw_event.get('QUERY_TYPE', '')
        user_name = raw_event.get('USER_NAME', '')
        role_name = raw_event.get('ROLE_NAME', '')
        database_name = raw_event.get('DATABASE_NAME', '')
        schema_name = raw_event.get('SCHEMA_NAME', '')
        warehouse_name = raw_event.get('WAREHOUSE_NAME', '')
        execution_status = raw_event.get('EXECUTION_STATUS', '')
        error_code = raw_event.get('ERROR_CODE', '')
        error_message = raw_event.get('ERROR_MESSAGE', '')

        # Determine outcome from execution status
        ecs_outcome = 'success' if execution_status == 'SUCCESS' else 'failure'

        # Determine ECS categories based on query type
        ecs_categories = self.QUERY_TYPE_CATEGORY_MAP.get(query_type, ['database'])

        # Determine ECS event type
        ecs_types = ['access']
        if query_type in ['CREATE', 'INSERT']:
            ecs_types = ['creation']
        elif query_type in ['ALTER', 'UPDATE', 'MERGE']:
            ecs_types = ['change']
        elif query_type in ['DROP', 'DELETE']:
            ecs_types = ['deletion']
        elif query_type in ['GRANT', 'REVOKE']:
            ecs_types = ['admin']

        # Performance metrics
        total_elapsed_time = raw_event.get('TOTAL_ELAPSED_TIME', 0)
        bytes_scanned = raw_event.get('BYTES_SCANNED', 0)
        rows_produced = raw_event.get('ROWS_PRODUCED', 0)
        rows_inserted = raw_event.get('ROWS_INSERTED', 0)
        rows_updated = raw_event.get('ROWS_UPDATED', 0)
        rows_deleted = raw_event.get('ROWS_DELETED', 0)

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': ecs_types,
                'action': f'query_{query_type.lower()}' if query_type else 'query',
                'outcome': ecs_outcome,
                'reason': error_message if ecs_outcome == 'failure' else None,
                'duration': total_elapsed_time * 1000000 if total_elapsed_time else None,
                'id': query_id,
                'provider': 'snowflake',
                'module': 'query_history'
            },

            'user': {
                'name': user_name,
                'roles': [role_name] if role_name else []
            },

            'related': {
                'user': [u for u in [user_name, role_name] if u]
            },

            'snowflake': {
                'query': {
                    'id': query_id,
                    'text': query_text[:5000] if query_text else '',
                    'type': query_type,
                    'tag': raw_event.get('QUERY_TAG', ''),
                    'hash': raw_event.get('QUERY_HASH', ''),
                    'parameterized_hash': raw_event.get('QUERY_PARAMETERIZED_HASH', '')
                },
                'execution': {
                    'status': execution_status,
                    'error_code': error_code,
                    'error_message': error_message
                },
                'database': {
                    'name': database_name,
                    'schema': schema_name
                },
                'warehouse': {
                    'name': warehouse_name,
                    'size': raw_event.get('WAREHOUSE_SIZE', ''),
                    'type': raw_event.get('WAREHOUSE_TYPE', '')
                },
                'role': role_name,
                'session_id': raw_event.get('SESSION_ID', ''),
                'performance': {
                    'elapsed_time_ms': total_elapsed_time,
                    'bytes_scanned': bytes_scanned,
                    'bytes_written': raw_event.get('BYTES_WRITTEN', 0),
                    'bytes_spilled_local': raw_event.get('BYTES_SPILLED_TO_LOCAL_STORAGE', 0),
                    'bytes_spilled_remote': raw_event.get('BYTES_SPILLED_TO_REMOTE_STORAGE', 0),
                    'rows_produced': rows_produced,
                    'rows_inserted': rows_inserted,
                    'rows_updated': rows_updated,
                    'rows_deleted': rows_deleted,
                    'compilation_time_ms': raw_event.get('COMPILATION_TIME', 0),
                    'execution_time_ms': raw_event.get('EXECUTION_TIME', 0),
                    'queued_provisioning_time_ms': raw_event.get('QUEUED_PROVISIONING_TIME', 0),
                    'queued_overload_time_ms': raw_event.get('QUEUED_OVERLOAD_TIME', 0),
                    'credits_used': raw_event.get('CREDITS_USED_CLOUD_SERVICES', 0),
                    'partitions_scanned': raw_event.get('PARTITIONS_SCANNED', 0),
                    'partitions_total': raw_event.get('PARTITIONS_TOTAL', 0)
                },
                'cluster_number': raw_event.get('CLUSTER_NUMBER', 0),
                'is_client_generated': raw_event.get('IS_CLIENT_GENERATED_STATEMENT', False)
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_access_history(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake ACCESS_HISTORY event"""
        timestamp = raw_event.get('QUERY_START_TIME', '')
        query_id = raw_event.get('QUERY_ID', '')
        user_name = raw_event.get('USER_NAME', '')
        direct_objects = raw_event.get('DIRECT_OBJECTS_ACCESSED', [])
        base_objects = raw_event.get('BASE_OBJECTS_ACCESSED', [])
        objects_modified = raw_event.get('OBJECTS_MODIFIED', [])

        # Extract object names for related fields
        accessed_objects = []
        if direct_objects:
            for obj in direct_objects:
                if isinstance(obj, dict):
                    obj_name = obj.get('objectName', '')
                    if obj_name:
                        accessed_objects.append(obj_name)

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['database'],
                'type': ['access'],
                'action': 'object_access',
                'outcome': 'success',
                'id': query_id,
                'provider': 'snowflake',
                'module': 'access_history'
            },

            'user': {
                'name': user_name,
                'roles': [raw_event.get('ROLE_NAME', '')] if raw_event.get('ROLE_NAME') else []
            },

            'related': {
                'user': [user_name] if user_name else []
            },

            'snowflake': {
                'query_id': query_id,
                'access': {
                    'direct_objects': direct_objects,
                    'base_objects': base_objects,
                    'objects_modified': objects_modified,
                    'object_count': len(accessed_objects),
                    'policy_name': raw_event.get('POLICY_NAME', ''),
                    'parent_query_id': raw_event.get('PARENT_QUERY_ID', ''),
                    'root_query_id': raw_event.get('ROOT_QUERY_ID', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_session_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake session event"""
        timestamp = raw_event.get('CREATED_ON', '')
        session_id = raw_event.get('SESSION_ID', '')
        user_name = raw_event.get('USER_NAME', '')
        client_environment = raw_event.get('CLIENT_ENVIRONMENT', {})

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['session'],
                'type': ['start'],
                'action': 'session_created',
                'outcome': 'success',
                'id': str(session_id),
                'provider': 'snowflake',
                'module': 'sessions'
            },

            'user': {
                'name': user_name
            },

            'related': {
                'user': [user_name] if user_name else []
            },

            'snowflake': {
                'session': {
                    'id': session_id,
                    'authentication_method': raw_event.get('AUTHENTICATION_METHOD', ''),
                    'login_event_id': raw_event.get('LOGIN_EVENT_ID', ''),
                    'client_application_id': raw_event.get('CLIENT_APPLICATION_ID', ''),
                    'client_environment': client_environment,
                    'client_build_id': raw_event.get('CLIENT_BUILD_ID', ''),
                    'client_version': raw_event.get('CLIENT_VERSION', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_grant_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake GRANTS event (GRANTS_TO_USERS or GRANTS_TO_ROLES)"""
        timestamp = raw_event.get('CREATED_ON', '')
        grantee_name = raw_event.get('GRANTEE_NAME', '')
        privilege = raw_event.get('PRIVILEGE', '')
        granted_on = raw_event.get('GRANTED_ON', '')
        name = raw_event.get('NAME', raw_event.get('TABLE_NAME', ''))
        granted_by = raw_event.get('GRANTED_BY', '')
        grant_option = raw_event.get('GRANT_OPTION', 'false')

        # Determine if this is a high-risk privilege
        high_risk_privileges = ['OWNERSHIP', 'MANAGE GRANTS', 'MONITOR',
                                'OPERATE', 'CREATE ACCOUNT', 'CREATE INTEGRATION',
                                'CREATE NETWORK POLICY', 'APPLY MASKING POLICY',
                                'APPLY ROW ACCESS POLICY', 'APPLY TAG']

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['iam'],
                'type': ['admin', 'allowed'],
                'action': 'grant_privilege',
                'outcome': 'success',
                'provider': 'snowflake',
                'module': 'grants'
            },

            'user': {
                'name': granted_by,
                'target': {
                    'name': grantee_name
                }
            },

            'related': {
                'user': [u for u in [granted_by, grantee_name] if u]
            },

            'snowflake': {
                'grant': {
                    'privilege': privilege,
                    'granted_on': granted_on,
                    'object_name': name,
                    'grantee_name': grantee_name,
                    'granted_by': granted_by,
                    'grant_option': grant_option == 'true',
                    'is_high_risk': privilege.upper() in high_risk_privileges,
                    'table_catalog': raw_event.get('TABLE_CATALOG', ''),
                    'table_schema': raw_event.get('TABLE_SCHEMA', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_warehouse_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake warehouse event"""
        timestamp = raw_event.get('TIMESTAMP', '')
        warehouse_name = raw_event.get('WAREHOUSE_NAME', '')
        event_type = raw_event.get('EVENT_TYPE', '')
        user_name = raw_event.get('USER_NAME', '')

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['configuration'],
                'type': ['change'],
                'action': f'warehouse_{event_type.lower()}' if event_type else 'warehouse_event',
                'outcome': 'success',
                'provider': 'snowflake',
                'module': 'warehouse_events'
            },

            'user': {
                'name': user_name
            },

            'related': {
                'user': [user_name] if user_name else []
            },

            'snowflake': {
                'warehouse': {
                    'name': warehouse_name,
                    'event_type': event_type,
                    'event_reason': raw_event.get('EVENT_REASON', ''),
                    'cluster_number': raw_event.get('CLUSTER_NUMBER', 0),
                    'size': raw_event.get('WAREHOUSE_SIZE', ''),
                    'state': raw_event.get('EVENT_STATE', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_copy_history(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake COPY_HISTORY event"""
        timestamp = raw_event.get('LAST_LOAD_TIME', '')
        file_name = raw_event.get('FILE_NAME', '')
        stage_location = raw_event.get('STAGE_LOCATION', '')
        table_name = raw_event.get('TABLE_NAME', '')
        status = raw_event.get('STATUS', '')
        row_count = raw_event.get('ROW_COUNT', 0)
        file_size = raw_event.get('FILE_SIZE', 0)

        ecs_outcome = 'success' if status == 'LOADED' else 'failure'

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['file', 'database'],
                'type': ['creation'],
                'action': 'data_load',
                'outcome': ecs_outcome,
                'provider': 'snowflake',
                'module': 'copy_history'
            },

            'file': {
                'name': file_name,
                'size': file_size,
                'path': stage_location
            },

            'snowflake': {
                'copy': {
                    'table_name': table_name,
                    'table_catalog': raw_event.get('TABLE_CATALOG_NAME', ''),
                    'table_schema': raw_event.get('TABLE_SCHEMA_NAME', ''),
                    'stage_location': stage_location,
                    'file_name': file_name,
                    'status': status,
                    'row_count': row_count,
                    'row_parsed': raw_event.get('ROW_PARSED', 0),
                    'file_size': file_size,
                    'first_error_message': raw_event.get('FIRST_ERROR_MESSAGE', ''),
                    'first_error_line_number': raw_event.get('FIRST_ERROR_LINE_NUMBER', 0),
                    'error_count': raw_event.get('ERROR_COUNT', 0),
                    'error_limit': raw_event.get('ERROR_LIMIT', 0),
                    'pipe_name': raw_event.get('PIPE_NAME', ''),
                    'pipe_received_time': raw_event.get('PIPE_RECEIVED_TIME', '')
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_data_transfer(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Snowflake DATA_TRANSFER_HISTORY event"""
        timestamp = raw_event.get('START_TIME', '')
        source_cloud = raw_event.get('SOURCE_CLOUD', '')
        source_region = raw_event.get('SOURCE_REGION', '')
        target_cloud = raw_event.get('TARGET_CLOUD', '')
        target_region = raw_event.get('TARGET_REGION', '')
        transfer_type = raw_event.get('TRANSFER_TYPE', '')
        bytes_transferred = raw_event.get('BYTES_TRANSFERRED', 0)

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['network'],
                'type': ['connection'],
                'action': 'data_transfer',
                'outcome': 'success',
                'provider': 'snowflake',
                'module': 'data_transfer'
            },

            'source': {
                'cloud': {
                    'provider': source_cloud.lower() if source_cloud else '',
                    'region': source_region
                }
            },

            'destination': {
                'cloud': {
                    'provider': target_cloud.lower() if target_cloud else '',
                    'region': target_region
                }
            },

            'snowflake': {
                'transfer': {
                    'type': transfer_type,
                    'source_cloud': source_cloud,
                    'source_region': source_region,
                    'target_cloud': target_cloud,
                    'target_region': target_region,
                    'bytes_transferred': bytes_transferred
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic Snowflake event"""
        # Try to find a timestamp
        timestamp = (
            raw_event.get('EVENT_TIMESTAMP') or
            raw_event.get('START_TIME') or
            raw_event.get('END_TIME') or
            raw_event.get('CREATED_ON') or
            raw_event.get('TIMESTAMP') or
            ''
        )

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['database'],
                'type': ['info'],
                'action': 'snowflake_event',
                'outcome': 'unknown',
                'provider': 'snowflake',
                'module': 'generic'
            },

            'snowflake': raw_event,

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_timestamp(self, timestamp_value: Any) -> str:
        """Parse and normalize Snowflake timestamp"""
        if not timestamp_value:
            return datetime.now(timezone.utc).isoformat()

        # If already a string in ISO format
        if isinstance(timestamp_value, str):
            # Handle various timestamp formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S.%f%z',
                '%Y-%m-%d %H:%M:%S',
            ]

            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_value, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except ValueError:
                    continue

            # Try ISO parsing
            try:
                if timestamp_value.endswith('Z'):
                    dt = datetime.fromisoformat(timestamp_value.replace('Z', '+00:00'))
                else:
                    dt = datetime.fromisoformat(timestamp_value)
                return dt.isoformat()
            except ValueError:
                pass

        # Handle numeric timestamps (unix epoch)
        if isinstance(timestamp_value, (int, float)):
            try:
                dt = datetime.fromtimestamp(timestamp_value, tz=timezone.utc)
                return dt.isoformat()
            except (ValueError, OSError):
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
        Validate that event has required Snowflake fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # Login history
        if 'IS_SUCCESS' in event or 'LOGIN_EVENT_TYPE' in event:
            return True

        # Query history
        if 'QUERY_ID' in event:
            return True

        # Session events
        if 'SESSION_ID' in event:
            return True

        # Grant events
        if 'GRANTEE_NAME' in event and 'PRIVILEGE' in event:
            return True

        # Warehouse events
        if 'WAREHOUSE_NAME' in event and 'EVENT_TYPE' in event:
            return True

        # Copy history
        if 'FILE_NAME' in event and 'STAGE_LOCATION' in event:
            return True

        # Data transfer
        if 'SOURCE_CLOUD' in event or 'TARGET_CLOUD' in event:
            return True

        # Generic - check for any timestamp field
        timestamp_fields = ['EVENT_TIMESTAMP', 'START_TIME', 'END_TIME',
                           'CREATED_ON', 'TIMESTAMP', 'LAST_LOAD_TIME']
        if any(field in event for field in timestamp_fields):
            return True

        return False
