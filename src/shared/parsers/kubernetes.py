"""
Kubernetes Audit Log Parser with ECS Normalization

Normalizes Kubernetes audit log events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports Kubernetes API server audit logs including:
- API requests (kubectl commands, pod operations)
- Admission controller decisions
- RBAC authorization events
- Resource modifications
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseParser


class KubernetesParser(BaseParser):
    """Parser for Kubernetes audit logs with ECS normalization"""

    def __init__(self):
        super().__init__()
        self.source_type = "kubernetes"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Kubernetes audit log event and normalize to ECS.

        Args:
            raw_event: Raw Kubernetes audit event

        Returns:
            Normalized event in ECS format
        """
        # Extract core audit fields
        audit_id = raw_event.get('auditID', '')
        stage = raw_event.get('stage', '')
        request_uri = raw_event.get('requestURI', '')
        verb = raw_event.get('verb', '')
        level = raw_event.get('level', '')

        # Extract timestamp
        stage_timestamp = raw_event.get('stageTimestamp', '')
        request_received_timestamp = raw_event.get('requestReceivedTimestamp', '')
        timestamp = stage_timestamp or request_received_timestamp

        # Extract user information
        user = raw_event.get('user', {})
        username = user.get('username', '')
        user_id = user.get('uid', '')
        groups = user.get('groups', [])

        # Extract source IP
        source_ips = raw_event.get('sourceIPs', [])
        source_ip = source_ips[0] if source_ips else ''

        # Extract user agent
        user_agent = raw_event.get('userAgent', '')

        # Extract object information
        object_ref = raw_event.get('objectRef', {})
        resource = object_ref.get('resource', '')
        namespace = object_ref.get('namespace', '')
        name = object_ref.get('name', '')
        api_version = object_ref.get('apiVersion', '')
        api_group = object_ref.get('apiGroup', '')

        # Extract response status
        response_status = raw_event.get('responseStatus', {})
        status_code = response_status.get('code', 0)

        # Determine outcome
        ecs_outcome = self._determine_outcome(status_code)

        # Categorize event
        ecs_category = self._categorize_event(verb, resource)
        ecs_type = self._get_event_type(verb)

        # Build ECS-normalized event
        normalized = {
            # ECS Core Fields
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ecs_category,
                'type': ecs_type,
                'action': verb,
                'outcome': ecs_outcome,
                'created': self._parse_timestamp(request_received_timestamp),
                'id': audit_id,
                'provider': 'kubernetes',
                'module': 'audit'
            },

            # User fields
            'user': {
                'name': username,
                'id': user_id,
                'roles': groups
            },

            # Source fields
            'source': {
                'ip': source_ip
            },

            # User agent
            'user_agent': {
                'original': user_agent
            },

            # HTTP fields (Kubernetes API is HTTP-based)
            'http': {
                'request': {
                    'method': self._verb_to_http_method(verb)
                },
                'response': {
                    'status_code': status_code
                }
            },

            # URL fields
            'url': {
                'path': request_uri,
                'original': request_uri
            },

            # Related fields
            'related': {
                'ip': source_ips,
                'user': [username, user_id] if username or user_id else []
            },

            # Kubernetes-specific fields
            'kubernetes': {
                'audit_id': audit_id,
                'stage': stage,
                'level': level,
                'verb': verb,
                'request_uri': request_uri,
                'user': {
                    'username': username,
                    'uid': user_id,
                    'groups': groups,
                    'extra': user.get('extra', {})
                },
                'source_ips': source_ips,
                'user_agent': user_agent,
                'object_ref': {
                    'resource': resource,
                    'namespace': namespace,
                    'name': name,
                    'api_version': api_version,
                    'api_group': api_group,
                    'subresource': object_ref.get('subresource', ''),
                    'resource_version': object_ref.get('resourceVersion', '')
                },
                'response_status': {
                    'metadata': response_status.get('metadata', {}),
                    'status': response_status.get('status', ''),
                    'message': response_status.get('message', ''),
                    'reason': response_status.get('reason', ''),
                    'code': status_code
                },
                'request_object': raw_event.get('requestObject'),
                'response_object': raw_event.get('responseObject'),
                'request_received_timestamp': request_received_timestamp,
                'stage_timestamp': stage_timestamp,
                'annotations': raw_event.get('annotations', {})
            },

            # Preserve raw event
            '_raw': raw_event
        }

        # Clean None values
        return self._remove_none_values(normalized)

    def _determine_outcome(self, status_code: int) -> str:
        """Determine ECS outcome from HTTP status code"""
        if status_code == 0:
            return 'unknown'
        elif 200 <= status_code < 300:
            return 'success'
        elif 400 <= status_code < 500:
            return 'failure'
        elif 500 <= status_code < 600:
            return 'failure'
        else:
            return 'unknown'

    def _categorize_event(self, verb: str, resource: str) -> List[str]:
        """Categorize event based on verb and resource type"""
        categories = []

        # Configuration changes
        if verb in ['create', 'update', 'patch', 'delete']:
            categories.append('configuration')

        # Authentication/Authorization
        if resource in ['serviceaccounts', 'tokenreviews', 'selfsubjectaccessreviews', 'selfsubjectrulesreviews']:
            categories.append('authentication')

        # IAM operations
        if resource in ['roles', 'rolebindings', 'clusterroles', 'clusterrolebindings', 'serviceaccounts']:
            categories.append('iam')

        # Network operations
        if resource in ['services', 'ingresses', 'networkpolicies', 'endpoints']:
            categories.append('network')

        # Process/Container operations
        if resource in ['pods', 'deployments', 'replicasets', 'daemonsets', 'statefulsets', 'jobs', 'cronjobs']:
            categories.append('process')

        # File/Storage operations
        if resource in ['persistentvolumes', 'persistentvolumeclaims', 'configmaps', 'secrets']:
            categories.append('file')

        return categories if categories else ['web']

    def _get_event_type(self, verb: str) -> List[str]:
        """Determine ECS event.type based on Kubernetes verb"""
        types = []

        if verb == 'create':
            types.append('creation')
        elif verb in ['update', 'patch']:
            types.append('change')
        elif verb == 'delete':
            types.append('deletion')
        elif verb in ['get', 'list', 'watch']:
            types.append('access')
        else:
            types.append('info')

        return types

    def _verb_to_http_method(self, verb: str) -> str:
        """Map Kubernetes verb to HTTP method"""
        verb_mapping = {
            'get': 'GET',
            'list': 'GET',
            'watch': 'GET',
            'create': 'POST',
            'update': 'PUT',
            'patch': 'PATCH',
            'delete': 'DELETE',
            'deletecollection': 'DELETE',
            'proxy': 'GET'
        }
        return verb_mapping.get(verb, 'GET')

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate RFC 3339 timestamp"""
        if not timestamp_str:
            return datetime.utcnow().isoformat() + 'Z'

        # Kubernetes uses RFC 3339 format
        try:
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
        Validate that event has required Kubernetes audit fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        required_fields = ['auditID', 'stage', 'requestURI', 'verb', 'user']

        for field in required_fields:
            if field not in event:
                return False

        # Validate user structure
        if not isinstance(event.get('user'), dict):
            return False

        return True
