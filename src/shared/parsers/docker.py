"""
Docker Container Runtime Log Parser with ECS Normalization

Normalizes Docker and container runtime events to Elastic Common Schema (ECS) format
for unified detection and analysis across all log sources.

Supports Docker daemon events including:
- Container lifecycle events (create, start, stop, kill, die, destroy, pause, unpause)
- Image events (pull, push, tag, untag, delete)
- Volume events (create, mount, unmount, destroy)
- Network events (create, connect, disconnect, destroy)
- Plugin events
- Daemon events
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


class BaseParser:
    """Base parser class for ECS normalization"""

    def __init__(self):
        self.source_type = "generic"


class DockerParser(BaseParser):
    """Parser for Docker container runtime logs with ECS normalization"""

    # Docker action to ECS event.type mapping
    ACTION_TYPE_MAP = {
        # Container lifecycle
        'create': ['creation'],
        'start': ['start'],
        'stop': ['end'],
        'kill': ['end'],
        'die': ['end'],
        'destroy': ['deletion'],
        'pause': ['change'],
        'unpause': ['change'],
        'restart': ['change'],
        'rename': ['change'],
        'update': ['change'],
        'attach': ['connection'],
        'detach': ['end'],
        'exec_create': ['creation'],
        'exec_start': ['start'],
        'exec_die': ['end'],
        'exec_detach': ['end'],
        'oom': ['error'],
        'health_status': ['info'],
        'top': ['access'],
        'resize': ['change'],
        'export': ['access'],
        'commit': ['creation'],
        'copy': ['access'],
        # Image events
        'pull': ['access'],
        'push': ['access'],
        'tag': ['change'],
        'untag': ['change'],
        'delete': ['deletion'],
        'import': ['creation'],
        'save': ['access'],
        'load': ['creation'],
        'build': ['creation'],
        'prune': ['deletion'],
        # Volume events
        'mount': ['access'],
        'unmount': ['end'],
        # Network events
        'connect': ['connection'],
        'disconnect': ['end'],
    }

    # Docker event type to ECS category mapping
    TYPE_CATEGORY_MAP = {
        'container': ['process', 'host'],
        'image': ['package', 'file'],
        'volume': ['file'],
        'network': ['network'],
        'plugin': ['package'],
        'daemon': ['host'],
        'config': ['configuration'],
        'secret': ['authentication'],
        'node': ['host'],
        'service': ['process'],
    }

    def __init__(self):
        super().__init__()
        self.source_type = "docker"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Docker event and normalize to ECS.

        Args:
            raw_event: Raw Docker event (from docker events API or logs)

        Returns:
            Normalized event in ECS format
        """
        # Handle different Docker log formats
        if 'Type' in raw_event:
            # Docker events API format
            return self._parse_docker_event(raw_event)
        elif 'log' in raw_event:
            # Container stdout/stderr log format (from Fluent Bit, etc.)
            return self._parse_container_log(raw_event)
        elif 'type' in raw_event and raw_event.get('type') in self.TYPE_CATEGORY_MAP:
            # Lowercase format (also common)
            return self._parse_docker_event_lowercase(raw_event)
        else:
            return self._parse_generic_docker_event(raw_event)

    def _parse_docker_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Docker events API format (uppercase keys)"""
        event_type = raw_event.get('Type', '')
        action = raw_event.get('Action', '')
        actor = raw_event.get('Actor', {})
        actor_id = actor.get('ID', '')
        attributes = actor.get('Attributes', {})

        # Parse timestamp
        time_value = raw_event.get('time', 0)
        time_nano = raw_event.get('timeNano', 0)
        timestamp = self._parse_docker_timestamp(time_value, time_nano)

        # Extract container/image details
        container_name = attributes.get('name', '')
        image = attributes.get('image', '')
        container_id = actor_id if event_type == 'container' else ''
        image_id = actor_id if event_type == 'image' else attributes.get('imageID', '')

        # Get ECS categorization
        ecs_categories = self.TYPE_CATEGORY_MAP.get(event_type.lower(), ['host'])
        ecs_types = self.ACTION_TYPE_MAP.get(action.split(':')[0].lower(), ['info'])

        # Determine outcome
        ecs_outcome = self._determine_outcome(action, raw_event)

        # Extract exit code if present
        exit_code = None
        if 'exitCode' in attributes:
            try:
                exit_code = int(attributes['exitCode'])
            except (ValueError, TypeError):
                pass

        # Build ECS-normalized event
        normalized = {
            '@timestamp': timestamp,
            'ecs.version': '8.0.0',

            # Event fields
            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': ecs_types,
                'action': f'{event_type.lower()}_{action.lower()}',
                'outcome': ecs_outcome,
                'provider': 'docker',
                'module': event_type.lower()
            },

            # Container fields (ECS standard)
            'container': {
                'id': container_id,
                'name': container_name,
                'image': {
                    'name': image.split(':')[0] if image else '',
                    'tag': image.split(':')[1] if ':' in image else 'latest'
                },
                'runtime': 'docker'
            },

            # Host fields
            'host': {
                'hostname': raw_event.get('host', ''),
                'name': raw_event.get('host', '')
            },

            # Process fields (for container events)
            'process': {
                'exit_code': exit_code
            } if exit_code is not None else {},

            # Related fields
            'related': {
                'hosts': [h for h in [raw_event.get('host', ''), container_name] if h]
            },

            # Docker-specific fields
            'docker': {
                'type': event_type,
                'action': action,
                'actor': {
                    'id': actor_id,
                    'attributes': attributes
                },
                'scope': raw_event.get('scope', ''),
                'status': raw_event.get('status', action),
                'container': {
                    'id': container_id,
                    'name': container_name,
                    'image': image,
                    'labels': {k: v for k, v in attributes.items() if k not in ['name', 'image', 'imageID', 'exitCode']}
                } if event_type == 'container' else {},
                'image': {
                    'id': image_id,
                    'name': image
                } if event_type == 'image' else {},
                'volume': {
                    'name': container_name,
                    'driver': attributes.get('driver', '')
                } if event_type == 'volume' else {},
                'network': {
                    'name': container_name,
                    'type': attributes.get('type', ''),
                    'container': attributes.get('container', '')
                } if event_type == 'network' else {}
            },

            # Preserve raw event
            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_docker_event_lowercase(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Docker events with lowercase keys"""
        event_type = raw_event.get('type', '')
        action = raw_event.get('action', '')
        actor = raw_event.get('actor', {})
        actor_id = actor.get('id', '')
        attributes = actor.get('attributes', {})

        # Parse timestamp
        time_value = raw_event.get('time', 0)
        time_nano = raw_event.get('timenano', raw_event.get('timeNano', 0))
        timestamp = self._parse_docker_timestamp(time_value, time_nano)

        # Extract container/image details
        container_name = attributes.get('name', '')
        image = attributes.get('image', '')
        container_id = actor_id if event_type == 'container' else ''
        image_id = actor_id if event_type == 'image' else attributes.get('imageID', '')

        # Get ECS categorization
        ecs_categories = self.TYPE_CATEGORY_MAP.get(event_type, ['host'])
        ecs_types = self.ACTION_TYPE_MAP.get(action.split(':')[0], ['info'])

        # Determine outcome
        ecs_outcome = self._determine_outcome(action, raw_event)

        # Extract exit code if present
        exit_code = None
        if 'exitCode' in attributes:
            try:
                exit_code = int(attributes['exitCode'])
            except (ValueError, TypeError):
                pass

        normalized = {
            '@timestamp': timestamp,
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': ecs_types,
                'action': f'{event_type}_{action}',
                'outcome': ecs_outcome,
                'provider': 'docker',
                'module': event_type
            },

            'container': {
                'id': container_id,
                'name': container_name,
                'image': {
                    'name': image.split(':')[0] if image else '',
                    'tag': image.split(':')[1] if ':' in image else 'latest'
                },
                'runtime': 'docker'
            },

            'host': {
                'hostname': raw_event.get('host', ''),
                'name': raw_event.get('host', '')
            },

            'process': {
                'exit_code': exit_code
            } if exit_code is not None else {},

            'related': {
                'hosts': [h for h in [raw_event.get('host', ''), container_name] if h]
            },

            'docker': {
                'type': event_type,
                'action': action,
                'actor': {
                    'id': actor_id,
                    'attributes': attributes
                },
                'scope': raw_event.get('scope', ''),
                'status': raw_event.get('status', action),
                'container': {
                    'id': container_id,
                    'name': container_name,
                    'image': image
                } if event_type == 'container' else {},
                'image': {
                    'id': image_id,
                    'name': image
                } if event_type == 'image' else {}
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_container_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse container stdout/stderr log format (from logging drivers)"""
        # Common fields from logging drivers (Fluent Bit, Fluentd, etc.)
        log_message = raw_event.get('log', '')
        stream = raw_event.get('stream', 'stdout')
        time_str = raw_event.get('time', '')
        container_id = raw_event.get('container_id', '')
        container_name = raw_event.get('container_name', '').lstrip('/')
        source = raw_event.get('source', stream)

        # Kubernetes enrichment if present
        k8s_namespace = raw_event.get('kubernetes', {}).get('namespace_name', '')
        k8s_pod = raw_event.get('kubernetes', {}).get('pod_name', '')
        k8s_container = raw_event.get('kubernetes', {}).get('container_name', '')

        # Parse timestamp
        timestamp = self._parse_log_timestamp(time_str)

        # Detect log level from message
        log_level = self._detect_log_level(log_message)

        normalized = {
            '@timestamp': timestamp,
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['process'],
                'type': ['info'],
                'action': 'container_log',
                'outcome': 'success',
                'provider': 'docker',
                'module': 'container_logs'
            },

            'message': log_message.strip(),

            'log': {
                'level': log_level,
                'logger': source
            },

            'container': {
                'id': container_id,
                'name': container_name,
                'runtime': 'docker'
            },

            'host': {
                'hostname': raw_event.get('host', '')
            },

            'related': {
                'hosts': [h for h in [container_name, k8s_pod] if h]
            },

            'docker': {
                'container': {
                    'id': container_id,
                    'name': container_name,
                    'stream': stream
                },
                'log': {
                    'stream': stream,
                    'source': source
                }
            },

            '_raw': raw_event
        }

        # Add Kubernetes context if present
        if k8s_namespace or k8s_pod:
            normalized['kubernetes'] = {
                'namespace': k8s_namespace,
                'pod': {
                    'name': k8s_pod
                },
                'container': {
                    'name': k8s_container
                }
            }

        return self._remove_none_values(normalized)

    def _parse_generic_docker_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic Docker event format"""
        timestamp = raw_event.get('time', raw_event.get('timestamp', 0))
        if isinstance(timestamp, (int, float)):
            timestamp = self._parse_docker_timestamp(timestamp, 0)
        else:
            timestamp = self._parse_log_timestamp(str(timestamp))

        normalized = {
            '@timestamp': timestamp,
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['host'],
                'type': ['info'],
                'action': 'docker_event',
                'outcome': 'unknown',
                'provider': 'docker',
                'module': 'generic'
            },

            'docker': raw_event,

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_docker_timestamp(self, time_value: int, time_nano: int) -> str:
        """Parse Docker timestamp (seconds + nanoseconds) to ISO 8601"""
        if time_nano:
            # Convert nanoseconds to datetime
            seconds = time_nano // 1_000_000_000
            microseconds = (time_nano % 1_000_000_000) // 1000
            try:
                dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
                dt = dt.replace(microsecond=microseconds)
                return dt.isoformat()
            except (ValueError, OSError):
                pass

        if time_value:
            try:
                dt = datetime.fromtimestamp(time_value, tz=timezone.utc)
                return dt.isoformat()
            except (ValueError, OSError):
                pass

        return datetime.now(timezone.utc).isoformat()

    def _parse_log_timestamp(self, time_str: str) -> str:
        """Parse log timestamp string to ISO 8601"""
        if not time_str:
            return datetime.now(timezone.utc).isoformat()

        # Docker container log format: RFC3339Nano
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(time_str[:26], fmt[:len(time_str)])
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

        # Try ISO format parsing
        try:
            if time_str.endswith('Z'):
                dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(time_str)
            return dt.isoformat()
        except ValueError:
            pass

        return datetime.now(timezone.utc).isoformat()

    def _determine_outcome(self, action: str, raw_event: Dict[str, Any]) -> str:
        """Determine ECS outcome based on action and event context"""
        action_lower = action.lower()

        # Failed/error outcomes
        if 'error' in action_lower or 'fail' in action_lower:
            return 'failure'
        if action_lower in ['die', 'kill', 'oom']:
            # Check exit code
            attributes = raw_event.get('Actor', raw_event.get('actor', {})).get('Attributes', raw_event.get('actor', {}).get('attributes', {}))
            exit_code = attributes.get('exitCode', '0')
            try:
                if int(exit_code) != 0:
                    return 'failure'
            except (ValueError, TypeError):
                pass

        # Success outcomes
        if action_lower in ['start', 'create', 'pull', 'push', 'connect', 'mount', 'exec_start']:
            return 'success'

        # Neutral outcomes
        if action_lower in ['stop', 'destroy', 'delete', 'unmount', 'disconnect', 'detach']:
            return 'success'

        return 'unknown'

    def _detect_log_level(self, message: str) -> str:
        """Detect log level from message content"""
        message_upper = message.upper()

        if any(x in message_upper for x in ['FATAL', 'CRIT', 'CRITICAL', 'EMERG']):
            return 'critical'
        if any(x in message_upper for x in ['ERROR', 'ERR', 'SEVERE']):
            return 'error'
        if any(x in message_upper for x in ['WARN', 'WARNING']):
            return 'warning'
        if any(x in message_upper for x in ['INFO', 'NOTICE']):
            return 'info'
        if any(x in message_upper for x in ['DEBUG', 'TRACE', 'VERBOSE']):
            return 'debug'

        return 'info'

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
        Validate that event has required Docker fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # Docker events API format
        if 'Type' in event and 'Action' in event:
            return True

        # Lowercase format
        if 'type' in event and 'action' in event:
            return True

        # Container log format
        if 'log' in event:
            return True

        # Generic format with time
        if 'time' in event or 'timestamp' in event:
            return True

        return False
