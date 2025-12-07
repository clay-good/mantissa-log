"""Unit tests for Docker parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.docker import DockerParser


class TestDockerParser:
    """Tests for DockerParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return DockerParser()

    @pytest.fixture
    def sample_container_start_event(self):
        """Sample Docker container start event."""
        return {
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": "abc123def456",
                "Attributes": {
                    "name": "my-app",
                    "image": "nginx:latest",
                    "maintainer": "NGINX Docker Maintainers"
                }
            },
            "scope": "local",
            "time": 1706500000,
            "timeNano": 1706500000123456789,
            "status": "start",
            "id": "abc123def456",
            "from": "nginx:latest"
        }

    @pytest.fixture
    def sample_container_die_event(self):
        """Sample Docker container die event with exit code."""
        return {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": "abc123def456",
                "Attributes": {
                    "name": "my-app",
                    "image": "nginx:latest",
                    "exitCode": "137"
                }
            },
            "scope": "local",
            "time": 1706500100,
            "timeNano": 1706500100000000000
        }

    @pytest.fixture
    def sample_container_create_event(self):
        """Sample Docker container create event."""
        return {
            "Type": "container",
            "Action": "create",
            "Actor": {
                "ID": "abc123def456",
                "Attributes": {
                    "name": "my-new-container",
                    "image": "alpine:3.18"
                }
            },
            "scope": "local",
            "time": 1706500000,
            "timeNano": 1706500000000000000
        }

    @pytest.fixture
    def sample_image_pull_event(self):
        """Sample Docker image pull event."""
        return {
            "Type": "image",
            "Action": "pull",
            "Actor": {
                "ID": "sha256:abc123def456",
                "Attributes": {
                    "name": "nginx:latest"
                }
            },
            "scope": "local",
            "time": 1706500000,
            "timeNano": 1706500000000000000
        }

    @pytest.fixture
    def sample_volume_mount_event(self):
        """Sample Docker volume mount event."""
        return {
            "Type": "volume",
            "Action": "mount",
            "Actor": {
                "ID": "my-volume",
                "Attributes": {
                    "driver": "local",
                    "container": "abc123def456"
                }
            },
            "scope": "local",
            "time": 1706500000,
            "timeNano": 1706500000000000000
        }

    @pytest.fixture
    def sample_network_connect_event(self):
        """Sample Docker network connect event."""
        return {
            "Type": "network",
            "Action": "connect",
            "Actor": {
                "ID": "net123",
                "Attributes": {
                    "name": "my-network",
                    "type": "bridge",
                    "container": "abc123def456"
                }
            },
            "scope": "local",
            "time": 1706500000,
            "timeNano": 1706500000000000000
        }

    @pytest.fixture
    def sample_container_log(self):
        """Sample container stdout log."""
        return {
            "log": "2024-01-28 12:00:00 INFO Starting application...\n",
            "stream": "stdout",
            "time": "2024-01-28T12:00:00.123456789Z",
            "container_id": "abc123def456",
            "container_name": "/my-app"
        }

    @pytest.fixture
    def sample_container_log_with_k8s(self):
        """Sample container log with Kubernetes context."""
        return {
            "log": "ERROR: Connection refused",
            "stream": "stderr",
            "time": "2024-01-28T12:00:00Z",
            "container_id": "abc123def456",
            "container_name": "/k8s_myapp_myapp-pod_default",
            "kubernetes": {
                "namespace_name": "default",
                "pod_name": "myapp-pod-abc123",
                "container_name": "myapp"
            }
        }

    @pytest.fixture
    def sample_lowercase_event(self):
        """Sample Docker event with lowercase keys."""
        return {
            "type": "container",
            "action": "stop",
            "actor": {
                "id": "abc123def456",
                "attributes": {
                    "name": "my-app",
                    "image": "nginx:latest"
                }
            },
            "scope": "local",
            "time": 1706500000,
            "timenano": 1706500000000000000
        }

    def test_parser_source_type(self, parser):
        """Test parser returns correct source type."""
        assert parser.source_type == "docker"

    def test_validate_docker_event_uppercase(self, parser, sample_container_start_event):
        """Test validation of Docker event with uppercase keys."""
        assert parser.validate(sample_container_start_event) is True

    def test_validate_docker_event_lowercase(self, parser, sample_lowercase_event):
        """Test validation of Docker event with lowercase keys."""
        assert parser.validate(sample_lowercase_event) is True

    def test_validate_container_log(self, parser, sample_container_log):
        """Test validation of container log."""
        assert parser.validate(sample_container_log) is True

    def test_validate_with_time_only(self, parser):
        """Test validation of event with time only."""
        assert parser.validate({"time": 1706500000}) is True

    def test_validate_invalid_event(self, parser):
        """Test validation of invalid event."""
        assert parser.validate({}) is False


class TestDockerParserContainerEvents:
    """Tests for container event parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    @pytest.fixture
    def start_event(self):
        return {
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": "abc123def456",
                "Attributes": {
                    "name": "my-app",
                    "image": "nginx:latest"
                }
            },
            "time": 1706500000,
            "timeNano": 1706500000123456789,
            "host": "docker-host-1"
        }

    def test_parse_container_start_basic_fields(self, parser, start_event):
        """Test parsing container start event extracts basic fields."""
        result = parser.parse(start_event)

        assert result['event']['action'] == 'container_start'
        assert result['event']['outcome'] == 'success'
        assert result['event']['provider'] == 'docker'
        assert 'process' in result['event']['category']

    def test_parse_container_start_container_fields(self, parser, start_event):
        """Test parsing container start extracts container fields."""
        result = parser.parse(start_event)

        assert result['container']['id'] == 'abc123def456'
        assert result['container']['name'] == 'my-app'
        assert result['container']['image']['name'] == 'nginx'
        assert result['container']['image']['tag'] == 'latest'
        assert result['container']['runtime'] == 'docker'

    def test_parse_container_start_host_fields(self, parser, start_event):
        """Test parsing container start extracts host fields."""
        result = parser.parse(start_event)

        assert result['host']['hostname'] == 'docker-host-1'

    def test_parse_container_start_docker_fields(self, parser, start_event):
        """Test parsing container start extracts docker-specific fields."""
        result = parser.parse(start_event)

        assert result['docker']['type'] == 'container'
        assert result['docker']['action'] == 'start'
        assert result['docker']['actor']['id'] == 'abc123def456'

    def test_parse_container_die_with_exit_code(self, parser):
        """Test parsing container die event with exit code."""
        event = {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": "abc123",
                "Attributes": {
                    "name": "my-app",
                    "image": "nginx:latest",
                    "exitCode": "1"
                }
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'container_die'
        assert result['event']['outcome'] == 'failure'
        assert result['process']['exit_code'] == 1

    def test_parse_container_die_exit_code_zero(self, parser):
        """Test container die with exit code 0 is success."""
        event = {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": "abc123",
                "Attributes": {
                    "name": "my-app",
                    "exitCode": "0"
                }
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['outcome'] != 'failure'

    def test_parse_container_oom(self, parser):
        """Test parsing OOM event."""
        event = {
            "Type": "container",
            "Action": "oom",
            "Actor": {
                "ID": "abc123",
                "Attributes": {"name": "memory-hog"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'container_oom'
        assert 'error' in result['event']['type']


class TestDockerParserImageEvents:
    """Tests for image event parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_image_pull(self, parser):
        """Test parsing image pull event."""
        event = {
            "Type": "image",
            "Action": "pull",
            "Actor": {
                "ID": "sha256:abc123",
                "Attributes": {"name": "nginx:latest"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'image_pull'
        assert 'package' in result['event']['category']
        assert 'access' in result['event']['type']

    def test_parse_image_delete(self, parser):
        """Test parsing image delete event."""
        event = {
            "Type": "image",
            "Action": "delete",
            "Actor": {
                "ID": "sha256:abc123",
                "Attributes": {"name": "old-image:v1"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'image_delete'
        assert 'deletion' in result['event']['type']

    def test_parse_image_build(self, parser):
        """Test parsing image build event."""
        event = {
            "Type": "image",
            "Action": "build",
            "Actor": {
                "ID": "sha256:newimage123",
                "Attributes": {"name": "my-app:v2"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'image_build'
        assert 'creation' in result['event']['type']


class TestDockerParserVolumeEvents:
    """Tests for volume event parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_volume_create(self, parser):
        """Test parsing volume create event."""
        event = {
            "Type": "volume",
            "Action": "create",
            "Actor": {
                "ID": "my-volume",
                "Attributes": {"driver": "local"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'volume_create'
        assert 'file' in result['event']['category']
        assert 'creation' in result['event']['type']

    def test_parse_volume_mount(self, parser):
        """Test parsing volume mount event."""
        event = {
            "Type": "volume",
            "Action": "mount",
            "Actor": {
                "ID": "data-volume",
                "Attributes": {"container": "abc123", "driver": "local"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'volume_mount'
        assert 'access' in result['event']['type']
        assert result['docker']['volume']['driver'] == 'local'


class TestDockerParserNetworkEvents:
    """Tests for network event parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_network_connect(self, parser):
        """Test parsing network connect event."""
        event = {
            "Type": "network",
            "Action": "connect",
            "Actor": {
                "ID": "net123",
                "Attributes": {
                    "name": "my-network",
                    "type": "bridge",
                    "container": "abc123"
                }
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'network_connect'
        assert 'network' in result['event']['category']
        assert 'connection' in result['event']['type']

    def test_parse_network_disconnect(self, parser):
        """Test parsing network disconnect event."""
        event = {
            "Type": "network",
            "Action": "disconnect",
            "Actor": {
                "ID": "net123",
                "Attributes": {"name": "my-network", "container": "abc123"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'network_disconnect'
        assert 'end' in result['event']['type']


class TestDockerParserContainerLogs:
    """Tests for container log parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_container_log_stdout(self, parser):
        """Test parsing container stdout log."""
        log_event = {
            "log": "INFO Starting application...\n",
            "stream": "stdout",
            "time": "2024-01-28T12:00:00.123456789Z",
            "container_id": "abc123",
            "container_name": "/my-app"
        }
        result = parser.parse(log_event)

        assert result['event']['action'] == 'container_log'
        assert result['message'] == 'INFO Starting application...'
        assert result['docker']['container']['stream'] == 'stdout'
        assert result['container']['name'] == 'my-app'

    def test_parse_container_log_stderr(self, parser):
        """Test parsing container stderr log."""
        log_event = {
            "log": "ERROR Connection failed",
            "stream": "stderr",
            "time": "2024-01-28T12:00:00Z",
            "container_id": "abc123",
            "container_name": "/my-app"
        }
        result = parser.parse(log_event)

        assert result['log']['level'] == 'error'
        assert result['docker']['log']['stream'] == 'stderr'

    def test_parse_container_log_with_kubernetes(self, parser):
        """Test parsing container log with Kubernetes context."""
        log_event = {
            "log": "Starting pod",
            "stream": "stdout",
            "time": "2024-01-28T12:00:00Z",
            "container_id": "abc123",
            "container_name": "/k8s_myapp_myapp-pod",
            "kubernetes": {
                "namespace_name": "production",
                "pod_name": "myapp-pod-abc123",
                "container_name": "myapp"
            }
        }
        result = parser.parse(log_event)

        assert 'kubernetes' in result
        assert result['kubernetes']['namespace'] == 'production'
        assert result['kubernetes']['pod']['name'] == 'myapp-pod-abc123'


class TestDockerParserLogLevelDetection:
    """Tests for log level detection."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_detect_critical_level(self, parser):
        """Test detecting critical log level."""
        assert parser._detect_log_level("FATAL: System failure") == 'critical'
        assert parser._detect_log_level("CRITICAL error occurred") == 'critical'

    def test_detect_error_level(self, parser):
        """Test detecting error log level."""
        assert parser._detect_log_level("ERROR: Connection failed") == 'error'
        assert parser._detect_log_level("[ERR] Something broke") == 'error'

    def test_detect_warning_level(self, parser):
        """Test detecting warning log level."""
        assert parser._detect_log_level("WARNING: Low memory") == 'warning'
        assert parser._detect_log_level("WARN deprecated API") == 'warning'

    def test_detect_info_level(self, parser):
        """Test detecting info log level."""
        assert parser._detect_log_level("INFO: Server started") == 'info'

    def test_detect_debug_level(self, parser):
        """Test detecting debug log level."""
        assert parser._detect_log_level("DEBUG: Variable x = 5") == 'debug'
        assert parser._detect_log_level("TRACE: Entering function") == 'debug'

    def test_default_to_info(self, parser):
        """Test defaulting to info level."""
        assert parser._detect_log_level("Just a plain message") == 'info'


class TestDockerParserLowercaseEvents:
    """Tests for lowercase event format parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_lowercase_container_event(self, parser):
        """Test parsing container event with lowercase keys."""
        event = {
            "type": "container",
            "action": "start",
            "actor": {
                "id": "abc123",
                "attributes": {"name": "my-app", "image": "nginx:latest"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'container_start'
        assert result['container']['id'] == 'abc123'

    def test_parse_lowercase_image_event(self, parser):
        """Test parsing image event with lowercase keys."""
        event = {
            "type": "image",
            "action": "pull",
            "actor": {
                "id": "sha256:abc123",
                "attributes": {"name": "nginx:latest"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'image_pull'


class TestDockerParserTimestamp:
    """Tests for timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_timestamp_from_nano(self, parser):
        """Test parsing timestamp from nanoseconds."""
        timestamp = parser._parse_docker_timestamp(0, 1706500000123456789)
        assert '2024-01-29' in timestamp

    def test_parse_timestamp_from_seconds(self, parser):
        """Test parsing timestamp from seconds."""
        timestamp = parser._parse_docker_timestamp(1706500000, 0)
        assert '2024-01-29' in timestamp

    def test_parse_log_timestamp_rfc3339(self, parser):
        """Test parsing RFC3339 log timestamp."""
        timestamp = parser._parse_log_timestamp("2024-01-28T12:00:00.123456789Z")
        assert '2024-01-28' in timestamp

    def test_parse_log_timestamp_without_nano(self, parser):
        """Test parsing log timestamp without nanoseconds."""
        timestamp = parser._parse_log_timestamp("2024-01-28T12:00:00Z")
        assert '2024-01-28' in timestamp

    def test_parse_log_timestamp_fallback(self, parser):
        """Test parsing invalid timestamp falls back to now."""
        timestamp = parser._parse_log_timestamp("invalid")
        assert timestamp is not None  # Should return current time


class TestDockerParserEventCategories:
    """Tests for event category mapping."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_container_category_includes_process(self, parser):
        """Test container events include process category."""
        assert 'process' in parser.TYPE_CATEGORY_MAP['container']

    def test_image_category_includes_package(self, parser):
        """Test image events include package category."""
        assert 'package' in parser.TYPE_CATEGORY_MAP['image']

    def test_volume_category_includes_file(self, parser):
        """Test volume events include file category."""
        assert 'file' in parser.TYPE_CATEGORY_MAP['volume']

    def test_network_category_includes_network(self, parser):
        """Test network events include network category."""
        assert 'network' in parser.TYPE_CATEGORY_MAP['network']

    def test_daemon_category_includes_host(self, parser):
        """Test daemon events include host category."""
        assert 'host' in parser.TYPE_CATEGORY_MAP['daemon']


class TestDockerParserActionTypes:
    """Tests for action type mapping."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_create_action_is_creation(self, parser):
        """Test create action maps to creation type."""
        assert parser.ACTION_TYPE_MAP['create'] == ['creation']

    def test_start_action_is_start(self, parser):
        """Test start action maps to start type."""
        assert parser.ACTION_TYPE_MAP['start'] == ['start']

    def test_stop_action_is_end(self, parser):
        """Test stop action maps to end type."""
        assert parser.ACTION_TYPE_MAP['stop'] == ['end']

    def test_kill_action_is_end(self, parser):
        """Test kill action maps to end type."""
        assert parser.ACTION_TYPE_MAP['kill'] == ['end']

    def test_delete_action_is_deletion(self, parser):
        """Test delete action maps to deletion type."""
        assert parser.ACTION_TYPE_MAP['delete'] == ['deletion']

    def test_connect_action_is_connection(self, parser):
        """Test connect action maps to connection type."""
        assert parser.ACTION_TYPE_MAP['connect'] == ['connection']


class TestDockerParserOutcomeDetection:
    """Tests for outcome detection."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_start_action_success(self, parser):
        """Test start action is success."""
        outcome = parser._determine_outcome('start', {})
        assert outcome == 'success'

    def test_create_action_success(self, parser):
        """Test create action is success."""
        outcome = parser._determine_outcome('create', {})
        assert outcome == 'success'

    def test_error_action_failure(self, parser):
        """Test error action is failure."""
        outcome = parser._determine_outcome('error', {})
        assert outcome == 'failure'

    def test_die_with_nonzero_exit_failure(self, parser):
        """Test die with non-zero exit code is failure."""
        event = {"Actor": {"Attributes": {"exitCode": "1"}}}
        outcome = parser._determine_outcome('die', event)
        assert outcome == 'failure'

    def test_die_with_zero_exit_not_failure(self, parser):
        """Test die with zero exit code is not failure."""
        event = {"Actor": {"Attributes": {"exitCode": "0"}}}
        outcome = parser._determine_outcome('die', event)
        # Zero exit doesn't mark as failure
        assert outcome != 'failure' or outcome == 'success'


class TestDockerParserEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def parser(self):
        return DockerParser()

    def test_parse_event_without_actor(self, parser):
        """Test parsing event without Actor field."""
        event = {
            "Type": "daemon",
            "Action": "reload",
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'daemon_reload'

    def test_parse_image_without_tag(self, parser):
        """Test parsing image without explicit tag."""
        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": "abc123",
                "Attributes": {"name": "my-app", "image": "nginx"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert result['container']['image']['name'] == 'nginx'
        assert result['container']['image']['tag'] == 'latest'

    def test_parse_action_with_subaction(self, parser):
        """Test parsing action with sub-action (e.g., health_status:healthy)."""
        event = {
            "Type": "container",
            "Action": "health_status:healthy",
            "Actor": {
                "ID": "abc123",
                "Attributes": {"name": "my-app"}
            },
            "time": 1706500000
        }
        result = parser.parse(event)

        assert 'health_status' in result['event']['action']

    def test_parse_generic_event(self, parser):
        """Test parsing generic event format."""
        event = {
            "time": 1706500000,
            "custom_field": "value"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'docker_event'
        assert result['event']['outcome'] == 'unknown'

    def test_remove_none_values(self, parser):
        """Test None values are removed from result."""
        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {"ID": "abc123", "Attributes": {}},
            "time": 1706500000
        }
        result = parser.parse(event)

        # Verify no None values in flattened result
        def check_no_none(obj):
            if isinstance(obj, dict):
                for v in obj.values():
                    assert v is not None
                    check_no_none(v)
            elif isinstance(obj, list):
                for item in obj:
                    assert item is not None
                    check_no_none(item)

        check_no_none(result)

    def test_preserves_raw_event(self, parser):
        """Test raw event is preserved."""
        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {"ID": "abc123", "Attributes": {"name": "test"}},
            "time": 1706500000,
            "custom_field": "preserved"
        }
        result = parser.parse(event)

        assert '_raw' in result
        assert result['_raw']['custom_field'] == 'preserved'
