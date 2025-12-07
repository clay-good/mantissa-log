"""Unit tests for Kubernetes audit log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.kubernetes import KubernetesParser


class TestKubernetesParser:
    """Tests for KubernetesParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return KubernetesParser()

    @pytest.fixture
    def sample_audit_event(self):
        """Sample Kubernetes audit log event."""
        return {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "RequestResponse",
            "auditID": "abc123-def456-789xyz",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/namespaces/default/pods",
            "verb": "create",
            "user": {
                "username": "system:serviceaccount:kube-system:deployment-controller",
                "uid": "sa-uid-12345",
                "groups": [
                    "system:serviceaccounts",
                    "system:serviceaccounts:kube-system",
                    "system:authenticated"
                ],
                "extra": {
                    "authentication.kubernetes.io/pod-name": ["controller-pod-abc"]
                }
            },
            "sourceIPs": ["10.0.0.10", "192.168.1.100"],
            "userAgent": "kube-controller-manager/v1.28.0",
            "objectRef": {
                "resource": "pods",
                "namespace": "default",
                "name": "my-app-pod-abc123",
                "apiVersion": "v1",
                "apiGroup": "",
                "subresource": "",
                "resourceVersion": "12345"
            },
            "responseStatus": {
                "metadata": {},
                "code": 201,
                "status": "Success",
                "message": "Pod created successfully",
                "reason": "Created"
            },
            "requestReceivedTimestamp": "2024-01-29T10:30:00.000000Z",
            "stageTimestamp": "2024-01-29T10:30:00.500000Z",
            "annotations": {
                "authorization.k8s.io/decision": "allow",
                "authorization.k8s.io/reason": "RBAC: allowed"
            }
        }

    @pytest.fixture
    def sample_get_event(self):
        """Sample Kubernetes GET audit event."""
        return {
            "auditID": "get-event-123",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/namespaces/default/pods/my-pod",
            "verb": "get",
            "user": {
                "username": "admin",
                "uid": "admin-uid",
                "groups": ["system:masters"]
            },
            "sourceIPs": ["203.0.113.50"],
            "userAgent": "kubectl/v1.28.0",
            "objectRef": {
                "resource": "pods",
                "namespace": "default",
                "name": "my-pod"
            },
            "responseStatus": {
                "code": 200
            },
            "requestReceivedTimestamp": "2024-01-29T10:30:00.000000Z",
            "stageTimestamp": "2024-01-29T10:30:00.100000Z"
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "kubernetes"

    def test_parse_event_basic_fields(self, parser, sample_audit_event):
        """Test parsing audit event extracts basic fields."""
        result = parser.parse(sample_audit_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "kubernetes"
        assert result["event"]["module"] == "audit"

    def test_parse_event_user_fields(self, parser, sample_audit_event):
        """Test parsing extracts user fields."""
        result = parser.parse(sample_audit_event)

        assert result["user"]["name"] == "system:serviceaccount:kube-system:deployment-controller"
        assert result["user"]["id"] == "sa-uid-12345"
        assert "system:authenticated" in result["user"]["roles"]

    def test_parse_event_source_fields(self, parser, sample_audit_event):
        """Test parsing extracts source IP."""
        result = parser.parse(sample_audit_event)

        assert result["source"]["ip"] == "10.0.0.10"

    def test_parse_event_http_fields(self, parser, sample_audit_event):
        """Test parsing extracts HTTP fields."""
        result = parser.parse(sample_audit_event)

        assert result["http"]["request"]["method"] == "POST"  # create -> POST
        assert result["http"]["response"]["status_code"] == 201

    def test_parse_event_url_fields(self, parser, sample_audit_event):
        """Test parsing extracts URL fields."""
        result = parser.parse(sample_audit_event)

        assert result["url"]["path"] == "/api/v1/namespaces/default/pods"

    def test_parse_event_action(self, parser, sample_audit_event):
        """Test parsing extracts action."""
        result = parser.parse(sample_audit_event)

        assert result["event"]["action"] == "create"

    def test_parse_event_outcome_success(self, parser, sample_audit_event):
        """Test parsing successful event sets correct outcome."""
        result = parser.parse(sample_audit_event)

        assert result["event"]["outcome"] == "success"

    def test_parse_event_outcome_failure(self, parser, sample_audit_event):
        """Test parsing failed event sets correct outcome."""
        sample_audit_event["responseStatus"]["code"] = 403
        result = parser.parse(sample_audit_event)

        assert result["event"]["outcome"] == "failure"

    def test_parse_event_kubernetes_fields(self, parser, sample_audit_event):
        """Test parsing extracts Kubernetes-specific fields."""
        result = parser.parse(sample_audit_event)

        assert result["kubernetes"]["audit_id"] == "abc123-def456-789xyz"
        assert result["kubernetes"]["stage"] == "ResponseComplete"
        assert result["kubernetes"]["level"] == "RequestResponse"
        assert result["kubernetes"]["verb"] == "create"
        assert result["kubernetes"]["object_ref"]["resource"] == "pods"
        assert result["kubernetes"]["object_ref"]["namespace"] == "default"
        assert result["kubernetes"]["object_ref"]["name"] == "my-app-pod-abc123"

    def test_parse_event_related_fields(self, parser, sample_audit_event):
        """Test parsing extracts related fields."""
        result = parser.parse(sample_audit_event)

        assert "10.0.0.10" in result["related"]["ip"]
        assert "192.168.1.100" in result["related"]["ip"]

    def test_validate_valid_event(self, parser, sample_audit_event):
        """Test validation of valid event."""
        assert parser.validate(sample_audit_event) is True

    def test_validate_missing_audit_id(self, parser):
        """Test validation fails without auditID."""
        event = {
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/pods",
            "verb": "get",
            "user": {"username": "test"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_user(self, parser):
        """Test validation fails without user."""
        event = {
            "auditID": "test",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/pods",
            "verb": "get"
        }
        assert parser.validate(event) is False

    def test_validate_invalid_user_type(self, parser):
        """Test validation fails with non-dict user."""
        event = {
            "auditID": "test",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/pods",
            "verb": "get",
            "user": "invalid"
        }
        assert parser.validate(event) is False

    def test_parse_preserves_raw_event(self, parser, sample_audit_event):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_audit_event)

        assert "_raw" in result
        assert result["_raw"] == sample_audit_event


class TestKubernetesParserVerbMapping:
    """Test HTTP method mapping from Kubernetes verbs."""

    @pytest.fixture
    def parser(self):
        return KubernetesParser()

    def test_get_verb_maps_to_get(self, parser):
        """Test get verb maps to GET."""
        assert parser._verb_to_http_method("get") == "GET"

    def test_list_verb_maps_to_get(self, parser):
        """Test list verb maps to GET."""
        assert parser._verb_to_http_method("list") == "GET"

    def test_watch_verb_maps_to_get(self, parser):
        """Test watch verb maps to GET."""
        assert parser._verb_to_http_method("watch") == "GET"

    def test_create_verb_maps_to_post(self, parser):
        """Test create verb maps to POST."""
        assert parser._verb_to_http_method("create") == "POST"

    def test_update_verb_maps_to_put(self, parser):
        """Test update verb maps to PUT."""
        assert parser._verb_to_http_method("update") == "PUT"

    def test_patch_verb_maps_to_patch(self, parser):
        """Test patch verb maps to PATCH."""
        assert parser._verb_to_http_method("patch") == "PATCH"

    def test_delete_verb_maps_to_delete(self, parser):
        """Test delete verb maps to DELETE."""
        assert parser._verb_to_http_method("delete") == "DELETE"

    def test_unknown_verb_defaults_to_get(self, parser):
        """Test unknown verb defaults to GET."""
        assert parser._verb_to_http_method("unknown") == "GET"


class TestKubernetesParserEventCategorization:
    """Test event categorization based on verb and resource."""

    @pytest.fixture
    def parser(self):
        return KubernetesParser()

    def test_create_categorized_as_configuration(self, parser):
        """Test create verb categorized as configuration."""
        categories = parser._categorize_event("create", "pods")
        assert "configuration" in categories

    def test_delete_categorized_as_configuration(self, parser):
        """Test delete verb categorized as configuration."""
        categories = parser._categorize_event("delete", "deployments")
        assert "configuration" in categories

    def test_rbac_resources_categorized_as_iam(self, parser):
        """Test RBAC resources categorized as IAM."""
        for resource in ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]:
            categories = parser._categorize_event("create", resource)
            assert "iam" in categories

    def test_network_resources_categorized_as_network(self, parser):
        """Test network resources categorized as network."""
        for resource in ["services", "ingresses", "networkpolicies"]:
            categories = parser._categorize_event("create", resource)
            assert "network" in categories

    def test_pod_resources_categorized_as_process(self, parser):
        """Test pod resources categorized as process."""
        for resource in ["pods", "deployments", "replicasets"]:
            categories = parser._categorize_event("create", resource)
            assert "process" in categories

    def test_storage_resources_categorized_as_file(self, parser):
        """Test storage resources categorized as file."""
        for resource in ["persistentvolumes", "configmaps", "secrets"]:
            categories = parser._categorize_event("create", resource)
            assert "file" in categories


class TestKubernetesParserEventTypes:
    """Test ECS event type determination."""

    @pytest.fixture
    def parser(self):
        return KubernetesParser()

    def test_create_verb_type(self, parser):
        """Test create verb gets creation type."""
        types = parser._get_event_type("create")
        assert "creation" in types

    def test_update_verb_type(self, parser):
        """Test update verb gets change type."""
        types = parser._get_event_type("update")
        assert "change" in types

    def test_patch_verb_type(self, parser):
        """Test patch verb gets change type."""
        types = parser._get_event_type("patch")
        assert "change" in types

    def test_delete_verb_type(self, parser):
        """Test delete verb gets deletion type."""
        types = parser._get_event_type("delete")
        assert "deletion" in types

    def test_get_verb_type(self, parser):
        """Test get verb gets access type."""
        types = parser._get_event_type("get")
        assert "access" in types

    def test_list_verb_type(self, parser):
        """Test list verb gets access type."""
        types = parser._get_event_type("list")
        assert "access" in types


class TestKubernetesParserOutcome:
    """Test outcome determination from status codes."""

    @pytest.fixture
    def parser(self):
        return KubernetesParser()

    def test_200_is_success(self, parser):
        """Test 200 status code is success."""
        assert parser._determine_outcome(200) == "success"

    def test_201_is_success(self, parser):
        """Test 201 status code is success."""
        assert parser._determine_outcome(201) == "success"

    def test_400_is_failure(self, parser):
        """Test 400 status code is failure."""
        assert parser._determine_outcome(400) == "failure"

    def test_403_is_failure(self, parser):
        """Test 403 status code is failure."""
        assert parser._determine_outcome(403) == "failure"

    def test_404_is_failure(self, parser):
        """Test 404 status code is failure."""
        assert parser._determine_outcome(404) == "failure"

    def test_500_is_failure(self, parser):
        """Test 500 status code is failure."""
        assert parser._determine_outcome(500) == "failure"

    def test_0_is_unknown(self, parser):
        """Test 0 status code is unknown."""
        assert parser._determine_outcome(0) == "unknown"


class TestKubernetesParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return KubernetesParser()

    def test_parse_rfc3339_with_z(self, parser):
        """Test parsing RFC 3339 timestamp with Z suffix."""
        result = parser._parse_timestamp("2024-01-29T10:30:00.000000Z")
        assert "2024-01-29" in result

    def test_parse_rfc3339_with_offset(self, parser):
        """Test parsing RFC 3339 timestamp with offset."""
        result = parser._parse_timestamp("2024-01-29T10:30:00+00:00")
        assert "2024-01-29" in result

    def test_empty_timestamp_returns_current(self, parser):
        """Test empty timestamp returns current time."""
        result = parser._parse_timestamp("")
        assert "T" in result  # ISO format has T separator
