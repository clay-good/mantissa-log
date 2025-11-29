"""Unit tests for CrowdStrike Falcon parser."""

import pytest
from datetime import datetime, timezone

from shared.parsers.crowdstrike import CrowdStrikeParser


class TestCrowdStrikeParser:
    """Tests for CrowdStrikeParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return CrowdStrikeParser()

    @pytest.fixture
    def sample_detection_event(self):
        """Sample CrowdStrike detection event."""
        return {
            "metadata": {
                "eventType": "DetectionSummaryEvent",
                "eventCreationTime": 1706500000000,
                "customerIDString": "customer-123",
                "offset": 12345
            },
            "event": {
                "DetectionId": "det-abc123-def456",
                "SeverityName": "High",
                "Tactic": "Initial Access",
                "Technique": "Phishing",
                "PatternDispositionDescription": "Process blocked",
                "ComputerName": "WORKSTATION-01",
                "HostName": "workstation-01.example.com",
                "MacAddress": "00:11:22:33:44:55",
                "LocalIP": "10.0.0.100",
                "UserName": "john.doe",
                "UserId": "user-123",
                "FileName": "malware.exe",
                "FilePath": "C:\\Users\\john.doe\\Downloads\\malware.exe",
                "CommandLine": "malware.exe --payload",
                "MD5String": "d41d8cd98f00b204e9800998ecf8427e",
                "SHA256String": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "Confidence": 90,
                "Objective": "Falcon Detection Method",
                "Scenario": "malware_execution"
            }
        }

    @pytest.fixture
    def sample_incident_event(self):
        """Sample CrowdStrike incident event."""
        return {
            "metadata": {
                "eventType": "IncidentSummaryEvent",
                "eventCreationTime": 1706500000000,
                "customerIDString": "customer-123",
                "offset": 12346
            },
            "event": {
                "IncidentId": "inc-xyz789-abc123",
                "State": "closed",
                "Status": "resolved",
                "FineScore": 85,
                "StartTime": "2024-01-29T09:00:00Z",
                "EndTime": "2024-01-29T10:30:00Z",
                "HostIds": ["host-1", "host-2"],
                "UserIds": ["user-1", "user-2"]
            }
        }

    @pytest.fixture
    def sample_audit_event(self):
        """Sample CrowdStrike audit event."""
        return {
            "metadata": {
                "eventType": "AuditEvent",
                "eventCreationTime": 1706500000000,
                "customerIDString": "customer-123",
                "offset": 12347
            },
            "event": {
                "UserId": "admin-user-id",
                "UserName": "admin@example.com",
                "OperationName": "CreateUser",
                "ServiceName": "UserManagement",
                "Success": True,
                "UTCTimestamp": 1706500000000,
                "AuditKeyValues": [
                    {"Key": "target_user", "ValueString": "newuser@example.com"},
                    {"Key": "role", "ValueString": "analyst"}
                ]
            }
        }

    @pytest.fixture
    def sample_user_activity_event(self):
        """Sample CrowdStrike user activity event."""
        return {
            "metadata": {
                "eventType": "UserActivityAuditEvent",
                "eventCreationTime": 1706500000000,
                "customerIDString": "customer-123",
                "offset": 12348
            },
            "event": {
                "UserId": "user-123",
                "UserName": "john.doe@example.com",
                "OperationName": "userAuthenticate",
                "Success": True,
                "UTCTimestamp": 1706500000000,
                "UserIp": "203.0.113.50"
            }
        }

    @pytest.fixture
    def sample_failed_auth_event(self):
        """Sample CrowdStrike failed authentication event."""
        return {
            "metadata": {
                "eventType": "UserActivityAuditEvent",
                "eventCreationTime": 1706500000000,
                "customerIDString": "customer-123",
                "offset": 12349
            },
            "event": {
                "UserId": "user-456",
                "UserName": "unknown@example.com",
                "OperationName": "userAuthenticate",
                "Success": False,
                "UTCTimestamp": 1706500000000,
                "UserIp": "203.0.113.100"
            }
        }

    @pytest.fixture
    def sample_unknown_event(self):
        """Sample CrowdStrike unknown event type."""
        return {
            "metadata": {
                "eventType": "CustomEventType",
                "eventCreationTime": 1706500000000,
                "customerIDString": "customer-123",
                "offset": 12350
            },
            "event": {
                "customField": "customValue"
            }
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "crowdstrike"

    def test_parse_detection_basic_fields(self, parser, sample_detection_event):
        """Test parsing detection event extracts basic fields."""
        result = parser.parse(sample_detection_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "crowdstrike"
        assert result["event"]["module"] == "falcon"
        assert result["event"]["kind"] == "alert"

    def test_parse_detection_threat_fields(self, parser, sample_detection_event):
        """Test parsing detection event extracts threat fields."""
        result = parser.parse(sample_detection_event)

        assert "Initial Access" in result["threat"]["tactic"]["name"]
        assert "Phishing" in result["threat"]["technique"]["name"]

    def test_parse_detection_host_fields(self, parser, sample_detection_event):
        """Test parsing detection event extracts host fields."""
        result = parser.parse(sample_detection_event)

        assert result["host"]["name"] == "workstation-01.example.com"
        assert "10.0.0.100" in result["host"]["ip"]
        assert "00:11:22:33:44:55" in result["host"]["mac"]

    def test_parse_detection_user_fields(self, parser, sample_detection_event):
        """Test parsing detection event extracts user fields."""
        result = parser.parse(sample_detection_event)

        assert result["user"]["name"] == "john.doe"
        assert result["user"]["id"] == "user-123"

    def test_parse_detection_file_fields(self, parser, sample_detection_event):
        """Test parsing detection event extracts file fields."""
        result = parser.parse(sample_detection_event)

        assert result["file"]["name"] == "malware.exe"
        assert "Downloads" in result["file"]["path"]
        assert result["file"]["hash"]["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert result["file"]["hash"]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_parse_detection_process_fields(self, parser, sample_detection_event):
        """Test parsing detection event extracts process fields."""
        result = parser.parse(sample_detection_event)

        assert result["process"]["command_line"] == "malware.exe --payload"

    def test_parse_detection_category(self, parser, sample_detection_event):
        """Test parsing detection event sets correct category."""
        result = parser.parse(sample_detection_event)

        assert "malware" in result["event"]["category"]
        assert "intrusion_detection" in result["event"]["category"]

    def test_parse_detection_crowdstrike_fields(self, parser, sample_detection_event):
        """Test parsing extracts CrowdStrike-specific fields."""
        result = parser.parse(sample_detection_event)

        assert result["crowdstrike"]["detection"]["id"] == "det-abc123-def456"
        assert result["crowdstrike"]["detection"]["severity"] == "High"
        assert result["crowdstrike"]["detection"]["confidence"] == 90

    def test_parse_incident_event(self, parser, sample_incident_event):
        """Test parsing incident event."""
        result = parser.parse(sample_incident_event)

        assert result["event"]["kind"] == "alert"
        assert result["event"]["action"] == "incident"
        assert result["crowdstrike"]["incident"]["id"] == "inc-xyz789-abc123"
        assert result["crowdstrike"]["incident"]["state"] == "closed"
        assert result["crowdstrike"]["incident"]["fine_score"] == 85

    def test_parse_audit_event(self, parser, sample_audit_event):
        """Test parsing audit event."""
        result = parser.parse(sample_audit_event)

        assert result["event"]["action"] == "CreateUser"
        assert result["event"]["outcome"] == "success"
        assert "iam" in result["event"]["category"]
        assert "configuration" in result["event"]["category"]
        assert result["user"]["name"] == "admin@example.com"
        assert result["crowdstrike"]["audit"]["operation_name"] == "CreateUser"

    def test_parse_audit_event_key_values(self, parser, sample_audit_event):
        """Test parsing audit event key values."""
        result = parser.parse(sample_audit_event)

        assert result["crowdstrike"]["audit"]["audit_key_values"]["target_user"] == "newuser@example.com"
        assert result["crowdstrike"]["audit"]["audit_key_values"]["role"] == "analyst"

    def test_parse_user_activity_event(self, parser, sample_user_activity_event):
        """Test parsing user activity event."""
        result = parser.parse(sample_user_activity_event)

        assert result["event"]["action"] == "userAuthenticate"
        assert result["event"]["outcome"] == "success"
        assert "authentication" in result["event"]["category"]
        assert result["source"]["ip"] == "203.0.113.50"

    def test_parse_user_activity_failure(self, parser, sample_failed_auth_event):
        """Test parsing failed user activity event."""
        result = parser.parse(sample_failed_auth_event)

        assert result["event"]["outcome"] == "failure"

    def test_parse_unknown_event_type(self, parser, sample_unknown_event):
        """Test parsing unknown event type uses generic parser."""
        result = parser.parse(sample_unknown_event)

        assert result["event"]["action"] == "CustomEventType"
        assert result["event"]["kind"] == "event"
        assert "session" in result["event"]["category"]

    def test_parse_preserves_raw_event(self, parser, sample_detection_event):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_detection_event)

        assert "_raw" in result
        assert result["_raw"] == sample_detection_event

    def test_validate_valid_event(self, parser, sample_detection_event):
        """Test validation of valid event."""
        assert parser.validate(sample_detection_event) is True

    def test_validate_missing_metadata(self, parser):
        """Test validation fails without metadata."""
        event = {"event": {"some": "data"}}
        assert parser.validate(event) is False

    def test_validate_missing_event(self, parser):
        """Test validation fails without event."""
        event = {
            "metadata": {
                "eventType": "TestEvent",
                "eventCreationTime": 1706500000000
            }
        }
        assert parser.validate(event) is False

    def test_validate_invalid_metadata_type(self, parser):
        """Test validation fails with non-dict metadata."""
        event = {
            "metadata": "invalid",
            "event": {}
        }
        assert parser.validate(event) is False

    def test_validate_missing_event_type(self, parser):
        """Test validation fails without eventType."""
        event = {
            "metadata": {
                "eventCreationTime": 1706500000000
            },
            "event": {}
        }
        assert parser.validate(event) is False

    def test_validate_missing_event_creation_time(self, parser):
        """Test validation fails without eventCreationTime."""
        event = {
            "metadata": {
                "eventType": "TestEvent"
            },
            "event": {}
        }
        assert parser.validate(event) is False


class TestCrowdStrikeParserSeverityMapping:
    """Test severity mapping."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_critical_severity(self, parser):
        """Test Critical maps to 100."""
        assert parser._map_detection_severity("Critical") == 100

    def test_high_severity(self, parser):
        """Test High maps to 80."""
        assert parser._map_detection_severity("High") == 80

    def test_medium_severity(self, parser):
        """Test Medium maps to 50."""
        assert parser._map_detection_severity("Medium") == 50

    def test_low_severity(self, parser):
        """Test Low maps to 20."""
        assert parser._map_detection_severity("Low") == 20

    def test_informational_severity(self, parser):
        """Test Informational maps to 10."""
        assert parser._map_detection_severity("Informational") == 10

    def test_unknown_severity(self, parser):
        """Test unknown severity defaults to 50."""
        assert parser._map_detection_severity("Unknown") == 50


class TestCrowdStrikeParserIncidentScore:
    """Test incident score mapping."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_high_score_is_critical(self, parser):
        """Test score >= 80 is critical."""
        assert parser._map_incident_score(85) == 100

    def test_medium_high_score_is_high(self, parser):
        """Test score 60-79 is high."""
        assert parser._map_incident_score(70) == 80

    def test_medium_score_is_medium(self, parser):
        """Test score 40-59 is medium."""
        assert parser._map_incident_score(50) == 50

    def test_low_score_is_low(self, parser):
        """Test score 20-39 is low."""
        assert parser._map_incident_score(30) == 20

    def test_very_low_score_is_informational(self, parser):
        """Test score < 20 is informational."""
        assert parser._map_incident_score(10) == 10


class TestCrowdStrikeParserAuditEventType:
    """Test audit event type determination."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_create_operation(self, parser):
        """Test create operations get creation type."""
        assert parser._get_audit_event_type("CreateUser") == "creation"

    def test_add_operation(self, parser):
        """Test add operations get creation type."""
        assert parser._get_audit_event_type("AddRoleMember") == "creation"

    def test_update_operation(self, parser):
        """Test update operations get change type."""
        assert parser._get_audit_event_type("UpdatePolicy") == "change"

    def test_modify_operation(self, parser):
        """Test modify operations get change type."""
        assert parser._get_audit_event_type("ModifyRule") == "change"

    def test_delete_operation(self, parser):
        """Test delete operations get deletion type."""
        assert parser._get_audit_event_type("DeleteUser") == "deletion"

    def test_remove_operation(self, parser):
        """Test remove operations get deletion type."""
        assert parser._get_audit_event_type("RemoveRoleMember") == "deletion"

    def test_unknown_operation(self, parser):
        """Test unknown operations default to admin type."""
        assert parser._get_audit_event_type("SomeOtherOperation") == "admin"


class TestCrowdStrikeParserUserActivityType:
    """Test user activity type determination."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_login_operation(self, parser):
        """Test login operations get start type."""
        assert parser._get_user_activity_type("userLogin") == "start"

    def test_signin_operation(self, parser):
        """Test signin operations get start type."""
        assert parser._get_user_activity_type("userSignin") == "start"

    def test_logout_operation(self, parser):
        """Test logout operations get end type."""
        assert parser._get_user_activity_type("userLogout") == "end"

    def test_signout_operation(self, parser):
        """Test signout operations get end type."""
        assert parser._get_user_activity_type("userSignout") == "end"

    def test_unknown_operation(self, parser):
        """Test unknown operations default to info type."""
        assert parser._get_user_activity_type("userAuthenticate") == "info"


class TestCrowdStrikeParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_parse_valid_timestamp(self, parser):
        """Test parsing valid Unix timestamp in milliseconds."""
        result = parser._parse_timestamp_ms(1706500000000)
        assert "2024-01-29" in result

    def test_parse_zero_timestamp(self, parser):
        """Test zero timestamp returns current time."""
        result = parser._parse_timestamp_ms(0)
        assert "T" in result  # ISO format has T separator

    def test_parse_none_timestamp(self, parser):
        """Test None timestamp returns current time."""
        result = parser._parse_timestamp_ms(None)
        assert "T" in result


class TestCrowdStrikeParserAuditKeyValues:
    """Test audit key-value parsing."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_parse_key_values(self, parser):
        """Test parsing key-value pairs."""
        audit_key_values = [
            {"Key": "key1", "ValueString": "value1"},
            {"Key": "key2", "ValueString": "value2"}
        ]
        result = parser._parse_audit_key_values(audit_key_values)

        assert result["key1"] == "value1"
        assert result["key2"] == "value2"

    def test_parse_empty_key_values(self, parser):
        """Test parsing empty key-value list."""
        result = parser._parse_audit_key_values([])
        assert result == {}

    def test_parse_skip_empty_keys(self, parser):
        """Test skipping items with empty keys."""
        audit_key_values = [
            {"Key": "", "ValueString": "value"},
            {"Key": "valid", "ValueString": "value"}
        ]
        result = parser._parse_audit_key_values(audit_key_values)

        assert "" not in result
        assert result["valid"] == "value"


class TestCrowdStrikeParserRemoveNoneValues:
    """Test None value removal."""

    @pytest.fixture
    def parser(self):
        return CrowdStrikeParser()

    def test_remove_none_values(self, parser):
        """Test None values are removed."""
        data = {
            "a": "value",
            "b": None,
            "c": {"d": "nested", "e": None}
        }
        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result
        assert "d" in result["c"]
        assert "e" not in result["c"]

    def test_remove_empty_dicts(self, parser):
        """Test empty dicts are removed."""
        data = {"a": "value", "b": {}}
        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result

    def test_remove_empty_lists(self, parser):
        """Test empty lists are removed."""
        data = {"a": "value", "b": []}
        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result
