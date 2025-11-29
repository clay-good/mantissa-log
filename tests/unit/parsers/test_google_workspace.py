"""Unit tests for Google Workspace Reports parser."""

import pytest
from datetime import datetime, timezone

from shared.parsers.google_workspace import GoogleWorkspaceParser


class TestGoogleWorkspaceParser:
    """Tests for GoogleWorkspaceParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return GoogleWorkspaceParser()

    @pytest.fixture
    def sample_login_event(self):
        """Sample Google Workspace login event."""
        return {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2024-01-29T10:30:00.000Z",
                "uniqueQualifier": "event-123-456",
                "applicationName": "login",
                "customerId": "C01234567"
            },
            "actor": {
                "email": "john.doe@example.com",
                "profileId": "123456789012345678901",
                "callerType": "USER"
            },
            "ipAddress": "203.0.113.50",
            "ownershipDomain": "example.com",
            "events": [
                {
                    "name": "login_success",
                    "type": "login",
                    "parameters": [
                        {"name": "login_type", "value": "google_password"},
                        {"name": "is_suspicious", "boolValue": False}
                    ]
                }
            ]
        }

    @pytest.fixture
    def sample_failed_login_event(self):
        """Sample Google Workspace failed login event."""
        return {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2024-01-29T10:30:00.000Z",
                "uniqueQualifier": "event-456-789",
                "applicationName": "login",
                "customerId": "C01234567"
            },
            "actor": {
                "email": "john.doe@example.com",
                "profileId": "123456789012345678901",
                "callerType": "USER"
            },
            "ipAddress": "203.0.113.100",
            "ownershipDomain": "example.com",
            "events": [
                {
                    "name": "login_failure",
                    "type": "login",
                    "parameters": [
                        {"name": "login_failure_type", "value": "invalid_password"}
                    ]
                }
            ]
        }

    @pytest.fixture
    def sample_drive_event(self):
        """Sample Google Workspace Drive file access event."""
        return {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2024-01-29T10:30:00.000Z",
                "uniqueQualifier": "event-drive-123",
                "applicationName": "drive",
                "customerId": "C01234567"
            },
            "actor": {
                "email": "john.doe@example.com",
                "profileId": "123456789012345678901",
                "callerType": "USER"
            },
            "ipAddress": "10.0.0.50",
            "ownershipDomain": "example.com",
            "events": [
                {
                    "name": "download",
                    "type": "access",
                    "parameters": [
                        {"name": "doc_id", "value": "1234567890abcdef"},
                        {"name": "doc_title", "value": "Confidential Report.docx"},
                        {"name": "owner", "value": "admin@example.com"}
                    ]
                }
            ]
        }

    @pytest.fixture
    def sample_admin_event(self):
        """Sample Google Workspace admin event."""
        return {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2024-01-29T10:30:00.000Z",
                "uniqueQualifier": "event-admin-123",
                "applicationName": "admin",
                "customerId": "C01234567"
            },
            "actor": {
                "email": "admin@example.com",
                "profileId": "987654321098765432109",
                "callerType": "USER"
            },
            "ipAddress": "10.0.0.10",
            "ownershipDomain": "example.com",
            "events": [
                {
                    "name": "CREATE_USER",
                    "type": "CREATE",
                    "parameters": [
                        {"name": "USER_EMAIL", "value": "newuser@example.com"},
                        {"name": "USER_NAME", "value": "New User"}
                    ]
                }
            ]
        }

    @pytest.fixture
    def sample_token_event(self):
        """Sample Google Workspace OAuth token event."""
        return {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2024-01-29T10:30:00.000Z",
                "uniqueQualifier": "event-token-123",
                "applicationName": "token",
                "customerId": "C01234567"
            },
            "actor": {
                "email": "john.doe@example.com",
                "profileId": "123456789012345678901",
                "callerType": "USER"
            },
            "ipAddress": "203.0.113.50",
            "ownershipDomain": "example.com",
            "events": [
                {
                    "name": "authorize",
                    "type": "token",
                    "parameters": [
                        {"name": "app_name", "value": "Third Party App"},
                        {"name": "scope", "multiValue": ["email", "profile"]}
                    ]
                }
            ]
        }

    @pytest.fixture
    def sample_groups_event(self):
        """Sample Google Workspace groups event."""
        return {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2024-01-29T10:30:00.000Z",
                "uniqueQualifier": "event-groups-123",
                "applicationName": "groups",
                "customerId": "C01234567"
            },
            "actor": {
                "email": "admin@example.com",
                "profileId": "987654321098765432109",
                "callerType": "USER"
            },
            "ipAddress": "10.0.0.10",
            "ownershipDomain": "example.com",
            "events": [
                {
                    "name": "ADD_GROUP_MEMBER",
                    "type": "GROUP_MEMBER_UPDATE",
                    "parameters": [
                        {"name": "group_email", "value": "security-team@example.com"},
                        {"name": "user_email", "value": "newmember@example.com"}
                    ]
                }
            ]
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "google_workspace"

    def test_parse_login_event_basic_fields(self, parser, sample_login_event):
        """Test parsing login event extracts basic fields."""
        result = parser.parse(sample_login_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "google_workspace"
        assert result["event"]["module"] == "login"
        assert result["event"]["action"] == "login_success"

    def test_parse_login_event_user_fields(self, parser, sample_login_event):
        """Test parsing login event extracts user fields."""
        result = parser.parse(sample_login_event)

        assert result["user"]["email"] == "john.doe@example.com"
        assert result["user"]["name"] == "john.doe"
        assert result["user"]["id"] == "123456789012345678901"

    def test_parse_login_event_source_fields(self, parser, sample_login_event):
        """Test parsing login event extracts source fields."""
        result = parser.parse(sample_login_event)

        assert result["source"]["ip"] == "203.0.113.50"

    def test_parse_login_event_outcome_success(self, parser, sample_login_event):
        """Test parsing successful login sets correct outcome."""
        result = parser.parse(sample_login_event)

        assert result["event"]["outcome"] == "success"

    def test_parse_login_event_outcome_failure(self, parser, sample_failed_login_event):
        """Test parsing failed login sets correct outcome."""
        result = parser.parse(sample_failed_login_event)

        assert result["event"]["outcome"] == "failure"

    def test_parse_login_event_category(self, parser, sample_login_event):
        """Test parsing login event sets correct category."""
        result = parser.parse(sample_login_event)

        assert "authentication" in result["event"]["category"]

    def test_parse_login_event_type(self, parser, sample_login_event):
        """Test parsing login event sets correct type."""
        result = parser.parse(sample_login_event)

        assert "start" in result["event"]["type"]

    def test_parse_drive_event(self, parser, sample_drive_event):
        """Test parsing Drive file access event."""
        result = parser.parse(sample_drive_event)

        assert result["event"]["action"] == "download"
        assert result["event"]["module"] == "drive"
        assert "file" in result["event"]["category"]
        assert "access" in result["event"]["type"]

    def test_parse_admin_event(self, parser, sample_admin_event):
        """Test parsing admin event."""
        result = parser.parse(sample_admin_event)

        assert result["event"]["action"] == "CREATE_USER"
        assert result["event"]["module"] == "admin"
        assert "iam" in result["event"]["category"]
        assert "creation" in result["event"]["type"]

    def test_parse_token_event(self, parser, sample_token_event):
        """Test parsing OAuth token event."""
        result = parser.parse(sample_token_event)

        assert result["event"]["action"] == "authorize"
        assert result["event"]["module"] == "token"
        assert "authentication" in result["event"]["category"]

    def test_parse_groups_event(self, parser, sample_groups_event):
        """Test parsing groups event."""
        result = parser.parse(sample_groups_event)

        assert result["event"]["action"] == "ADD_GROUP_MEMBER"
        assert result["event"]["module"] == "groups"
        assert "iam" in result["event"]["category"]

    def test_parse_related_fields(self, parser, sample_login_event):
        """Test parsing extracts related fields for correlation."""
        result = parser.parse(sample_login_event)

        assert "203.0.113.50" in result["related"]["ip"]
        assert "john.doe@example.com" in result["related"]["user"]

    def test_parse_google_workspace_specific_fields(self, parser, sample_login_event):
        """Test parsing extracts Google Workspace-specific fields."""
        result = parser.parse(sample_login_event)

        assert result["google_workspace"]["id"]["application_name"] == "login"
        assert result["google_workspace"]["id"]["customer_id"] == "C01234567"
        assert result["google_workspace"]["actor"]["caller_type"] == "USER"
        assert result["google_workspace"]["ownership_domain"] == "example.com"

    def test_parse_organization_fields(self, parser, sample_login_event):
        """Test parsing extracts organization fields."""
        result = parser.parse(sample_login_event)

        assert result["organization"]["id"] == "C01234567"
        assert result["organization"]["name"] == "example.com"

    def test_parse_preserves_raw_event(self, parser, sample_login_event):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_login_event)

        assert "_raw" in result
        assert result["_raw"] == sample_login_event

    def test_validate_valid_event(self, parser, sample_login_event):
        """Test validation of valid event."""
        assert parser.validate(sample_login_event) is True

    def test_validate_missing_id(self, parser):
        """Test validation fails without id."""
        event = {
            "actor": {"email": "test@example.com"},
            "events": []
        }
        assert parser.validate(event) is False

    def test_validate_missing_actor(self, parser):
        """Test validation fails without actor."""
        event = {
            "id": {
                "time": "2024-01-29T10:30:00Z",
                "uniqueQualifier": "test",
                "applicationName": "login"
            },
            "events": []
        }
        assert parser.validate(event) is False

    def test_validate_missing_events(self, parser):
        """Test validation fails without events."""
        event = {
            "id": {
                "time": "2024-01-29T10:30:00Z",
                "uniqueQualifier": "test",
                "applicationName": "login"
            },
            "actor": {"email": "test@example.com"}
        }
        assert parser.validate(event) is False

    def test_validate_invalid_id_structure(self, parser):
        """Test validation fails with non-dict id."""
        event = {
            "id": "invalid",
            "actor": {"email": "test@example.com"},
            "events": []
        }
        assert parser.validate(event) is False

    def test_validate_missing_id_fields(self, parser):
        """Test validation fails with missing id fields."""
        event = {
            "id": {
                "time": "2024-01-29T10:30:00Z"
                # Missing uniqueQualifier and applicationName
            },
            "actor": {"email": "test@example.com"},
            "events": []
        }
        assert parser.validate(event) is False


class TestGoogleWorkspaceParserEventCategorization:
    """Test event categorization."""

    @pytest.fixture
    def parser(self):
        return GoogleWorkspaceParser()

    def test_login_app_categorized_as_authentication(self, parser):
        """Test login app events are categorized as authentication."""
        categories = parser._categorize_event("login", ["login_success"])
        assert "authentication" in categories

    def test_login_event_categorized_as_authentication(self, parser):
        """Test login events are categorized as authentication."""
        categories = parser._categorize_event("admin", ["login_challenge"])
        assert "authentication" in categories

    def test_admin_app_categorized_as_iam(self, parser):
        """Test admin app events are categorized as IAM."""
        categories = parser._categorize_event("admin", ["CREATE_USER"])
        assert "iam" in categories

    def test_groups_app_categorized_as_iam(self, parser):
        """Test groups app events are categorized as IAM."""
        categories = parser._categorize_event("groups", ["ADD_GROUP_MEMBER"])
        assert "iam" in categories

    def test_drive_app_categorized_as_file(self, parser):
        """Test drive app events are categorized as file."""
        categories = parser._categorize_event("drive", ["download"])
        assert "file" in categories

    def test_token_app_categorized_as_authentication(self, parser):
        """Test token app events are categorized as authentication."""
        categories = parser._categorize_event("token", ["authorize"])
        assert "authentication" in categories

    def test_config_change_categorized_as_configuration(self, parser):
        """Test config changes are categorized as configuration."""
        categories = parser._categorize_event("admin", ["CHANGE_APPLICATION_SETTING"])
        assert "configuration" in categories

    def test_unknown_events_default_to_session(self, parser):
        """Test unknown events default to session category."""
        categories = parser._categorize_event("unknown", ["some_event"])
        assert categories == ["session"]


class TestGoogleWorkspaceParserEventTypes:
    """Test ECS event type determination."""

    @pytest.fixture
    def parser(self):
        return GoogleWorkspaceParser()

    def test_create_event_type(self, parser):
        """Test create events get creation type."""
        types = parser._get_event_type(["CREATE_USER"], ["CREATE"])
        assert "creation" in types

    def test_update_event_type(self, parser):
        """Test update events get change type."""
        types = parser._get_event_type(["update_profile"], ["UPDATE"])
        assert "change" in types

    def test_delete_event_type(self, parser):
        """Test delete events get deletion type."""
        types = parser._get_event_type(["delete_user"], ["DELETE"])
        assert "deletion" in types

    def test_login_event_type(self, parser):
        """Test login events get start type."""
        types = parser._get_event_type(["login_success"], ["login"])
        assert "start" in types

    def test_logout_event_type(self, parser):
        """Test logout events get end type."""
        types = parser._get_event_type(["logout"], ["logout"])
        assert "end" in types

    def test_download_event_type(self, parser):
        """Test download events get access type."""
        types = parser._get_event_type(["download"], ["access"])
        assert "access" in types

    def test_view_event_type(self, parser):
        """Test view events get access type."""
        types = parser._get_event_type(["view"], ["access"])
        assert "access" in types

    def test_grant_event_type(self, parser):
        """Test grant events get allowed type."""
        types = parser._get_event_type(["grant_permission"], ["PERMISSION"])
        assert "allowed" in types

    def test_revoke_event_type(self, parser):
        """Test revoke events get denied type."""
        types = parser._get_event_type(["revoke_permission"], ["PERMISSION"])
        assert "denied" in types

    def test_unknown_event_type_defaults_to_info(self, parser):
        """Test unknown events default to info type."""
        types = parser._get_event_type(["some_event"], ["some_type"])
        assert types == ["info"]


class TestGoogleWorkspaceParserOutcome:
    """Test outcome determination."""

    @pytest.fixture
    def parser(self):
        return GoogleWorkspaceParser()

    def test_login_failure_type_is_failure(self, parser):
        """Test login_failure_type parameter indicates failure."""
        params = {"login_failure_type": "invalid_password"}
        assert parser._determine_outcome(params) == "failure"

    def test_challenge_failed_is_failure(self, parser):
        """Test failed challenge indicates failure."""
        params = {"login_challenge_status": "Challenge Failed"}
        assert parser._determine_outcome(params) == "failure"

    def test_suspicious_is_failure(self, parser):
        """Test suspicious flag indicates failure."""
        params = {"is_suspicious": True}
        assert parser._determine_outcome(params) == "failure"

    def test_login_type_is_success(self, parser):
        """Test login_type parameter indicates success."""
        params = {"login_type": "google_password"}
        assert parser._determine_outcome(params) == "success"

    def test_empty_params_is_unknown(self, parser):
        """Test empty params returns unknown."""
        assert parser._determine_outcome({}) == "unknown"


class TestGoogleWorkspaceParserParameterExtraction:
    """Test parameter extraction."""

    @pytest.fixture
    def parser(self):
        return GoogleWorkspaceParser()

    def test_extract_value_parameter(self, parser):
        """Test extracting value parameter."""
        events = [
            {
                "parameters": [
                    {"name": "test_param", "value": "test_value"}
                ]
            }
        ]
        params = parser._extract_parameters(events)
        assert params["test_param"] == "test_value"

    def test_extract_multi_value_parameter(self, parser):
        """Test extracting multiValue parameter."""
        events = [
            {
                "parameters": [
                    {"name": "test_param", "multiValue": ["val1", "val2"]}
                ]
            }
        ]
        params = parser._extract_parameters(events)
        assert params["test_param"] == ["val1", "val2"]

    def test_extract_int_value_parameter(self, parser):
        """Test extracting intValue parameter."""
        events = [
            {
                "parameters": [
                    {"name": "test_param", "intValue": 42}
                ]
            }
        ]
        params = parser._extract_parameters(events)
        assert params["test_param"] == 42

    def test_extract_bool_value_parameter(self, parser):
        """Test extracting boolValue parameter."""
        events = [
            {
                "parameters": [
                    {"name": "test_param", "boolValue": True}
                ]
            }
        ]
        params = parser._extract_parameters(events)
        assert params["test_param"] is True


class TestGoogleWorkspaceParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return GoogleWorkspaceParser()

    def test_parse_z_suffix_timestamp(self, parser):
        """Test parsing timestamp with Z suffix."""
        result = parser._parse_timestamp("2024-01-29T10:30:00.000Z")
        assert "2024-01-29" in result

    def test_parse_offset_timestamp(self, parser):
        """Test parsing timestamp with offset."""
        result = parser._parse_timestamp("2024-01-29T10:30:00+00:00")
        assert "2024-01-29" in result

    def test_parse_empty_timestamp_returns_current(self, parser):
        """Test empty timestamp returns current time."""
        result = parser._parse_timestamp("")
        assert "T" in result  # ISO format has T separator

    def test_parse_invalid_timestamp_returns_current(self, parser):
        """Test invalid timestamp returns current time."""
        result = parser._parse_timestamp("not-a-timestamp")
        assert "T" in result


class TestGoogleWorkspaceParserRemoveNoneValues:
    """Test None value removal."""

    @pytest.fixture
    def parser(self):
        return GoogleWorkspaceParser()

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
