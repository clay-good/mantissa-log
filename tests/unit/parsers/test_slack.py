"""Unit tests for Slack Enterprise Grid audit log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.slack import SlackParser


class TestSlackParser:
    """Tests for SlackParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SlackParser()

    @pytest.fixture
    def sample_login_event(self):
        """Sample Slack login event."""
        return {
            "id": "event-123-456",
            "action": "user_login",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U123ABC456",
                    "email": "john.doe@example.com",
                    "name": "john.doe",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "ip_address": "203.0.113.50",
                "session_id": "session-abc-123",
                "location": {
                    "country": "United States",
                    "region": "California",
                    "city": "San Francisco"
                }
            },
            "entity": {
                "type": "workspace",
                "id": "E123ABC456"
            },
            "details": {}
        }

    @pytest.fixture
    def sample_logout_event(self):
        """Sample Slack logout event."""
        return {
            "id": "event-456-789",
            "action": "user_logout",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U123ABC456",
                    "email": "john.doe@example.com",
                    "name": "john.doe",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Mozilla/5.0",
                "ip_address": "203.0.113.50",
                "session_id": "session-abc-123",
                "location": {}
            },
            "entity": {},
            "details": {}
        }

    @pytest.fixture
    def sample_file_download_event(self):
        """Sample Slack file download event."""
        return {
            "id": "event-file-123",
            "action": "file_downloaded",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U123ABC456",
                    "email": "john.doe@example.com",
                    "name": "john.doe",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Slack Desktop",
                "ip_address": "10.0.0.50",
                "session_id": "session-xyz-789",
                "location": {}
            },
            "entity": {
                "type": "file",
                "id": "F123ABC456",
                "name": "confidential.pdf"
            },
            "details": {
                "file_name": "confidential.pdf",
                "file_size": 1024000
            }
        }

    @pytest.fixture
    def sample_channel_created_event(self):
        """Sample Slack channel creation event."""
        return {
            "id": "event-channel-123",
            "action": "channel_created",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U123ABC456",
                    "email": "admin@example.com",
                    "name": "admin",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Slack Web",
                "ip_address": "10.0.0.10",
                "session_id": "session-admin-123",
                "location": {}
            },
            "entity": {
                "type": "channel",
                "id": "C123ABC456",
                "name": "security-team",
                "privacy": "private"
            },
            "details": {
                "channel_name": "security-team"
            }
        }

    @pytest.fixture
    def sample_user_added_event(self):
        """Sample Slack user added event."""
        return {
            "id": "event-user-123",
            "action": "member_added",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U_ADMIN",
                    "email": "admin@example.com",
                    "name": "admin",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Slack Admin",
                "ip_address": "10.0.0.10",
                "session_id": "session-admin-456",
                "location": {}
            },
            "entity": {
                "type": "user",
                "id": "U_NEW_USER",
                "name": "newuser@example.com"
            },
            "details": {}
        }

    @pytest.fixture
    def sample_app_installed_event(self):
        """Sample Slack app installation event."""
        return {
            "id": "event-app-123",
            "action": "app_installed",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U_ADMIN",
                    "email": "admin@example.com",
                    "name": "admin",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Slack Admin",
                "ip_address": "10.0.0.10",
                "session_id": "session-admin-789",
                "app": {
                    "id": "A123ABC456",
                    "name": "Third Party App"
                },
                "location": {}
            },
            "entity": {
                "type": "app",
                "id": "A123ABC456",
                "name": "Third Party App",
                "app": {
                    "is_distributed": True,
                    "scopes": ["chat:write", "files:read"]
                }
            },
            "details": {}
        }

    @pytest.fixture
    def sample_failed_event(self):
        """Sample Slack failed event."""
        return {
            "id": "event-fail-123",
            "action": "user_login_failed",
            "date_create": 1706500000,
            "actor": {
                "type": "user",
                "user": {
                    "id": "U123ABC456",
                    "email": "john.doe@example.com",
                    "name": "john.doe",
                    "team": "T123ABC456"
                }
            },
            "context": {
                "ua": "Mozilla/5.0",
                "ip_address": "203.0.113.100",
                "session_id": "",
                "location": {}
            },
            "entity": {},
            "details": {
                "is_failure": True
            }
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "slack"

    def test_parse_login_basic_fields(self, parser, sample_login_event):
        """Test parsing login event extracts basic fields."""
        result = parser.parse(sample_login_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "slack"
        assert result["event"]["module"] == "audit"
        assert result["event"]["action"] == "user_login"

    def test_parse_login_user_fields(self, parser, sample_login_event):
        """Test parsing login event extracts user fields."""
        result = parser.parse(sample_login_event)

        assert result["user"]["id"] == "U123ABC456"
        assert result["user"]["email"] == "john.doe@example.com"
        assert result["user"]["name"] == "john.doe"

    def test_parse_login_source_fields(self, parser, sample_login_event):
        """Test parsing login event extracts source fields."""
        result = parser.parse(sample_login_event)

        assert result["source"]["ip"] == "203.0.113.50"
        assert result["source"]["geo"]["city_name"] == "San Francisco"
        assert result["source"]["geo"]["region_name"] == "California"
        assert result["source"]["geo"]["country_name"] == "United States"

    def test_parse_login_category(self, parser, sample_login_event):
        """Test parsing login event sets correct category."""
        result = parser.parse(sample_login_event)

        assert "authentication" in result["event"]["category"]

    def test_parse_login_type(self, parser, sample_login_event):
        """Test parsing login event sets correct type."""
        result = parser.parse(sample_login_event)

        assert "start" in result["event"]["type"]

    def test_parse_logout_type(self, parser, sample_logout_event):
        """Test parsing logout event sets correct type."""
        result = parser.parse(sample_logout_event)

        assert "end" in result["event"]["type"]

    def test_parse_file_download_event(self, parser, sample_file_download_event):
        """Test parsing file download event."""
        result = parser.parse(sample_file_download_event)

        assert result["event"]["action"] == "file_downloaded"
        assert "file" in result["event"]["category"]
        assert "access" in result["event"]["type"]
        assert result["slack"]["entity"]["name"] == "confidential.pdf"

    def test_parse_channel_created_event(self, parser, sample_channel_created_event):
        """Test parsing channel creation event."""
        result = parser.parse(sample_channel_created_event)

        assert result["event"]["action"] == "channel_created"
        assert "configuration" in result["event"]["category"]
        assert "creation" in result["event"]["type"]
        assert result["slack"]["entity"]["privacy"] == "private"

    def test_parse_user_added_event(self, parser, sample_user_added_event):
        """Test parsing user added event."""
        result = parser.parse(sample_user_added_event)

        assert result["event"]["action"] == "member_added"
        assert "iam" in result["event"]["category"]
        assert "creation" in result["event"]["type"]

    def test_parse_app_installed_event(self, parser, sample_app_installed_event):
        """Test parsing app installation event."""
        result = parser.parse(sample_app_installed_event)

        assert result["event"]["action"] == "app_installed"
        assert "configuration" in result["event"]["category"]
        assert result["slack"]["entity"]["app"]["is_distributed"] is True

    def test_parse_failed_event(self, parser, sample_failed_event):
        """Test parsing failed event sets correct outcome."""
        result = parser.parse(sample_failed_event)

        assert result["event"]["outcome"] == "failure"

    def test_parse_related_fields(self, parser, sample_login_event):
        """Test parsing extracts related fields for correlation."""
        result = parser.parse(sample_login_event)

        assert "203.0.113.50" in result["related"]["ip"]
        assert "U123ABC456" in result["related"]["user"]
        assert "john.doe@example.com" in result["related"]["user"]

    def test_parse_slack_specific_fields(self, parser, sample_login_event):
        """Test parsing extracts Slack-specific fields."""
        result = parser.parse(sample_login_event)

        assert result["slack"]["id"] == "event-123-456"
        assert result["slack"]["action"] == "user_login"
        assert result["slack"]["actor"]["type"] == "user"
        assert result["slack"]["context"]["session_id"] == "session-abc-123"

    def test_parse_user_agent(self, parser, sample_login_event):
        """Test parsing extracts user agent."""
        result = parser.parse(sample_login_event)

        assert "Mozilla" in result["user_agent"]["original"]

    def test_parse_preserves_raw_event(self, parser, sample_login_event):
        """Test parsing preserves raw event (with None/empty values cleaned)."""
        result = parser.parse(sample_login_event)

        assert "_raw" in result
        # Parser cleans None/empty values from _raw, so check key fields
        assert result["_raw"]["id"] == sample_login_event["id"]
        assert result["_raw"]["action"] == sample_login_event["action"]
        assert result["_raw"]["date_create"] == sample_login_event["date_create"]
        assert result["_raw"]["actor"]["user"]["id"] == sample_login_event["actor"]["user"]["id"]

    def test_validate_valid_event(self, parser, sample_login_event):
        """Test validation of valid event."""
        assert parser.validate(sample_login_event) is True

    def test_validate_missing_id(self, parser):
        """Test validation fails without id."""
        event = {
            "action": "user_login",
            "date_create": 1706500000,
            "actor": {"type": "user"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_action(self, parser):
        """Test validation fails without action."""
        event = {
            "id": "test",
            "date_create": 1706500000,
            "actor": {"type": "user"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_date_create(self, parser):
        """Test validation fails without date_create."""
        event = {
            "id": "test",
            "action": "user_login",
            "actor": {"type": "user"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_actor(self, parser):
        """Test validation fails without actor."""
        event = {
            "id": "test",
            "action": "user_login",
            "date_create": 1706500000
        }
        assert parser.validate(event) is False

    def test_validate_invalid_actor_type(self, parser):
        """Test validation fails with non-dict actor."""
        event = {
            "id": "test",
            "action": "user_login",
            "date_create": 1706500000,
            "actor": "invalid"
        }
        assert parser.validate(event) is False


class TestSlackParserEventCategorization:
    """Test event categorization."""

    @pytest.fixture
    def parser(self):
        return SlackParser()

    def test_signin_categorized_as_authentication(self, parser):
        """Test signin events are categorized as authentication."""
        categories = parser._categorize_event("user_signin")
        assert "authentication" in categories

    def test_login_categorized_as_authentication(self, parser):
        """Test login events are categorized as authentication."""
        categories = parser._categorize_event("user_login")
        assert "authentication" in categories

    def test_logout_categorized_as_authentication(self, parser):
        """Test logout events are categorized as authentication."""
        categories = parser._categorize_event("user_logout")
        assert "authentication" in categories

    def test_session_categorized_as_authentication(self, parser):
        """Test session events are categorized as authentication."""
        categories = parser._categorize_event("session_invalidated")
        assert "authentication" in categories

    def test_user_events_categorized_as_iam(self, parser):
        """Test user events are categorized as IAM."""
        categories = parser._categorize_event("user_created")
        assert "iam" in categories

    def test_member_events_categorized_as_iam(self, parser):
        """Test member events are categorized as IAM."""
        categories = parser._categorize_event("member_added")
        assert "iam" in categories

    def test_team_events_categorized_as_iam(self, parser):
        """Test team events are categorized as IAM."""
        categories = parser._categorize_event("team_member_joined")
        assert "iam" in categories

    def test_file_events_categorized_as_file(self, parser):
        """Test file events are categorized as file."""
        categories = parser._categorize_event("file_downloaded")
        assert "file" in categories

    def test_download_events_categorized_as_file(self, parser):
        """Test download events are categorized as file."""
        categories = parser._categorize_event("download_initiated")
        assert "file" in categories

    def test_workspace_events_categorized_as_configuration(self, parser):
        """Test workspace events are categorized as configuration."""
        categories = parser._categorize_event("workspace_settings_changed")
        assert "configuration" in categories

    def test_app_events_categorized_as_configuration(self, parser):
        """Test app events are categorized as configuration."""
        categories = parser._categorize_event("app_installed")
        assert "configuration" in categories

    def test_channel_events_categorized_as_configuration(self, parser):
        """Test channel events are categorized as configuration."""
        categories = parser._categorize_event("channel_created")
        assert "configuration" in categories

    def test_export_events_categorized_as_file(self, parser):
        """Test export events are categorized as file."""
        categories = parser._categorize_event("compliance_export_started")
        assert "file" in categories

    def test_unknown_events_default_to_session(self, parser):
        """Test unknown events default to session category."""
        categories = parser._categorize_event("unknown_action")
        assert categories == ["session"]


class TestSlackParserEventTypes:
    """Test ECS event type determination."""

    @pytest.fixture
    def parser(self):
        return SlackParser()

    def test_created_event_type(self, parser):
        """Test created events get creation type."""
        types = parser._get_event_type("channel_created")
        assert "creation" in types

    def test_added_event_type(self, parser):
        """Test added events get creation type."""
        types = parser._get_event_type("member_added")
        assert "creation" in types

    def test_invited_event_type(self, parser):
        """Test invited events get creation type."""
        types = parser._get_event_type("user_invited")
        assert "creation" in types

    def test_changed_event_type(self, parser):
        """Test changed events get change type."""
        types = parser._get_event_type("settings_changed")
        assert "change" in types

    def test_updated_event_type(self, parser):
        """Test updated events get change type."""
        types = parser._get_event_type("profile_updated")
        assert "change" in types

    def test_deleted_event_type(self, parser):
        """Test deleted events get deletion type."""
        types = parser._get_event_type("channel_deleted")
        assert "deletion" in types

    def test_removed_event_type(self, parser):
        """Test removed events get deletion type."""
        types = parser._get_event_type("member_removed")
        assert "deletion" in types

    def test_revoked_event_type(self, parser):
        """Test revoked events get deletion type."""
        types = parser._get_event_type("token_revoked")
        assert "deletion" in types

    def test_login_event_type(self, parser):
        """Test login events get start type."""
        types = parser._get_event_type("user_login")
        assert "start" in types

    def test_logout_event_type(self, parser):
        """Test logout events get end type."""
        types = parser._get_event_type("user_logout")
        assert "end" in types

    def test_download_event_type(self, parser):
        """Test download events get access type."""
        types = parser._get_event_type("file_downloaded")
        assert "access" in types

    def test_export_event_type(self, parser):
        """Test export events get access type."""
        types = parser._get_event_type("compliance_export")
        assert "access" in types

    def test_approved_event_type(self, parser):
        """Test approved events get allowed type."""
        types = parser._get_event_type("app_approved")
        assert "allowed" in types

    def test_denied_event_type(self, parser):
        """Test denied events get denied type."""
        types = parser._get_event_type("request_denied")
        assert "denied" in types

    def test_failed_event_type(self, parser):
        """Test failed events get denied type."""
        types = parser._get_event_type("user_login_failed")
        assert "denied" in types

    def test_unknown_event_type_defaults_to_info(self, parser):
        """Test unknown events default to info type."""
        types = parser._get_event_type("some_other_action")
        assert types == ["info"]


class TestSlackParserOutcome:
    """Test outcome determination."""

    @pytest.fixture
    def parser(self):
        return SlackParser()

    def test_is_failure_true_is_failure(self, parser):
        """Test is_failure flag indicates failure."""
        details = {"is_failure": True}
        assert parser._determine_outcome(details) == "failure"

    def test_is_denied_true_is_failure(self, parser):
        """Test is_denied flag indicates failure."""
        details = {"is_denied": True}
        assert parser._determine_outcome(details) == "failure"

    def test_is_success_true_is_success(self, parser):
        """Test is_success flag indicates success."""
        details = {"is_success": True}
        assert parser._determine_outcome(details) == "success"

    def test_empty_details_defaults_to_success(self, parser):
        """Test empty details defaults to success."""
        # This is because is_success defaults to True check
        details = {}
        assert parser._determine_outcome(details) == "success"


class TestSlackParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return SlackParser()

    def test_parse_valid_timestamp(self, parser):
        """Test parsing valid Unix timestamp."""
        result = parser._parse_timestamp(1706500000)
        # Result may vary by timezone, just check it's a valid ISO timestamp
        assert "2024-01-2" in result  # Could be 28 or 29 depending on timezone

    def test_parse_zero_timestamp(self, parser):
        """Test zero timestamp returns current time."""
        result = parser._parse_timestamp(0)
        assert "T" in result  # ISO format has T separator

    def test_parse_none_timestamp(self, parser):
        """Test None timestamp returns current time."""
        result = parser._parse_timestamp(None)
        assert "T" in result


class TestSlackParserRemoveNoneValues:
    """Test None value removal."""

    @pytest.fixture
    def parser(self):
        return SlackParser()

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
