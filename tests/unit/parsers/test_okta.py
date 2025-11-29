"""Unit tests for Okta System Log parser."""

import pytest
from datetime import datetime, timezone

from shared.parsers.okta import OktaParser


class TestOktaParser:
    """Tests for OktaParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return OktaParser()

    @pytest.fixture
    def sample_login_event(self):
        """Sample Okta login event."""
        return {
            "uuid": "event-uuid-123",
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "user.session.start",
            "displayMessage": "User login to Okta",
            "severity": "INFO",
            "actor": {
                "id": "00u1234567890ABCDEF",
                "type": "User",
                "alternateId": "john.doe@example.com",
                "displayName": "John Doe"
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "os": "Windows",
                    "browser": "Chrome"
                },
                "zone": "null",
                "device": "Computer",
                "id": None,
                "ipAddress": "203.0.113.50",
                "geographicalContext": {
                    "city": "San Francisco",
                    "state": "California",
                    "country": "United States",
                    "postalCode": "94102",
                    "geolocation": {
                        "lat": 37.7749,
                        "lon": -122.4194
                    }
                }
            },
            "outcome": {
                "result": "SUCCESS"
            },
            "target": [],
            "transaction": {
                "type": "WEB",
                "id": "txn123"
            },
            "authenticationContext": {
                "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
                "authenticationStep": 0,
                "externalSessionId": "session-123"
            },
            "securityContext": {
                "asNumber": 12345,
                "asOrg": "Example ISP",
                "isp": "Example ISP"
            },
            "debugContext": {},
            "request": {
                "ipChain": [
                    {"ip": "203.0.113.50", "geographicalContext": {}}
                ]
            }
        }

    @pytest.fixture
    def sample_failed_login_event(self):
        """Sample failed Okta login event."""
        return {
            "uuid": "event-uuid-456",
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "user.session.start",
            "displayMessage": "User login to Okta",
            "severity": "WARN",
            "actor": {
                "id": "00u1234567890ABCDEF",
                "type": "User",
                "alternateId": "john.doe@example.com",
                "displayName": "John Doe"
            },
            "client": {
                "ipAddress": "203.0.113.100",
                "userAgent": {"rawUserAgent": "Mozilla/5.0"},
                "device": "Computer",
                "geographicalContext": {}
            },
            "outcome": {
                "result": "FAILURE",
                "reason": "INVALID_CREDENTIALS"
            },
            "target": [],
            "transaction": {"type": "WEB", "id": "txn456"},
            "authenticationContext": {}
        }

    @pytest.fixture
    def sample_user_create_event(self):
        """Sample Okta user creation event."""
        return {
            "uuid": "event-uuid-789",
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "user.lifecycle.create",
            "displayMessage": "Create user",
            "severity": "INFO",
            "actor": {
                "id": "00u_admin_id",
                "type": "User",
                "alternateId": "admin@example.com",
                "displayName": "Admin User"
            },
            "client": {
                "ipAddress": "10.0.0.50",
                "userAgent": {"rawUserAgent": "Okta Admin Console"},
                "device": "Unknown",
                "geographicalContext": {}
            },
            "outcome": {
                "result": "SUCCESS"
            },
            "target": [
                {
                    "id": "00u_new_user_id",
                    "type": "User",
                    "alternateId": "newuser@example.com",
                    "displayName": "New User"
                }
            ],
            "transaction": {"type": "WEB", "id": "txn789"},
            "authenticationContext": {}
        }

    @pytest.fixture
    def sample_mfa_event(self):
        """Sample Okta MFA verification event."""
        return {
            "uuid": "event-uuid-mfa",
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "displayMessage": "Verify factor",
            "severity": "INFO",
            "actor": {
                "id": "00u1234567890ABCDEF",
                "type": "User",
                "alternateId": "john.doe@example.com",
                "displayName": "John Doe"
            },
            "client": {
                "ipAddress": "203.0.113.50",
                "userAgent": {"rawUserAgent": "Mozilla/5.0"},
                "device": "Computer",
                "geographicalContext": {}
            },
            "outcome": {
                "result": "SUCCESS"
            },
            "target": [
                {
                    "id": "factor-id-123",
                    "type": "AuthenticatorEnrollment",
                    "alternateId": "unknown",
                    "displayName": "Okta Verify"
                }
            ],
            "transaction": {"type": "WEB", "id": "txn-mfa"},
            "authenticationContext": {
                "credentialType": "OTP"
            }
        }

    @pytest.fixture
    def sample_policy_event(self):
        """Sample Okta policy modification event."""
        return {
            "uuid": "event-uuid-policy",
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "policy.lifecycle.update",
            "displayMessage": "Update policy",
            "severity": "INFO",
            "actor": {
                "id": "00u_admin_id",
                "type": "User",
                "alternateId": "admin@example.com",
                "displayName": "Admin User"
            },
            "client": {
                "ipAddress": "10.0.0.50",
                "userAgent": {"rawUserAgent": "Okta Admin Console"},
                "device": "Computer",
                "geographicalContext": {}
            },
            "outcome": {
                "result": "SUCCESS"
            },
            "target": [
                {
                    "id": "policy-id-123",
                    "type": "Policy",
                    "alternateId": "MFA Policy",
                    "displayName": "MFA Policy"
                }
            ],
            "transaction": {"type": "WEB", "id": "txn-policy"},
            "authenticationContext": {}
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "okta"

    def test_parse_login_event_basic_fields(self, parser, sample_login_event):
        """Test parsing login event extracts basic fields."""
        result = parser.parse(sample_login_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "okta"
        assert result["event"]["action"] == "user.session.start"

    def test_parse_login_event_user_fields(self, parser, sample_login_event):
        """Test parsing login event extracts user fields."""
        result = parser.parse(sample_login_event)

        assert result["user"]["name"] == "john.doe@example.com"
        assert result["user"]["id"] == "00u1234567890ABCDEF"
        assert result["user"]["full_name"] == "John Doe"
        assert result["user"]["email"] == "john.doe@example.com"

    def test_parse_login_event_source_fields(self, parser, sample_login_event):
        """Test parsing login event extracts source fields."""
        result = parser.parse(sample_login_event)

        assert result["source"]["ip"] == "203.0.113.50"
        assert result["source"]["geo"]["city_name"] == "San Francisco"
        assert result["source"]["geo"]["country_name"] == "United States"
        assert result["source"]["geo"]["region_name"] == "California"

    def test_parse_login_event_outcome_success(self, parser, sample_login_event):
        """Test parsing successful login sets correct outcome."""
        result = parser.parse(sample_login_event)

        assert result["event"]["outcome"] == "success"

    def test_parse_login_event_outcome_failure(self, parser, sample_failed_login_event):
        """Test parsing failed login sets correct outcome."""
        result = parser.parse(sample_failed_login_event)

        assert result["event"]["outcome"] == "failure"
        assert result["event"]["reason"] == "INVALID_CREDENTIALS"

    def test_parse_login_event_category(self, parser, sample_login_event):
        """Test parsing login event sets correct category."""
        result = parser.parse(sample_login_event)

        assert "authentication" in result["event"]["category"]

    def test_parse_user_create_event(self, parser, sample_user_create_event):
        """Test parsing user creation event."""
        result = parser.parse(sample_user_create_event)

        assert result["event"]["action"] == "user.lifecycle.create"
        assert "iam" in result["event"]["category"]
        assert "creation" in result["event"]["type"]
        assert len(result["okta"]["target"]) == 1
        assert result["okta"]["target"][0]["alternate_id"] == "newuser@example.com"

    def test_parse_mfa_event(self, parser, sample_mfa_event):
        """Test parsing MFA verification event."""
        result = parser.parse(sample_mfa_event)

        assert result["event"]["action"] == "user.authentication.auth_via_mfa"
        assert "authentication" in result["event"]["category"]
        assert result["okta"]["target"][0]["display_name"] == "Okta Verify"

    def test_parse_policy_event(self, parser, sample_policy_event):
        """Test parsing policy modification event."""
        result = parser.parse(sample_policy_event)

        assert result["event"]["action"] == "policy.lifecycle.update"
        assert "configuration" in result["event"]["category"]
        assert "change" in result["event"]["type"]

    def test_parse_related_fields(self, parser, sample_login_event):
        """Test parsing extracts related fields for correlation."""
        result = parser.parse(sample_login_event)

        assert "203.0.113.50" in result["related"]["ip"]
        assert "john.doe@example.com" in result["related"]["user"]

    def test_parse_okta_specific_fields(self, parser, sample_login_event):
        """Test parsing extracts Okta-specific fields."""
        result = parser.parse(sample_login_event)

        assert result["okta"]["event_type"] == "user.session.start"
        assert result["okta"]["transaction"]["id"] == "txn123"
        assert result["okta"]["authentication_context"]["authentication_provider"] == "OKTA_AUTHENTICATION_PROVIDER"

    def test_parse_preserves_raw_event(self, parser, sample_login_event):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_login_event)

        assert "_raw" in result
        assert result["_raw"] == sample_login_event

    def test_validate_valid_event(self, parser, sample_login_event):
        """Test validation of valid event."""
        assert parser.validate(sample_login_event) is True

    def test_validate_missing_uuid(self, parser):
        """Test validation fails without uuid."""
        event = {
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "user.session.start",
            "actor": {"id": "test"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_published(self, parser):
        """Test validation fails without published."""
        event = {
            "uuid": "test-uuid",
            "eventType": "user.session.start",
            "actor": {"id": "test"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_event_type(self, parser):
        """Test validation fails without eventType."""
        event = {
            "uuid": "test-uuid",
            "published": "2024-01-29T10:30:00.000Z",
            "actor": {"id": "test"}
        }
        assert parser.validate(event) is False

    def test_validate_missing_actor(self, parser):
        """Test validation fails without actor."""
        event = {
            "uuid": "test-uuid",
            "published": "2024-01-29T10:30:00.000Z",
            "eventType": "user.session.start"
        }
        assert parser.validate(event) is False


class TestOktaParserSeverityMapping:
    """Test severity mapping."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

    def test_info_severity(self, parser):
        """Test INFO maps to 20."""
        assert parser._map_severity("INFO") == 20

    def test_warn_severity(self, parser):
        """Test WARN maps to 50."""
        assert parser._map_severity("WARN") == 50

    def test_error_severity(self, parser):
        """Test ERROR maps to 80."""
        assert parser._map_severity("ERROR") == 80

    def test_unknown_severity(self, parser):
        """Test unknown maps to default 20."""
        assert parser._map_severity("UNKNOWN") == 20


class TestOktaParserOutcomeMapping:
    """Test outcome mapping."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

    def test_success_outcome(self, parser):
        """Test SUCCESS maps to success."""
        assert parser._map_outcome("SUCCESS") == "success"

    def test_allow_outcome(self, parser):
        """Test ALLOW maps to success."""
        assert parser._map_outcome("ALLOW") == "success"

    def test_failure_outcome(self, parser):
        """Test FAILURE maps to failure."""
        assert parser._map_outcome("FAILURE") == "failure"

    def test_deny_outcome(self, parser):
        """Test DENY maps to failure."""
        assert parser._map_outcome("DENY") == "failure"

    def test_unknown_outcome(self, parser):
        """Test unknown result maps to unknown."""
        assert parser._map_outcome("SOMETHING_ELSE") == "unknown"


class TestOktaParserEventCategorization:
    """Test event categorization."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

    def test_session_events_categorized_as_authentication(self, parser):
        """Test session events are categorized as authentication."""
        categories = parser._categorize_event("user.session.start")
        assert "authentication" in categories

    def test_authentication_events_categorized(self, parser):
        """Test authentication events are categorized correctly."""
        categories = parser._categorize_event("user.authentication.auth_via_mfa")
        assert "authentication" in categories

    def test_user_create_categorized_as_iam(self, parser):
        """Test user creation is categorized as IAM."""
        categories = parser._categorize_event("user.lifecycle.create")
        assert "iam" in categories

    def test_group_events_categorized_as_iam(self, parser):
        """Test group events are categorized as IAM."""
        categories = parser._categorize_event("group.user_membership.add")
        assert "iam" in categories

    def test_application_events_categorized_as_configuration(self, parser):
        """Test application events are categorized as configuration."""
        categories = parser._categorize_event("application.lifecycle.create")
        assert "configuration" in categories

    def test_policy_events_categorized_as_configuration(self, parser):
        """Test policy events are categorized as configuration."""
        categories = parser._categorize_event("policy.lifecycle.update")
        assert "configuration" in categories

    def test_system_events_categorized_as_configuration(self, parser):
        """Test system events are categorized as configuration."""
        categories = parser._categorize_event("system.api_token.create")
        assert "configuration" in categories

    def test_unknown_events_default_to_session(self, parser):
        """Test unknown events default to session category."""
        categories = parser._categorize_event("some.unknown.event")
        assert categories == ["session"]


class TestOktaParserEventTypes:
    """Test ECS event type determination."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

    def test_create_event_type(self, parser):
        """Test create events get creation type."""
        types = parser._get_event_type("user.lifecycle.create")
        assert "creation" in types

    def test_update_event_type(self, parser):
        """Test update events get change type."""
        types = parser._get_event_type("user.account.update_profile")
        assert "change" in types

    def test_delete_event_type(self, parser):
        """Test delete events get deletion type."""
        types = parser._get_event_type("user.lifecycle.delete")
        assert "deletion" in types

    def test_login_event_type(self, parser):
        """Test login events get start type."""
        types = parser._get_event_type("user.session.login")
        assert "start" in types

    def test_logout_event_type(self, parser):
        """Test logout events get end type."""
        types = parser._get_event_type("user.session.logout")
        assert "end" in types

    def test_deny_event_type(self, parser):
        """Test deny events get denied type."""
        types = parser._get_event_type("app.inbound_del_auth.credentials_denied")
        assert "denied" in types

    def test_allow_event_type(self, parser):
        """Test allow events get allowed type."""
        types = parser._get_event_type("policy.evaluate_sign_on.allow")
        assert "allowed" in types

    def test_unknown_event_type_defaults_to_info(self, parser):
        """Test unknown events default to info type."""
        types = parser._get_event_type("some.other.event")
        assert types == ["info"]


class TestOktaParserTargetExtraction:
    """Test target resource extraction."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

    def test_extract_single_target(self, parser):
        """Test extracting single target."""
        targets = [
            {
                "id": "target-id-1",
                "type": "User",
                "alternateId": "user@example.com",
                "displayName": "Test User"
            }
        ]
        result = parser._extract_targets(targets)

        assert len(result) == 1
        assert result[0]["id"] == "target-id-1"
        assert result[0]["type"] == "User"
        assert result[0]["alternate_id"] == "user@example.com"

    def test_extract_multiple_targets(self, parser):
        """Test extracting multiple targets."""
        targets = [
            {"id": "target-1", "type": "User", "alternateId": "user1@example.com", "displayName": "User 1"},
            {"id": "target-2", "type": "AppInstance", "alternateId": "app-1", "displayName": "App 1"}
        ]
        result = parser._extract_targets(targets)

        assert len(result) == 2
        assert result[0]["id"] == "target-1"
        assert result[1]["id"] == "target-2"

    def test_extract_empty_targets(self, parser):
        """Test extracting empty target list."""
        result = parser._extract_targets([])
        assert result == []


class TestOktaParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

    def test_parse_valid_timestamp(self, parser):
        """Test parsing valid ISO timestamp."""
        result = parser._parse_timestamp("2024-01-29T10:30:00.000Z")
        assert "2024-01-29" in result

    def test_parse_empty_timestamp_returns_current(self, parser):
        """Test empty timestamp returns current time."""
        result = parser._parse_timestamp("")
        assert "T" in result  # ISO format has T separator

    def test_parse_invalid_timestamp_returns_current(self, parser):
        """Test invalid timestamp returns current time."""
        result = parser._parse_timestamp("not-a-timestamp")
        assert "T" in result


class TestOktaParserRemoveNoneValues:
    """Test None value removal."""

    @pytest.fixture
    def parser(self):
        return OktaParser()

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
