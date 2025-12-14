"""Unit tests for Duo Security parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.duo import DuoParser


class TestDuoParser:
    """Tests for DuoParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return DuoParser()

    @pytest.fixture
    def sample_auth_event(self):
        """Sample Duo authentication event."""
        return {
            "txid": "tx-abc123-def456",
            "timestamp": 1706500000,
            "user": {
                "name": "john.doe@example.com",
                "key": "DU123456789ABCDEF",
                "email": "john.doe@example.com",
                "groups": ["Domain Users", "VPN Users"]
            },
            "factor": "Duo Push",
            "result": "SUCCESS",
            "reason": "User approved",
            "event_type": "authentication",
            "access_device": {
                "ip": "203.0.113.50",
                "hostname": "workstation.example.com",
                "browser": "Chrome",
                "browser_version": "120.0.0.0",
                "os": "Windows",
                "os_version": "10",
                "flash_version": "",
                "java_version": "",
                "is_encryption_enabled": True,
                "is_firewall_enabled": True,
                "is_password_set": True,
                "location": {
                    "city": "San Francisco",
                    "state": "California",
                    "country": "US"
                }
            },
            "auth_device": {
                "name": "iPhone",
                "ip": "10.0.0.50",
                "type": "phone",
                "location": {
                    "city": "San Francisco",
                    "state": "California",
                    "country": "US"
                }
            },
            "application": {
                "name": "Corporate VPN",
                "key": "DIKEY123456789ABC"
            },
            "alias": "",
            "email": "john.doe@example.com",
            "isotimestamp": "2024-01-29T00:26:40+00:00",
            "new_enrollment": False,
            "trusted_endpoint_status": "trusted"
        }

    @pytest.fixture
    def sample_admin_event(self):
        """Sample Duo administrator activity event."""
        return {
            "timestamp": 1706500000,
            "username": "admin@example.com",
            "action": "user_create",
            "object": "john.doe@example.com",
            "description": {
                "email": "john.doe@example.com",
                "realname": "John Doe"
            },
            "isotimestamp": "2024-01-29T00:26:40+00:00"
        }

    @pytest.fixture
    def sample_telephony_event(self):
        """Sample Duo telephony event."""
        return {
            "timestamp": 1706500000,
            "phone": "+14155551234",
            "type": "sms",
            "context": "authentication",
            "credits": 1,
            "isotimestamp": "2024-01-29T00:26:40+00:00"
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "duo"

    def test_parse_auth_event_basic_fields(self, parser, sample_auth_event):
        """Test parsing authentication event extracts basic fields."""
        result = parser.parse(sample_auth_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "duo"
        assert result["event"]["module"] == "authentication"

    def test_parse_auth_event_user_fields(self, parser, sample_auth_event):
        """Test parsing authentication event extracts user fields."""
        result = parser.parse(sample_auth_event)

        assert result["user"]["name"] == "john.doe@example.com"
        assert result["user"]["id"] == "DU123456789ABCDEF"
        assert result["user"]["email"] == "john.doe@example.com"

    def test_parse_auth_event_source_fields(self, parser, sample_auth_event):
        """Test parsing authentication event extracts source fields."""
        result = parser.parse(sample_auth_event)

        assert result["source"]["ip"] == "203.0.113.50"
        assert result["source"]["geo"]["city_name"] == "San Francisco"
        assert result["source"]["geo"]["region_name"] == "California"
        assert result["source"]["geo"]["country_iso_code"] == "US"

    def test_parse_auth_event_outcome_success(self, parser, sample_auth_event):
        """Test parsing successful authentication sets correct outcome."""
        result = parser.parse(sample_auth_event)

        assert result["event"]["outcome"] == "success"
        assert result["event"]["action"] == "mfa_duo push"

    def test_parse_auth_event_outcome_failure(self, parser, sample_auth_event):
        """Test parsing failed authentication sets correct outcome."""
        sample_auth_event["result"] = "FAILURE"
        result = parser.parse(sample_auth_event)

        assert result["event"]["outcome"] == "failure"

    def test_parse_auth_event_duo_specific_fields(self, parser, sample_auth_event):
        """Test parsing extracts Duo-specific fields."""
        result = parser.parse(sample_auth_event)

        assert result["duo"]["txid"] == "tx-abc123-def456"
        assert result["duo"]["factor"] == "Duo Push"
        assert result["duo"]["result"] == "SUCCESS"
        assert result["duo"]["integration"] == "Corporate VPN"
        assert result["duo"]["user"]["groups"] == ["Domain Users", "VPN Users"]

    def test_parse_auth_event_related_fields(self, parser, sample_auth_event):
        """Test parsing extracts related fields for correlation."""
        result = parser.parse(sample_auth_event)

        assert "203.0.113.50" in result["related"]["ip"]
        assert "10.0.0.50" in result["related"]["ip"]
        assert "john.doe@example.com" in result["related"]["user"]

    def test_parse_admin_event(self, parser, sample_admin_event):
        """Test parsing administrator activity event."""
        result = parser.parse(sample_admin_event)

        assert result["event"]["provider"] == "duo"
        assert result["event"]["module"] == "admin"
        assert result["event"]["action"] == "user_create"
        assert "creation" in result["event"]["type"]
        assert "iam" in result["event"]["category"]

    def test_parse_admin_event_user_fields(self, parser, sample_admin_event):
        """Test parsing admin event extracts user fields."""
        result = parser.parse(sample_admin_event)

        assert result["user"]["name"] == "admin@example.com"
        assert result["duo"]["object"] == "john.doe@example.com"

    def test_parse_telephony_event(self, parser, sample_telephony_event):
        """Test parsing telephony event."""
        result = parser.parse(sample_telephony_event)

        assert result["event"]["provider"] == "duo"
        assert result["event"]["module"] == "telephony"
        assert result["event"]["action"] == "telephony_sms"
        assert result["duo"]["phone"] == "+14155551234"
        assert result["duo"]["credits"] == 1

    def test_validate_auth_event(self, parser, sample_auth_event):
        """Test validation of authentication event."""
        assert parser.validate(sample_auth_event) is True

    def test_validate_admin_event(self, parser, sample_admin_event):
        """Test validation of admin event."""
        assert parser.validate(sample_admin_event) is True

    def test_validate_telephony_event(self, parser, sample_telephony_event):
        """Test validation of telephony event."""
        assert parser.validate(sample_telephony_event) is True

    def test_validate_missing_timestamp(self, parser):
        """Test validation fails without timestamp."""
        event = {"txid": "test", "factor": "push"}
        assert parser.validate(event) is False

    def test_parse_preserves_raw_event(self, parser, sample_auth_event):
        """Test parsing preserves raw event (with None/empty values cleaned)."""
        result = parser.parse(sample_auth_event)

        assert "_raw" in result
        # Parser cleans None/empty values from _raw, so check key fields
        assert result["_raw"]["txid"] == sample_auth_event["txid"]
        assert result["_raw"]["timestamp"] == sample_auth_event["timestamp"]
        assert result["_raw"]["factor"] == sample_auth_event["factor"]
        assert result["_raw"]["user"]["name"] == sample_auth_event["user"]["name"]

    def test_unix_to_iso_conversion(self, parser):
        """Test Unix timestamp to ISO conversion."""
        iso = parser._unix_to_iso(1706500000)

        # Should be a valid ISO timestamp
        assert "2024-01-29" in iso
        assert iso.endswith("Z") or "+00:00" in iso

    def test_unix_to_iso_handles_zero(self, parser):
        """Test Unix timestamp conversion handles zero."""
        iso = parser._unix_to_iso(0)

        # Should return current time instead
        assert "T" in iso

    def test_remove_none_values(self, parser):
        """Test None value removal from nested dicts."""
        data = {
            "a": "value",
            "b": None,
            "c": {
                "d": "nested",
                "e": None,
                "f": {}
            },
            "g": []
        }

        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result
        assert "d" in result["c"]
        assert "e" not in result["c"]
        assert "f" not in result["c"]  # Empty dict removed
        assert "g" not in result  # Empty list removed


class TestDuoParserEventTypes:
    """Test event type detection and parsing."""

    @pytest.fixture
    def parser(self):
        return DuoParser()

    def test_detects_auth_event_by_txid_and_factor(self, parser):
        """Test auth event detection."""
        event = {"timestamp": 123, "txid": "abc", "factor": "push"}
        result = parser.parse(event)
        assert result["event"]["module"] == "authentication"

    def test_detects_admin_event_by_action_and_object(self, parser):
        """Test admin event detection."""
        event = {"timestamp": 123, "action": "user_delete", "object": "user@test.com"}
        result = parser.parse(event)
        assert result["event"]["module"] == "admin"

    def test_detects_telephony_event_by_credits(self, parser):
        """Test telephony event detection by credits field."""
        event = {"timestamp": 123, "credits": 1}
        result = parser.parse(event)
        assert result["event"]["module"] == "telephony"

    def test_detects_telephony_event_by_phone(self, parser):
        """Test telephony event detection by phone field."""
        event = {"timestamp": 123, "phone": "+1234567890"}
        result = parser.parse(event)
        assert result["event"]["module"] == "telephony"

    def test_generic_fallback_for_unknown_event(self, parser):
        """Test generic parsing for unknown event types."""
        event = {"timestamp": 123, "unknown_field": "value"}
        result = parser.parse(event)
        assert result["event"]["module"] == "generic"


class TestDuoParserAdminActions:
    """Test admin action event type categorization."""

    @pytest.fixture
    def parser(self):
        return DuoParser()

    def test_delete_action_type(self, parser):
        """Test delete actions are categorized correctly."""
        event = {"timestamp": 123, "action": "user_delete", "object": "test"}
        result = parser.parse(event)
        assert "deletion" in result["event"]["type"]

    def test_create_action_type(self, parser):
        """Test create actions are categorized correctly."""
        event = {"timestamp": 123, "action": "user_create", "object": "test"}
        result = parser.parse(event)
        assert "creation" in result["event"]["type"]

    def test_update_action_type(self, parser):
        """Test update actions are categorized correctly."""
        event = {"timestamp": 123, "action": "user_update", "object": "test"}
        result = parser.parse(event)
        assert "change" in result["event"]["type"]

    def test_add_action_type(self, parser):
        """Test add actions are categorized correctly."""
        event = {"timestamp": 123, "action": "group_add_user", "object": "test"}
        result = parser.parse(event)
        assert "creation" in result["event"]["type"]
