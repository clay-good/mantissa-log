"""Unit tests for Microsoft 365 Management Activity parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.microsoft365 import Microsoft365Parser


class TestMicrosoft365Parser:
    """Tests for Microsoft365Parser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return Microsoft365Parser()

    @pytest.fixture
    def sample_aad_login_event(self):
        """Sample Azure AD login event."""
        return {
            "RecordType": 15,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-123",
            "Operation": "UserLoggedIn",
            "OrganizationId": "org-123-456",
            "UserId": "john.doe@example.com",
            "UserType": 0,
            "UserKey": "user-key-123",
            "Workload": "AzureActiveDirectory",
            "ClientIP": "203.0.113.50",
            "ResultStatus": "Success"
        }

    @pytest.fixture
    def sample_aad_failed_login_event(self):
        """Sample Azure AD failed login event."""
        return {
            "RecordType": 15,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-456",
            "Operation": "UserLoginFailed",
            "OrganizationId": "org-123-456",
            "UserId": "john.doe@example.com",
            "UserType": 0,
            "UserKey": "user-key-123",
            "Workload": "AzureActiveDirectory",
            "ClientIP": "203.0.113.100",
            "ResultStatus": "Failed"
        }

    @pytest.fixture
    def sample_sharepoint_file_event(self):
        """Sample SharePoint file access event."""
        return {
            "RecordType": 6,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-789",
            "Operation": "FileAccessed",
            "OrganizationId": "org-123-456",
            "UserId": "john.doe@example.com",
            "UserType": 0,
            "Workload": "SharePoint",
            "ClientIP": "10.0.0.50",
            "ObjectId": "https://example.sharepoint.com/sites/docs/file.docx",
            "ItemType": "File",
            "SiteUrl": "https://example.sharepoint.com/sites/docs",
            "SourceFileName": "file.docx",
            "SourceRelativeUrl": "sites/docs/",
            "ResultStatus": "Success"
        }

    @pytest.fixture
    def sample_exchange_mailbox_event(self):
        """Sample Exchange mailbox event."""
        return {
            "RecordType": 2,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-exchange",
            "Operation": "MailboxLogin",
            "OrganizationId": "org-123-456",
            "UserId": "jane.doe@example.com",
            "UserType": 0,
            "Workload": "Exchange",
            "ClientIP": "192.168.1.100",
            "ResultStatus": "Success"
        }

    @pytest.fixture
    def sample_exchange_admin_event(self):
        """Sample Exchange admin cmdlet event."""
        return {
            "RecordType": 1,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-admin",
            "Operation": "New-InboxRule",
            "OrganizationId": "org-123-456",
            "UserId": "admin@example.com",
            "UserType": 2,
            "Workload": "Exchange",
            "ClientIP": "10.0.0.10",
            "ResultStatus": "Success",
            "Parameters": [
                {"Name": "Name", "Value": "Forward All"},
                {"Name": "ForwardTo", "Value": "external@attacker.com"}
            ]
        }

    @pytest.fixture
    def sample_teams_event(self):
        """Sample Microsoft Teams event."""
        return {
            "RecordType": 25,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-teams",
            "Operation": "TeamCreated",
            "OrganizationId": "org-123-456",
            "UserId": "john.doe@example.com",
            "UserType": 0,
            "Workload": "MicrosoftTeams",
            "ClientIP": "10.0.0.50",
            "ResultStatus": "Success"
        }

    @pytest.fixture
    def sample_dlp_event(self):
        """Sample DLP event."""
        return {
            "RecordType": 28,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "event-uuid-dlp",
            "Operation": "DlpRuleMatch",
            "OrganizationId": "org-123-456",
            "UserId": "john.doe@example.com",
            "UserType": 0,
            "Workload": "DLP",
            "ClientIP": "10.0.0.50",
            "ResultStatus": "Success"
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "microsoft365"

    def test_parse_aad_login_basic_fields(self, parser, sample_aad_login_event):
        """Test parsing Azure AD login event extracts basic fields."""
        result = parser.parse(sample_aad_login_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "microsoft365"
        assert result["event"]["module"] == "azureactivedirectory"
        assert result["event"]["action"] == "UserLoggedIn"

    def test_parse_aad_login_user_fields(self, parser, sample_aad_login_event):
        """Test parsing Azure AD login event extracts user fields."""
        result = parser.parse(sample_aad_login_event)

        assert result["user"]["email"] == "john.doe@example.com"
        assert result["user"]["name"] == "john.doe"
        assert result["user"]["id"] == "user-key-123"

    def test_parse_aad_login_source_fields(self, parser, sample_aad_login_event):
        """Test parsing Azure AD login event extracts source fields."""
        result = parser.parse(sample_aad_login_event)

        assert result["source"]["ip"] == "203.0.113.50"

    def test_parse_aad_login_outcome_success(self, parser, sample_aad_login_event):
        """Test parsing successful login sets correct outcome."""
        result = parser.parse(sample_aad_login_event)

        assert result["event"]["outcome"] == "success"

    def test_parse_aad_login_outcome_failure(self, parser, sample_aad_failed_login_event):
        """Test parsing failed login sets correct outcome."""
        result = parser.parse(sample_aad_failed_login_event)

        assert result["event"]["outcome"] == "failure"

    def test_parse_aad_login_category(self, parser, sample_aad_login_event):
        """Test parsing Azure AD login sets correct category."""
        result = parser.parse(sample_aad_login_event)

        assert "authentication" in result["event"]["category"]

    def test_parse_aad_login_type(self, parser, sample_aad_login_event):
        """Test parsing login event sets correct type."""
        result = parser.parse(sample_aad_login_event)

        assert "start" in result["event"]["type"]

    def test_parse_sharepoint_file_event(self, parser, sample_sharepoint_file_event):
        """Test parsing SharePoint file access event."""
        result = parser.parse(sample_sharepoint_file_event)

        assert result["event"]["action"] == "FileAccessed"
        assert result["event"]["module"] == "sharepoint"
        assert "file" in result["event"]["category"]
        assert "access" in result["event"]["type"]
        assert result["microsoft365"]["source_file_name"] == "file.docx"
        assert "sharepoint.com" in result["microsoft365"]["site_url"]

    def test_parse_exchange_mailbox_event(self, parser, sample_exchange_mailbox_event):
        """Test parsing Exchange mailbox event."""
        result = parser.parse(sample_exchange_mailbox_event)

        assert result["event"]["action"] == "MailboxLogin"
        assert result["event"]["module"] == "exchange"
        assert "email" in result["event"]["category"]

    def test_parse_exchange_admin_event(self, parser, sample_exchange_admin_event):
        """Test parsing Exchange admin event."""
        result = parser.parse(sample_exchange_admin_event)

        assert result["event"]["action"] == "New-InboxRule"
        assert "configuration" in result["event"]["category"]
        assert "creation" in result["event"]["type"]
        assert len(result["microsoft365"]["parameters"]) == 2

    def test_parse_teams_event(self, parser, sample_teams_event):
        """Test parsing Microsoft Teams event."""
        result = parser.parse(sample_teams_event)

        assert result["event"]["action"] == "TeamCreated"
        assert result["event"]["module"] == "microsoftteams"

    def test_parse_dlp_event(self, parser, sample_dlp_event):
        """Test parsing DLP event."""
        result = parser.parse(sample_dlp_event)

        assert result["event"]["action"] == "DlpRuleMatch"
        assert "intrusion_detection" in result["event"]["category"]

    def test_parse_related_fields(self, parser, sample_aad_login_event):
        """Test parsing extracts related fields for correlation."""
        result = parser.parse(sample_aad_login_event)

        assert "203.0.113.50" in result["related"]["ip"]
        assert "john.doe@example.com" in result["related"]["user"]

    def test_parse_microsoft365_specific_fields(self, parser, sample_aad_login_event):
        """Test parsing extracts Microsoft 365-specific fields."""
        result = parser.parse(sample_aad_login_event)

        assert result["microsoft365"]["record_type"] == 15
        assert result["microsoft365"]["record_type_name"] == "AzureActiveDirectoryStsLogon"
        assert result["microsoft365"]["workload"] == "AzureActiveDirectory"
        assert result["microsoft365"]["organization_id"] == "org-123-456"

    def test_parse_preserves_raw_event(self, parser, sample_aad_login_event):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_aad_login_event)

        assert "_raw" in result
        assert result["_raw"] == sample_aad_login_event

    def test_validate_valid_event(self, parser, sample_aad_login_event):
        """Test validation of valid event."""
        assert parser.validate(sample_aad_login_event) is True

    def test_validate_missing_record_type(self, parser):
        """Test validation fails without RecordType."""
        event = {
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "test",
            "Operation": "Test",
            "Workload": "Test"
        }
        assert parser.validate(event) is False

    def test_validate_missing_creation_time(self, parser):
        """Test validation fails without CreationTime."""
        event = {
            "RecordType": 15,
            "Id": "test",
            "Operation": "Test",
            "Workload": "Test"
        }
        assert parser.validate(event) is False

    def test_validate_missing_operation(self, parser):
        """Test validation fails without Operation."""
        event = {
            "RecordType": 15,
            "CreationTime": "2024-01-29T10:30:00Z",
            "Id": "test",
            "Workload": "Test"
        }
        assert parser.validate(event) is False


class TestMicrosoft365ParserEventCategorization:
    """Test event categorization."""

    @pytest.fixture
    def parser(self):
        return Microsoft365Parser()

    def test_azure_ad_categorized_as_authentication(self, parser):
        """Test Azure AD events are categorized as authentication."""
        categories = parser._categorize_event(15, "AzureActiveDirectory", "UserLoggedIn")
        assert "authentication" in categories

    def test_azure_ad_user_events_categorized_as_iam(self, parser):
        """Test Azure AD user events are categorized as IAM."""
        categories = parser._categorize_event(8, "AzureActiveDirectory", "AddUser")
        assert "iam" in categories

    def test_exchange_categorized_as_email(self, parser):
        """Test Exchange events are categorized as email."""
        categories = parser._categorize_event(2, "Exchange", "MailboxLogin")
        assert "email" in categories

    def test_sharepoint_categorized_as_file(self, parser):
        """Test SharePoint events are categorized as file."""
        categories = parser._categorize_event(6, "SharePoint", "FileAccessed")
        assert "file" in categories

    def test_dlp_categorized_as_intrusion_detection(self, parser):
        """Test DLP events are categorized as intrusion detection."""
        categories = parser._categorize_event(28, "DLP", "DlpRuleMatch")
        assert "intrusion_detection" in categories

    def test_new_cmdlet_categorized_as_configuration(self, parser):
        """Test new-* cmdlets are categorized as configuration."""
        categories = parser._categorize_event(1, "Exchange", "New-InboxRule")
        assert "configuration" in categories

    def test_set_cmdlet_categorized_as_configuration(self, parser):
        """Test set-* cmdlets are categorized as configuration."""
        categories = parser._categorize_event(1, "Exchange", "Set-Mailbox")
        assert "configuration" in categories

    def test_unknown_events_default_to_session(self, parser):
        """Test unknown events default to session category."""
        categories = parser._categorize_event(999, "Unknown", "UnknownOperation")
        assert categories == ["session"]


class TestMicrosoft365ParserEventTypes:
    """Test ECS event type determination."""

    @pytest.fixture
    def parser(self):
        return Microsoft365Parser()

    def test_new_cmdlet_event_type(self, parser):
        """Test new-* cmdlets get creation type."""
        types = parser._get_event_type("New-InboxRule")
        assert "creation" in types

    def test_add_event_type(self, parser):
        """Test add actions get creation type."""
        types = parser._get_event_type("AddUser")
        assert "creation" in types

    def test_set_cmdlet_event_type(self, parser):
        """Test set-* cmdlets get change type."""
        types = parser._get_event_type("Set-Mailbox")
        assert "change" in types

    def test_update_event_type(self, parser):
        """Test update actions get change type."""
        types = parser._get_event_type("UpdateGroup")
        assert "change" in types

    def test_remove_cmdlet_event_type(self, parser):
        """Test remove-* cmdlets get deletion type."""
        types = parser._get_event_type("Remove-InboxRule")
        assert "deletion" in types

    def test_login_event_type(self, parser):
        """Test login events get start type."""
        types = parser._get_event_type("UserLoggedIn")
        assert "start" in types

    def test_file_accessed_event_type(self, parser):
        """Test file accessed events get access type."""
        types = parser._get_event_type("FileAccessed")
        assert "access" in types

    def test_denied_event_type(self, parser):
        """Test denied events get denied type."""
        types = parser._get_event_type("AccessDenied")
        assert "denied" in types

    def test_unknown_event_type_defaults_to_info(self, parser):
        """Test unknown events default to info type."""
        types = parser._get_event_type("SomeOtherOperation")
        assert types == ["info"]


class TestMicrosoft365ParserResultStatus:
    """Test result status mapping."""

    @pytest.fixture
    def parser(self):
        return Microsoft365Parser()

    def test_success_status(self, parser):
        """Test Success maps to success."""
        assert parser._map_result_status("Success") == "success"

    def test_succeeded_status(self, parser):
        """Test Succeeded maps to success."""
        assert parser._map_result_status("Succeeded") == "success"

    def test_partially_processed_status(self, parser):
        """Test PartiallyProcessed maps to success."""
        assert parser._map_result_status("PartiallyProcessed") == "success"

    def test_failed_status(self, parser):
        """Test Failed maps to failure."""
        assert parser._map_result_status("Failed") == "failure"

    def test_failure_status(self, parser):
        """Test Failure maps to failure."""
        assert parser._map_result_status("Failure") == "failure"

    def test_empty_status(self, parser):
        """Test empty status maps to unknown."""
        assert parser._map_result_status("") == "unknown"

    def test_unknown_status(self, parser):
        """Test unknown status maps to unknown."""
        assert parser._map_result_status("SomeOtherStatus") == "unknown"


class TestMicrosoft365ParserRecordTypeName:
    """Test record type name mapping."""

    @pytest.fixture
    def parser(self):
        return Microsoft365Parser()

    def test_exchange_admin_record_type(self, parser):
        """Test ExchangeAdmin record type name."""
        assert parser._get_record_type_name(1) == "ExchangeAdmin"

    def test_exchange_item_record_type(self, parser):
        """Test ExchangeItem record type name."""
        assert parser._get_record_type_name(2) == "ExchangeItem"

    def test_sharepoint_record_type(self, parser):
        """Test SharePoint record type name."""
        assert parser._get_record_type_name(4) == "SharePoint"

    def test_azure_ad_record_type(self, parser):
        """Test AzureActiveDirectory record type name."""
        assert parser._get_record_type_name(8) == "AzureActiveDirectory"

    def test_azure_ad_sts_logon_record_type(self, parser):
        """Test AzureActiveDirectoryStsLogon record type name."""
        assert parser._get_record_type_name(15) == "AzureActiveDirectoryStsLogon"

    def test_teams_record_type(self, parser):
        """Test MicrosoftTeams record type name."""
        assert parser._get_record_type_name(25) == "MicrosoftTeams"

    def test_threat_intelligence_record_type(self, parser):
        """Test ThreatIntelligence record type name."""
        assert parser._get_record_type_name(28) == "ThreatIntelligence"

    def test_unknown_record_type(self, parser):
        """Test unknown record type returns Unknown_N."""
        assert parser._get_record_type_name(999) == "Unknown_999"


class TestMicrosoft365ParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return Microsoft365Parser()

    def test_parse_valid_timestamp(self, parser):
        """Test parsing valid ISO timestamp."""
        result = parser._parse_timestamp("2024-01-29T10:30:00Z")
        assert "2024-01-29" in result

    def test_parse_empty_timestamp_returns_current(self, parser):
        """Test empty timestamp returns current time."""
        result = parser._parse_timestamp("")
        assert "T" in result  # ISO format has T separator

    def test_parse_invalid_timestamp_returns_current(self, parser):
        """Test invalid timestamp returns current time."""
        result = parser._parse_timestamp("not-a-timestamp")
        assert "T" in result


class TestMicrosoft365ParserRemoveNoneValues:
    """Test None value removal."""

    @pytest.fixture
    def parser(self):
        return Microsoft365Parser()

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
