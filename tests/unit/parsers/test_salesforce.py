"""Unit tests for Salesforce parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.salesforce import SalesforceParser


class TestSalesforceParser:
    """Tests for SalesforceParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SalesforceParser()

    @pytest.fixture
    def sample_event_log_api(self):
        """Sample Salesforce API EventLogFile event."""
        return {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "USER_ID": "005000000000001AAA",
            "USER_NAME": "admin@example.com",
            "CLIENT_IP": "192.168.1.100",
            "SESSION_KEY": "session123abc",
            "REQUEST_ID": "req-abc-123",
            "URI": "/services/data/v58.0/sobjects/Account",
            "METHOD": "GET",
            "STATUS_CODE": "200",
            "API_TYPE": "REST",
            "API_VERSION": "58.0",
            "CPU_TIME": 150,
            "DB_TOTAL_TIME": 200,
            "RUN_TIME": 350,
            "ROWS_PROCESSED": 10,
            "ORGANIZATION_ID": "00D000000000001AAA",
            "USER_AGENT": "Mozilla/5.0",
            "SUCCESS": True
        }

    @pytest.fixture
    def sample_login_event(self):
        """Sample Salesforce Login History event."""
        return {
            "UserId": "005000000000002BBB",
            "Username": "user@example.com",
            "LoginTime": "2024-01-28T10:00:00.000Z",
            "SourceIp": "10.0.0.50",
            "LoginType": "SAML Sfdc Initiated",
            "Status": "Success",
            "Platform": "Windows 10",
            "Browser": "Chrome 120.0",
            "Application": "Salesforce for Outlook",
            "LoginGeoId": "geo123",
            "ApiType": "Partner SOAP",
            "ApiVersion": "58.0",
            "CipherSuite": "TLS_AES_128_GCM_SHA256",
            "CountryIso": "US",
            "LoginUrl": "https://login.salesforce.com",
            "TlsProtocol": "TLSv1.3"
        }

    @pytest.fixture
    def sample_failed_login_event(self):
        """Sample Salesforce failed login event."""
        return {
            "UserId": "005000000000003CCC",
            "Username": "attacker@example.com",
            "LoginTime": "2024-01-28T11:00:00.000Z",
            "SourceIp": "203.0.113.100",
            "LoginType": "Application",
            "Status": "Invalid Password",
            "Platform": "Unknown",
            "Browser": "Unknown"
        }

    @pytest.fixture
    def sample_audit_trail_event(self):
        """Sample Salesforce Setup Audit Trail event."""
        return {
            "Id": "0YM000000000001AAA",
            "CreatedDate": "2024-01-28T09:00:00.000Z",
            "CreatedById": "005000000000001AAA",
            "CreatedByName": "System Admin",
            "Action": "changedPermissionSetGroupAssignment",
            "Section": "Permission Sets",
            "Display": "Assigned permission set group SalesAdmin to user John Doe",
            "DelegateUser": "",
            "ResponsibleNamespacePrefix": ""
        }

    @pytest.fixture
    def sample_report_export_event(self):
        """Sample Salesforce Report Export event."""
        return {
            "EventType": "ReportExport",
            "TIMESTAMP_DERIVED": "2024-01-28T14:00:00.000Z",
            "USER_ID": "005000000000004DDD",
            "USER_NAME": "analyst@example.com",
            "CLIENT_IP": "192.168.1.200",
            "REPORT_ID": "00O000000000001AAA",
            "ROWS_PROCESSED": 50000,
            "NUMBER_COLUMNS": 25,
            "STATUS_CODE": "200",
            "SUCCESS": True
        }

    @pytest.fixture
    def sample_apex_execution_event(self):
        """Sample Salesforce Apex Execution event."""
        return {
            "EventType": "ApexExecution",
            "TIMESTAMP_DERIVED": "2024-01-28T15:00:00.000Z",
            "USER_ID": "005000000000005EEE",
            "USER_NAME": "developer@example.com",
            "CLIENT_IP": "192.168.1.150",
            "ENTRY_POINT": "AccountTrigger.handleBeforeInsert",
            "CPU_TIME": 500,
            "DB_TOTAL_TIME": 1000,
            "RUN_TIME": 1500,
            "SUCCESS": True
        }

    @pytest.fixture
    def sample_login_as_event(self):
        """Sample Salesforce LoginAs event."""
        return {
            "EventType": "LoginAs",
            "TIMESTAMP_DERIVED": "2024-01-28T16:00:00.000Z",
            "USER_ID": "005000000000001AAA",
            "USER_NAME": "admin@example.com",
            "TARGET_USER_ID": "005000000000006FFF",
            "TARGET_USER_NAME": "targetuser@example.com",
            "CLIENT_IP": "192.168.1.100",
            "SUCCESS": True
        }

    def test_parser_source_type(self, parser):
        """Test parser returns correct source type."""
        assert parser.source_type == "salesforce"

    def test_validate_event_log_format(self, parser, sample_event_log_api):
        """Test validation of EventLogFile format."""
        assert parser.validate(sample_event_log_api) is True

    def test_validate_login_history_format(self, parser, sample_login_event):
        """Test validation of Login History format."""
        assert parser.validate(sample_login_event) is True

    def test_validate_audit_trail_format(self, parser, sample_audit_trail_event):
        """Test validation of Setup Audit Trail format."""
        assert parser.validate(sample_audit_trail_event) is True

    def test_validate_generic_with_timestamp(self, parser):
        """Test validation of generic event with timestamp."""
        assert parser.validate({"TIMESTAMP_DERIVED": "2024-01-28T12:00:00Z"}) is True
        assert parser.validate({"CreatedDate": "2024-01-28T12:00:00Z"}) is True

    def test_validate_invalid_event(self, parser):
        """Test validation of invalid event."""
        assert parser.validate({}) is False
        assert parser.validate({"random_field": "value"}) is False


class TestSalesforceParserEventLogFile:
    """Tests for EventLogFile parsing."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    @pytest.fixture
    def api_event(self):
        return {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "USER_ID": "005000000000001AAA",
            "USER_NAME": "admin@example.com",
            "CLIENT_IP": "192.168.1.100",
            "REQUEST_ID": "req-abc-123",
            "URI": "/services/data/v58.0/sobjects/Account",
            "METHOD": "GET",
            "STATUS_CODE": "200",
            "API_TYPE": "REST",
            "API_VERSION": "58.0",
            "CPU_TIME": 150,
            "RUN_TIME": 350,
            "ORGANIZATION_ID": "00D000000000001AAA"
        }

    def test_parse_api_event_basic_fields(self, parser, api_event):
        """Test parsing API event extracts basic ECS fields."""
        result = parser.parse(api_event)

        assert result['event']['action'] == 'api'
        assert result['event']['outcome'] == 'success'
        assert result['event']['provider'] == 'salesforce'
        assert 'web' in result['event']['category']

    def test_parse_api_event_user_fields(self, parser, api_event):
        """Test parsing API event extracts user fields."""
        result = parser.parse(api_event)

        assert result['user']['id'] == '005000000000001AAA'
        assert result['user']['name'] == 'admin@example.com'
        assert result['user']['email'] == 'admin@example.com'

    def test_parse_api_event_source_fields(self, parser, api_event):
        """Test parsing API event extracts source fields."""
        result = parser.parse(api_event)

        assert result['source']['ip'] == '192.168.1.100'

    def test_parse_api_event_url_fields(self, parser, api_event):
        """Test parsing API event extracts URL fields."""
        result = parser.parse(api_event)

        assert result['url']['path'] == '/services/data/v58.0/sobjects/Account'
        assert result['url']['original'] == '/services/data/v58.0/sobjects/Account'

    def test_parse_api_event_http_fields(self, parser, api_event):
        """Test parsing API event extracts HTTP fields."""
        result = parser.parse(api_event)

        assert result['http']['request']['method'] == 'GET'
        assert result['http']['response']['status_code'] == 200

    def test_parse_api_event_salesforce_fields(self, parser, api_event):
        """Test parsing API event extracts Salesforce-specific fields."""
        result = parser.parse(api_event)

        assert result['salesforce']['event_type'] == 'API'
        assert result['salesforce']['api']['type'] == 'REST'
        assert result['salesforce']['api']['version'] == '58.0'
        assert result['salesforce']['organization_id'] == '00D000000000001AAA'

    def test_parse_api_event_performance_metrics(self, parser, api_event):
        """Test parsing API event extracts performance metrics."""
        result = parser.parse(api_event)

        assert result['salesforce']['performance']['cpu_time'] == 150
        assert result['salesforce']['performance']['run_time'] == 350

    def test_parse_api_event_related_fields(self, parser, api_event):
        """Test parsing API event extracts related fields."""
        result = parser.parse(api_event)

        assert '192.168.1.100' in result['related']['ip']
        assert 'admin@example.com' in result['related']['user']

    def test_parse_event_preserves_raw(self, parser, api_event):
        """Test raw event is preserved."""
        result = parser.parse(api_event)

        assert '_raw' in result
        assert result['_raw']['EventType'] == 'API'

    def test_parse_report_export_event(self, parser):
        """Test parsing Report Export event."""
        event = {
            "EventType": "ReportExport",
            "TIMESTAMP_DERIVED": "2024-01-28T14:00:00.000Z",
            "USER_ID": "005000000000004DDD",
            "USER_NAME": "analyst@example.com",
            "ROWS_PROCESSED": 50000,
            "STATUS_CODE": "200"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'reportexport'
        assert 'file' in result['event']['category']
        assert 'access' in result['event']['type']

    def test_parse_apex_execution_event(self, parser):
        """Test parsing Apex Execution event."""
        event = {
            "EventType": "ApexExecution",
            "TIMESTAMP_DERIVED": "2024-01-28T15:00:00.000Z",
            "USER_ID": "005000000000005EEE",
            "CPU_TIME": 500,
            "SUCCESS": True
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'apexexecution'
        assert 'process' in result['event']['category']


class TestSalesforceParserLoginHistory:
    """Tests for Login History parsing."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    @pytest.fixture
    def success_login(self):
        return {
            "UserId": "005000000000002BBB",
            "Username": "user@example.com",
            "LoginTime": "2024-01-28T10:00:00.000Z",
            "SourceIp": "10.0.0.50",
            "LoginType": "SAML Sfdc Initiated",
            "Status": "Success",
            "Platform": "Windows 10",
            "Browser": "Chrome 120.0",
            "Application": "Browser",
            "TlsProtocol": "TLSv1.3",
            "CountryIso": "US"
        }

    @pytest.fixture
    def failed_login(self):
        return {
            "UserId": "005000000000003CCC",
            "Username": "attacker@example.com",
            "LoginTime": "2024-01-28T11:00:00.000Z",
            "SourceIp": "203.0.113.100",
            "LoginType": "Application",
            "Status": "Invalid Password"
        }

    def test_parse_successful_login_basic_fields(self, parser, success_login):
        """Test parsing successful login extracts basic ECS fields."""
        result = parser.parse(success_login)

        assert result['event']['action'] == 'user_login'
        assert result['event']['outcome'] == 'success'
        assert 'authentication' in result['event']['category']
        assert 'start' in result['event']['type']

    def test_parse_successful_login_user_fields(self, parser, success_login):
        """Test parsing successful login extracts user fields."""
        result = parser.parse(success_login)

        assert result['user']['id'] == '005000000000002BBB'
        assert result['user']['name'] == 'user@example.com'
        assert result['user']['email'] == 'user@example.com'

    def test_parse_successful_login_source_fields(self, parser, success_login):
        """Test parsing successful login extracts source fields."""
        result = parser.parse(success_login)

        assert result['source']['ip'] == '10.0.0.50'

    def test_parse_successful_login_user_agent_fields(self, parser, success_login):
        """Test parsing successful login extracts user agent fields."""
        result = parser.parse(success_login)

        assert result['user_agent']['name'] == 'Chrome 120.0'
        assert result['user_agent']['os']['name'] == 'Windows 10'

    def test_parse_successful_login_salesforce_fields(self, parser, success_login):
        """Test parsing successful login extracts Salesforce-specific fields."""
        result = parser.parse(success_login)

        assert result['salesforce']['login']['type'] == 'SAML Sfdc Initiated'
        assert result['salesforce']['login']['status'] == 'Success'
        assert result['salesforce']['login']['application'] == 'Browser'
        assert result['salesforce']['login']['tls_protocol'] == 'TLSv1.3'
        assert result['salesforce']['login']['country_iso'] == 'US'

    def test_parse_failed_login_outcome(self, parser, failed_login):
        """Test parsing failed login sets correct outcome."""
        result = parser.parse(failed_login)

        assert result['event']['outcome'] == 'failure'
        assert result['event']['reason'] == 'Invalid Password'
        assert 'info' in result['event']['type']  # Not 'start' for failures

    def test_parse_lockout_login(self, parser):
        """Test parsing user lockout event."""
        event = {
            "UserId": "005000000000004DDD",
            "Username": "locked@example.com",
            "LoginTime": "2024-01-28T11:30:00.000Z",
            "SourceIp": "198.51.100.50",
            "LoginType": "Application",
            "Status": "User Lockout"
        }
        result = parser.parse(event)

        assert result['event']['outcome'] == 'failure'

    def test_parse_login_various_status_codes(self, parser):
        """Test parsing various login status codes."""
        statuses = {
            'Success': 'success',
            'Invalid Password': 'failure',
            'Invalid Credentials': 'failure',
            'User Lockout': 'failure',
            'Failed': 'failure',
            'Pending': 'unknown'
        }

        for status, expected_outcome in statuses.items():
            event = {
                "UserId": "005test",
                "Username": "test@example.com",
                "Status": status
            }
            result = parser.parse(event)
            assert result['event']['outcome'] == expected_outcome, f"Status '{status}' should map to '{expected_outcome}'"


class TestSalesforceParserAuditTrail:
    """Tests for Setup Audit Trail parsing."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    @pytest.fixture
    def permission_change(self):
        return {
            "Id": "0YM000000000001AAA",
            "CreatedDate": "2024-01-28T09:00:00.000Z",
            "CreatedById": "005000000000001AAA",
            "CreatedByName": "System Admin",
            "Action": "changedPermissionSetGroupAssignment",
            "Section": "Permission Sets",
            "Display": "Assigned permission set group SalesAdmin to user John Doe"
        }

    def test_parse_audit_trail_basic_fields(self, parser, permission_change):
        """Test parsing audit trail extracts basic ECS fields."""
        result = parser.parse(permission_change)

        assert result['event']['action'] == 'changedpermissionsetgroupassignment'
        assert result['event']['outcome'] == 'success'
        assert result['event']['provider'] == 'salesforce'
        assert result['event']['module'] == 'setup_audit_trail'
        assert 'configuration' in result['event']['category']
        assert 'iam' in result['event']['category']

    def test_parse_audit_trail_user_fields(self, parser, permission_change):
        """Test parsing audit trail extracts user fields."""
        result = parser.parse(permission_change)

        assert result['user']['id'] == '005000000000001AAA'
        assert result['user']['name'] == 'System Admin'

    def test_parse_audit_trail_message(self, parser, permission_change):
        """Test parsing audit trail extracts message."""
        result = parser.parse(permission_change)

        assert result['message'] == 'Assigned permission set group SalesAdmin to user John Doe'

    def test_parse_audit_trail_salesforce_fields(self, parser, permission_change):
        """Test parsing audit trail extracts Salesforce-specific fields."""
        result = parser.parse(permission_change)

        assert result['salesforce']['audit_trail']['action'] == 'changedPermissionSetGroupAssignment'
        assert result['salesforce']['audit_trail']['section'] == 'Permission Sets'
        assert result['salesforce']['id'] == '0YM000000000001AAA'

    def test_parse_audit_trail_with_delegate(self, parser):
        """Test parsing audit trail with delegate user."""
        event = {
            "CreatedDate": "2024-01-28T09:30:00.000Z",
            "CreatedById": "005000000000001AAA",
            "CreatedByName": "Admin Support",
            "Action": "createdUser",
            "Section": "Users",
            "Display": "Created user account for new.employee@example.com",
            "DelegateUser": "support@example.com"
        }
        result = parser.parse(event)

        assert result['salesforce']['audit_trail']['delegate_user'] == 'support@example.com'
        assert 'support@example.com' in result['related']['user']

    def test_parse_audit_trail_event_type_creation(self, parser):
        """Test audit trail creation action maps to creation type."""
        event = {
            "CreatedDate": "2024-01-28T10:00:00.000Z",
            "CreatedById": "005test",
            "Action": "Created new profile",
            "Section": "Profiles"
        }
        result = parser.parse(event)

        assert 'creation' in result['event']['type']

    def test_parse_audit_trail_event_type_deletion(self, parser):
        """Test audit trail deletion action maps to deletion type."""
        event = {
            "CreatedDate": "2024-01-28T10:00:00.000Z",
            "CreatedById": "005test",
            "Action": "Deleted user account",
            "Section": "Users"
        }
        result = parser.parse(event)

        assert 'deletion' in result['event']['type']

    def test_parse_audit_trail_event_type_granted(self, parser):
        """Test audit trail granted action maps to allowed type."""
        event = {
            "CreatedDate": "2024-01-28T10:00:00.000Z",
            "CreatedById": "005test",
            "Action": "Granted login access",
            "Section": "Security"
        }
        result = parser.parse(event)

        assert 'allowed' in result['event']['type']


class TestSalesforceParserGenericEvents:
    """Tests for generic event parsing."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_parse_generic_event(self, parser):
        """Test parsing generic event with only timestamp."""
        event = {
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "custom_field": "custom_value"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'salesforce_event'
        assert result['event']['outcome'] == 'unknown'
        assert result['event']['provider'] == 'salesforce'
        assert result['event']['module'] == 'generic'

    def test_parse_event_with_created_date(self, parser):
        """Test parsing event with CreatedDate timestamp."""
        event = {
            "CreatedDate": "2024-01-28T12:00:00.000Z"
        }
        result = parser.parse(event)

        assert '@timestamp' in result


class TestSalesforceParserOutcomeDetection:
    """Tests for outcome detection."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_outcome_from_success_field_true(self, parser):
        """Test outcome from SUCCESS field when true."""
        outcome = parser._determine_outcome('', {"SUCCESS": True})
        assert outcome == 'success'

    def test_outcome_from_success_field_false(self, parser):
        """Test outcome from SUCCESS field when false."""
        outcome = parser._determine_outcome('', {"SUCCESS": False})
        assert outcome == 'failure'

    def test_outcome_from_is_success_field(self, parser):
        """Test outcome from IsSuccess field."""
        outcome = parser._determine_outcome('', {"IsSuccess": True})
        assert outcome == 'success'

    def test_outcome_from_status_code_200(self, parser):
        """Test outcome from 2xx status code."""
        outcome = parser._determine_outcome('200', {})
        assert outcome == 'success'

    def test_outcome_from_status_code_201(self, parser):
        """Test outcome from 201 status code."""
        outcome = parser._determine_outcome('201', {})
        assert outcome == 'success'

    def test_outcome_from_status_code_400(self, parser):
        """Test outcome from 4xx status code."""
        outcome = parser._determine_outcome('400', {})
        assert outcome == 'failure'

    def test_outcome_from_status_code_500(self, parser):
        """Test outcome from 5xx status code."""
        outcome = parser._determine_outcome('500', {})
        assert outcome == 'failure'

    def test_outcome_from_request_status_success(self, parser):
        """Test outcome from REQUEST_STATUS success."""
        outcome = parser._determine_outcome('', {"REQUEST_STATUS": "S"})
        assert outcome == 'success'

    def test_outcome_from_request_status_failure(self, parser):
        """Test outcome from REQUEST_STATUS failure."""
        outcome = parser._determine_outcome('', {"REQUEST_STATUS": "F"})
        assert outcome == 'failure'

    def test_outcome_unknown_for_empty_event(self, parser):
        """Test outcome unknown when no indicators."""
        outcome = parser._determine_outcome('', {})
        assert outcome == 'unknown'


class TestSalesforceParserEventTypeMapping:
    """Tests for event type mapping."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_login_event_type_is_start(self, parser):
        """Test Login event type maps to start."""
        types = parser._get_event_type('Login')
        assert 'start' in types

    def test_logout_event_type_is_end(self, parser):
        """Test Logout event type maps to end."""
        types = parser._get_event_type('Logout')
        assert 'end' in types

    def test_create_event_type_is_creation(self, parser):
        """Test create-related events map to creation."""
        types = parser._get_event_type('ContentCreate')
        assert 'creation' in types

    def test_update_event_type_is_change(self, parser):
        """Test update-related events map to change."""
        types = parser._get_event_type('RecordUpdate')
        assert 'change' in types

    def test_delete_event_type_is_deletion(self, parser):
        """Test delete-related events map to deletion."""
        types = parser._get_event_type('ContentDelete')
        assert 'deletion' in types

    def test_export_event_type_is_access(self, parser):
        """Test export events map to access."""
        types = parser._get_event_type('ReportExport')
        assert 'access' in types

    def test_api_event_type_is_access(self, parser):
        """Test API events map to access."""
        types = parser._get_event_type('API')
        assert 'access' in types

    def test_error_event_type_is_error(self, parser):
        """Test error events map to error."""
        types = parser._get_event_type('LightningError')
        assert 'error' in types

    def test_default_event_type_is_info(self, parser):
        """Test default event type is info."""
        types = parser._get_event_type('UnknownEventType')
        assert 'info' in types


class TestSalesforceParserCategoryMapping:
    """Tests for event category mapping."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_login_category_includes_authentication(self, parser):
        """Test Login events include authentication category."""
        assert 'authentication' in parser.EVENT_TYPE_CATEGORY_MAP['Login']

    def test_api_category_includes_web(self, parser):
        """Test API events include web category."""
        assert 'web' in parser.EVENT_TYPE_CATEGORY_MAP['API']

    def test_report_category_includes_file(self, parser):
        """Test Report events include file category."""
        assert 'file' in parser.EVENT_TYPE_CATEGORY_MAP['Report']

    def test_apex_category_includes_process(self, parser):
        """Test ApexExecution events include process category."""
        assert 'process' in parser.EVENT_TYPE_CATEGORY_MAP['ApexExecution']

    def test_setup_audit_category_includes_configuration(self, parser):
        """Test SetupAuditTrail events include configuration category."""
        assert 'configuration' in parser.EVENT_TYPE_CATEGORY_MAP['SetupAuditTrail']
        assert 'iam' in parser.EVENT_TYPE_CATEGORY_MAP['SetupAuditTrail']

    def test_package_install_category_includes_package(self, parser):
        """Test PackageInstall events include package category."""
        assert 'package' in parser.EVENT_TYPE_CATEGORY_MAP['PackageInstall']

    def test_callout_category_includes_network(self, parser):
        """Test ApexCallout events include network category."""
        assert 'network' in parser.EVENT_TYPE_CATEGORY_MAP['ApexCallout']


class TestSalesforceParserTimestamp:
    """Tests for timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_parse_timestamp_iso_with_z(self, parser):
        """Test parsing ISO timestamp with Z suffix."""
        timestamp = parser._parse_timestamp("2024-01-28T12:00:00.000Z")
        assert '2024-01-28' in timestamp

    def test_parse_timestamp_iso_with_timezone(self, parser):
        """Test parsing ISO timestamp with timezone."""
        timestamp = parser._parse_timestamp("2024-01-28T12:00:00.000+00:00")
        assert '2024-01-28' in timestamp

    def test_parse_timestamp_simple_format(self, parser):
        """Test parsing simple timestamp format."""
        timestamp = parser._parse_timestamp("2024-01-28 12:00:00")
        assert '2024-01-28' in timestamp

    def test_parse_timestamp_empty_returns_now(self, parser):
        """Test empty timestamp returns current time."""
        timestamp = parser._parse_timestamp("")
        assert timestamp is not None
        # Should be today's date
        today = datetime.now(timezone.utc).strftime('%Y-%m')
        assert today in timestamp

    def test_parse_timestamp_invalid_returns_now(self, parser):
        """Test invalid timestamp returns current time."""
        timestamp = parser._parse_timestamp("not-a-timestamp")
        assert timestamp is not None


class TestSalesforceParserRemoveNoneValues:
    """Tests for None value removal."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_remove_none_values_from_dict(self, parser):
        """Test None values are removed from dict."""
        data = {"a": 1, "b": None, "c": "value"}
        result = parser._remove_none_values(data)

        assert result == {"a": 1, "c": "value"}

    def test_remove_empty_dict_values(self, parser):
        """Test empty dict values are removed."""
        data = {"a": 1, "b": {}, "c": "value"}
        result = parser._remove_none_values(data)

        assert result == {"a": 1, "c": "value"}

    def test_remove_empty_list_values(self, parser):
        """Test empty list values are removed."""
        data = {"a": 1, "b": [], "c": "value"}
        result = parser._remove_none_values(data)

        assert result == {"a": 1, "c": "value"}

    def test_remove_empty_string_values(self, parser):
        """Test empty string values are removed."""
        data = {"a": 1, "b": "", "c": "value"}
        result = parser._remove_none_values(data)

        assert result == {"a": 1, "c": "value"}

    def test_remove_none_from_nested_dict(self, parser):
        """Test None values are removed from nested dict."""
        data = {"a": {"b": 1, "c": None}, "d": "value"}
        result = parser._remove_none_values(data)

        assert result == {"a": {"b": 1}, "d": "value"}

    def test_remove_none_from_list(self, parser):
        """Test None values are removed from list."""
        data = {"a": [1, None, 3]}
        result = parser._remove_none_values(data)

        assert result == {"a": [1, 3]}


class TestSalesforceParserEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_parse_event_without_username(self, parser):
        """Test parsing event without username."""
        event = {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "USER_ID": "005000000000001AAA"
        }
        result = parser.parse(event)

        assert result['user']['id'] == '005000000000001AAA'
        assert 'email' not in result['user']

    def test_parse_event_with_non_email_username(self, parser):
        """Test parsing event with non-email username."""
        event = {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "USER_ID": "005000000000001AAA",
            "USER_NAME": "admin_user"
        }
        result = parser.parse(event)

        assert result['user']['name'] == 'admin_user'
        assert 'email' not in result['user']

    def test_parse_login_without_status(self, parser):
        """Test parsing login event without status defaults to Success."""
        event = {
            "UserId": "005000000000001AAA",
            "Username": "user@example.com",
            "LoginType": "Application"
        }
        result = parser.parse(event)

        assert result['event']['outcome'] == 'success'

    def test_parse_event_with_invalid_status_code(self, parser):
        """Test parsing event with invalid status code."""
        event = {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "STATUS_CODE": "invalid"
        }
        result = parser.parse(event)

        assert 'status_code' not in result.get('http', {}).get('response', {})

    def test_parse_audit_without_created_by_name(self, parser):
        """Test parsing audit trail without CreatedByName."""
        event = {
            "CreatedDate": "2024-01-28T09:00:00.000Z",
            "CreatedById": "005000000000001AAA",
            "Action": "Changed setting",
            "Section": "Settings"
        }
        result = parser.parse(event)

        assert result['user']['id'] == '005000000000001AAA'

    def test_parse_preserves_all_raw_fields(self, parser):
        """Test all raw fields are preserved in _raw."""
        event = {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "CUSTOM_FIELD_1": "value1",
            "CUSTOM_FIELD_2": "value2"
        }
        result = parser.parse(event)

        assert result['_raw']['CUSTOM_FIELD_1'] == 'value1'
        assert result['_raw']['CUSTOM_FIELD_2'] == 'value2'

    def test_event_duration_calculation(self, parser):
        """Test event duration is converted to nanoseconds."""
        event = {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "RUN_TIME": 100  # 100ms
        }
        result = parser.parse(event)

        assert result['event']['duration'] == 100000000  # 100ms in ns

    def test_event_id_from_request_id(self, parser):
        """Test event ID is set from request ID."""
        event = {
            "EventType": "API",
            "TIMESTAMP_DERIVED": "2024-01-28T12:00:00.000Z",
            "REQUEST_ID": "req-unique-123"
        }
        result = parser.parse(event)

        assert result['event']['id'] == 'req-unique-123'


class TestSalesforceParserLoginStatusMap:
    """Tests for login status mapping."""

    @pytest.fixture
    def parser(self):
        return SalesforceParser()

    def test_all_failure_statuses(self, parser):
        """Test all failure status mappings."""
        failure_statuses = ['Invalid Password', 'User Lockout', 'Invalid Credentials', 'Failed: Invalid Password', 'Failed']
        for status in failure_statuses:
            assert parser.LOGIN_STATUS_MAP[status] == 'failure', f"Status '{status}' should map to 'failure'"

    def test_success_status(self, parser):
        """Test success status mapping."""
        assert parser.LOGIN_STATUS_MAP['Success'] == 'success'

    def test_pending_status(self, parser):
        """Test pending status mapping."""
        assert parser.LOGIN_STATUS_MAP['Pending'] == 'unknown'
