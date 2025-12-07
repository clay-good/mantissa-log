"""Unit tests for Snowflake parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.snowflake import SnowflakeParser


class TestSnowflakeParser:
    """Tests for SnowflakeParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SnowflakeParser()

    @pytest.fixture
    def sample_login_success(self):
        """Sample Snowflake successful login event."""
        return {
            "EVENT_ID": "12345678901234567890",
            "EVENT_TIMESTAMP": "2024-01-28T10:00:00.000Z",
            "EVENT_TYPE": "LOGIN",
            "USER_NAME": "analyst_user",
            "CLIENT_IP": "192.168.1.100",
            "REPORTED_CLIENT_TYPE": "SNOWFLAKE_UI",
            "REPORTED_CLIENT_VERSION": "1.0.0",
            "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
            "SECOND_AUTHENTICATION_FACTOR": "DUO_SECURITY",
            "IS_SUCCESS": "YES",
            "ERROR_CODE": "",
            "ERROR_MESSAGE": "",
            "CONNECTION_ID": "conn-123",
            "SESSION_ID": "987654321"
        }

    @pytest.fixture
    def sample_login_failure(self):
        """Sample Snowflake failed login event."""
        return {
            "EVENT_ID": "12345678901234567891",
            "EVENT_TIMESTAMP": "2024-01-28T10:05:00.000Z",
            "EVENT_TYPE": "LOGIN",
            "USER_NAME": "attacker_user",
            "CLIENT_IP": "203.0.113.50",
            "REPORTED_CLIENT_TYPE": "PYTHON",
            "REPORTED_CLIENT_VERSION": "2.7.0",
            "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
            "IS_SUCCESS": "NO",
            "ERROR_CODE": "INCORRECT_USERNAME_PASSWORD",
            "ERROR_MESSAGE": "Incorrect username or password"
        }

    @pytest.fixture
    def sample_query_history(self):
        """Sample Snowflake query history event."""
        return {
            "QUERY_ID": "01a12345-0000-1234-0000-000123456789",
            "QUERY_TEXT": "SELECT * FROM customers WHERE region = 'US'",
            "QUERY_TYPE": "SELECT",
            "DATABASE_NAME": "ANALYTICS_DB",
            "SCHEMA_NAME": "PUBLIC",
            "USER_NAME": "analyst_user",
            "ROLE_NAME": "ANALYST_ROLE",
            "WAREHOUSE_NAME": "COMPUTE_WH",
            "WAREHOUSE_SIZE": "X-Small",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z",
            "END_TIME": "2024-01-28T12:00:05.000Z",
            "TOTAL_ELAPSED_TIME": 5000,
            "BYTES_SCANNED": 1024000,
            "ROWS_PRODUCED": 500,
            "ROWS_INSERTED": 0,
            "ROWS_UPDATED": 0,
            "ROWS_DELETED": 0,
            "COMPILATION_TIME": 100,
            "EXECUTION_TIME": 4900,
            "CREDITS_USED_CLOUD_SERVICES": 0.001,
            "SESSION_ID": "987654321",
            "QUERY_TAG": "adhoc-analysis"
        }

    @pytest.fixture
    def sample_grant_event(self):
        """Sample Snowflake grant event."""
        return {
            "GRANTEE_NAME": "JUNIOR_ANALYST",
            "PRIVILEGE": "SELECT",
            "GRANTED_ON": "TABLE",
            "NAME": "CUSTOMERS",
            "GRANTED_BY": "ADMIN_USER",
            "GRANT_OPTION": "false",
            "CREATED_ON": "2024-01-28T09:00:00.000Z",
            "TABLE_CATALOG": "ANALYTICS_DB",
            "TABLE_SCHEMA": "PUBLIC"
        }

    @pytest.fixture
    def sample_session_event(self):
        """Sample Snowflake session event."""
        return {
            "SESSION_ID": 987654321,
            "USER_NAME": "analyst_user",
            "CREATED_ON": "2024-01-28T10:00:00.000Z",
            "AUTHENTICATION_METHOD": "PASSWORD_DUO_SECURITY",
            "LOGIN_EVENT_ID": "12345678901234567890",
            "CLIENT_APPLICATION_ID": "snowflake-ui",
            "CLIENT_VERSION": "1.0.0"
        }

    @pytest.fixture
    def sample_copy_history(self):
        """Sample Snowflake copy history event."""
        return {
            "FILE_NAME": "data_20240128.csv",
            "STAGE_LOCATION": "s3://my-bucket/data/",
            "TABLE_NAME": "RAW_DATA",
            "TABLE_CATALOG_NAME": "ANALYTICS_DB",
            "TABLE_SCHEMA_NAME": "STAGING",
            "LAST_LOAD_TIME": "2024-01-28T08:00:00.000Z",
            "STATUS": "LOADED",
            "ROW_COUNT": 10000,
            "ROW_PARSED": 10000,
            "FILE_SIZE": 5242880,
            "ERROR_COUNT": 0
        }

    @pytest.fixture
    def sample_data_transfer(self):
        """Sample Snowflake data transfer event."""
        return {
            "START_TIME": "2024-01-28T06:00:00.000Z",
            "SOURCE_CLOUD": "AWS",
            "SOURCE_REGION": "us-east-1",
            "TARGET_CLOUD": "AZURE",
            "TARGET_REGION": "eastus2",
            "TRANSFER_TYPE": "REPLICATION",
            "BYTES_TRANSFERRED": 104857600
        }

    def test_parser_source_type(self, parser):
        """Test parser returns correct source type."""
        assert parser.source_type == "snowflake"

    def test_validate_login_history(self, parser, sample_login_success):
        """Test validation of login history event."""
        assert parser.validate(sample_login_success) is True

    def test_validate_query_history(self, parser, sample_query_history):
        """Test validation of query history event."""
        assert parser.validate(sample_query_history) is True

    def test_validate_grant_event(self, parser, sample_grant_event):
        """Test validation of grant event."""
        assert parser.validate(sample_grant_event) is True

    def test_validate_session_event(self, parser, sample_session_event):
        """Test validation of session event."""
        assert parser.validate(sample_session_event) is True

    def test_validate_copy_history(self, parser, sample_copy_history):
        """Test validation of copy history event."""
        assert parser.validate(sample_copy_history) is True

    def test_validate_data_transfer(self, parser, sample_data_transfer):
        """Test validation of data transfer event."""
        assert parser.validate(sample_data_transfer) is True

    def test_validate_invalid_event(self, parser):
        """Test validation of invalid event."""
        assert parser.validate({}) is False


class TestSnowflakeParserLoginHistory:
    """Tests for login history parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    @pytest.fixture
    def success_login(self):
        return {
            "EVENT_ID": "12345",
            "EVENT_TIMESTAMP": "2024-01-28T10:00:00.000Z",
            "EVENT_TYPE": "LOGIN",
            "USER_NAME": "analyst_user",
            "CLIENT_IP": "192.168.1.100",
            "REPORTED_CLIENT_TYPE": "SNOWFLAKE_UI",
            "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
            "SECOND_AUTHENTICATION_FACTOR": "DUO_SECURITY",
            "IS_SUCCESS": "YES"
        }

    @pytest.fixture
    def failed_login(self):
        return {
            "EVENT_TIMESTAMP": "2024-01-28T10:05:00.000Z",
            "USER_NAME": "bad_user",
            "CLIENT_IP": "203.0.113.50",
            "IS_SUCCESS": "NO",
            "ERROR_CODE": "INCORRECT_USERNAME_PASSWORD",
            "ERROR_MESSAGE": "Incorrect username or password",
            "LOGIN_EVENT_TYPE": "LOGIN"
        }

    def test_parse_login_success_basic_fields(self, parser, success_login):
        """Test parsing successful login extracts basic ECS fields."""
        result = parser.parse(success_login)

        assert result['event']['action'] == 'user_login'
        assert result['event']['outcome'] == 'success'
        assert result['event']['provider'] == 'snowflake'
        assert 'authentication' in result['event']['category']
        assert 'start' in result['event']['type']

    def test_parse_login_success_user_fields(self, parser, success_login):
        """Test parsing successful login extracts user fields."""
        result = parser.parse(success_login)

        assert result['user']['name'] == 'analyst_user'

    def test_parse_login_success_source_fields(self, parser, success_login):
        """Test parsing successful login extracts source fields."""
        result = parser.parse(success_login)

        assert result['source']['ip'] == '192.168.1.100'

    def test_parse_login_success_user_agent_fields(self, parser, success_login):
        """Test parsing successful login extracts user agent fields."""
        result = parser.parse(success_login)

        assert result['user_agent']['name'] == 'SNOWFLAKE_UI'

    def test_parse_login_success_snowflake_fields(self, parser, success_login):
        """Test parsing successful login extracts Snowflake-specific fields."""
        result = parser.parse(success_login)

        assert result['snowflake']['login']['is_success'] == 'YES'
        assert result['snowflake']['login']['first_auth_factor'] == 'PASSWORD'
        assert result['snowflake']['login']['second_auth_factor'] == 'DUO_SECURITY'

    def test_parse_login_failure_outcome(self, parser, failed_login):
        """Test parsing failed login sets correct outcome."""
        result = parser.parse(failed_login)

        assert result['event']['outcome'] == 'failure'
        assert result['event']['reason'] == 'Incorrect username or password'

    def test_parse_login_failure_error_fields(self, parser, failed_login):
        """Test parsing failed login extracts error fields."""
        result = parser.parse(failed_login)

        assert result['snowflake']['login']['error_code'] == 'INCORRECT_USERNAME_PASSWORD'
        assert result['snowflake']['login']['error_message'] == 'Incorrect username or password'


class TestSnowflakeParserQueryHistory:
    """Tests for query history parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    @pytest.fixture
    def select_query(self):
        return {
            "QUERY_ID": "01a12345-0000-1234-0000-000123456789",
            "QUERY_TEXT": "SELECT * FROM customers",
            "QUERY_TYPE": "SELECT",
            "DATABASE_NAME": "ANALYTICS_DB",
            "SCHEMA_NAME": "PUBLIC",
            "USER_NAME": "analyst",
            "ROLE_NAME": "ANALYST_ROLE",
            "WAREHOUSE_NAME": "COMPUTE_WH",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z",
            "TOTAL_ELAPSED_TIME": 5000,
            "BYTES_SCANNED": 1024000,
            "ROWS_PRODUCED": 500
        }

    @pytest.fixture
    def failed_query(self):
        return {
            "QUERY_ID": "01a12345-0000-1234-0000-000123456790",
            "QUERY_TEXT": "SELECT * FROM nonexistent",
            "QUERY_TYPE": "SELECT",
            "USER_NAME": "analyst",
            "EXECUTION_STATUS": "FAIL",
            "ERROR_CODE": "002003",
            "ERROR_MESSAGE": "SQL compilation error: Object 'NONEXISTENT' does not exist",
            "START_TIME": "2024-01-28T12:05:00.000Z"
        }

    def test_parse_select_query_basic_fields(self, parser, select_query):
        """Test parsing SELECT query extracts basic ECS fields."""
        result = parser.parse(select_query)

        assert result['event']['action'] == 'query_select'
        assert result['event']['outcome'] == 'success'
        assert 'database' in result['event']['category']
        assert 'access' in result['event']['type']

    def test_parse_select_query_user_fields(self, parser, select_query):
        """Test parsing SELECT query extracts user fields."""
        result = parser.parse(select_query)

        assert result['user']['name'] == 'analyst'
        assert 'ANALYST_ROLE' in result['user']['roles']

    def test_parse_select_query_snowflake_fields(self, parser, select_query):
        """Test parsing SELECT query extracts Snowflake-specific fields."""
        result = parser.parse(select_query)

        assert result['snowflake']['query']['id'] == '01a12345-0000-1234-0000-000123456789'
        assert result['snowflake']['query']['type'] == 'SELECT'
        assert result['snowflake']['database']['name'] == 'ANALYTICS_DB'
        assert result['snowflake']['database']['schema'] == 'PUBLIC'
        assert result['snowflake']['warehouse']['name'] == 'COMPUTE_WH'

    def test_parse_select_query_performance_fields(self, parser, select_query):
        """Test parsing SELECT query extracts performance fields."""
        result = parser.parse(select_query)

        assert result['snowflake']['performance']['elapsed_time_ms'] == 5000
        assert result['snowflake']['performance']['bytes_scanned'] == 1024000
        assert result['snowflake']['performance']['rows_produced'] == 500

    def test_parse_select_query_duration(self, parser, select_query):
        """Test parsing SELECT query sets event duration."""
        result = parser.parse(select_query)

        # Duration should be in nanoseconds (5000ms = 5000000000ns)
        assert result['event']['duration'] == 5000000000

    def test_parse_failed_query_outcome(self, parser, failed_query):
        """Test parsing failed query sets correct outcome."""
        result = parser.parse(failed_query)

        assert result['event']['outcome'] == 'failure'

    def test_parse_failed_query_error_fields(self, parser, failed_query):
        """Test parsing failed query extracts error fields."""
        result = parser.parse(failed_query)

        assert result['snowflake']['execution']['error_code'] == '002003'
        assert 'does not exist' in result['snowflake']['execution']['error_message']

    def test_parse_insert_query_event_type(self, parser):
        """Test INSERT query maps to creation type."""
        event = {
            "QUERY_ID": "query-123",
            "QUERY_TEXT": "INSERT INTO table1 VALUES (1, 2)",
            "QUERY_TYPE": "INSERT",
            "USER_NAME": "etl_user",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'query_insert'
        assert 'creation' in result['event']['type']

    def test_parse_delete_query_event_type(self, parser):
        """Test DELETE query maps to deletion type."""
        event = {
            "QUERY_ID": "query-124",
            "QUERY_TEXT": "DELETE FROM table1 WHERE id = 1",
            "QUERY_TYPE": "DELETE",
            "USER_NAME": "admin_user",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'query_delete'
        assert 'deletion' in result['event']['type']

    def test_parse_grant_query_event_type(self, parser):
        """Test GRANT query maps to admin type."""
        event = {
            "QUERY_ID": "query-125",
            "QUERY_TEXT": "GRANT SELECT ON table1 TO role1",
            "QUERY_TYPE": "GRANT",
            "USER_NAME": "admin_user",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'query_grant'
        assert 'admin' in result['event']['type']
        assert 'iam' in result['event']['category']


class TestSnowflakeParserGrants:
    """Tests for grant event parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    @pytest.fixture
    def grant_event(self):
        return {
            "GRANTEE_NAME": "JUNIOR_ANALYST",
            "PRIVILEGE": "SELECT",
            "GRANTED_ON": "TABLE",
            "NAME": "CUSTOMERS",
            "GRANTED_BY": "ADMIN_USER",
            "GRANT_OPTION": "false",
            "CREATED_ON": "2024-01-28T09:00:00.000Z",
            "TABLE_CATALOG": "ANALYTICS_DB",
            "TABLE_SCHEMA": "PUBLIC"
        }

    def test_parse_grant_basic_fields(self, parser, grant_event):
        """Test parsing grant extracts basic ECS fields."""
        result = parser.parse(grant_event)

        assert result['event']['action'] == 'grant_privilege'
        assert result['event']['outcome'] == 'success'
        assert 'iam' in result['event']['category']
        assert 'admin' in result['event']['type']
        assert 'allowed' in result['event']['type']

    def test_parse_grant_user_fields(self, parser, grant_event):
        """Test parsing grant extracts user fields."""
        result = parser.parse(grant_event)

        assert result['user']['name'] == 'ADMIN_USER'
        assert result['user']['target']['name'] == 'JUNIOR_ANALYST'

    def test_parse_grant_snowflake_fields(self, parser, grant_event):
        """Test parsing grant extracts Snowflake-specific fields."""
        result = parser.parse(grant_event)

        assert result['snowflake']['grant']['privilege'] == 'SELECT'
        assert result['snowflake']['grant']['granted_on'] == 'TABLE'
        assert result['snowflake']['grant']['object_name'] == 'CUSTOMERS'
        assert result['snowflake']['grant']['grant_option'] is False

    def test_parse_high_risk_grant(self, parser):
        """Test parsing high-risk grant is flagged."""
        event = {
            "GRANTEE_NAME": "SUSPICIOUS_USER",
            "PRIVILEGE": "OWNERSHIP",
            "GRANTED_ON": "DATABASE",
            "NAME": "PRODUCTION_DB",
            "GRANTED_BY": "ADMIN_USER",
            "GRANT_OPTION": "true",
            "CREATED_ON": "2024-01-28T09:00:00.000Z"
        }
        result = parser.parse(event)

        assert result['snowflake']['grant']['is_high_risk'] is True
        assert result['snowflake']['grant']['grant_option'] is True


class TestSnowflakeParserSessions:
    """Tests for session event parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    @pytest.fixture
    def session_event(self):
        return {
            "SESSION_ID": 987654321,
            "USER_NAME": "analyst_user",
            "CREATED_ON": "2024-01-28T10:00:00.000Z",
            "AUTHENTICATION_METHOD": "PASSWORD_DUO_SECURITY",
            "LOGIN_EVENT_ID": "12345",
            "CLIENT_APPLICATION_ID": "snowflake-ui",
            "CLIENT_VERSION": "1.0.0"
        }

    def test_parse_session_basic_fields(self, parser, session_event):
        """Test parsing session extracts basic ECS fields."""
        result = parser.parse(session_event)

        assert result['event']['action'] == 'session_created'
        assert result['event']['outcome'] == 'success'
        assert 'session' in result['event']['category']
        assert 'start' in result['event']['type']

    def test_parse_session_user_fields(self, parser, session_event):
        """Test parsing session extracts user fields."""
        result = parser.parse(session_event)

        assert result['user']['name'] == 'analyst_user'

    def test_parse_session_snowflake_fields(self, parser, session_event):
        """Test parsing session extracts Snowflake-specific fields."""
        result = parser.parse(session_event)

        assert result['snowflake']['session']['id'] == 987654321
        assert result['snowflake']['session']['authentication_method'] == 'PASSWORD_DUO_SECURITY'


class TestSnowflakeParserCopyHistory:
    """Tests for copy history parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    @pytest.fixture
    def copy_event(self):
        return {
            "FILE_NAME": "data_20240128.csv",
            "STAGE_LOCATION": "s3://my-bucket/data/",
            "TABLE_NAME": "RAW_DATA",
            "LAST_LOAD_TIME": "2024-01-28T08:00:00.000Z",
            "STATUS": "LOADED",
            "ROW_COUNT": 10000,
            "FILE_SIZE": 5242880
        }

    def test_parse_copy_basic_fields(self, parser, copy_event):
        """Test parsing copy history extracts basic ECS fields."""
        result = parser.parse(copy_event)

        assert result['event']['action'] == 'data_load'
        assert result['event']['outcome'] == 'success'
        assert 'file' in result['event']['category']
        assert 'database' in result['event']['category']
        assert 'creation' in result['event']['type']

    def test_parse_copy_file_fields(self, parser, copy_event):
        """Test parsing copy history extracts file fields."""
        result = parser.parse(copy_event)

        assert result['file']['name'] == 'data_20240128.csv'
        assert result['file']['size'] == 5242880
        assert result['file']['path'] == 's3://my-bucket/data/'

    def test_parse_copy_snowflake_fields(self, parser, copy_event):
        """Test parsing copy history extracts Snowflake-specific fields."""
        result = parser.parse(copy_event)

        assert result['snowflake']['copy']['table_name'] == 'RAW_DATA'
        assert result['snowflake']['copy']['status'] == 'LOADED'
        assert result['snowflake']['copy']['row_count'] == 10000

    def test_parse_copy_failure(self, parser):
        """Test parsing failed copy operation."""
        event = {
            "FILE_NAME": "bad_data.csv",
            "STAGE_LOCATION": "s3://my-bucket/data/",
            "TABLE_NAME": "RAW_DATA",
            "LAST_LOAD_TIME": "2024-01-28T08:00:00.000Z",
            "STATUS": "LOAD_FAILED",
            "ROW_COUNT": 0,
            "ERROR_COUNT": 5,
            "FIRST_ERROR_MESSAGE": "Invalid data format"
        }
        result = parser.parse(event)

        assert result['event']['outcome'] == 'failure'


class TestSnowflakeParserDataTransfer:
    """Tests for data transfer parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    @pytest.fixture
    def transfer_event(self):
        return {
            "START_TIME": "2024-01-28T06:00:00.000Z",
            "SOURCE_CLOUD": "AWS",
            "SOURCE_REGION": "us-east-1",
            "TARGET_CLOUD": "AZURE",
            "TARGET_REGION": "eastus2",
            "TRANSFER_TYPE": "REPLICATION",
            "BYTES_TRANSFERRED": 104857600
        }

    def test_parse_transfer_basic_fields(self, parser, transfer_event):
        """Test parsing data transfer extracts basic ECS fields."""
        result = parser.parse(transfer_event)

        assert result['event']['action'] == 'data_transfer'
        assert result['event']['outcome'] == 'success'
        assert 'network' in result['event']['category']

    def test_parse_transfer_source_fields(self, parser, transfer_event):
        """Test parsing data transfer extracts source fields."""
        result = parser.parse(transfer_event)

        assert result['source']['cloud']['provider'] == 'aws'
        assert result['source']['cloud']['region'] == 'us-east-1'

    def test_parse_transfer_destination_fields(self, parser, transfer_event):
        """Test parsing data transfer extracts destination fields."""
        result = parser.parse(transfer_event)

        assert result['destination']['cloud']['provider'] == 'azure'
        assert result['destination']['cloud']['region'] == 'eastus2'

    def test_parse_transfer_snowflake_fields(self, parser, transfer_event):
        """Test parsing data transfer extracts Snowflake-specific fields."""
        result = parser.parse(transfer_event)

        assert result['snowflake']['transfer']['type'] == 'REPLICATION'
        assert result['snowflake']['transfer']['bytes_transferred'] == 104857600


class TestSnowflakeParserGenericEvents:
    """Tests for generic event parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    def test_parse_generic_event(self, parser):
        """Test parsing generic event with timestamp."""
        event = {
            "EVENT_TIMESTAMP": "2024-01-28T12:00:00.000Z",
            "custom_field": "custom_value"
        }
        result = parser.parse(event)

        assert result['event']['action'] == 'snowflake_event'
        assert result['event']['outcome'] == 'unknown'
        assert result['event']['provider'] == 'snowflake'


class TestSnowflakeParserTimestamp:
    """Tests for timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    def test_parse_timestamp_iso_z(self, parser):
        """Test parsing ISO timestamp with Z suffix."""
        timestamp = parser._parse_timestamp("2024-01-28T12:00:00.000Z")
        assert '2024-01-28' in timestamp

    def test_parse_timestamp_iso_timezone(self, parser):
        """Test parsing ISO timestamp with timezone."""
        timestamp = parser._parse_timestamp("2024-01-28T12:00:00.000+00:00")
        assert '2024-01-28' in timestamp

    def test_parse_timestamp_space_format(self, parser):
        """Test parsing timestamp with space."""
        timestamp = parser._parse_timestamp("2024-01-28 12:00:00.000")
        assert '2024-01-28' in timestamp

    def test_parse_timestamp_empty(self, parser):
        """Test empty timestamp returns current time."""
        timestamp = parser._parse_timestamp("")
        assert timestamp is not None

    def test_parse_timestamp_unix(self, parser):
        """Test parsing Unix timestamp."""
        timestamp = parser._parse_timestamp(1706443200)
        assert timestamp is not None


class TestSnowflakeParserCategoryMapping:
    """Tests for query type category mapping."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    def test_select_category(self, parser):
        """Test SELECT maps to database category."""
        assert 'database' in parser.QUERY_TYPE_CATEGORY_MAP['SELECT']

    def test_grant_category(self, parser):
        """Test GRANT maps to iam category."""
        assert 'iam' in parser.QUERY_TYPE_CATEGORY_MAP['GRANT']

    def test_copy_category(self, parser):
        """Test COPY maps to file and database categories."""
        assert 'file' in parser.QUERY_TYPE_CATEGORY_MAP['COPY']
        assert 'database' in parser.QUERY_TYPE_CATEGORY_MAP['COPY']

    def test_create_category(self, parser):
        """Test CREATE maps to configuration category."""
        assert 'configuration' in parser.QUERY_TYPE_CATEGORY_MAP['CREATE']


class TestSnowflakeParserLoginErrorMapping:
    """Tests for login error code mapping."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    def test_incorrect_password_failure(self, parser):
        """Test incorrect password maps to failure."""
        assert parser.LOGIN_ERROR_MAP['INCORRECT_USERNAME_PASSWORD'] == 'failure'

    def test_user_locked_out_failure(self, parser):
        """Test user lockout maps to failure."""
        assert parser.LOGIN_ERROR_MAP['USER_LOCKED_OUT'] == 'failure'

    def test_ip_blocked_failure(self, parser):
        """Test IP blocked maps to failure."""
        assert parser.LOGIN_ERROR_MAP['CLIENT_IP_BLOCKED'] == 'failure'

    def test_empty_error_success(self, parser):
        """Test empty error code maps to success."""
        assert parser.LOGIN_ERROR_MAP[''] == 'success'
        assert parser.LOGIN_ERROR_MAP[None] == 'success'


class TestSnowflakeParserEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def parser(self):
        return SnowflakeParser()

    def test_parse_preserves_raw(self, parser):
        """Test raw event is preserved."""
        event = {
            "QUERY_ID": "query-123",
            "QUERY_TEXT": "SELECT 1",
            "QUERY_TYPE": "SELECT",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z"
        }
        result = parser.parse(event)

        assert '_raw' in result
        assert result['_raw']['QUERY_ID'] == 'query-123'

    def test_truncate_long_query_text(self, parser):
        """Test long query text is truncated."""
        long_query = "SELECT " + "x, " * 3000 + "y FROM table1"
        event = {
            "QUERY_ID": "query-123",
            "QUERY_TEXT": long_query,
            "QUERY_TYPE": "SELECT",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z"
        }
        result = parser.parse(event)

        assert len(result['snowflake']['query']['text']) <= 5000

    def test_remove_none_values(self, parser):
        """Test None values are removed."""
        event = {
            "QUERY_ID": "query-123",
            "QUERY_TEXT": "SELECT 1",
            "QUERY_TYPE": "SELECT",
            "EXECUTION_STATUS": "SUCCESS",
            "START_TIME": "2024-01-28T12:00:00.000Z",
            "WAREHOUSE_NAME": None
        }
        result = parser.parse(event)

        # Warehouse should not be in result if None
        assert 'warehouse' not in result.get('snowflake', {}) or result['snowflake'].get('warehouse', {}).get('name') != None
