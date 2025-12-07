"""Unit tests for CloudTrail log parser."""

import pytest
import json
from datetime import datetime, timezone

from src.shared.parsers.cloudtrail import CloudTrailParser
from src.shared.parsers.base import ParserError


class TestCloudTrailParser:
    """Tests for CloudTrailParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return CloudTrailParser()

    @pytest.fixture
    def sample_api_call_event(self):
        """Sample CloudTrail API call event."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLE123456789",
                "arn": "arn:aws:iam::123456789012:user/admin",
                "accountId": "123456789012",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName": "admin"
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "userAgent": "aws-cli/2.0",
            "requestParameters": {
                "instancesSet": {"items": [{"instanceId": "i-1234567890abcdef0"}]}
            },
            "responseElements": None,
            "requestID": "abcd1234-5678-90ef-ghij-klmnopqrstuv",
            "eventID": "1234abcd-5678-90ef-ghij-klmnopqrstuv",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        }

    @pytest.fixture
    def sample_console_login_success(self):
        """Sample successful console login event."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLE123456789",
                "arn": "arn:aws:iam::123456789012:user/admin",
                "accountId": "123456789012",
                "userName": "admin"
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "userAgent": "Mozilla/5.0",
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "additionalEventData": {
                "MFAUsed": "Yes",
                "LoginTo": "https://console.aws.amazon.com"
            },
            "eventID": "login-event-123",
            "eventType": "AwsConsoleSignIn"
        }

    @pytest.fixture
    def sample_console_login_failure(self):
        """Sample failed console login event."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLE123456789",
                "arn": "arn:aws:iam::123456789012:user/admin",
                "accountId": "123456789012",
                "userName": "admin"
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "userAgent": "Mozilla/5.0",
            "responseElements": {
                "ConsoleLogin": "Failure"
            },
            "errorMessage": "Failed authentication",
            "eventID": "login-event-456",
            "eventType": "AwsConsoleSignIn"
        }

    @pytest.fixture
    def sample_assumed_role_event(self):
        """Sample CloudTrail event with AssumedRole identity."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAEXAMPLE123456789:session-name",
                "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
                "accountId": "123456789012",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROAEXAMPLE123456789",
                        "arn": "arn:aws:iam::123456789012:role/MyRole",
                        "accountId": "123456789012",
                        "userName": "MyRole"
                    },
                    "attributes": {
                        "creationDate": "2024-01-29T10:00:00Z",
                        "mfaAuthenticated": "true"
                    }
                }
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.0.0.50",
            "userAgent": "boto3/1.28.0",
            "eventType": "AwsApiCall",
            "eventID": "s3-event-123"
        }

    @pytest.fixture
    def sample_root_event(self):
        """Sample CloudTrail event with Root identity."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "Root",
                "principalId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012"
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.100",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {
                "userName": "newuser"
            },
            "responseElements": {
                "user": {
                    "userName": "newuser",
                    "userId": "AIDANEWUSER12345"
                }
            },
            "eventType": "AwsApiCall",
            "eventID": "root-event-123"
        }

    @pytest.fixture
    def sample_error_event(self):
        """Sample CloudTrail event with error."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin"
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "errorCode": "UnauthorizedOperation",
            "errorMessage": "You are not authorized to perform this operation.",
            "eventType": "AwsApiCall",
            "eventID": "error-event-123"
        }

    @pytest.fixture
    def sample_service_event(self):
        """Sample CloudTrail event from AWS service."""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AWSService",
                "invokedBy": "cloudformation.amazonaws.com"
            },
            "eventTime": "2024-01-29T10:30:00Z",
            "eventSource": "lambda.amazonaws.com",
            "eventName": "CreateFunction",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "eventType": "AwsApiCall",
            "eventID": "service-event-123"
        }

    def test_parser_log_type(self, parser):
        """Test parser returns correct log type."""
        assert parser.log_type == "cloudtrail"

    def test_parser_required_fields(self, parser):
        """Test parser has correct required fields."""
        assert "eventTime" in parser.required_fields
        assert "eventName" in parser.required_fields
        assert "eventSource" in parser.required_fields

    def test_validate_valid_event(self, parser, sample_api_call_event):
        """Test validation of valid event."""
        raw = json.dumps(sample_api_call_event)
        assert parser.validate(raw) is True

    def test_validate_missing_event_time(self, parser):
        """Test validation fails without eventTime."""
        event = {"eventName": "Test", "eventSource": "test.amazonaws.com"}
        raw = json.dumps(event)
        assert parser.validate(raw) is False

    def test_validate_missing_event_name(self, parser):
        """Test validation fails without eventName."""
        event = {"eventTime": "2024-01-29T10:30:00Z", "eventSource": "test.amazonaws.com"}
        raw = json.dumps(event)
        assert parser.validate(raw) is False

    def test_validate_missing_event_source(self, parser):
        """Test validation fails without eventSource."""
        event = {"eventTime": "2024-01-29T10:30:00Z", "eventName": "Test"}
        raw = json.dumps(event)
        assert parser.validate(raw) is False

    def test_validate_invalid_json(self, parser):
        """Test validation fails with invalid JSON."""
        assert parser.validate("not valid json") is False

    def test_parse_api_call_basic_fields(self, parser, sample_api_call_event):
        """Test parsing API call event extracts basic fields."""
        raw = json.dumps(sample_api_call_event)
        result = parser.parse(raw)

        assert result.action == "DescribeInstances"
        assert result.user == "admin"
        assert result.source_ip == "203.0.113.50"
        assert result.service == "ec2"
        assert result.result == "success"

    def test_parse_api_call_metadata(self, parser, sample_api_call_event):
        """Test parsing API call event extracts metadata."""
        raw = json.dumps(sample_api_call_event)
        result = parser.parse(raw)

        assert result.metadata["user_type"] == "IAMUser"
        assert result.metadata["aws_region"] == "us-east-1"
        assert result.metadata["user_agent"] == "aws-cli/2.0"
        assert result.metadata["event_type"] == "AwsApiCall"

    def test_parse_console_login_success(self, parser, sample_console_login_success):
        """Test parsing successful console login."""
        raw = json.dumps(sample_console_login_success)
        result = parser.parse(raw)

        assert result.action == "ConsoleLogin"
        assert result.result == "success"
        assert result.metadata["is_auth_event"] is True
        assert result.metadata["mfa_used"] == "Yes"

    def test_parse_console_login_failure(self, parser, sample_console_login_failure):
        """Test parsing failed console login."""
        raw = json.dumps(sample_console_login_failure)
        result = parser.parse(raw)

        assert result.action == "ConsoleLogin"
        assert result.result == "failure"

    def test_parse_assumed_role_identity(self, parser, sample_assumed_role_event):
        """Test parsing AssumedRole identity."""
        raw = json.dumps(sample_assumed_role_event)
        result = parser.parse(raw)

        assert result.user == "MyRole"
        assert result.metadata["user_type"] == "AssumedRole"

    def test_parse_root_identity(self, parser, sample_root_event):
        """Test parsing Root identity."""
        raw = json.dumps(sample_root_event)
        result = parser.parse(raw)

        assert result.user == "root"
        assert result.metadata["user_type"] == "Root"
        assert result.metadata["is_auth_event"] is True  # CreateUser is auth event

    def test_parse_error_event(self, parser, sample_error_event):
        """Test parsing event with error."""
        raw = json.dumps(sample_error_event)
        result = parser.parse(raw)

        assert result.result == "failure"
        assert result.metadata["error_code"] == "UnauthorizedOperation"
        assert "not authorized" in result.metadata["error_message"]

    def test_parse_service_identity(self, parser, sample_service_event):
        """Test parsing AWSService identity."""
        raw = json.dumps(sample_service_event)
        result = parser.parse(raw)

        assert result.user == "cloudformation.amazonaws.com"
        assert result.metadata["user_type"] == "AWSService"

    def test_parse_preserves_raw_event(self, parser, sample_api_call_event):
        """Test parsing preserves raw event."""
        raw = json.dumps(sample_api_call_event)
        result = parser.parse(raw)

        assert result.raw_event == sample_api_call_event

    def test_parse_extracts_resources(self, parser):
        """Test parsing extracts resources."""
        event = {
            "eventTime": "2024-01-29T10:30:00Z",
            "eventName": "DeleteBucket",
            "eventSource": "s3.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "eventType": "AwsApiCall",
            "resources": [
                {
                    "ARN": "arn:aws:s3:::my-bucket",
                    "accountId": "123456789012",
                    "type": "AWS::S3::Bucket"
                }
            ]
        }
        raw = json.dumps(event)
        result = parser.parse(raw)

        assert len(result.metadata["resources"]) == 1
        assert result.metadata["resources"][0]["arn"] == "arn:aws:s3:::my-bucket"
        assert result.metadata["resources"][0]["type"] == "AWS::S3::Bucket"

    def test_parse_skips_digest_event(self, parser):
        """Test parsing skips CloudTrail digest files."""
        event = {
            "eventTime": "2024-01-29T10:30:00Z",
            "eventName": "Digest",
            "eventSource": "cloudtrail.amazonaws.com",
            "userIdentity": {"type": "AWSService"}
        }
        raw = json.dumps(event)

        with pytest.raises(ParserError) as exc_info:
            parser.parse(raw)
        assert "digest" in str(exc_info.value).lower()


class TestCloudTrailParserUserIdentity:
    """Test user identity extraction."""

    @pytest.fixture
    def parser(self):
        return CloudTrailParser()

    def test_extract_iam_user(self, parser):
        """Test extracting IAM user identity."""
        identity = {"type": "IAMUser", "userName": "testuser"}
        user, user_type = parser._extract_user_identity(identity)
        assert user == "testuser"
        assert user_type == "IAMUser"

    def test_extract_root_user(self, parser):
        """Test extracting root user identity."""
        identity = {"type": "Root", "accountId": "123456789012"}
        user, user_type = parser._extract_user_identity(identity)
        assert user == "root"
        assert user_type == "Root"

    def test_extract_assumed_role_from_session_context(self, parser):
        """Test extracting assumed role from sessionContext."""
        identity = {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/session",
            "sessionContext": {
                "sessionIssuer": {
                    "userName": "AdminRole"
                }
            }
        }
        user, user_type = parser._extract_user_identity(identity)
        assert user == "AdminRole"
        assert user_type == "AssumedRole"

    def test_extract_assumed_role_from_arn(self, parser):
        """Test extracting assumed role from ARN when sessionIssuer missing."""
        identity = {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/session",
            "sessionContext": {}
        }
        user, user_type = parser._extract_user_identity(identity)
        assert user == "AdminRole"
        assert user_type == "AssumedRole"

    def test_extract_federated_user(self, parser):
        """Test extracting federated user identity."""
        identity = {"type": "FederatedUser", "userName": "feduser@example.com"}
        user, user_type = parser._extract_user_identity(identity)
        assert user == "feduser@example.com"
        assert user_type == "FederatedUser"

    def test_extract_aws_service(self, parser):
        """Test extracting AWS service identity."""
        identity = {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}
        user, user_type = parser._extract_user_identity(identity)
        assert user == "lambda.amazonaws.com"
        assert user_type == "AWSService"

    def test_extract_aws_account(self, parser):
        """Test extracting AWS account identity."""
        identity = {"type": "AWSAccount", "accountId": "987654321098"}
        user, user_type = parser._extract_user_identity(identity)
        assert user == "987654321098"
        assert user_type == "AWSAccount"

    def test_extract_unknown_type(self, parser):
        """Test extracting unknown identity type."""
        identity = {"type": "UnknownType"}
        user, user_type = parser._extract_user_identity(identity)
        assert user == "Unknown"
        assert user_type == "UnknownType"


class TestCloudTrailParserResult:
    """Test result determination."""

    @pytest.fixture
    def parser(self):
        return CloudTrailParser()

    def test_error_code_means_failure(self, parser):
        """Test event with errorCode is failure."""
        event = {"errorCode": "AccessDenied"}
        assert parser._determine_result(event) == "failure"

    def test_api_call_without_error_is_success(self, parser):
        """Test API call without error is success."""
        event = {"eventType": "AwsApiCall"}
        assert parser._determine_result(event) == "success"

    def test_console_login_success(self, parser):
        """Test ConsoleLogin success."""
        event = {
            "eventName": "ConsoleLogin",
            "responseElements": {"ConsoleLogin": "Success"}
        }
        assert parser._determine_result(event) == "success"

    def test_console_login_failure(self, parser):
        """Test ConsoleLogin failure."""
        event = {
            "eventName": "ConsoleLogin",
            "responseElements": {"ConsoleLogin": "Failure"}
        }
        assert parser._determine_result(event) == "failure"


class TestCloudTrailParserAuthEvents:
    """Test authentication event detection."""

    @pytest.fixture
    def parser(self):
        return CloudTrailParser()

    def test_console_login_is_auth_event(self, parser):
        """Test ConsoleLogin is auth event."""
        assert parser._is_auth_event("ConsoleLogin") is True

    def test_assume_role_is_auth_event(self, parser):
        """Test AssumeRole is auth event."""
        assert parser._is_auth_event("AssumeRole") is True

    def test_create_user_is_auth_event(self, parser):
        """Test CreateUser is auth event."""
        assert parser._is_auth_event("CreateUser") is True

    def test_enable_mfa_is_auth_event(self, parser):
        """Test EnableMFADevice is auth event."""
        assert parser._is_auth_event("EnableMFADevice") is True

    def test_describe_instances_not_auth_event(self, parser):
        """Test DescribeInstances is not auth event."""
        assert parser._is_auth_event("DescribeInstances") is False

    def test_put_object_not_auth_event(self, parser):
        """Test PutObject is not auth event."""
        assert parser._is_auth_event("PutObject") is False
