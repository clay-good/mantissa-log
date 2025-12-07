"""Unit tests for GuardDuty findings parser."""

import pytest
import json
from datetime import datetime, timezone

from src.shared.parsers.guardduty import GuardDutyParser
from src.shared.parsers.base import ParserError


class TestGuardDutyParser:
    """Tests for GuardDutyParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return GuardDutyParser()

    @pytest.fixture
    def sample_network_finding(self):
        """Sample GuardDuty network connection finding."""
        return {
            "id": "finding-123-456-789",
            "type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "severity": 8.0,
            "createdAt": "2024-01-29T10:30:00.000Z",
            "updatedAt": "2024-01-29T10:35:00.000Z",
            "title": "SSH brute force attack detected",
            "description": "EC2 instance i-1234567890abcdef0 is performing SSH brute force attacks",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/123",
            "schemaVersion": "2.0",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-1234567890abcdef0",
                    "instanceType": "t2.micro",
                    "availabilityZone": "us-east-1a",
                    "imageId": "ami-12345678",
                    "tags": [
                        {"key": "Name", "value": "WebServer"}
                    ]
                }
            },
            "service": {
                "archived": False,
                "count": 5,
                "detectorId": "detector-123",
                "eventFirstSeen": "2024-01-29T10:00:00.000Z",
                "eventLastSeen": "2024-01-29T10:30:00.000Z",
                "resourceRole": "TARGET",
                "serviceName": "guardduty",
                "action": {
                    "actionType": "NETWORK_CONNECTION",
                    "networkConnectionAction": {
                        "connectionDirection": "INBOUND",
                        "protocol": "TCP",
                        "localPortDetails": {
                            "port": 22,
                            "portName": "SSH"
                        },
                        "remoteIpDetails": {
                            "ipAddressV4": "203.0.113.100",
                            "organization": {
                                "asn": "12345",
                                "asnOrg": "Evil ISP"
                            },
                            "country": {"countryName": "Unknown"}
                        },
                        "localIpDetails": {
                            "ipAddressV4": "10.0.0.50"
                        }
                    }
                }
            }
        }

    @pytest.fixture
    def sample_api_call_finding(self):
        """Sample GuardDuty API call finding."""
        return {
            "id": "finding-api-123",
            "type": "Recon:IAMUser/MaliciousIPCaller",
            "severity": 5.0,
            "createdAt": "2024-01-29T10:30:00.000Z",
            "title": "API call from malicious IP",
            "description": "AWS API call from known malicious IP address",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/456",
            "schemaVersion": "2.0",
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "principalId": "AIDAEXAMPLE123456789",
                    "userName": "malicious-user",
                    "userType": "IAMUser"
                }
            },
            "service": {
                "archived": False,
                "count": 10,
                "detectorId": "detector-123",
                "eventFirstSeen": "2024-01-29T09:00:00.000Z",
                "eventLastSeen": "2024-01-29T10:30:00.000Z",
                "resourceRole": "ACTOR",
                "serviceName": "guardduty",
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": "DescribeInstances",
                        "serviceName": "ec2.amazonaws.com",
                        "callerType": "Remote IP",
                        "remoteIpDetails": {
                            "ipAddressV4": "198.51.100.50",
                            "country": {"countryName": "Unknown"}
                        },
                        "userDetails": {
                            "userIdentity": {
                                "type": "IAMUser",
                                "userName": "malicious-user"
                            }
                        }
                    }
                }
            }
        }

    @pytest.fixture
    def sample_port_probe_finding(self):
        """Sample GuardDuty port probe finding."""
        return {
            "id": "finding-probe-123",
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "severity": 2.0,
            "createdAt": "2024-01-29T10:30:00.000Z",
            "title": "Port probe detected",
            "description": "Port scan detected on unprotected port",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/789",
            "schemaVersion": "2.0",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-1234567890abcdef0",
                    "instanceType": "t2.micro",
                    "availabilityZone": "us-east-1a",
                    "imageId": "ami-12345678"
                }
            },
            "service": {
                "archived": False,
                "count": 100,
                "detectorId": "detector-123",
                "eventFirstSeen": "2024-01-29T08:00:00.000Z",
                "eventLastSeen": "2024-01-29T10:30:00.000Z",
                "resourceRole": "TARGET",
                "serviceName": "guardduty",
                "action": {
                    "actionType": "PORT_PROBE",
                    "portProbeAction": {
                        "blocked": False,
                        "portProbeDetails": [
                            {
                                "localPortDetails": {
                                    "port": 80,
                                    "portName": "HTTP"
                                },
                                "remoteIpDetails": {
                                    "ipAddressV4": "192.0.2.100",
                                    "country": {"countryName": "Unknown"}
                                }
                            }
                        ]
                    }
                }
            }
        }

    @pytest.fixture
    def sample_s3_finding(self):
        """Sample GuardDuty S3 bucket finding."""
        return {
            "id": "finding-s3-123",
            "type": "Policy:S3/BucketPublicAccessGranted",
            "severity": 7.5,
            "createdAt": "2024-01-29T10:30:00.000Z",
            "title": "S3 bucket made public",
            "description": "S3 bucket policy allows public access",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/s3",
            "schemaVersion": "2.0",
            "resource": {
                "resourceType": "S3Bucket",
                "s3BucketDetails": [
                    {
                        "name": "sensitive-data-bucket",
                        "arn": "arn:aws:s3:::sensitive-data-bucket",
                        "type": "Destination"
                    }
                ]
            },
            "service": {
                "archived": False,
                "count": 1,
                "detectorId": "detector-123",
                "serviceName": "guardduty",
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": "PutBucketPolicy",
                        "serviceName": "s3.amazonaws.com"
                    }
                }
            }
        }

    def test_parser_log_type(self, parser):
        """Test parser returns correct log type."""
        assert parser.log_type == "guardduty"

    def test_parser_required_fields(self, parser):
        """Test parser has correct required fields."""
        assert "id" in parser.required_fields
        assert "type" in parser.required_fields
        assert "severity" in parser.required_fields
        assert "createdAt" in parser.required_fields

    def test_validate_valid_finding(self, parser, sample_network_finding):
        """Test validation of valid finding."""
        raw = json.dumps(sample_network_finding)
        assert parser.validate(raw) is True

    def test_validate_missing_id(self, parser):
        """Test validation fails without id."""
        finding = {"type": "Test", "severity": 5.0, "createdAt": "2024-01-29T10:30:00Z"}
        raw = json.dumps(finding)
        assert parser.validate(raw) is False

    def test_validate_missing_type(self, parser):
        """Test validation fails without type."""
        finding = {"id": "test", "severity": 5.0, "createdAt": "2024-01-29T10:30:00Z"}
        raw = json.dumps(finding)
        assert parser.validate(raw) is False

    def test_validate_missing_severity(self, parser):
        """Test validation fails without severity."""
        finding = {"id": "test", "type": "Test", "createdAt": "2024-01-29T10:30:00Z"}
        raw = json.dumps(finding)
        assert parser.validate(raw) is False

    def test_validate_missing_created_at(self, parser):
        """Test validation fails without createdAt."""
        finding = {"id": "test", "type": "Test", "severity": 5.0}
        raw = json.dumps(finding)
        assert parser.validate(raw) is False

    def test_validate_invalid_json(self, parser):
        """Test validation fails with invalid JSON."""
        assert parser.validate("not valid json") is False

    def test_parse_network_finding_basic_fields(self, parser, sample_network_finding):
        """Test parsing network finding extracts basic fields."""
        raw = json.dumps(sample_network_finding)
        result = parser.parse(raw)

        assert result.action == "guardduty_finding_UnauthorizedAccess:EC2/SSHBruteForce"
        assert result.result == "failure"
        assert result.service == "guardduty"

    def test_parse_network_finding_ip_addresses(self, parser, sample_network_finding):
        """Test parsing network finding extracts IP addresses."""
        raw = json.dumps(sample_network_finding)
        result = parser.parse(raw)

        assert result.source_ip == "203.0.113.100"
        assert result.destination_ip == "10.0.0.50"

    def test_parse_network_finding_metadata(self, parser, sample_network_finding):
        """Test parsing network finding extracts metadata."""
        raw = json.dumps(sample_network_finding)
        result = parser.parse(raw)

        assert result.metadata["finding_id"] == "finding-123-456-789"
        assert result.metadata["finding_type"] == "UnauthorizedAccess:EC2/SSHBruteForce"
        assert result.metadata["severity"] == 8.0
        assert result.metadata["severity_level"] == "HIGH"
        assert result.metadata["account_id"] == "123456789012"
        assert result.metadata["region"] == "us-east-1"

    def test_parse_network_finding_resource(self, parser, sample_network_finding):
        """Test parsing network finding extracts resource info."""
        raw = json.dumps(sample_network_finding)
        result = parser.parse(raw)

        assert result.metadata["resource"]["type"] == "Instance"
        assert result.metadata["resource"]["instance_id"] == "i-1234567890abcdef0"
        assert result.metadata["resource"]["instance_type"] == "t2.micro"

    def test_parse_api_call_finding(self, parser, sample_api_call_finding):
        """Test parsing API call finding."""
        raw = json.dumps(sample_api_call_finding)
        result = parser.parse(raw)

        assert result.source_ip == "198.51.100.50"
        assert result.user == "malicious-user"
        assert result.metadata["severity_level"] == "MEDIUM"

    def test_parse_api_call_finding_user_extraction(self, parser, sample_api_call_finding):
        """Test parsing API call finding extracts user from userDetails."""
        raw = json.dumps(sample_api_call_finding)
        result = parser.parse(raw)

        assert result.user == "malicious-user"

    def test_parse_api_call_finding_access_key_resource(self, parser, sample_api_call_finding):
        """Test parsing API call finding extracts AccessKey resource."""
        raw = json.dumps(sample_api_call_finding)
        result = parser.parse(raw)

        assert result.metadata["resource"]["type"] == "AccessKey"
        assert result.metadata["resource"]["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert result.metadata["resource"]["user_name"] == "malicious-user"

    def test_parse_port_probe_finding(self, parser, sample_port_probe_finding):
        """Test parsing port probe finding."""
        raw = json.dumps(sample_port_probe_finding)
        result = parser.parse(raw)

        assert result.source_ip == "192.0.2.100"
        assert result.metadata["severity_level"] == "LOW"

    def test_parse_s3_finding(self, parser, sample_s3_finding):
        """Test parsing S3 bucket finding."""
        raw = json.dumps(sample_s3_finding)
        result = parser.parse(raw)

        assert result.metadata["resource"]["type"] == "S3Bucket"
        assert result.metadata["resource"]["bucket_name"] == "sensitive-data-bucket"
        assert result.metadata["resource"]["bucket_arn"] == "arn:aws:s3:::sensitive-data-bucket"
        assert result.metadata["severity_level"] == "HIGH"

    def test_parse_preserves_raw_event(self, parser, sample_network_finding):
        """Test parsing preserves raw event."""
        raw = json.dumps(sample_network_finding)
        result = parser.parse(raw)

        assert result.raw_event == sample_network_finding

    def test_parse_service_info(self, parser, sample_network_finding):
        """Test parsing extracts service info."""
        raw = json.dumps(sample_network_finding)
        result = parser.parse(raw)

        assert result.metadata["service"]["archived"] is False
        assert result.metadata["service"]["count"] == 5
        assert result.metadata["service"]["detector_id"] == "detector-123"
        assert result.metadata["service"]["action_type"] == "NETWORK_CONNECTION"


class TestGuardDutyParserSeverityMapping:
    """Test severity mapping."""

    @pytest.fixture
    def parser(self):
        return GuardDutyParser()

    def test_high_severity(self, parser):
        """Test severity >= 7.0 is HIGH."""
        assert parser._map_severity(7.0) == "HIGH"
        assert parser._map_severity(8.5) == "HIGH"
        assert parser._map_severity(10.0) == "HIGH"

    def test_medium_severity(self, parser):
        """Test severity 4.0-6.9 is MEDIUM."""
        assert parser._map_severity(4.0) == "MEDIUM"
        assert parser._map_severity(5.5) == "MEDIUM"
        assert parser._map_severity(6.9) == "MEDIUM"

    def test_low_severity(self, parser):
        """Test severity < 4.0 is LOW."""
        assert parser._map_severity(0.0) == "LOW"
        assert parser._map_severity(2.0) == "LOW"
        assert parser._map_severity(3.9) == "LOW"


class TestGuardDutyParserNetworkExtraction:
    """Test network info extraction."""

    @pytest.fixture
    def parser(self):
        return GuardDutyParser()

    def test_extract_network_connection_ips(self, parser):
        """Test extracting IPs from network connection action."""
        finding = {
            "service": {
                "action": {
                    "networkConnectionAction": {
                        "remoteIpDetails": {"ipAddressV4": "203.0.113.50"},
                        "localIpDetails": {"ipAddressV4": "10.0.0.100"}
                    }
                }
            }
        }
        source, dest = parser._extract_network_info(finding)
        assert source == "203.0.113.50"
        assert dest == "10.0.0.100"

    def test_extract_api_call_ip(self, parser):
        """Test extracting IP from API call action."""
        finding = {
            "service": {
                "action": {
                    "awsApiCallAction": {
                        "remoteIpDetails": {"ipAddressV4": "198.51.100.50"}
                    }
                }
            }
        }
        source, dest = parser._extract_network_info(finding)
        assert source == "198.51.100.50"
        assert dest is None

    def test_extract_port_probe_ip(self, parser):
        """Test extracting IP from port probe action."""
        finding = {
            "service": {
                "action": {
                    "portProbeAction": {
                        "portProbeDetails": [
                            {"remoteIpDetails": {"ipAddressV4": "192.0.2.100"}}
                        ]
                    }
                }
            }
        }
        source, dest = parser._extract_network_info(finding)
        assert source == "192.0.2.100"
        assert dest is None

    def test_no_network_info(self, parser):
        """Test when no network info is available."""
        finding = {"service": {"action": {}}}
        source, dest = parser._extract_network_info(finding)
        assert source is None
        assert dest is None


class TestGuardDutyParserPrincipalExtraction:
    """Test principal extraction."""

    @pytest.fixture
    def parser(self):
        return GuardDutyParser()

    def test_extract_iam_user_from_api_call(self, parser):
        """Test extracting IAM user from API call action."""
        finding = {
            "service": {
                "action": {
                    "awsApiCallAction": {
                        "userDetails": {
                            "userIdentity": {
                                "type": "IAMUser",
                                "userName": "test-user"
                            }
                        }
                    }
                }
            },
            "resource": {}
        }
        user = parser._extract_principal(finding)
        assert user == "test-user"

    def test_extract_assumed_role_from_api_call(self, parser):
        """Test extracting assumed role from API call action."""
        finding = {
            "service": {
                "action": {
                    "awsApiCallAction": {
                        "userDetails": {
                            "userIdentity": {
                                "type": "AssumedRole",
                                "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session"
                            }
                        }
                    }
                }
            },
            "resource": {}
        }
        user = parser._extract_principal(finding)
        assert user == "arn:aws:sts::123456789012:assumed-role/MyRole/session"

    def test_extract_user_from_access_key(self, parser):
        """Test extracting user from access key details."""
        finding = {
            "service": {"action": {}},
            "resource": {
                "accessKeyDetails": {
                    "userName": "access-key-user"
                }
            }
        }
        user = parser._extract_principal(finding)
        assert user == "access-key-user"

    def test_no_principal(self, parser):
        """Test when no principal info is available."""
        finding = {
            "service": {"action": {}},
            "resource": {}
        }
        user = parser._extract_principal(finding)
        assert user is None


class TestGuardDutyParserResourceExtraction:
    """Test resource info extraction."""

    @pytest.fixture
    def parser(self):
        return GuardDutyParser()

    def test_extract_instance_resource(self, parser):
        """Test extracting instance resource info."""
        finding = {
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-1234567890abcdef0",
                    "instanceType": "t2.micro",
                    "availabilityZone": "us-east-1a",
                    "imageId": "ami-12345678",
                    "tags": [{"key": "Name", "value": "Test"}]
                }
            }
        }
        resource = parser._extract_resource_info(finding)
        assert resource["type"] == "Instance"
        assert resource["instance_id"] == "i-1234567890abcdef0"
        assert resource["instance_type"] == "t2.micro"
        assert len(resource["tags"]) == 1

    def test_extract_access_key_resource(self, parser):
        """Test extracting access key resource info."""
        finding = {
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "principalId": "AIDAEXAMPLE",
                    "userName": "test-user",
                    "userType": "IAMUser"
                }
            }
        }
        resource = parser._extract_resource_info(finding)
        assert resource["type"] == "AccessKey"
        assert resource["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert resource["user_name"] == "test-user"

    def test_extract_s3_bucket_resource(self, parser):
        """Test extracting S3 bucket resource info."""
        finding = {
            "resource": {
                "resourceType": "S3Bucket",
                "s3BucketDetails": [
                    {
                        "name": "test-bucket",
                        "arn": "arn:aws:s3:::test-bucket",
                        "type": "Destination"
                    }
                ]
            }
        }
        resource = parser._extract_resource_info(finding)
        assert resource["type"] == "S3Bucket"
        assert resource["bucket_name"] == "test-bucket"
        assert resource["bucket_arn"] == "arn:aws:s3:::test-bucket"
