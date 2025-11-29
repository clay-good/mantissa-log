"""Unit tests for VPC Flow Logs parser."""

import pytest
from datetime import datetime

from shared.parsers.vpc_flow import VPCFlowLogsParser
from shared.parsers.base import ParserError


class TestVPCFlowLogsParser:
    """Tests for VPCFlowLogsParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return VPCFlowLogsParser()

    @pytest.fixture
    def sample_v2_accept(self):
        """Sample VPC Flow Log version 2 ACCEPT entry."""
        return "2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK"

    @pytest.fixture
    def sample_v2_reject(self):
        """Sample VPC Flow Log version 2 REJECT entry."""
        return "2 123456789012 eni-1234567890abcdef0 203.0.113.100 10.0.0.50 12345 22 6 5 500 1706500000 1706500030 REJECT OK"

    @pytest.fixture
    def sample_v2_udp(self):
        """Sample VPC Flow Log version 2 UDP entry."""
        return "2 123456789012 eni-1234567890abcdef0 10.0.0.100 8.8.8.8 50000 53 17 2 200 1706500000 1706500010 ACCEPT OK"

    @pytest.fixture
    def sample_v2_icmp(self):
        """Sample VPC Flow Log version 2 ICMP entry."""
        return "2 123456789012 eni-1234567890abcdef0 10.0.0.100 10.0.0.50 0 0 1 1 64 1706500000 1706500001 ACCEPT OK"

    @pytest.fixture
    def sample_v5_extended(self):
        """Sample VPC Flow Log version 5 with extended fields."""
        return "5 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK vpc-12345678 subnet-12345678 i-1234567890abcdef0 2 egress 10.0.0.100 203.0.113.50 us-east-1 use1-az1"

    @pytest.fixture
    def sample_nodata(self):
        """Sample VPC Flow Log with NODATA status."""
        return "2 123456789012 eni-1234567890abcdef0 - - - - - - - 1706500000 1706500060 - NODATA"

    def test_parser_log_type(self, parser):
        """Test parser returns correct log type."""
        assert parser.log_type == "vpc_flow_logs"

    def test_parser_required_fields(self, parser):
        """Test parser has correct required fields."""
        assert "srcaddr" in parser.required_fields
        assert "dstaddr" in parser.required_fields
        assert "start" in parser.required_fields
        assert "end" in parser.required_fields
        assert "action" in parser.required_fields

    def test_validate_v2_accept(self, parser, sample_v2_accept):
        """Test validation of valid version 2 entry."""
        assert parser.validate(sample_v2_accept) is True

    def test_validate_v5_extended(self, parser, sample_v5_extended):
        """Test validation of valid version 5 entry."""
        assert parser.validate(sample_v5_extended) is True

    def test_validate_insufficient_fields(self, parser):
        """Test validation fails with insufficient fields."""
        assert parser.validate("2 123456789012 eni-1234") is False

    def test_validate_invalid_version(self, parser):
        """Test validation fails with non-numeric version."""
        assert parser.validate("invalid 123456789012 eni-1234 10.0.0.1 10.0.0.2 80 443 6 10 1500 1000 1060 ACCEPT OK") is False

    def test_validate_invalid_port(self, parser):
        """Test validation fails with non-numeric port."""
        assert parser.validate("2 123456789012 eni-1234 10.0.0.1 10.0.0.2 invalid 443 6 10 1500 1000 1060 ACCEPT OK") is False

    def test_parse_v2_accept_basic_fields(self, parser, sample_v2_accept):
        """Test parsing version 2 ACCEPT entry extracts basic fields."""
        result = parser.parse(sample_v2_accept)

        assert result.source_ip == "10.0.0.100"
        assert result.destination_ip == "203.0.113.50"
        assert result.action == "network_accept"
        assert result.result == "success"
        assert result.service == "vpc"

    def test_parse_v2_accept_metadata(self, parser, sample_v2_accept):
        """Test parsing version 2 ACCEPT entry extracts metadata."""
        result = parser.parse(sample_v2_accept)

        assert result.metadata["version"] == 2
        assert result.metadata["account_id"] == "123456789012"
        assert result.metadata["interface_id"] == "eni-1234567890abcdef0"
        assert result.metadata["srcport"] == 54321
        assert result.metadata["dstport"] == 443
        assert result.metadata["protocol"] == 6
        assert result.metadata["protocol_name"] == "TCP"
        assert result.metadata["packets"] == 10
        assert result.metadata["bytes"] == 1500
        assert result.metadata["log_status"] == "OK"

    def test_parse_v2_reject(self, parser, sample_v2_reject):
        """Test parsing version 2 REJECT entry."""
        result = parser.parse(sample_v2_reject)

        assert result.source_ip == "203.0.113.100"
        assert result.destination_ip == "10.0.0.50"
        assert result.action == "network_reject"
        assert result.result == "failure"
        assert result.metadata["dstport"] == 22

    def test_parse_v2_udp_protocol(self, parser, sample_v2_udp):
        """Test parsing UDP protocol entry."""
        result = parser.parse(sample_v2_udp)

        assert result.metadata["protocol"] == 17
        assert result.metadata["protocol_name"] == "UDP"
        assert result.metadata["dstport"] == 53

    def test_parse_v2_icmp_protocol(self, parser, sample_v2_icmp):
        """Test parsing ICMP protocol entry."""
        result = parser.parse(sample_v2_icmp)

        assert result.metadata["protocol"] == 1
        assert result.metadata["protocol_name"] == "ICMP"

    def test_parse_v5_extended_fields(self, parser, sample_v5_extended):
        """Test parsing version 5 extended fields."""
        result = parser.parse(sample_v5_extended)

        assert result.metadata["version"] == 5
        assert result.metadata["vpc_id"] == "vpc-12345678"
        assert result.metadata["subnet_id"] == "subnet-12345678"
        assert result.metadata["instance_id"] == "i-1234567890abcdef0"
        assert result.metadata["tcp_flags"] == "2"
        assert result.metadata["flow_type"] == "egress"
        assert result.metadata["pkt_srcaddr"] == "10.0.0.100"
        assert result.metadata["pkt_dstaddr"] == "203.0.113.50"
        assert result.metadata["region"] == "us-east-1"
        assert result.metadata["az_id"] == "use1-az1"

    def test_parse_preserves_raw_event(self, parser, sample_v2_accept):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_v2_accept)

        assert result.raw_event is not None
        assert "raw" in result.raw_event

    def test_parse_timestamp(self, parser, sample_v2_accept):
        """Test parsing extracts timestamp."""
        result = parser.parse(sample_v2_accept)

        assert result.timestamp is not None
        assert isinstance(result.timestamp, datetime)

    def test_parse_v3_format(self, parser):
        """Test parsing version 3 uses v5 parser."""
        v3_entry = "3 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(v3_entry)

        assert result.metadata["version"] == 3
        assert result.source_ip == "10.0.0.100"

    def test_parse_v4_format(self, parser):
        """Test parsing version 4 uses v5 parser."""
        v4_entry = "4 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(v4_entry)

        assert result.metadata["version"] == 4
        assert result.source_ip == "10.0.0.100"

    def test_parse_unsupported_version(self, parser):
        """Test parsing unsupported version raises error."""
        unsupported = "1 123456789012 eni-1234 10.0.0.1 10.0.0.2 80 443 6 10 1500 1000 1060 ACCEPT OK"

        with pytest.raises(ParserError) as exc_info:
            parser.parse(unsupported)
        assert "Unsupported VPC Flow Log version" in str(exc_info.value)

    def test_parse_insufficient_fields(self, parser):
        """Test parsing with insufficient fields raises error."""
        short_entry = "2 123456789012 eni-1234"

        with pytest.raises(ParserError) as exc_info:
            parser.parse(short_entry)
        assert "insufficient fields" in str(exc_info.value).lower()


class TestVPCFlowLogsParserProtocols:
    """Test protocol mapping."""

    @pytest.fixture
    def parser(self):
        return VPCFlowLogsParser()

    def test_icmp_protocol(self, parser):
        """Test ICMP protocol mapping."""
        assert parser.PROTOCOL_MAP[1] == "ICMP"

    def test_tcp_protocol(self, parser):
        """Test TCP protocol mapping."""
        assert parser.PROTOCOL_MAP[6] == "TCP"

    def test_udp_protocol(self, parser):
        """Test UDP protocol mapping."""
        assert parser.PROTOCOL_MAP[17] == "UDP"

    def test_gre_protocol(self, parser):
        """Test GRE protocol mapping."""
        assert parser.PROTOCOL_MAP[47] == "GRE"

    def test_esp_protocol(self, parser):
        """Test ESP protocol mapping."""
        assert parser.PROTOCOL_MAP[50] == "ESP"

    def test_ah_protocol(self, parser):
        """Test AH protocol mapping."""
        assert parser.PROTOCOL_MAP[51] == "AH"

    def test_icmpv6_protocol(self, parser):
        """Test ICMPv6 protocol mapping."""
        assert parser.PROTOCOL_MAP[58] == "ICMPv6"

    def test_unknown_protocol_uses_number(self, parser):
        """Test unknown protocol returns number as string."""
        entry = "2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 99 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["protocol_name"] == "99"


class TestVPCFlowLogsParserActions:
    """Test action parsing."""

    @pytest.fixture
    def parser(self):
        return VPCFlowLogsParser()

    def test_accept_action(self, parser):
        """Test ACCEPT action mapping."""
        entry = "2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)

        assert result.action == "network_accept"
        assert result.result == "success"

    def test_reject_action(self, parser):
        """Test REJECT action mapping."""
        entry = "2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 REJECT OK"
        result = parser.parse(entry)

        assert result.action == "network_reject"
        assert result.result == "failure"


class TestVPCFlowLogsParserEdgeCases:
    """Test edge cases."""

    @pytest.fixture
    def parser(self):
        return VPCFlowLogsParser()

    def test_large_byte_count(self, parser):
        """Test parsing large byte counts."""
        entry = "2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 1000000 999999999999 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)

        assert result.metadata["packets"] == 1000000
        assert result.metadata["bytes"] == 999999999999

    def test_zero_port(self, parser):
        """Test parsing with zero ports (like ICMP)."""
        entry = "2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 0 0 1 1 64 1706500000 1706500001 ACCEPT OK"
        result = parser.parse(entry)

        assert result.metadata["srcport"] == 0
        assert result.metadata["dstport"] == 0

    def test_ipv6_addresses(self, parser):
        """Test parsing IPv6 addresses."""
        entry = "2 123456789012 eni-1234567890abcdef0 2001:db8::1 2001:db8::2 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)

        assert result.source_ip == "2001:db8::1"
        assert result.destination_ip == "2001:db8::2"

    def test_v5_partial_extended_fields(self, parser):
        """Test version 5 with partial extended fields."""
        entry = "5 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK vpc-12345678"
        result = parser.parse(entry)

        assert result.metadata["vpc_id"] == "vpc-12345678"
        assert result.metadata.get("subnet_id") is None

    def test_whitespace_handling(self, parser):
        """Test handling of extra whitespace."""
        entry = "  2 123456789012 eni-1234567890abcdef0 10.0.0.100 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK  "
        result = parser.parse(entry)

        assert result.source_ip == "10.0.0.100"
        assert result.action == "network_accept"
