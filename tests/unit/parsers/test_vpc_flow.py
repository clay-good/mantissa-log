"""Unit tests for VPC Flow Logs parser.

Covers version 2 and 3-5 parsing, protocol mapping, action mapping, edge
cases, TCP flag bitmask decoding, RFC 1918 internal-traffic detection,
NDR-normalized metadata fields, and full v5 extended field support (indices
14-28).
"""

import pytest
from datetime import datetime

from src.shared.parsers.vpc_flow import VPCFlowLogsParser
from src.shared.parsers.base import ParserError


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
        # tcp_flags is now a parsed list; raw value in tcp_flags_raw
        assert result.metadata["tcp_flags"] == ["SYN"]
        assert result.metadata["tcp_flags_raw"] == "2"
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
        # Error message indicates missing required fields
        assert "missing required fields" in str(exc_info.value).lower()


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


# ======================================================================
# TCP Flag Bitmask Parsing
# ======================================================================


class TestTCPFlagParsing:
    """Tests for TCP flag bitmask decoding."""

    def test_syn_flag(self):
        """SYN = 0x02 = 2."""
        assert VPCFlowLogsParser._parse_tcp_flags("2") == ["SYN"]

    def test_ack_flag(self):
        """ACK = 0x10 = 16."""
        assert VPCFlowLogsParser._parse_tcp_flags("16") == ["ACK"]

    def test_syn_ack_flags(self):
        """SYN+ACK = 0x12 = 18."""
        assert VPCFlowLogsParser._parse_tcp_flags("18") == ["ACK", "SYN"]

    def test_fin_ack_flags(self):
        """FIN+ACK = 0x11 = 17."""
        assert VPCFlowLogsParser._parse_tcp_flags("17") == ["ACK", "FIN"]

    def test_rst_flag(self):
        """RST = 0x04 = 4."""
        assert VPCFlowLogsParser._parse_tcp_flags("4") == ["RST"]

    def test_psh_ack_flags(self):
        """PSH+ACK = 0x18 = 24."""
        assert VPCFlowLogsParser._parse_tcp_flags("24") == ["ACK", "PSH"]

    def test_urg_flag(self):
        """URG = 0x20 = 32."""
        assert VPCFlowLogsParser._parse_tcp_flags("32") == ["URG"]

    def test_all_flags(self):
        """All six standard flags = 0x3F = 63."""
        result = VPCFlowLogsParser._parse_tcp_flags("63")
        assert result == ["ACK", "FIN", "PSH", "RST", "SYN", "URG"]

    def test_zero_bitmask(self):
        """Zero bitmask means no flags set."""
        assert VPCFlowLogsParser._parse_tcp_flags("0") == []

    def test_none_value(self):
        """None returns empty list."""
        assert VPCFlowLogsParser._parse_tcp_flags(None) == []

    def test_dash_value(self):
        """Dash placeholder returns empty list."""
        assert VPCFlowLogsParser._parse_tcp_flags("-") == []

    def test_invalid_string(self):
        """Non-numeric string returns empty list."""
        assert VPCFlowLogsParser._parse_tcp_flags("invalid") == []

    def test_v5_tcp_flags_parsed_in_metadata(self):
        """tcp_flags in metadata is the parsed list for v5 entries."""
        parser = VPCFlowLogsParser()
        # tcp_flags field at index 17 = "18" (SYN+ACK)
        entry = "5 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK vpc-1 sub-1 i-1 18 ingress 10.0.0.1 10.0.0.2 us-east-1 use1-az1"
        result = parser.parse(entry)
        assert result.metadata["tcp_flags"] == ["ACK", "SYN"]
        assert result.metadata["tcp_flags_raw"] == "18"

    def test_v2_tcp_flags_empty(self):
        """v2 entries have empty tcp_flags (no flag data available)."""
        parser = VPCFlowLogsParser()
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["tcp_flags"] == []


# ======================================================================
# RFC 1918 / Internal Traffic Detection
# ======================================================================


class TestInternalTrafficDetection:
    """Tests for RFC 1918 private address detection."""

    def test_10_x_is_private(self):
        """10.0.0.0/8 is private."""
        assert VPCFlowLogsParser._is_rfc1918("10.0.0.1") is True
        assert VPCFlowLogsParser._is_rfc1918("10.255.255.255") is True

    def test_172_16_31_is_private(self):
        """172.16.0.0/12 is private."""
        assert VPCFlowLogsParser._is_rfc1918("172.16.0.1") is True
        assert VPCFlowLogsParser._is_rfc1918("172.31.255.255") is True

    def test_172_15_is_public(self):
        """172.15.x.x is public."""
        assert VPCFlowLogsParser._is_rfc1918("172.15.0.1") is False

    def test_172_32_is_public(self):
        """172.32.x.x is public."""
        assert VPCFlowLogsParser._is_rfc1918("172.32.0.1") is False

    def test_192_168_is_private(self):
        """192.168.0.0/16 is private."""
        assert VPCFlowLogsParser._is_rfc1918("192.168.1.1") is True
        assert VPCFlowLogsParser._is_rfc1918("192.168.255.255") is True

    def test_public_ip(self):
        """Public IPs are not RFC 1918."""
        assert VPCFlowLogsParser._is_rfc1918("203.0.113.50") is False
        assert VPCFlowLogsParser._is_rfc1918("8.8.8.8") is False

    def test_ipv6_is_not_rfc1918(self):
        """IPv6 addresses are not matched by RFC 1918 regex."""
        assert VPCFlowLogsParser._is_rfc1918("2001:db8::1") is False

    def test_is_internal_both_private(self):
        """Both 10.x addresses → internal."""
        assert VPCFlowLogsParser._is_internal("10.0.0.1", "10.0.0.2") is True

    def test_is_internal_mixed(self):
        """One private, one public → not internal."""
        assert VPCFlowLogsParser._is_internal("10.0.0.1", "203.0.113.50") is False

    def test_is_internal_both_public(self):
        """Both public → not internal."""
        assert VPCFlowLogsParser._is_internal("203.0.113.1", "8.8.8.8") is False

    def test_v2_internal_traffic(self):
        """v2 entry with both private IPs is marked internal."""
        parser = VPCFlowLogsParser()
        entry = "2 123456789012 eni-abc 10.0.0.100 10.0.0.50 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["is_internal"] is True

    def test_v2_external_traffic(self):
        """v2 entry with one public IP is not internal."""
        parser = VPCFlowLogsParser()
        entry = "2 123456789012 eni-abc 10.0.0.100 203.0.113.50 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["is_internal"] is False


# ======================================================================
# NDR-Normalized Metadata Fields
# ======================================================================


class TestNDRNormalizedFields:
    """Tests for NDR-normalized metadata fields on ParsedEvent."""

    @pytest.fixture
    def parser(self):
        return VPCFlowLogsParser()

    def test_v2_source_and_destination_port(self, parser):
        """v2 includes source_port and destination_port."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["source_port"] == 54321
        assert result.metadata["destination_port"] == 443

    def test_v2_bytes_transferred(self, parser):
        """v2 includes bytes_transferred mirroring bytes."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["bytes_transferred"] == 1500
        assert result.metadata["bytes"] == 1500

    def test_v2_start_and_end_time(self, parser):
        """v2 includes ISO 8601 start_time and end_time."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["start_time"] == datetime.fromtimestamp(1706500000).isoformat()
        assert result.metadata["end_time"] == datetime.fromtimestamp(1706500060).isoformat()

    def test_v2_duration_seconds(self, parser):
        """v2 includes duration_seconds."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["duration_seconds"] == 60

    def test_v2_duration_zero(self, parser):
        """Duration is zero when start == end."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 1 64 1706500000 1706500000 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["duration_seconds"] == 0

    def test_v2_network_tag(self, parser):
        """v2 includes 'network' tag."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert "network" in result.metadata["tags"]

    def test_v2_aws_service_is_none(self, parser):
        """v2 entries have no AWS service info."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["aws_service"] is None

    def test_v2_flow_direction_is_none(self, parser):
        """v2 entries have no flow direction info."""
        entry = "2 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)
        assert result.metadata["flow_direction"] is None

    def test_v5_ndr_fields(self, parser):
        """v5 entries include all NDR-normalized fields."""
        entry = "5 123456789012 eni-abc 10.0.0.1 203.0.113.50 54321 443 6 10 1500 1706500000 1706500060 ACCEPT OK vpc-1 sub-1 i-1 18 egress 10.0.0.1 203.0.113.50 us-east-1 use1-az1"
        result = parser.parse(entry)

        assert result.metadata["source_port"] == 54321
        assert result.metadata["destination_port"] == 443
        assert result.metadata["bytes_transferred"] == 1500
        assert result.metadata["tcp_flags"] == ["ACK", "SYN"]
        assert result.metadata["duration_seconds"] == 60
        assert result.metadata["is_internal"] is False
        assert result.metadata["aws_service"] is None
        assert "network" in result.metadata["tags"]


# ======================================================================
# V5 Full Extended Fields (indices 14-28)
# ======================================================================


class TestV5FullExtendedFields:
    """Tests for all VPC Flow Log v5 extended fields (indices 14-28)."""

    @pytest.fixture
    def parser(self):
        return VPCFlowLogsParser()

    @pytest.fixture
    def full_v5_entry(self):
        """Complete v5 entry with all 29 fields (indices 0-28)."""
        fields = [
            "5",                    # 0:  version
            "123456789012",         # 1:  account-id
            "eni-abc",              # 2:  interface-id
            "10.0.0.100",           # 3:  srcaddr
            "52.94.133.10",         # 4:  dstaddr (S3 IP)
            "54321",                # 5:  srcport
            "443",                  # 6:  dstport
            "6",                    # 7:  protocol (TCP)
            "100",                  # 8:  packets
            "50000",                # 9:  bytes
            "1706500000",           # 10: start
            "1706500120",           # 11: end
            "ACCEPT",               # 12: action
            "OK",                   # 13: log-status
            "vpc-abcdef12",         # 14: vpc-id
            "subnet-abcdef12",      # 15: subnet-id
            "i-0abcdef1234567890",  # 16: instance-id
            "18",                   # 17: tcp-flags (SYN+ACK)
            "egress",               # 18: type (flow type)
            "10.0.0.100",           # 19: pkt-srcaddr
            "52.94.133.10",         # 20: pkt-dstaddr
            "us-east-1",            # 21: region
            "use1-az1",             # 22: az-id
            "wavelength",           # 23: sublocation-type
            "wl-sub-123",           # 24: sublocation-id
            "-",                    # 25: pkt-src-aws-service
            "S3",                   # 26: pkt-dst-aws-service
            "egress",               # 27: flow-direction
            "8",                    # 28: traffic-path
        ]
        return " ".join(fields)

    def test_sublocation_type(self, parser, full_v5_entry):
        """Index 23: sublocation_type parsed correctly."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["sublocation_type"] == "wavelength"

    def test_sublocation_id(self, parser, full_v5_entry):
        """Index 24: sublocation_id parsed correctly."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["sublocation_id"] == "wl-sub-123"

    def test_pkt_src_aws_service_dash(self, parser, full_v5_entry):
        """Index 25: pkt_src_aws_service '-' maps to None."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["pkt_src_aws_service"] is None

    def test_pkt_dst_aws_service(self, parser, full_v5_entry):
        """Index 26: pkt_dst_aws_service parsed correctly."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["pkt_dst_aws_service"] == "S3"

    def test_flow_direction(self, parser, full_v5_entry):
        """Index 27: flow_direction parsed correctly."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["flow_direction"] == "egress"

    def test_traffic_path(self, parser, full_v5_entry):
        """Index 28: traffic_path parsed correctly."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["traffic_path"] == "8"

    def test_aws_service_from_dst(self, parser, full_v5_entry):
        """aws_service is derived from pkt_dst_aws_service (S3)."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["aws_service"] == "S3"

    def test_aws_service_from_src(self, parser):
        """aws_service falls back to pkt_src_aws_service if dst is empty."""
        fields = [
            "5", "123456789012", "eni-abc", "52.94.133.10", "10.0.0.100",
            "443", "54321", "6", "100", "50000", "1706500000", "1706500120",
            "ACCEPT", "OK", "vpc-1", "sub-1", "i-1", "18", "ingress",
            "52.94.133.10", "10.0.0.100", "us-east-1", "use1-az1",
            "-", "-", "DYNAMODB", "-", "ingress", "1",
        ]
        result = parser.parse(" ".join(fields))
        assert result.metadata["pkt_src_aws_service"] == "DYNAMODB"
        assert result.metadata["pkt_dst_aws_service"] is None
        assert result.metadata["aws_service"] == "DYNAMODB"

    def test_duration_seconds_120(self, parser, full_v5_entry):
        """Duration is end - start = 1706500120 - 1706500000 = 120."""
        result = parser.parse(full_v5_entry)
        assert result.metadata["duration_seconds"] == 120

    def test_v5_missing_extended_fields_default_to_none(self, parser):
        """v5 with only 14 base fields has all extended fields as None."""
        entry = "5 123456789012 eni-abc 10.0.0.1 10.0.0.2 80 443 6 10 1500 1706500000 1706500060 ACCEPT OK"
        result = parser.parse(entry)

        assert result.metadata["vpc_id"] is None
        assert result.metadata["subnet_id"] is None
        assert result.metadata["instance_id"] is None
        assert result.metadata["tcp_flags"] == []
        assert result.metadata["tcp_flags_raw"] is None
        assert result.metadata["flow_type"] is None
        assert result.metadata["pkt_srcaddr"] is None
        assert result.metadata["pkt_dstaddr"] is None
        assert result.metadata["region"] is None
        assert result.metadata["az_id"] is None
        assert result.metadata["sublocation_type"] is None
        assert result.metadata["sublocation_id"] is None
        assert result.metadata["pkt_src_aws_service"] is None
        assert result.metadata["pkt_dst_aws_service"] is None
        assert result.metadata["flow_direction"] is None
        assert result.metadata["traffic_path"] is None
        assert result.metadata["aws_service"] is None

    def test_dash_fields_become_none(self, parser):
        """Extended fields set to '-' are normalised to None."""
        fields = [
            "5", "123456789012", "eni-abc", "10.0.0.1", "10.0.0.2",
            "80", "443", "6", "10", "1500", "1706500000", "1706500060",
            "ACCEPT", "OK",
            "-", "-", "-", "-", "-", "-", "-", "-", "-",
            "-", "-", "-", "-", "-", "-",
        ]
        result = parser.parse(" ".join(fields))

        assert result.metadata["vpc_id"] is None
        assert result.metadata["subnet_id"] is None
        assert result.metadata["instance_id"] is None
        assert result.metadata["tcp_flags"] == []
        assert result.metadata["tcp_flags_raw"] is None
        assert result.metadata["flow_type"] is None
        assert result.metadata["sublocation_type"] is None
        assert result.metadata["sublocation_id"] is None
        assert result.metadata["pkt_src_aws_service"] is None
        assert result.metadata["pkt_dst_aws_service"] is None
        assert result.metadata["flow_direction"] is None
        assert result.metadata["traffic_path"] is None


# ======================================================================
# _safe_field helper
# ======================================================================


class TestSafeField:
    """Tests for the _safe_field static method."""

    def test_present_value(self):
        """Returns value when index is within range."""
        assert VPCFlowLogsParser._safe_field(["a", "b", "c"], 1) == "b"

    def test_missing_index(self):
        """Returns None when index is out of range."""
        assert VPCFlowLogsParser._safe_field(["a", "b"], 5) is None

    def test_dash_becomes_none(self):
        """Returns None when value is '-'."""
        assert VPCFlowLogsParser._safe_field(["a", "-", "c"], 1) is None

    def test_empty_list(self):
        """Returns None for empty list."""
        assert VPCFlowLogsParser._safe_field([], 0) is None
