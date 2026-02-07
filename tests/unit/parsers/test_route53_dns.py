"""Unit tests for AWS Route 53 DNS Query Log parser."""

import math
import pytest
from datetime import datetime, timezone

from src.shared.parsers.route53_dns import Route53DNSParser, shannon_entropy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return Route53DNSParser()


def _make_dns_event(
    version="1.100000",
    account_id="123456789012",
    region="us-east-1",
    vpc_id="vpc-abc123",
    query_timestamp="2025-06-15T10:00:00Z",
    query_name="api.example.com.",
    query_type="A",
    query_class="IN",
    rcode="NOERROR",
    answers=None,
    srcaddr="10.0.0.4",
    srcport="54321",
    transport="UDP",
    edns_client_subnet="",
    srcids=None,
    firewall_rule_group_id="",
    firewall_rule_action="",
    firewall_domain_list_id="",
):
    """Build a synthetic Route 53 DNS query log event."""
    if answers is None:
        answers = [{"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}]
    if srcids is None:
        srcids = {"instance": "i-0abc123", "resolver_endpoint": ""}

    return {
        "version": version,
        "account_id": account_id,
        "region": region,
        "vpc_id": vpc_id,
        "query_timestamp": query_timestamp,
        "query_name": query_name,
        "query_type": query_type,
        "query_class": query_class,
        "rcode": rcode,
        "answers": answers,
        "srcaddr": srcaddr,
        "srcport": srcport,
        "transport": transport,
        "edns_client_subnet": edns_client_subnet,
        "srcids": srcids,
        "firewall_rule_group_id": firewall_rule_group_id,
        "firewall_rule_action": firewall_rule_action,
        "firewall_domain_list_id": firewall_domain_list_id,
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestRoute53DNSParserInit:
    """Tests for parser initialisation."""

    def test_source_type(self, parser):
        assert parser.source_type == "route53_dns"


class TestShannonEntropy:
    """Tests for the shannon_entropy helper function."""

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("a") == 0.0

    def test_repeated_chars(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" → 2 chars, each p=0.5, entropy = -2*(0.5*log2(0.5)) = 1.0
        assert shannon_entropy("ab") == 1.0

    def test_four_equal_chars(self):
        # "abcd" → 4 chars, each p=0.25, entropy = -4*(0.25*log2(0.25)) = 2.0
        assert shannon_entropy("abcd") == 2.0

    def test_high_entropy_string(self):
        # Random-looking string typical of DNS tunneling
        s = "aG9zdC5leGFtcGxlLmNvbQ"
        entropy = shannon_entropy(s)
        assert entropy > 3.0  # High entropy indicates potential tunneling

    def test_low_entropy_string(self):
        # Normal word
        entropy = shannon_entropy("www")
        assert entropy == 0.0

    def test_moderate_entropy(self):
        # Normal subdomain
        entropy = shannon_entropy("api")
        assert 0.5 < entropy < 2.0

    def test_numeric_subdomain(self):
        # Numeric-heavy subdomains are suspicious
        entropy = shannon_entropy("1234567890abcdef")
        assert entropy > 3.0


class TestValidation:
    """Tests for event validation."""

    def test_valid_full_event(self, parser):
        event = _make_dns_event()
        assert parser.validate(event) is True

    def test_valid_minimal_event(self, parser):
        event = {"query_name": "example.com.", "rcode": "NOERROR"}
        assert parser.validate(event) is True

    def test_valid_with_query_type(self, parser):
        event = {"query_name": "example.com.", "query_type": "A"}
        assert parser.validate(event) is True

    def test_valid_with_srcaddr(self, parser):
        event = {"query_name": "example.com.", "srcaddr": "10.0.0.1"}
        assert parser.validate(event) is True

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_invalid_non_dict(self, parser):
        assert parser.validate("not a dict") is False

    def test_invalid_no_query_name(self, parser):
        event = {"rcode": "NOERROR", "query_type": "A"}
        assert parser.validate(event) is False

    def test_invalid_query_name_only(self, parser):
        # Has query_name but no R53-specific fields
        event = {"query_name": "example.com."}
        assert parser.validate(event) is False


class TestBasicParsing:
    """Tests for core parsing fields."""

    def test_action_with_query_type(self, parser):
        result = parser.parse(_make_dns_event(query_type="A"))
        assert result["action"] == "dns_query_a"

    def test_action_aaaa(self, parser):
        result = parser.parse(_make_dns_event(query_type="AAAA"))
        assert result["action"] == "dns_query_aaaa"

    def test_action_mx(self, parser):
        result = parser.parse(_make_dns_event(query_type="MX"))
        assert result["action"] == "dns_query_mx"

    def test_action_txt(self, parser):
        result = parser.parse(_make_dns_event(query_type="TXT"))
        assert result["action"] == "dns_query_txt"

    def test_action_no_query_type(self, parser):
        result = parser.parse(_make_dns_event(query_type=""))
        assert result["action"] == "dns_query"

    def test_result_noerror(self, parser):
        result = parser.parse(_make_dns_event(rcode="NOERROR"))
        assert result["result"] == "success"

    def test_result_nxdomain(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["result"] == "failure"

    def test_result_servfail(self, parser):
        result = parser.parse(_make_dns_event(rcode="SERVFAIL"))
        assert result["result"] == "failure"

    def test_result_empty_rcode(self, parser):
        result = parser.parse(_make_dns_event(rcode=""))
        assert result["result"] == "unknown"

    def test_service(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["service"] == "route53"

    def test_source_ip(self, parser):
        result = parser.parse(_make_dns_event(srcaddr="192.168.1.5"))
        assert result["source_ip"] == "192.168.1.5"

    def test_source_ip_empty(self, parser):
        result = parser.parse(_make_dns_event(srcaddr=""))
        assert result["source_ip"] is None

    def test_destination_ip_is_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["destination_ip"] is None

    def test_user_is_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["user"] is None

    def test_timestamp(self, parser):
        result = parser.parse(_make_dns_event(
            query_timestamp="2025-06-15T10:00:00Z"
        ))
        assert "2025-06-15T10:00:00" in result["timestamp"]

    def test_raw_event_preserved(self, parser):
        event = _make_dns_event()
        result = parser.parse(event)
        assert result["raw_event"] is event


class TestQueryMetadata:
    """Tests for DNS query metadata fields."""

    def test_query_name_trailing_dot_stripped(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        assert result["metadata"]["query_name"] == "api.example.com"

    def test_query_name_no_trailing_dot(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com"))
        assert result["metadata"]["query_name"] == "api.example.com"

    def test_query_type(self, parser):
        result = parser.parse(_make_dns_event(query_type="CNAME"))
        assert result["metadata"]["query_type"] == "CNAME"

    def test_query_class(self, parser):
        result = parser.parse(_make_dns_event(query_class="IN"))
        assert result["metadata"]["query_class"] == "IN"

    def test_response_code(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["metadata"]["response_code"] == "NXDOMAIN"

    def test_transport(self, parser):
        result = parser.parse(_make_dns_event(transport="TCP"))
        assert result["metadata"]["transport"] == "TCP"

    def test_source_port(self, parser):
        result = parser.parse(_make_dns_event(srcport="54321"))
        assert result["metadata"]["source_port"] == 54321

    def test_source_port_as_int(self, parser):
        event = _make_dns_event()
        event["srcport"] = 12345
        result = parser.parse(event)
        assert result["metadata"]["source_port"] == 12345

    def test_edns_client_subnet(self, parser):
        result = parser.parse(_make_dns_event(edns_client_subnet="10.0.0.0/24"))
        assert result["metadata"]["edns_client_subnet"] == "10.0.0.0/24"

    def test_edns_client_subnet_empty(self, parser):
        result = parser.parse(_make_dns_event(edns_client_subnet=""))
        assert result["metadata"]["edns_client_subnet"] is None


class TestAnswersAndResolvedIPs:
    """Tests for answer parsing and resolved IP extraction."""

    def test_single_a_record(self, parser):
        answers = [{"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_multiple_a_records(self, parser):
        answers = [
            {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"},
            {"Rdata": "93.184.216.35", "Type": "A", "Class": "IN"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34", "93.184.216.35"]

    def test_aaaa_record(self, parser):
        answers = [{"Rdata": "2606:2800:220:1:248:1893:25c8:1946", "Type": "AAAA", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert "2606:2800:220:1:248:1893:25c8:1946" in result["metadata"]["resolved_ips"]

    def test_cname_not_in_resolved_ips(self, parser):
        answers = [
            {"Rdata": "edge.example.com.", "Type": "CNAME", "Class": "IN"},
            {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_empty_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=[]))
        assert result["metadata"]["resolved_ips"] == []

    def test_no_answers_key(self, parser):
        event = _make_dns_event()
        del event["answers"]
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == []

    def test_answers_preserved_in_metadata(self, parser):
        answers = [{"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["answers"] == answers

    def test_deduplicated_ips(self, parser):
        answers = [
            {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"},
            {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_lowercase_rdata_key(self, parser):
        """Some log formats use lowercase rdata."""
        answers = [{"rdata": "93.184.216.34", "type": "A"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]


class TestNXDomain:
    """Tests for NXDOMAIN detection."""

    def test_is_nxdomain_true(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_is_nxdomain_false_noerror(self, parser):
        result = parser.parse(_make_dns_event(rcode="NOERROR"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_is_nxdomain_false_servfail(self, parser):
        result = parser.parse(_make_dns_event(rcode="SERVFAIL"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_is_nxdomain_case_insensitive(self, parser):
        result = parser.parse(_make_dns_event(rcode="nxdomain"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_is_nxdomain_empty_rcode(self, parser):
        result = parser.parse(_make_dns_event(rcode=""))
        assert result["metadata"]["is_nxdomain"] is False


class TestSubdomainAnalysis:
    """Tests for subdomain count and entropy."""

    def test_subdomain_count_three_labels(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        assert result["metadata"]["subdomain_count"] == 3

    def test_subdomain_count_two_labels(self, parser):
        result = parser.parse(_make_dns_event(query_name="example.com."))
        assert result["metadata"]["subdomain_count"] == 2

    def test_subdomain_count_single_label(self, parser):
        result = parser.parse(_make_dns_event(query_name="localhost."))
        assert result["metadata"]["subdomain_count"] == 1

    def test_subdomain_count_deep_nesting(self, parser):
        result = parser.parse(_make_dns_event(
            query_name="a.b.c.d.e.example.com."
        ))
        assert result["metadata"]["subdomain_count"] == 7

    def test_subdomain_count_empty(self, parser):
        result = parser.parse(_make_dns_event(query_name=""))
        assert result["metadata"]["subdomain_count"] == 0

    def test_entropy_normal_subdomain(self, parser):
        result = parser.parse(_make_dns_event(query_name="www.example.com."))
        # "www" has 0 entropy (all same char)
        assert result["metadata"]["subdomain_entropy"] == 0.0

    def test_entropy_varied_subdomain(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        # "api" has moderate entropy
        entropy = result["metadata"]["subdomain_entropy"]
        assert entropy > 0

    def test_entropy_tunneling_subdomain(self, parser):
        """High-entropy leftmost label suggests DNS tunneling."""
        result = parser.parse(_make_dns_event(
            query_name="aG9zdC5leGFtcGxlLmNvbQ.tunnel.evil.com."
        ))
        entropy = result["metadata"]["subdomain_entropy"]
        assert entropy > 3.0

    def test_entropy_random_hex(self, parser):
        result = parser.parse(_make_dns_event(
            query_name="a1b2c3d4e5f6a7b8.example.com."
        ))
        entropy = result["metadata"]["subdomain_entropy"]
        assert entropy > 3.0


class TestExternalResolution:
    """Tests for is_external_resolution."""

    def test_public_ip(self, parser):
        answers = [{"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is True

    def test_private_ip_10(self, parser):
        answers = [{"Rdata": "10.0.0.1", "Type": "A", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is False

    def test_private_ip_172(self, parser):
        answers = [{"Rdata": "172.16.0.1", "Type": "A", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is False

    def test_private_ip_192(self, parser):
        answers = [{"Rdata": "192.168.1.1", "Type": "A", "Class": "IN"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is False

    def test_mixed_public_private(self, parser):
        """If ANY resolved IP is public, is_external is True."""
        answers = [
            {"Rdata": "10.0.0.1", "Type": "A", "Class": "IN"},
            {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is True

    def test_no_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=[]))
        assert result["metadata"]["is_external_resolution"] is False


class TestAWSContext:
    """Tests for AWS-specific metadata fields."""

    def test_version(self, parser):
        result = parser.parse(_make_dns_event(version="1.100000"))
        assert result["metadata"]["version"] == "1.100000"

    def test_account_id(self, parser):
        result = parser.parse(_make_dns_event(account_id="123456789012"))
        assert result["metadata"]["account_id"] == "123456789012"

    def test_region(self, parser):
        result = parser.parse(_make_dns_event(region="us-west-2"))
        assert result["metadata"]["region"] == "us-west-2"

    def test_vpc_id(self, parser):
        result = parser.parse(_make_dns_event(vpc_id="vpc-xyz789"))
        assert result["metadata"]["vpc_id"] == "vpc-xyz789"

    def test_instance_id(self, parser):
        result = parser.parse(_make_dns_event(
            srcids={"instance": "i-0abc123", "resolver_endpoint": ""}
        ))
        assert result["metadata"]["instance_id"] == "i-0abc123"

    def test_instance_id_empty(self, parser):
        result = parser.parse(_make_dns_event(
            srcids={"instance": "", "resolver_endpoint": ""}
        ))
        assert result["metadata"]["instance_id"] is None

    def test_resolver_endpoint(self, parser):
        result = parser.parse(_make_dns_event(
            srcids={"instance": "", "resolver_endpoint": "rslvr-in-abc123"}
        ))
        assert result["metadata"]["resolver_endpoint"] == "rslvr-in-abc123"


class TestFirewallInfo:
    """Tests for Route 53 DNS Firewall metadata."""

    def test_firewall_rule_group_id(self, parser):
        result = parser.parse(_make_dns_event(
            firewall_rule_group_id="rslvr-frg-abc123"
        ))
        assert result["metadata"]["firewall_rule_group_id"] == "rslvr-frg-abc123"

    def test_firewall_rule_action(self, parser):
        result = parser.parse(_make_dns_event(
            firewall_rule_action="BLOCK"
        ))
        assert result["metadata"]["firewall_rule_action"] == "BLOCK"

    def test_firewall_domain_list_id(self, parser):
        result = parser.parse(_make_dns_event(
            firewall_domain_list_id="rslvr-fdl-abc123"
        ))
        assert result["metadata"]["firewall_domain_list_id"] == "rslvr-fdl-abc123"

    def test_firewall_fields_empty(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["firewall_rule_group_id"] is None
        assert result["metadata"]["firewall_rule_action"] is None
        assert result["metadata"]["firewall_domain_list_id"] is None


class TestDNSTags:
    """Tests for NDR tagging."""

    def test_dns_tag_present(self, parser):
        result = parser.parse(_make_dns_event())
        assert "dns" in result["metadata"]["tags"]

    def test_no_network_tag(self, parser):
        result = parser.parse(_make_dns_event())
        assert "network" not in result["metadata"]["tags"]


class TestDomainAgeDays:
    """Tests for domain_age_days placeholder."""

    def test_domain_age_is_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["domain_age_days"] is None


class TestOutputSchema:
    """Tests verifying the output matches ParsedEvent.to_dict() keys."""

    def test_output_keys(self, parser):
        result = parser.parse(_make_dns_event())
        expected_keys = {
            "timestamp", "source_ip", "destination_ip", "user",
            "action", "result", "service", "metadata", "raw_event",
        }
        assert set(result.keys()) == expected_keys


class TestHelpers:
    """Tests for helper methods."""

    def test_strip_trailing_dot(self):
        assert Route53DNSParser._strip_trailing_dot("example.com.") == "example.com"

    def test_strip_no_trailing_dot(self):
        assert Route53DNSParser._strip_trailing_dot("example.com") == "example.com"

    def test_strip_empty_string(self):
        assert Route53DNSParser._strip_trailing_dot("") == ""

    def test_safe_int_integer(self):
        assert Route53DNSParser._safe_int(42) == 42

    def test_safe_int_string(self):
        assert Route53DNSParser._safe_int("123") == 123

    def test_safe_int_none(self):
        assert Route53DNSParser._safe_int(None) is None

    def test_safe_int_empty_string(self):
        assert Route53DNSParser._safe_int("") is None

    def test_safe_int_invalid(self):
        assert Route53DNSParser._safe_int("abc") is None

    def test_parse_timestamp_rfc3339(self):
        dt = Route53DNSParser._parse_timestamp("2025-06-15T10:00:00Z")
        assert dt is not None
        assert dt.year == 2025
        assert dt.tzinfo is not None

    def test_parse_timestamp_with_offset(self):
        dt = Route53DNSParser._parse_timestamp("2025-06-15T10:00:00+05:30")
        assert dt is not None

    def test_parse_timestamp_none(self):
        assert Route53DNSParser._parse_timestamp(None) is None

    def test_parse_timestamp_empty(self):
        assert Route53DNSParser._parse_timestamp("") is None

    def test_parse_timestamp_invalid(self):
        assert Route53DNSParser._parse_timestamp("not-a-date") is None

    def test_is_rfc1918_private(self):
        assert Route53DNSParser._is_rfc1918("10.0.0.1") is True
        assert Route53DNSParser._is_rfc1918("172.16.0.1") is True
        assert Route53DNSParser._is_rfc1918("192.168.1.1") is True

    def test_is_rfc1918_public(self):
        assert Route53DNSParser._is_rfc1918("8.8.8.8") is False


class TestFullIntegration:
    """Integration tests with realistic DNS query data."""

    def test_normal_a_query(self, parser):
        event = _make_dns_event(
            query_name="www.example.com.",
            query_type="A",
            rcode="NOERROR",
            answers=[{"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}],
            srcaddr="10.0.0.4",
        )
        result = parser.parse(event)

        assert result["action"] == "dns_query_a"
        assert result["result"] == "success"
        assert result["source_ip"] == "10.0.0.4"
        m = result["metadata"]
        assert m["query_name"] == "www.example.com"
        assert m["query_type"] == "A"
        assert m["response_code"] == "NOERROR"
        assert m["resolved_ips"] == ["93.184.216.34"]
        assert m["is_nxdomain"] is False
        assert m["subdomain_count"] == 3
        assert m["is_external_resolution"] is True
        assert "dns" in m["tags"]

    def test_nxdomain_query(self, parser):
        event = _make_dns_event(
            query_name="nonexistent.example.com.",
            query_type="A",
            rcode="NXDOMAIN",
            answers=[],
        )
        result = parser.parse(event)

        assert result["result"] == "failure"
        m = result["metadata"]
        assert m["is_nxdomain"] is True
        assert m["resolved_ips"] == []
        assert m["is_external_resolution"] is False

    def test_dns_tunneling_pattern(self, parser):
        """Query with long, high-entropy subdomain labels."""
        event = _make_dns_event(
            query_name="aG9zdC5leGFtcGxlLmNvbQo.data.tunnel.evil.com.",
            query_type="TXT",
            rcode="NOERROR",
            answers=[],
        )
        result = parser.parse(event)

        m = result["metadata"]
        assert m["subdomain_count"] == 5
        assert m["subdomain_entropy"] > 3.0  # High entropy
        assert m["query_type"] == "TXT"

    def test_internal_dns_resolution(self, parser):
        event = _make_dns_event(
            query_name="db.internal.corp.",
            answers=[{"Rdata": "10.0.1.50", "Type": "A", "Class": "IN"}],
        )
        result = parser.parse(event)

        m = result["metadata"]
        assert m["resolved_ips"] == ["10.0.1.50"]
        assert m["is_external_resolution"] is False

    def test_mx_query(self, parser):
        event = _make_dns_event(
            query_name="example.com.",
            query_type="MX",
            rcode="NOERROR",
            answers=[
                {"Rdata": "10 mail.example.com.", "Type": "MX", "Class": "IN"},
            ],
        )
        result = parser.parse(event)

        assert result["action"] == "dns_query_mx"
        # MX records are not IPs, so resolved_ips should be empty
        assert result["metadata"]["resolved_ips"] == []

    def test_firewall_blocked_query(self, parser):
        event = _make_dns_event(
            query_name="malware.evil.com.",
            rcode="NXDOMAIN",
            answers=[],
            firewall_rule_group_id="rslvr-frg-block",
            firewall_rule_action="BLOCK",
            firewall_domain_list_id="rslvr-fdl-malware",
        )
        result = parser.parse(event)

        m = result["metadata"]
        assert m["is_nxdomain"] is True
        assert m["firewall_rule_action"] == "BLOCK"
        assert m["firewall_rule_group_id"] == "rslvr-frg-block"
