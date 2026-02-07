"""Unit tests for Azure DNS Analytics Log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.azure_dns import AzureDNSParser, _is_ip_address
from src.shared.parsers.route53_dns import shannon_entropy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return AzureDNSParser()


def _make_dns_event(
    query_name="api.example.com.",
    query_type=1,
    rcode="NOERROR",
    client_ip="10.0.0.4",
    answer="93.184.216.34",
    time_taken=15,
    qname=None,
    message="R]3[api]7[example]3[com]0[ Q]1[A] C]IN]",
    client_subnet="10.0.0.0/24",
    zone="example.com",
    server="dns-server-01",
    time="2025-06-15T10:00:00.0000000Z",
    resource_id="/subscriptions/abc-def/resourceGroups/my-rg/providers/Microsoft.Network/dnszones/example.com",
    operation_name="DnsQueryLog",
    category="DnsQueryLog",
):
    """Build a synthetic Azure DNS Analytics log event."""
    properties = {
        "QueryName": query_name,
        "QueryType": query_type,
        "RCODE": rcode,
        "ClientIP": client_ip,
        "Answer": answer,
        "TimeTaken": time_taken,
        "Message": message,
        "ClientSubnet": client_subnet,
        "Zone": zone,
        "Server": server,
    }
    if qname is not None:
        properties["QNAME"] = qname

    return {
        "time": time,
        "resourceId": resource_id,
        "operationName": operation_name,
        "category": category,
        "properties": properties,
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestAzureDNSParserInit:
    """Tests for parser initialisation."""

    def test_source_type(self, parser):
        assert parser.source_type == "azure_dns"


class TestShannonEntropyIntegration:
    """Verify shannon_entropy is reused from route53_dns module."""

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("a") == 0.0

    def test_uniform_distribution(self):
        assert shannon_entropy("ab") == 1.0

    def test_high_entropy(self):
        entropy = shannon_entropy("x7k2m9q4w1")
        assert entropy > 3.0

    def test_low_entropy(self):
        assert shannon_entropy("aaaaaaa") == 0.0


class TestValidation:
    """Tests for validate()."""

    def test_valid_dns_category(self, parser):
        event = _make_dns_event()
        assert parser.validate(event) is True

    def test_valid_dns_operation_name(self, parser):
        event = {"operationName": "DnsQueryLog"}
        assert parser.validate(event) is True

    def test_valid_category_case_insensitive(self, parser):
        event = {"category": "dnsquerylog"}
        assert parser.validate(event) is True

    def test_valid_properties_query_name(self, parser):
        event = {"properties": {"QueryName": "example.com."}}
        assert parser.validate(event) is True

    def test_valid_properties_qname(self, parser):
        event = {"properties": {"QNAME": "example.com."}}
        assert parser.validate(event) is True

    def test_valid_properties_query_type(self, parser):
        event = {"properties": {"QueryType": 1}}
        assert parser.validate(event) is True

    def test_valid_properties_rcode(self, parser):
        event = {"properties": {"RCODE": "NOERROR"}}
        assert parser.validate(event) is True

    def test_valid_resource_id_dnszones(self, parser):
        event = {
            "resourceId": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.com"
        }
        assert parser.validate(event) is True

    def test_invalid_not_dict(self, parser):
        assert parser.validate("not a dict") is False

    def test_invalid_none(self, parser):
        assert parser.validate(None) is False

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_invalid_unrelated_event(self, parser):
        event = {
            "operationName": "VirtualMachineStart",
            "category": "Administrative",
            "properties": {"status": "Succeeded"},
        }
        assert parser.validate(event) is False

    def test_invalid_non_dict_properties(self, parser):
        event = {"properties": "not a dict"}
        assert parser.validate(event) is False

    def test_invalid_non_string_category(self, parser):
        event = {"category": 123, "properties": {"status": "ok"}}
        assert parser.validate(event) is False

    def test_invalid_non_string_resource_id(self, parser):
        event = {"resourceId": 123}
        assert parser.validate(event) is False


class TestBasicParsing:
    """Tests for basic parse() output structure."""

    def test_returns_dict(self, parser):
        result = parser.parse(_make_dns_event())
        assert isinstance(result, dict)

    def test_timestamp_present(self, parser):
        result = parser.parse(_make_dns_event())
        assert "timestamp" in result
        assert isinstance(result["timestamp"], str)

    def test_action_a_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=1))
        assert result["action"] == "dns_query_a"

    def test_action_aaaa_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=28))
        assert result["action"] == "dns_query_aaaa"

    def test_action_mx_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=15))
        assert result["action"] == "dns_query_mx"

    def test_action_txt_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=16))
        assert result["action"] == "dns_query_txt"

    def test_action_cname_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=5))
        assert result["action"] == "dns_query_cname"

    def test_action_srv_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=33))
        assert result["action"] == "dns_query_srv"

    def test_action_ptr_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=12))
        assert result["action"] == "dns_query_ptr"

    def test_action_ns_record(self, parser):
        result = parser.parse(_make_dns_event(query_type=2))
        assert result["action"] == "dns_query_ns"

    def test_action_unknown_numeric_type(self, parser):
        result = parser.parse(_make_dns_event(query_type=9999))
        assert result["action"] == "dns_query_type9999"

    def test_action_string_type(self, parser):
        result = parser.parse(_make_dns_event(query_type="AAAA"))
        assert result["action"] == "dns_query_aaaa"

    def test_action_empty_type(self, parser):
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

    def test_result_unknown(self, parser):
        result = parser.parse(_make_dns_event(rcode=""))
        assert result["result"] == "unknown"

    def test_service_name(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["service"] == "azure_dns"

    def test_source_ip(self, parser):
        result = parser.parse(_make_dns_event(client_ip="10.0.0.4"))
        assert result["source_ip"] == "10.0.0.4"

    def test_source_ip_none_when_empty(self, parser):
        result = parser.parse(_make_dns_event(client_ip=""))
        assert result["source_ip"] is None

    def test_destination_ip_always_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["destination_ip"] is None

    def test_user_is_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["user"] is None

    def test_raw_event_preserved(self, parser):
        event = _make_dns_event()
        result = parser.parse(event)
        assert result["raw_event"] == event


class TestQueryTypeResolution:
    """Tests for _resolve_query_type."""

    def test_int_a(self):
        assert AzureDNSParser._resolve_query_type(1) == "A"

    def test_int_aaaa(self):
        assert AzureDNSParser._resolve_query_type(28) == "AAAA"

    def test_int_mx(self):
        assert AzureDNSParser._resolve_query_type(15) == "MX"

    def test_int_txt(self):
        assert AzureDNSParser._resolve_query_type(16) == "TXT"

    def test_int_cname(self):
        assert AzureDNSParser._resolve_query_type(5) == "CNAME"

    def test_int_srv(self):
        assert AzureDNSParser._resolve_query_type(33) == "SRV"

    def test_int_soa(self):
        assert AzureDNSParser._resolve_query_type(6) == "SOA"

    def test_int_ns(self):
        assert AzureDNSParser._resolve_query_type(2) == "NS"

    def test_int_ptr(self):
        assert AzureDNSParser._resolve_query_type(12) == "PTR"

    def test_int_any(self):
        assert AzureDNSParser._resolve_query_type(255) == "ANY"

    def test_int_caa(self):
        assert AzureDNSParser._resolve_query_type(257) == "CAA"

    def test_int_unknown_numeric(self):
        assert AzureDNSParser._resolve_query_type(9999) == "TYPE9999"

    def test_string_digit(self):
        assert AzureDNSParser._resolve_query_type("1") == "A"

    def test_string_digit_unknown(self):
        assert AzureDNSParser._resolve_query_type("9999") == "TYPE9999"

    def test_string_name(self):
        assert AzureDNSParser._resolve_query_type("AAAA") == "AAAA"

    def test_string_name_custom(self):
        assert AzureDNSParser._resolve_query_type("HTTPS") == "HTTPS"

    def test_empty_string(self):
        assert AzureDNSParser._resolve_query_type("") == ""

    def test_none(self):
        assert AzureDNSParser._resolve_query_type(None) == ""

    def test_float_returns_empty(self):
        assert AzureDNSParser._resolve_query_type(1.5) == ""

    def test_list_returns_empty(self):
        assert AzureDNSParser._resolve_query_type([1]) == ""


class TestQueryMetadata:
    """Tests for DNS query metadata fields."""

    def test_query_name_stripped(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        assert result["metadata"]["query_name"] == "api.example.com"

    def test_query_name_no_trailing_dot(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com"))
        assert result["metadata"]["query_name"] == "api.example.com"

    def test_query_type_name(self, parser):
        result = parser.parse(_make_dns_event(query_type=28))
        assert result["metadata"]["query_type"] == "AAAA"

    def test_query_type_id(self, parser):
        result = parser.parse(_make_dns_event(query_type=1))
        assert result["metadata"]["query_type_id"] == 1

    def test_query_type_id_string(self, parser):
        result = parser.parse(_make_dns_event(query_type="28"))
        assert result["metadata"]["query_type_id"] == 28

    def test_query_type_id_none_for_name(self, parser):
        result = parser.parse(_make_dns_event(query_type="AAAA"))
        assert result["metadata"]["query_type_id"] is None

    def test_response_code(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["metadata"]["response_code"] == "NXDOMAIN"

    def test_answer_raw(self, parser):
        result = parser.parse(_make_dns_event(answer="93.184.216.34"))
        assert result["metadata"]["answer_raw"] == "93.184.216.34"

    def test_answer_raw_empty_is_none(self, parser):
        result = parser.parse(_make_dns_event(answer=""))
        assert result["metadata"]["answer_raw"] is None

    def test_domain_age_days_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["domain_age_days"] is None

    def test_qname_fallback(self, parser):
        """When QueryName is empty, falls back to QNAME."""
        result = parser.parse(
            _make_dns_event(query_name="", qname="fallback.example.com.")
        )
        assert result["metadata"]["query_name"] == "fallback.example.com"


class TestAnswersAndResolvedIPs:
    """Tests for answer extraction and resolved IPs."""

    def test_single_ip_string(self, parser):
        result = parser.parse(_make_dns_event(answer="93.184.216.34"))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_semicolon_separated(self, parser):
        result = parser.parse(
            _make_dns_event(answer="93.184.216.34;93.184.216.35")
        )
        assert result["metadata"]["resolved_ips"] == [
            "93.184.216.34",
            "93.184.216.35",
        ]

    def test_semicolon_separated_with_spaces(self, parser):
        result = parser.parse(
            _make_dns_event(answer="93.184.216.34 ; 93.184.216.35")
        )
        assert result["metadata"]["resolved_ips"] == [
            "93.184.216.34",
            "93.184.216.35",
        ]

    def test_empty_answer(self, parser):
        result = parser.parse(_make_dns_event(answer=""))
        assert result["metadata"]["resolved_ips"] == []

    def test_none_answer(self, parser):
        event = _make_dns_event()
        event["properties"]["Answer"] = None
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == []

    def test_cname_answer_no_ips(self, parser):
        result = parser.parse(_make_dns_event(answer="alias.example.com."))
        assert result["metadata"]["resolved_ips"] == []

    def test_complex_answer_with_embedded_ip(self, parser):
        """Answer with mixed text and an embedded IP."""
        result = parser.parse(
            _make_dns_event(answer="CNAME:alias.example.com 93.184.216.34")
        )
        # Regex extraction should find the IP
        assert "93.184.216.34" in result["metadata"]["resolved_ips"]

    def test_list_of_dicts(self, parser):
        event = _make_dns_event()
        event["properties"]["Answer"] = [
            {"rdata": "93.184.216.34"},
            {"rdata": "93.184.216.35"},
        ]
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == [
            "93.184.216.34",
            "93.184.216.35",
        ]

    def test_list_of_strings(self, parser):
        event = _make_dns_event()
        event["properties"]["Answer"] = ["93.184.216.34", "10.0.0.1"]
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == [
            "93.184.216.34",
            "10.0.0.1",
        ]

    def test_deduplication(self, parser):
        result = parser.parse(
            _make_dns_event(answer="93.184.216.34;93.184.216.34")
        )
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_non_string_non_list_answer(self, parser):
        event = _make_dns_event()
        event["properties"]["Answer"] = 12345
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == []


class TestNXDomain:
    """Tests for NXDOMAIN detection."""

    def test_nxdomain_true(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_nxdomain_false_noerror(self, parser):
        result = parser.parse(_make_dns_event(rcode="NOERROR"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_nxdomain_case_insensitive(self, parser):
        result = parser.parse(_make_dns_event(rcode="nxdomain"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_nxdomain_false_empty(self, parser):
        result = parser.parse(_make_dns_event(rcode=""))
        assert result["metadata"]["is_nxdomain"] is False

    def test_nxdomain_false_servfail(self, parser):
        result = parser.parse(_make_dns_event(rcode="SERVFAIL"))
        assert result["metadata"]["is_nxdomain"] is False


class TestSubdomainAnalysis:
    """Tests for subdomain count and entropy."""

    def test_subdomain_count_simple(self, parser):
        result = parser.parse(_make_dns_event(query_name="example.com."))
        assert result["metadata"]["subdomain_count"] == 2

    def test_subdomain_count_with_subdomain(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        assert result["metadata"]["subdomain_count"] == 3

    def test_subdomain_count_deep(self, parser):
        result = parser.parse(
            _make_dns_event(query_name="a.b.c.d.example.com.")
        )
        assert result["metadata"]["subdomain_count"] == 6

    def test_subdomain_count_single_label(self, parser):
        result = parser.parse(_make_dns_event(query_name="localhost."))
        assert result["metadata"]["subdomain_count"] == 1

    def test_subdomain_entropy_present(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        assert isinstance(result["metadata"]["subdomain_entropy"], float)

    def test_subdomain_entropy_low_for_simple(self, parser):
        result = parser.parse(_make_dns_event(query_name="www.example.com."))
        assert result["metadata"]["subdomain_entropy"] < 2.0

    def test_subdomain_entropy_high_for_random(self, parser):
        result = parser.parse(
            _make_dns_event(query_name="x7k2m9q4w1z8.example.com.")
        )
        assert result["metadata"]["subdomain_entropy"] > 3.0

    def test_subdomain_count_empty(self, parser):
        result = parser.parse(_make_dns_event(query_name=""))
        assert result["metadata"]["subdomain_count"] == 0

    def test_subdomain_entropy_empty(self, parser):
        result = parser.parse(_make_dns_event(query_name=""))
        assert result["metadata"]["subdomain_entropy"] == 0.0


class TestExternalResolution:
    """Tests for external resolution detection."""

    def test_external_public_ip(self, parser):
        result = parser.parse(_make_dns_event(answer="93.184.216.34"))
        assert result["metadata"]["is_external_resolution"] is True

    def test_internal_private_ip(self, parser):
        result = parser.parse(_make_dns_event(answer="10.0.0.1"))
        assert result["metadata"]["is_external_resolution"] is False

    def test_internal_172_16(self, parser):
        result = parser.parse(_make_dns_event(answer="172.16.0.1"))
        assert result["metadata"]["is_external_resolution"] is False

    def test_internal_192_168(self, parser):
        result = parser.parse(_make_dns_event(answer="192.168.1.1"))
        assert result["metadata"]["is_external_resolution"] is False

    def test_mixed_internal_external(self, parser):
        result = parser.parse(
            _make_dns_event(answer="10.0.0.1;93.184.216.34")
        )
        assert result["metadata"]["is_external_resolution"] is True

    def test_no_resolved_ips(self, parser):
        result = parser.parse(_make_dns_event(answer=""))
        assert result["metadata"]["is_external_resolution"] is False


class TestAzureContext:
    """Tests for Azure-specific context fields."""

    def test_subscription_id(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["subscription_id"] == "abc-def"

    def test_resource_group(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["resource_group"] == "my-rg"

    def test_dns_zone_from_resource_id(self, parser):
        result = parser.parse(_make_dns_event(zone=""))
        assert result["metadata"]["dns_zone"] == "example.com"

    def test_dns_zone_from_properties(self, parser):
        result = parser.parse(
            _make_dns_event(
                resource_id="",
                zone="custom-zone.com",
            )
        )
        assert result["metadata"]["dns_zone"] == "custom-zone.com"

    def test_server(self, parser):
        result = parser.parse(_make_dns_event(server="dns-server-01"))
        assert result["metadata"]["server"] == "dns-server-01"

    def test_client_subnet(self, parser):
        result = parser.parse(_make_dns_event(client_subnet="10.0.0.0/24"))
        assert result["metadata"]["client_subnet"] == "10.0.0.0/24"

    def test_message(self, parser):
        result = parser.parse(_make_dns_event(message="some message"))
        assert result["metadata"]["message"] == "some message"

    def test_resource_id(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["resource_id"] is not None
        assert "dnszones" in result["metadata"]["resource_id"]

    def test_operation_name(self, parser):
        result = parser.parse(_make_dns_event(operation_name="DnsQueryLog"))
        assert result["metadata"]["operation_name"] == "DnsQueryLog"

    def test_category(self, parser):
        result = parser.parse(_make_dns_event(category="DnsQueryLog"))
        assert result["metadata"]["category"] == "DnsQueryLog"

    def test_empty_server_is_none(self, parser):
        result = parser.parse(_make_dns_event(server=""))
        assert result["metadata"]["server"] is None

    def test_empty_client_subnet_is_none(self, parser):
        result = parser.parse(_make_dns_event(client_subnet=""))
        assert result["metadata"]["client_subnet"] is None

    def test_empty_message_is_none(self, parser):
        result = parser.parse(_make_dns_event(message=""))
        assert result["metadata"]["message"] is None

    def test_empty_resource_id_is_none(self, parser):
        result = parser.parse(_make_dns_event(resource_id=""))
        assert result["metadata"]["resource_id"] is None


class TestTimeTaken:
    """Tests for TimeTaken parsing (microseconds to ms)."""

    def test_standard_value(self, parser):
        result = parser.parse(_make_dns_event(time_taken=15))
        assert result["metadata"]["time_taken_ms"] == 0.015

    def test_large_value(self, parser):
        result = parser.parse(_make_dns_event(time_taken=5000))
        assert result["metadata"]["time_taken_ms"] == 5.0

    def test_zero(self, parser):
        result = parser.parse(_make_dns_event(time_taken=0))
        assert result["metadata"]["time_taken_ms"] == 0.0

    def test_none_value(self, parser):
        result = parser.parse(_make_dns_event(time_taken=None))
        assert result["metadata"]["time_taken_ms"] is None

    def test_string_numeric(self, parser):
        result = parser.parse(_make_dns_event(time_taken="1000"))
        assert result["metadata"]["time_taken_ms"] == 1.0

    def test_invalid_string(self, parser):
        result = parser.parse(_make_dns_event(time_taken="not-a-number"))
        assert result["metadata"]["time_taken_ms"] is None

    def test_float_value(self, parser):
        result = parser.parse(_make_dns_event(time_taken=1500.5))
        assert result["metadata"]["time_taken_ms"] == pytest.approx(1.5005, abs=0.0001)


class TestDNSTags:
    """Tests for NDR tags."""

    def test_dns_tag_present(self, parser):
        result = parser.parse(_make_dns_event())
        assert "dns" in result["metadata"]["tags"]

    def test_tags_is_list(self, parser):
        result = parser.parse(_make_dns_event())
        assert isinstance(result["metadata"]["tags"], list)


class TestTimestampParsing:
    """Tests for timestamp parsing."""

    def test_azure_7_digit_fractional(self, parser):
        result = parser.parse(
            _make_dns_event(time="2025-06-15T10:00:00.0000000Z")
        )
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.year == 2025
        assert ts.month == 6
        assert ts.day == 15

    def test_standard_iso8601(self, parser):
        result = parser.parse(
            _make_dns_event(time="2025-06-15T10:00:00Z")
        )
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.hour == 10

    def test_with_microseconds(self, parser):
        result = parser.parse(
            _make_dns_event(time="2025-06-15T10:00:00.123456Z")
        )
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.microsecond == 123456

    def test_with_timezone_offset(self, parser):
        result = parser.parse(
            _make_dns_event(time="2025-06-15T10:00:00+05:00")
        )
        assert "timestamp" in result

    def test_fallback_to_timestamp_field(self, parser):
        event = _make_dns_event()
        del event["time"]
        event["timestamp"] = "2025-06-15T12:00:00Z"
        result = parser.parse(event)
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.hour == 12

    def test_empty_timestamp_uses_now(self, parser):
        result = parser.parse(_make_dns_event(time=""))
        assert "timestamp" in result

    def test_invalid_timestamp_uses_now(self, parser):
        result = parser.parse(_make_dns_event(time="not-a-timestamp"))
        assert "timestamp" in result


class TestParseTimestamp:
    """Tests for _parse_timestamp static method."""

    def test_iso8601_with_z(self):
        dt = AzureDNSParser._parse_timestamp("2025-06-15T10:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.year == 2025

    def test_7_digit_fractional(self):
        dt = AzureDNSParser._parse_timestamp("2025-06-15T10:00:00.1234567Z")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_without_timezone(self):
        dt = AzureDNSParser._parse_timestamp("2025-06-15T10:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_none_input(self):
        assert AzureDNSParser._parse_timestamp(None) is None

    def test_empty_input(self):
        assert AzureDNSParser._parse_timestamp("") is None

    def test_invalid_input(self):
        assert AzureDNSParser._parse_timestamp("not-a-timestamp") is None

    def test_non_string(self):
        assert AzureDNSParser._parse_timestamp(12345) is None


class TestParseTimeTaken:
    """Tests for _parse_time_taken static method."""

    def test_int_value(self):
        assert AzureDNSParser._parse_time_taken(1000) == 1.0

    def test_zero(self):
        assert AzureDNSParser._parse_time_taken(0) == 0.0

    def test_float_value(self):
        result = AzureDNSParser._parse_time_taken(1500.5)
        assert result == pytest.approx(1.5005, abs=0.0001)

    def test_string_numeric(self):
        assert AzureDNSParser._parse_time_taken("2000") == 2.0

    def test_none(self):
        assert AzureDNSParser._parse_time_taken(None) is None

    def test_invalid_string(self):
        assert AzureDNSParser._parse_time_taken("abc") is None


class TestParseResourceId:
    """Tests for _parse_resource_id static method."""

    def test_full_resource_id(self):
        rid = "/subscriptions/abc-def/resourceGroups/my-rg/providers/Microsoft.Network/dnszones/example.com"
        sub, rg, zone = AzureDNSParser._parse_resource_id(rid)
        assert sub == "abc-def"
        assert rg == "my-rg"
        assert zone == "example.com"

    def test_empty_string(self):
        sub, rg, zone = AzureDNSParser._parse_resource_id("")
        assert sub == ""
        assert rg == ""
        assert zone == ""

    def test_none_input(self):
        sub, rg, zone = AzureDNSParser._parse_resource_id(None)
        assert sub == ""
        assert rg == ""
        assert zone == ""

    def test_partial_resource_id(self):
        rid = "/subscriptions/abc-def/resourceGroups/my-rg"
        sub, rg, zone = AzureDNSParser._parse_resource_id(rid)
        assert sub == "abc-def"
        assert rg == "my-rg"
        assert zone == ""

    def test_case_insensitive_keys(self):
        rid = "/Subscriptions/abc/ResourceGroups/rg/providers/Microsoft.Network/DnsZones/zone.com"
        sub, rg, zone = AzureDNSParser._parse_resource_id(rid)
        assert sub == "abc"
        assert rg == "rg"
        assert zone == "zone.com"

    def test_non_string_input(self):
        sub, rg, zone = AzureDNSParser._parse_resource_id(123)
        assert sub == ""
        assert rg == ""
        assert zone == ""


class TestStripTrailingDot:
    """Tests for _strip_trailing_dot static method."""

    def test_with_trailing_dot(self):
        assert AzureDNSParser._strip_trailing_dot("example.com.") == "example.com"

    def test_without_trailing_dot(self):
        assert AzureDNSParser._strip_trailing_dot("example.com") == "example.com"

    def test_empty_string(self):
        assert AzureDNSParser._strip_trailing_dot("") == ""

    def test_only_dot(self):
        assert AzureDNSParser._strip_trailing_dot(".") == ""


class TestRFC1918:
    """Tests for RFC 1918 private address detection."""

    def test_10_network(self):
        assert AzureDNSParser._is_rfc1918("10.0.0.1") is True

    def test_10_large(self):
        assert AzureDNSParser._is_rfc1918("10.255.255.255") is True

    def test_172_16(self):
        assert AzureDNSParser._is_rfc1918("172.16.0.1") is True

    def test_172_31(self):
        assert AzureDNSParser._is_rfc1918("172.31.255.255") is True

    def test_172_15_not_private(self):
        assert AzureDNSParser._is_rfc1918("172.15.0.1") is False

    def test_172_32_not_private(self):
        assert AzureDNSParser._is_rfc1918("172.32.0.1") is False

    def test_192_168(self):
        assert AzureDNSParser._is_rfc1918("192.168.1.1") is True

    def test_public_ip(self):
        assert AzureDNSParser._is_rfc1918("8.8.8.8") is False


class TestIsIPAddress:
    """Tests for module-level _is_ip_address helper."""

    def test_valid_ipv4(self):
        assert _is_ip_address("93.184.216.34") is True

    def test_valid_ipv6(self):
        assert _is_ip_address("2001:db8::1") is True

    def test_not_ip(self):
        assert _is_ip_address("example.com") is False

    def test_empty(self):
        assert _is_ip_address("") is False

    def test_none(self):
        assert _is_ip_address(None) is False

    def test_cname(self):
        assert _is_ip_address("alias.example.com.") is False


class TestPayloadEdgeCases:
    """Tests for edge cases in payload handling."""

    def test_missing_properties(self, parser):
        event = {
            "time": "2025-06-15T10:00:00Z",
            "category": "DnsQueryLog",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)
        assert result["metadata"]["query_name"] == ""

    def test_non_dict_properties(self, parser):
        event = {
            "time": "2025-06-15T10:00:00Z",
            "properties": "not a dict",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)

    def test_minimal_event(self, parser):
        event = {"properties": {"QueryName": "example.com."}}
        result = parser.parse(event)
        assert isinstance(result, dict)
        assert result["metadata"]["query_name"] == "example.com"

    def test_empty_event(self, parser):
        result = parser.parse({})
        assert isinstance(result, dict)
        assert result["action"] == "dns_query"


class TestOutputSchema:
    """Verify the output matches ParsedEvent.to_dict() schema."""

    def test_all_required_keys(self, parser):
        result = parser.parse(_make_dns_event())
        required_keys = {
            "timestamp", "source_ip", "destination_ip", "user",
            "action", "result", "service", "raw_event", "metadata",
        }
        assert required_keys.issubset(result.keys())

    def test_metadata_dns_keys(self, parser):
        result = parser.parse(_make_dns_event())
        metadata = result["metadata"]
        dns_keys = {
            "query_name", "query_type", "response_code",
            "resolved_ips", "is_nxdomain", "subdomain_count",
            "subdomain_entropy", "is_external_resolution", "domain_age_days",
            "tags",
        }
        assert dns_keys.issubset(metadata.keys())

    def test_metadata_azure_keys(self, parser):
        result = parser.parse(_make_dns_event())
        metadata = result["metadata"]
        azure_keys = {
            "subscription_id", "resource_group", "dns_zone",
            "server", "client_subnet", "message", "resource_id",
            "operation_name", "category", "time_taken_ms",
            "query_type_id", "answer_raw",
        }
        assert azure_keys.issubset(metadata.keys())


class TestFullIntegration:
    """End-to-end integration tests."""

    def test_standard_a_query(self, parser):
        event = _make_dns_event()
        result = parser.parse(event)
        assert result["action"] == "dns_query_a"
        assert result["result"] == "success"
        assert result["service"] == "azure_dns"
        assert result["source_ip"] == "10.0.0.4"
        assert result["metadata"]["query_name"] == "api.example.com"
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]
        assert result["metadata"]["is_nxdomain"] is False
        assert result["metadata"]["is_external_resolution"] is True
        assert result["metadata"]["subdomain_count"] == 3
        assert "dns" in result["metadata"]["tags"]
        assert result["metadata"]["time_taken_ms"] == 0.015
        assert result["metadata"]["subscription_id"] == "abc-def"
        assert result["metadata"]["resource_group"] == "my-rg"
        assert result["metadata"]["dns_zone"] == "example.com"

    def test_nxdomain_query(self, parser):
        event = _make_dns_event(
            query_name="nonexistent.example.com.",
            rcode="NXDOMAIN",
            answer="",
        )
        result = parser.parse(event)
        assert result["result"] == "failure"
        assert result["metadata"]["is_nxdomain"] is True
        assert result["metadata"]["resolved_ips"] == []
        assert result["metadata"]["is_external_resolution"] is False

    def test_internal_dns_resolution(self, parser):
        event = _make_dns_event(
            query_name="internal.corp.local.",
            answer="10.0.0.100",
            client_ip="10.0.0.4",
        )
        result = parser.parse(event)
        assert result["metadata"]["is_external_resolution"] is False
        assert result["metadata"]["resolved_ips"] == ["10.0.0.100"]

    def test_high_entropy_subdomain(self, parser):
        event = _make_dns_event(
            query_name="aGVsbG8gd29ybGQ.tunnel.attacker.com.",
        )
        result = parser.parse(event)
        assert result["metadata"]["subdomain_count"] == 4
        assert result["metadata"]["subdomain_entropy"] > 2.5

    def test_numeric_query_type_mapping(self, parser):
        event = _make_dns_event(query_type=28)
        result = parser.parse(event)
        assert result["action"] == "dns_query_aaaa"
        assert result["metadata"]["query_type"] == "AAAA"
        assert result["metadata"]["query_type_id"] == 28

    def test_txt_query(self, parser):
        event = _make_dns_event(
            query_name="example.com.",
            query_type=16,
            answer="v=spf1 include:_spf.google.com ~all",
        )
        result = parser.parse(event)
        assert result["action"] == "dns_query_txt"
        assert result["metadata"]["resolved_ips"] == []
