"""Unit tests for GCP Cloud DNS Query Log parser."""

import math
import pytest
from datetime import datetime, timezone

from src.shared.parsers.gcp_cloud_dns import GCPCloudDNSParser, _is_ip_address
from src.shared.parsers.route53_dns import shannon_entropy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return GCPCloudDNSParser()


def _make_dns_event(
    query_name="api.example.com.",
    query_type="A",
    response_code="NOERROR",
    protocol="UDP",
    source_ip="10.0.0.4",
    vm_instance_id="123456789",
    vm_instance_name="my-instance",
    vm_project_id="my-project",
    vm_zone_name="us-central1-a",
    answers=None,
    server_latency="0.001s",
    source_network="default",
    destination_ip="8.8.8.8",
    egress_error="",
    vm_instance_id_string=None,
    timestamp="2025-06-15T10:00:00.000000Z",
    resource_type="dns_query",
    project_id="my-project",
    target_name="my-policy",
    target_type="policy",
    source_type_label="internet",
    insert_id="abc123",
):
    """Build a synthetic GCP Cloud DNS query log event."""
    if answers is None:
        answers = [
            {
                "name": "api.example.com.",
                "type": "A",
                "class": "IN",
                "rdata": "93.184.216.34",
                "ttl": 300,
            }
        ]

    payload = {
        "queryName": query_name,
        "queryType": query_type,
        "responseCode": response_code,
        "protocol": protocol,
        "sourceIP": source_ip,
        "vmInstanceId": vm_instance_id,
        "vmInstanceName": vm_instance_name,
        "vmProjectId": vm_project_id,
        "vmZoneName": vm_zone_name,
        "answers": answers,
        "serverLatency": server_latency,
        "sourceNetwork": source_network,
        "destinationIP": destination_ip,
        "egressError": egress_error,
    }

    if vm_instance_id_string is not None:
        payload["vmInstanceIdString"] = vm_instance_id_string

    return {
        "insertId": insert_id,
        "resource": {
            "type": resource_type,
            "labels": {
                "project_id": project_id,
                "target_name": target_name,
                "target_type": target_type,
                "source_type": source_type_label,
            },
        },
        "timestamp": timestamp,
        "jsonPayload": payload,
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestGCPCloudDNSParserInit:
    """Tests for parser initialisation."""

    def test_source_type(self, parser):
        assert parser.source_type == "gcp_cloud_dns"


class TestShannonEntropyIntegration:
    """Verify shannon_entropy is reused from route53_dns module."""

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("a") == 0.0

    def test_uniform_distribution(self):
        # "ab" — each char has p=0.5 → entropy = 1.0
        assert shannon_entropy("ab") == 1.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        entropy = shannon_entropy("x7k2m9q4w1")
        assert entropy > 3.0

    def test_low_entropy(self):
        # Repeated character should have entropy = 0
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_known_value(self):
        # "aabb" → 2 chars, each with p=0.5 → entropy = 1.0
        assert shannon_entropy("aabb") == 1.0


class TestValidation:
    """Tests for validate()."""

    def test_valid_dns_query_resource_type(self, parser):
        event = _make_dns_event()
        assert parser.validate(event) is True

    def test_valid_with_query_name_and_dns_fields(self, parser):
        event = {
            "jsonPayload": {
                "queryName": "example.com.",
                "queryType": "A",
                "responseCode": "NOERROR",
            }
        }
        assert parser.validate(event) is True

    def test_invalid_not_dict(self, parser):
        assert parser.validate("not a dict") is False

    def test_invalid_none(self, parser):
        assert parser.validate(None) is False

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_invalid_no_query_name_no_resource_type(self, parser):
        event = {
            "jsonPayload": {
                "queryType": "A",
            }
        }
        assert parser.validate(event) is False

    def test_valid_resource_type_alone(self, parser):
        event = {"resource": {"type": "dns_query"}}
        assert parser.validate(event) is True

    def test_invalid_wrong_resource_type(self, parser):
        event = {"resource": {"type": "gce_instance"}}
        assert parser.validate(event) is False

    def test_valid_query_name_with_source_ip(self, parser):
        event = {
            "jsonPayload": {
                "queryName": "example.com.",
                "sourceIP": "10.0.0.1",
            }
        }
        assert parser.validate(event) is True

    def test_valid_query_name_with_protocol(self, parser):
        event = {
            "jsonPayload": {
                "queryName": "example.com.",
                "protocol": "UDP",
            }
        }
        assert parser.validate(event) is True

    def test_valid_query_name_with_server_latency(self, parser):
        event = {
            "jsonPayload": {
                "queryName": "example.com.",
                "serverLatency": "0.001s",
            }
        }
        assert parser.validate(event) is True

    def test_invalid_query_name_alone(self, parser):
        # queryName without any GCP DNS specific fields
        event = {
            "jsonPayload": {
                "queryName": "example.com.",
            }
        }
        assert parser.validate(event) is False

    def test_invalid_non_dict_resource(self, parser):
        event = {"resource": "not a dict", "jsonPayload": {"queryName": "a."}}
        assert parser.validate(event) is False

    def test_invalid_non_dict_payload(self, parser):
        event = {"jsonPayload": "not a dict"}
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

    def test_action_cname(self, parser):
        result = parser.parse(_make_dns_event(query_type="CNAME"))
        assert result["action"] == "dns_query_cname"

    def test_action_srv(self, parser):
        result = parser.parse(_make_dns_event(query_type="SRV"))
        assert result["action"] == "dns_query_srv"

    def test_action_no_query_type(self, parser):
        result = parser.parse(_make_dns_event(query_type=""))
        assert result["action"] == "dns_query"

    def test_result_noerror(self, parser):
        result = parser.parse(_make_dns_event(response_code="NOERROR"))
        assert result["result"] == "success"

    def test_result_nxdomain(self, parser):
        result = parser.parse(_make_dns_event(response_code="NXDOMAIN"))
        assert result["result"] == "failure"

    def test_result_servfail(self, parser):
        result = parser.parse(_make_dns_event(response_code="SERVFAIL"))
        assert result["result"] == "failure"

    def test_result_unknown(self, parser):
        result = parser.parse(_make_dns_event(response_code=""))
        assert result["result"] == "unknown"

    def test_service_name(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["service"] == "cloud_dns"

    def test_source_ip(self, parser):
        result = parser.parse(_make_dns_event(source_ip="10.0.0.4"))
        assert result["source_ip"] == "10.0.0.4"

    def test_destination_ip(self, parser):
        result = parser.parse(_make_dns_event(destination_ip="8.8.8.8"))
        assert result["destination_ip"] == "8.8.8.8"

    def test_source_ip_none_when_empty(self, parser):
        result = parser.parse(_make_dns_event(source_ip=""))
        assert result["source_ip"] is None

    def test_raw_event_preserved(self, parser):
        event = _make_dns_event()
        result = parser.parse(event)
        assert result["raw_event"] == event

    def test_user_is_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["user"] is None


class TestQueryMetadata:
    """Tests for DNS query metadata fields."""

    def test_query_name_stripped(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com."))
        assert result["metadata"]["query_name"] == "api.example.com"

    def test_query_name_no_trailing_dot(self, parser):
        result = parser.parse(_make_dns_event(query_name="api.example.com"))
        assert result["metadata"]["query_name"] == "api.example.com"

    def test_query_type(self, parser):
        result = parser.parse(_make_dns_event(query_type="AAAA"))
        assert result["metadata"]["query_type"] == "AAAA"

    def test_response_code(self, parser):
        result = parser.parse(_make_dns_event(response_code="NXDOMAIN"))
        assert result["metadata"]["response_code"] == "NXDOMAIN"

    def test_transport_udp(self, parser):
        result = parser.parse(_make_dns_event(protocol="UDP"))
        assert result["metadata"]["transport"] == "UDP"

    def test_transport_tcp(self, parser):
        result = parser.parse(_make_dns_event(protocol="TCP"))
        assert result["metadata"]["transport"] == "TCP"

    def test_answers_passed_through(self, parser):
        answers = [{"name": "a.com.", "type": "A", "rdata": "1.2.3.4", "ttl": 60}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["answers"] == answers

    def test_domain_age_days_none(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["domain_age_days"] is None


class TestAnswersAndResolvedIPs:
    """Tests for answer extraction and resolved IPs."""

    def test_single_a_record(self, parser):
        answers = [{"type": "A", "rdata": "93.184.216.34"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_single_aaaa_record(self, parser):
        answers = [{"type": "AAAA", "rdata": "2001:db8::1"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["2001:db8::1"]

    def test_multiple_a_records(self, parser):
        answers = [
            {"type": "A", "rdata": "93.184.216.34"},
            {"type": "A", "rdata": "93.184.216.35"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == [
            "93.184.216.34",
            "93.184.216.35",
        ]

    def test_mixed_a_and_aaaa(self, parser):
        answers = [
            {"type": "A", "rdata": "93.184.216.34"},
            {"type": "AAAA", "rdata": "2001:db8::1"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert "93.184.216.34" in result["metadata"]["resolved_ips"]
        assert "2001:db8::1" in result["metadata"]["resolved_ips"]

    def test_cname_not_in_resolved_ips(self, parser):
        answers = [
            {"type": "CNAME", "rdata": "alias.example.com."},
            {"type": "A", "rdata": "93.184.216.34"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_empty_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=[]))
        assert result["metadata"]["resolved_ips"] == []

    def test_no_answers_key(self, parser):
        event = _make_dns_event()
        del event["jsonPayload"]["answers"]
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == []

    def test_deduplication(self, parser):
        answers = [
            {"type": "A", "rdata": "93.184.216.34"},
            {"type": "A", "rdata": "93.184.216.34"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_invalid_answer_entry_skipped(self, parser):
        answers = [
            "not a dict",
            {"type": "A", "rdata": "93.184.216.34"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_answers_not_list(self, parser):
        event = _make_dns_event()
        event["jsonPayload"]["answers"] = "not a list"
        result = parser.parse(event)
        assert result["metadata"]["resolved_ips"] == []

    def test_answer_with_uppercase_rdata_key(self, parser):
        """GCP uses lowercase but handle Rdata for compatibility."""
        answers = [{"type": "A", "Rdata": "1.2.3.4"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["1.2.3.4"]

    def test_answer_with_no_type_but_ip_rdata(self, parser):
        answers = [{"rdata": "10.0.0.1"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["resolved_ips"] == ["10.0.0.1"]


class TestNXDomain:
    """Tests for NXDOMAIN detection."""

    def test_nxdomain_true(self, parser):
        result = parser.parse(_make_dns_event(response_code="NXDOMAIN"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_nxdomain_false_noerror(self, parser):
        result = parser.parse(_make_dns_event(response_code="NOERROR"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_nxdomain_false_servfail(self, parser):
        result = parser.parse(_make_dns_event(response_code="SERVFAIL"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_nxdomain_case_insensitive(self, parser):
        result = parser.parse(_make_dns_event(response_code="nxdomain"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_nxdomain_false_empty(self, parser):
        result = parser.parse(_make_dns_event(response_code=""))
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
        entropy = result["metadata"]["subdomain_entropy"]
        assert entropy < 2.0

    def test_subdomain_entropy_high_for_random(self, parser):
        result = parser.parse(
            _make_dns_event(query_name="x7k2m9q4w1z8.example.com.")
        )
        entropy = result["metadata"]["subdomain_entropy"]
        assert entropy > 3.0

    def test_subdomain_count_empty(self, parser):
        result = parser.parse(_make_dns_event(query_name=""))
        assert result["metadata"]["subdomain_count"] == 0

    def test_subdomain_entropy_empty(self, parser):
        result = parser.parse(_make_dns_event(query_name=""))
        assert result["metadata"]["subdomain_entropy"] == 0.0


class TestExternalResolution:
    """Tests for external resolution detection."""

    def test_external_public_ip(self, parser):
        answers = [{"type": "A", "rdata": "93.184.216.34"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is True

    def test_internal_private_ip(self, parser):
        answers = [{"type": "A", "rdata": "10.0.0.1"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is False

    def test_internal_172_16(self, parser):
        answers = [{"type": "A", "rdata": "172.16.0.1"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is False

    def test_internal_192_168(self, parser):
        answers = [{"type": "A", "rdata": "192.168.1.1"}]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is False

    def test_mixed_internal_external(self, parser):
        answers = [
            {"type": "A", "rdata": "10.0.0.1"},
            {"type": "A", "rdata": "93.184.216.34"},
        ]
        result = parser.parse(_make_dns_event(answers=answers))
        assert result["metadata"]["is_external_resolution"] is True

    def test_no_resolved_ips(self, parser):
        result = parser.parse(_make_dns_event(answers=[]))
        assert result["metadata"]["is_external_resolution"] is False


class TestGCPContext:
    """Tests for GCP-specific context fields."""

    def test_project_id_from_resource_labels(self, parser):
        result = parser.parse(_make_dns_event(project_id="my-project"))
        assert result["metadata"]["project_id"] == "my-project"

    def test_project_id_falls_back_to_vm_project(self, parser):
        event = _make_dns_event(project_id="", vm_project_id="vm-proj")
        result = parser.parse(event)
        assert result["metadata"]["project_id"] == "vm-proj"

    def test_vm_instance_id(self, parser):
        result = parser.parse(_make_dns_event(vm_instance_id="123456789"))
        assert result["metadata"]["vm_instance_id"] == "123456789"

    def test_vm_instance_id_string_preferred(self, parser):
        result = parser.parse(
            _make_dns_event(
                vm_instance_id="numeric-id",
                vm_instance_id_string="string-id",
            )
        )
        assert result["metadata"]["vm_instance_id"] == "string-id"

    def test_vm_instance_name(self, parser):
        result = parser.parse(_make_dns_event(vm_instance_name="my-vm"))
        assert result["metadata"]["vm_instance_name"] == "my-vm"

    def test_vm_zone_name(self, parser):
        result = parser.parse(_make_dns_event(vm_zone_name="us-central1-a"))
        assert result["metadata"]["vm_zone_name"] == "us-central1-a"

    def test_source_network(self, parser):
        result = parser.parse(_make_dns_event(source_network="default"))
        assert result["metadata"]["source_network"] == "default"

    def test_destination_ip_in_metadata(self, parser):
        result = parser.parse(_make_dns_event(destination_ip="8.8.8.8"))
        assert result["metadata"]["destination_ip"] == "8.8.8.8"

    def test_target_name(self, parser):
        result = parser.parse(_make_dns_event(target_name="my-policy"))
        assert result["metadata"]["target_name"] == "my-policy"

    def test_target_type(self, parser):
        result = parser.parse(_make_dns_event(target_type="policy"))
        assert result["metadata"]["target_type"] == "policy"

    def test_source_type_label(self, parser):
        result = parser.parse(_make_dns_event(source_type_label="internet"))
        assert result["metadata"]["source_type_label"] == "internet"

    def test_empty_vm_fields_are_none(self, parser):
        result = parser.parse(
            _make_dns_event(vm_instance_id="", vm_instance_name="", vm_zone_name="")
        )
        assert result["metadata"]["vm_instance_id"] is None
        assert result["metadata"]["vm_instance_name"] is None
        assert result["metadata"]["vm_zone_name"] is None

    def test_egress_error(self, parser):
        result = parser.parse(_make_dns_event(egress_error="timeout"))
        assert result["metadata"]["egress_error"] == "timeout"

    def test_egress_error_empty_is_none(self, parser):
        result = parser.parse(_make_dns_event(egress_error=""))
        assert result["metadata"]["egress_error"] is None


class TestServerLatency:
    """Tests for serverLatency parsing."""

    def test_latency_milliseconds(self, parser):
        result = parser.parse(_make_dns_event(server_latency="0.001s"))
        assert result["metadata"]["server_latency_ms"] == 1.0

    def test_latency_sub_millisecond(self, parser):
        result = parser.parse(_make_dns_event(server_latency="0.000234s"))
        assert result["metadata"]["server_latency_ms"] == pytest.approx(0.234, abs=0.001)

    def test_latency_one_second(self, parser):
        result = parser.parse(_make_dns_event(server_latency="1.0s"))
        assert result["metadata"]["server_latency_ms"] == 1000.0

    def test_latency_empty(self, parser):
        result = parser.parse(_make_dns_event(server_latency=""))
        assert result["metadata"]["server_latency_ms"] is None

    def test_latency_none(self, parser):
        event = _make_dns_event()
        del event["jsonPayload"]["serverLatency"]
        result = parser.parse(event)
        assert result["metadata"]["server_latency_ms"] is None

    def test_latency_invalid(self, parser):
        result = parser.parse(_make_dns_event(server_latency="not-a-number"))
        assert result["metadata"]["server_latency_ms"] is None

    def test_latency_no_s_suffix(self, parser):
        # Edge case: numeric value without 's' suffix — method tries
        # to strip 's', then float("0.005") still works → 5.0ms
        result = parser.parse(_make_dns_event(server_latency="0.005"))
        assert result["metadata"]["server_latency_ms"] == 5.0

    def test_latency_zero(self, parser):
        result = parser.parse(_make_dns_event(server_latency="0s"))
        assert result["metadata"]["server_latency_ms"] == 0.0


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

    def test_standard_iso8601(self, parser):
        result = parser.parse(
            _make_dns_event(timestamp="2025-06-15T10:00:00.000000Z")
        )
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.year == 2025
        assert ts.month == 6
        assert ts.day == 15
        assert ts.hour == 10

    def test_nanosecond_precision_truncated(self, parser):
        result = parser.parse(
            _make_dns_event(timestamp="2025-06-15T10:00:00.123456789Z")
        )
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.microsecond == 123456

    def test_no_fractional_seconds(self, parser):
        result = parser.parse(
            _make_dns_event(timestamp="2025-06-15T10:00:00Z")
        )
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.year == 2025

    def test_with_timezone_offset(self, parser):
        result = parser.parse(
            _make_dns_event(timestamp="2025-06-15T10:00:00+05:00")
        )
        assert "timestamp" in result

    def test_empty_timestamp_uses_now(self, parser):
        result = parser.parse(_make_dns_event(timestamp=""))
        assert "timestamp" in result

    def test_invalid_timestamp_uses_now(self, parser):
        result = parser.parse(_make_dns_event(timestamp="not-a-timestamp"))
        assert "timestamp" in result

    def test_none_timestamp(self, parser):
        event = _make_dns_event()
        event["timestamp"] = None
        result = parser.parse(event)
        assert "timestamp" in result


class TestParseLatencyHelper:
    """Tests for _parse_latency static method."""

    def test_normal_value(self):
        assert GCPCloudDNSParser._parse_latency("0.001s") == 1.0

    def test_large_value(self):
        assert GCPCloudDNSParser._parse_latency("5.0s") == 5000.0

    def test_zero(self):
        assert GCPCloudDNSParser._parse_latency("0s") == 0.0

    def test_sub_ms(self):
        result = GCPCloudDNSParser._parse_latency("0.0001s")
        assert result == pytest.approx(0.1, abs=0.01)

    def test_none_input(self):
        assert GCPCloudDNSParser._parse_latency(None) is None

    def test_empty_input(self):
        assert GCPCloudDNSParser._parse_latency("") is None

    def test_non_string(self):
        assert GCPCloudDNSParser._parse_latency(123) is None

    def test_invalid_string(self):
        assert GCPCloudDNSParser._parse_latency("abc") is None

    def test_whitespace_stripped(self):
        assert GCPCloudDNSParser._parse_latency(" 0.002s ") == 2.0


class TestParseTimestamp:
    """Tests for _parse_timestamp static method."""

    def test_iso8601_with_z(self):
        dt = GCPCloudDNSParser._parse_timestamp("2025-06-15T10:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.year == 2025

    def test_iso8601_with_microseconds(self):
        dt = GCPCloudDNSParser._parse_timestamp("2025-06-15T10:00:00.123456Z")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_nanosecond_truncation(self):
        dt = GCPCloudDNSParser._parse_timestamp("2025-06-15T10:00:00.123456789Z")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_with_offset(self):
        dt = GCPCloudDNSParser._parse_timestamp("2025-06-15T10:00:00+05:00")
        assert dt is not None
        assert dt.hour == 10

    def test_without_timezone(self):
        dt = GCPCloudDNSParser._parse_timestamp("2025-06-15T10:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_none_input(self):
        assert GCPCloudDNSParser._parse_timestamp(None) is None

    def test_empty_input(self):
        assert GCPCloudDNSParser._parse_timestamp("") is None

    def test_invalid_input(self):
        assert GCPCloudDNSParser._parse_timestamp("not-a-timestamp") is None

    def test_non_string(self):
        assert GCPCloudDNSParser._parse_timestamp(12345) is None


class TestStripTrailingDot:
    """Tests for _strip_trailing_dot static method."""

    def test_with_trailing_dot(self):
        assert GCPCloudDNSParser._strip_trailing_dot("example.com.") == "example.com"

    def test_without_trailing_dot(self):
        assert GCPCloudDNSParser._strip_trailing_dot("example.com") == "example.com"

    def test_empty_string(self):
        assert GCPCloudDNSParser._strip_trailing_dot("") == ""

    def test_only_dot(self):
        assert GCPCloudDNSParser._strip_trailing_dot(".") == ""


class TestRFC1918:
    """Tests for RFC 1918 private address detection."""

    def test_10_network(self):
        assert GCPCloudDNSParser._is_rfc1918("10.0.0.1") is True

    def test_10_large(self):
        assert GCPCloudDNSParser._is_rfc1918("10.255.255.255") is True

    def test_172_16(self):
        assert GCPCloudDNSParser._is_rfc1918("172.16.0.1") is True

    def test_172_31(self):
        assert GCPCloudDNSParser._is_rfc1918("172.31.255.255") is True

    def test_172_15_not_private(self):
        assert GCPCloudDNSParser._is_rfc1918("172.15.0.1") is False

    def test_172_32_not_private(self):
        assert GCPCloudDNSParser._is_rfc1918("172.32.0.1") is False

    def test_192_168(self):
        assert GCPCloudDNSParser._is_rfc1918("192.168.1.1") is True

    def test_public_ip(self):
        assert GCPCloudDNSParser._is_rfc1918("8.8.8.8") is False

    def test_another_public(self):
        assert GCPCloudDNSParser._is_rfc1918("93.184.216.34") is False


class TestIsIPAddress:
    """Tests for module-level _is_ip_address helper."""

    def test_valid_ipv4(self):
        assert _is_ip_address("93.184.216.34") is True

    def test_valid_ipv6(self):
        assert _is_ip_address("2001:db8::1") is True

    def test_ipv6_full(self):
        assert _is_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001") is True

    def test_not_ip(self):
        assert _is_ip_address("example.com") is False

    def test_empty(self):
        assert _is_ip_address("") is False

    def test_cname(self):
        assert _is_ip_address("alias.example.com.") is False


class TestPayloadEdgeCases:
    """Tests for edge cases in payload handling."""

    def test_missing_json_payload(self, parser):
        event = {
            "resource": {"type": "dns_query"},
            "timestamp": "2025-06-15T10:00:00Z",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)
        assert result["metadata"]["query_name"] == ""

    def test_non_dict_json_payload(self, parser):
        event = {
            "resource": {"type": "dns_query"},
            "jsonPayload": "not a dict",
            "timestamp": "2025-06-15T10:00:00Z",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)

    def test_non_dict_resource(self, parser):
        event = {
            "resource": "not a dict",
            "jsonPayload": {"queryName": "example.com."},
            "timestamp": "2025-06-15T10:00:00Z",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)
        assert result["metadata"]["project_id"] is None

    def test_non_dict_resource_labels(self, parser):
        event = {
            "resource": {"type": "dns_query", "labels": "not a dict"},
            "jsonPayload": {"queryName": "example.com.", "queryType": "A"},
            "timestamp": "2025-06-15T10:00:00Z",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)

    def test_minimal_event(self, parser):
        event = {"jsonPayload": {"queryName": "example.com."}}
        result = parser.parse(event)
        assert isinstance(result, dict)
        assert result["metadata"]["query_name"] == "example.com"


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
            "query_name", "query_type", "response_code", "transport",
            "answers", "resolved_ips", "is_nxdomain", "subdomain_count",
            "subdomain_entropy", "is_external_resolution", "domain_age_days",
            "tags",
        }
        assert dns_keys.issubset(metadata.keys())

    def test_metadata_gcp_keys(self, parser):
        result = parser.parse(_make_dns_event())
        metadata = result["metadata"]
        gcp_keys = {
            "project_id", "vm_instance_id", "vm_instance_name",
            "vm_zone_name", "source_network", "destination_ip",
            "target_name", "target_type", "source_type_label",
            "server_latency_ms", "egress_error",
        }
        assert gcp_keys.issubset(metadata.keys())


class TestFullIntegration:
    """End-to-end integration tests."""

    def test_standard_a_query(self, parser):
        event = _make_dns_event()
        result = parser.parse(event)
        assert result["action"] == "dns_query_a"
        assert result["result"] == "success"
        assert result["service"] == "cloud_dns"
        assert result["source_ip"] == "10.0.0.4"
        assert result["metadata"]["query_name"] == "api.example.com"
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]
        assert result["metadata"]["is_nxdomain"] is False
        assert result["metadata"]["is_external_resolution"] is True
        assert result["metadata"]["subdomain_count"] == 3
        assert "dns" in result["metadata"]["tags"]
        assert result["metadata"]["server_latency_ms"] == 1.0
        assert result["metadata"]["vm_instance_id"] == "123456789"
        assert result["metadata"]["project_id"] == "my-project"

    def test_nxdomain_query(self, parser):
        event = _make_dns_event(
            query_name="nonexistent.example.com.",
            response_code="NXDOMAIN",
            answers=[],
        )
        result = parser.parse(event)
        assert result["result"] == "failure"
        assert result["metadata"]["is_nxdomain"] is True
        assert result["metadata"]["resolved_ips"] == []
        assert result["metadata"]["is_external_resolution"] is False

    def test_internal_dns_resolution(self, parser):
        event = _make_dns_event(
            query_name="internal.corp.local.",
            answers=[{"type": "A", "rdata": "10.0.0.100"}],
            source_ip="10.0.0.4",
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

    def test_txt_query(self, parser):
        event = _make_dns_event(
            query_name="example.com.",
            query_type="TXT",
            answers=[
                {"type": "TXT", "rdata": "v=spf1 include:_spf.google.com ~all"}
            ],
        )
        result = parser.parse(event)
        assert result["action"] == "dns_query_txt"
        assert result["metadata"]["resolved_ips"] == []

    def test_no_vm_context(self, parser):
        event = _make_dns_event(
            vm_instance_id="",
            vm_instance_name="",
            vm_project_id="",
            vm_zone_name="",
        )
        result = parser.parse(event)
        assert result["metadata"]["vm_instance_id"] is None
        assert result["metadata"]["vm_instance_name"] is None
        assert result["metadata"]["vm_zone_name"] is None
