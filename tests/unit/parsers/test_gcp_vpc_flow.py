"""Unit tests for GCP VPC Flow Log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.gcp_vpc_flow import GCPVPCFlowParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return GCPVPCFlowParser()


def _make_flow_event(
    src_ip="10.0.0.1",
    dest_ip="10.0.0.2",
    src_port=12345,
    dest_port=443,
    protocol=6,
    bytes_sent=1024,
    packets_sent=10,
    start_time="2025-06-15T10:00:00.000000Z",
    end_time="2025-06-15T10:00:30.000000Z",
    reporter="SRC",
    src_instance=None,
    dest_instance=None,
    src_vpc=None,
    dest_vpc=None,
    src_location=None,
    dest_location=None,
    dest_gke=None,
    src_gke=None,
    rtt_msec=None,
    project_id="my-project",
    subnetwork_name="default",
    log_name="projects/my-project/logs/compute.googleapis.com%2Fvpc_flows",
):
    """Build a synthetic GCP VPC Flow Log event."""
    json_payload = {
        "connection": {
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol,
        },
        "bytes_sent": bytes_sent,
        "packets_sent": packets_sent,
        "start_time": start_time,
        "end_time": end_time,
        "reporter": reporter,
    }
    if src_instance is not None:
        json_payload["src_instance"] = src_instance
    if dest_instance is not None:
        json_payload["dest_instance"] = dest_instance
    if src_vpc is not None:
        json_payload["src_vpc"] = src_vpc
    if dest_vpc is not None:
        json_payload["dest_vpc"] = dest_vpc
    if src_location is not None:
        json_payload["src_location"] = src_location
    if dest_location is not None:
        json_payload["dest_location"] = dest_location
    if dest_gke is not None:
        json_payload["dest_gke"] = dest_gke
    if src_gke is not None:
        json_payload["src_gke"] = src_gke
    if rtt_msec is not None:
        json_payload["rtt_msec"] = rtt_msec

    return {
        "logName": log_name,
        "timestamp": start_time,
        "insertId": "test-insert-id",
        "resource": {
            "type": "gce_subnetwork",
            "labels": {
                "project_id": project_id,
                "subnetwork_name": subnetwork_name,
                "subnetwork_id": "1234567890",
                "location": "us-central1-a",
            },
        },
        "jsonPayload": json_payload,
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestGCPVPCFlowParserInit:
    """Tests for parser initialisation."""

    def test_source_type(self, parser):
        assert parser.source_type == "gcp_vpc_flow"

    def test_protocol_map(self, parser):
        assert parser.PROTOCOL_MAP[6] == "TCP"
        assert parser.PROTOCOL_MAP[17] == "UDP"
        assert parser.PROTOCOL_MAP[1] == "ICMP"


class TestValidation:
    """Tests for event validation."""

    def test_valid_vpc_flows_log_name(self, parser):
        event = _make_flow_event()
        assert parser.validate(event) is True

    def test_valid_subnetwork_resource_type(self, parser):
        event = _make_flow_event(log_name="some-other-log")
        # Still has resource.type=gce_subnetwork + connection
        assert parser.validate(event) is True

    def test_valid_json_payload_with_connection_and_bytes(self, parser):
        event = {
            "jsonPayload": {
                "connection": {"src_ip": "1.2.3.4"},
                "bytes_sent": 100,
            }
        }
        assert parser.validate(event) is True

    def test_valid_json_payload_with_connection_and_start_time(self, parser):
        event = {
            "jsonPayload": {
                "connection": {"src_ip": "1.2.3.4"},
                "start_time": "2025-01-01T00:00:00Z",
            }
        }
        assert parser.validate(event) is True

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_invalid_non_dict(self, parser):
        assert parser.validate("not a dict") is False

    def test_invalid_no_connection(self, parser):
        event = {"jsonPayload": {"bytes_sent": 100}}
        assert parser.validate(event) is False

    def test_invalid_connection_only_no_bytes_or_time(self, parser):
        event = {"jsonPayload": {"connection": {"src_ip": "1.2.3.4"}}}
        assert parser.validate(event) is False


class TestBasicParsing:
    """Tests for core parsing of a minimal flow event."""

    def test_action(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["action"] == "network_flow"

    def test_result(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["result"] == "success"

    def test_service(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["service"] == "gcp_vpc"

    def test_source_ip(self, parser):
        result = parser.parse(_make_flow_event(src_ip="192.168.1.5"))
        assert result["source_ip"] == "192.168.1.5"

    def test_destination_ip(self, parser):
        result = parser.parse(_make_flow_event(dest_ip="8.8.8.8"))
        assert result["destination_ip"] == "8.8.8.8"

    def test_user_is_none(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["user"] is None

    def test_timestamp_iso_format(self, parser):
        result = parser.parse(_make_flow_event(
            start_time="2025-06-15T10:00:00.000000Z"
        ))
        assert "2025-06-15" in result["timestamp"]

    def test_raw_event_preserved(self, parser):
        event = _make_flow_event()
        result = parser.parse(event)
        assert result["raw_event"] is event


class TestConnectionMetadata:
    """Tests for connection-level metadata fields."""

    def test_source_port(self, parser):
        result = parser.parse(_make_flow_event(src_port=54321))
        assert result["metadata"]["source_port"] == 54321

    def test_destination_port(self, parser):
        result = parser.parse(_make_flow_event(dest_port=80))
        assert result["metadata"]["destination_port"] == 80

    def test_protocol(self, parser):
        result = parser.parse(_make_flow_event(protocol=17))
        assert result["metadata"]["protocol"] == 17
        assert result["metadata"]["protocol_name"] == "UDP"

    def test_protocol_name_tcp(self, parser):
        result = parser.parse(_make_flow_event(protocol=6))
        assert result["metadata"]["protocol_name"] == "TCP"

    def test_protocol_name_icmp(self, parser):
        result = parser.parse(_make_flow_event(protocol=1))
        assert result["metadata"]["protocol_name"] == "ICMP"

    def test_protocol_unknown_number(self, parser):
        result = parser.parse(_make_flow_event(protocol=132))
        assert result["metadata"]["protocol_name"] == "132"

    def test_bytes_transferred(self, parser):
        result = parser.parse(_make_flow_event(bytes_sent=4096))
        assert result["metadata"]["bytes_transferred"] == 4096

    def test_packets_sent(self, parser):
        result = parser.parse(_make_flow_event(packets_sent=42))
        assert result["metadata"]["packets_sent"] == 42

    def test_reporter(self, parser):
        result = parser.parse(_make_flow_event(reporter="DEST"))
        assert result["metadata"]["reporter"] == "DEST"

    def test_rtt_msec(self, parser):
        result = parser.parse(_make_flow_event(rtt_msec=15))
        assert result["metadata"]["rtt_msec"] == 15


class TestTimestamps:
    """Tests for timestamp parsing and duration computation."""

    def test_start_time(self, parser):
        result = parser.parse(_make_flow_event(
            start_time="2025-06-15T10:00:00.000000Z"
        ))
        assert result["metadata"]["start_time"] == "2025-06-15T10:00:00+00:00"

    def test_end_time(self, parser):
        result = parser.parse(_make_flow_event(
            end_time="2025-06-15T10:00:30.000000Z"
        ))
        assert result["metadata"]["end_time"] == "2025-06-15T10:00:30+00:00"

    def test_duration_seconds(self, parser):
        result = parser.parse(_make_flow_event(
            start_time="2025-06-15T10:00:00.000000Z",
            end_time="2025-06-15T10:00:30.000000Z",
        ))
        assert result["metadata"]["duration_seconds"] == 30

    def test_duration_zero_same_timestamps(self, parser):
        ts = "2025-06-15T10:00:00.000000Z"
        result = parser.parse(_make_flow_event(start_time=ts, end_time=ts))
        assert result["metadata"]["duration_seconds"] == 0

    def test_duration_none_when_end_missing(self, parser):
        result = parser.parse(_make_flow_event(
            start_time="2025-06-15T10:00:00.000000Z",
            end_time="",
        ))
        assert result["metadata"]["duration_seconds"] is None

    def test_nanosecond_precision_truncated(self, parser):
        """GCP timestamps can have nanosecond precision (9 digits)."""
        result = parser.parse(_make_flow_event(
            start_time="2025-06-15T10:00:00.123456789Z"
        ))
        assert "2025-06-15T10:00:00.123456" in result["metadata"]["start_time"]

    def test_timestamp_with_timezone_offset(self, parser):
        result = parser.parse(_make_flow_event(
            start_time="2025-06-15T10:00:00.000000+05:30"
        ))
        assert result["metadata"]["start_time"] is not None

    def test_falls_back_to_envelope_timestamp(self, parser):
        """When start_time is empty, uses envelope timestamp."""
        event = _make_flow_event(start_time="")
        event["timestamp"] = "2025-06-15T12:00:00Z"
        result = parser.parse(event)
        assert "2025-06-15T12:00:00" in result["timestamp"]


class TestInstanceInfo:
    """Tests for VM instance metadata."""

    def test_src_instance(self, parser):
        result = parser.parse(_make_flow_event(src_instance={
            "vm_name": "web-server-1",
            "zone": "us-central1-a",
            "project_id": "my-project",
            "region": "us-central1",
        }))
        inst = result["metadata"]["src_instance"]
        assert inst["vm_name"] == "web-server-1"
        assert inst["zone"] == "us-central1-a"
        assert inst["project_id"] == "my-project"
        assert inst["region"] == "us-central1"

    def test_dest_instance(self, parser):
        result = parser.parse(_make_flow_event(dest_instance={
            "vm_name": "db-server-1",
            "zone": "us-east1-b",
            "project_id": "my-project",
            "region": "us-east1",
        }))
        inst = result["metadata"]["dest_instance"]
        assert inst["vm_name"] == "db-server-1"
        assert inst["zone"] == "us-east1-b"

    def test_src_instance_none_when_absent(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["src_instance"] is None

    def test_dest_instance_none_when_absent(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["dest_instance"] is None


class TestVPCInfo:
    """Tests for VPC metadata."""

    def test_src_vpc(self, parser):
        result = parser.parse(_make_flow_event(src_vpc={
            "vpc_name": "production-vpc",
            "project_id": "my-project",
            "subnetwork_name": "subnet-1",
        }))
        vpc = result["metadata"]["src_vpc"]
        assert vpc["vpc_name"] == "production-vpc"
        assert vpc["subnetwork_name"] == "subnet-1"

    def test_dest_vpc(self, parser):
        result = parser.parse(_make_flow_event(dest_vpc={
            "vpc_name": "staging-vpc",
            "project_id": "my-project",
            "subnetwork_name": "subnet-2",
        }))
        vpc = result["metadata"]["dest_vpc"]
        assert vpc["vpc_name"] == "staging-vpc"

    def test_vpc_none_when_absent(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["src_vpc"] is None
        assert result["metadata"]["dest_vpc"] is None


class TestGeolocation:
    """Tests for geolocation metadata."""

    def test_src_location(self, parser):
        result = parser.parse(_make_flow_event(src_location={
            "country": "US",
            "region": "California",
            "city": "Mountain View",
            "continent": "North America",
        }))
        loc = result["metadata"]["src_location"]
        assert loc["country"] == "US"
        assert loc["region"] == "California"
        assert loc["city"] == "Mountain View"
        assert loc["continent"] == "North America"

    def test_dest_location(self, parser):
        result = parser.parse(_make_flow_event(dest_location={
            "country": "DE",
            "region": "Hesse",
            "city": "Frankfurt",
            "continent": "Europe",
        }))
        loc = result["metadata"]["dest_location"]
        assert loc["country"] == "DE"

    def test_location_none_when_absent(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["src_location"] is None
        assert result["metadata"]["dest_location"] is None


class TestGKEInfo:
    """Tests for GKE cluster metadata."""

    def test_dest_gke(self, parser):
        result = parser.parse(_make_flow_event(dest_gke={
            "cluster_name": "prod-cluster",
            "cluster_location": "us-central1",
            "pod_name": "api-server-abc123",
            "pod_namespace": "default",
            "service_name": "api-service",
            "service_namespace": "default",
        }))
        gke = result["metadata"]["dest_gke"]
        assert gke["cluster_name"] == "prod-cluster"
        assert gke["pod_name"] == "api-server-abc123"
        assert gke["service_name"] == "api-service"

    def test_src_gke(self, parser):
        result = parser.parse(_make_flow_event(src_gke={
            "cluster_name": "staging-cluster",
            "cluster_location": "europe-west1",
        }))
        gke = result["metadata"]["src_gke"]
        assert gke["cluster_name"] == "staging-cluster"
        assert gke["cluster_location"] == "europe-west1"
        assert gke["pod_name"] is None

    def test_gke_none_when_absent(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["dest_gke"] is None
        assert result["metadata"]["src_gke"] is None


class TestResourceLabels:
    """Tests for Cloud Logging envelope labels."""

    def test_project_id(self, parser):
        result = parser.parse(_make_flow_event(project_id="my-gcp-project"))
        assert result["metadata"]["project_id"] == "my-gcp-project"

    def test_subnetwork_name(self, parser):
        result = parser.parse(_make_flow_event(subnetwork_name="my-subnet"))
        assert result["metadata"]["subnetwork_name"] == "my-subnet"

    def test_subnetwork_id(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["subnetwork_id"] == "1234567890"

    def test_location(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["location"] == "us-central1-a"


class TestNDRTags:
    """Tests for NDR tagging."""

    def test_network_tag_present(self, parser):
        result = parser.parse(_make_flow_event())
        assert "network" in result["metadata"]["tags"]


class TestInternalTrafficDetection:
    """Tests for is_internal determination."""

    def test_both_rfc1918_10_dot(self, parser):
        result = parser.parse(_make_flow_event(
            src_ip="10.0.0.1", dest_ip="10.0.0.2"
        ))
        assert result["metadata"]["is_internal"] is True

    def test_both_rfc1918_172_16(self, parser):
        result = parser.parse(_make_flow_event(
            src_ip="172.16.0.1", dest_ip="172.31.255.254"
        ))
        assert result["metadata"]["is_internal"] is True

    def test_both_rfc1918_192_168(self, parser):
        result = parser.parse(_make_flow_event(
            src_ip="192.168.1.1", dest_ip="192.168.2.2"
        ))
        assert result["metadata"]["is_internal"] is True

    def test_mixed_private_public(self, parser):
        result = parser.parse(_make_flow_event(
            src_ip="10.0.0.1", dest_ip="8.8.8.8"
        ))
        assert result["metadata"]["is_internal"] is False

    def test_both_public(self, parser):
        result = parser.parse(_make_flow_event(
            src_ip="1.2.3.4", dest_ip="5.6.7.8"
        ))
        assert result["metadata"]["is_internal"] is False

    def test_same_vpc_is_internal(self, parser):
        """Both sides in the same VPC → internal, even with public IPs."""
        result = parser.parse(_make_flow_event(
            src_ip="35.192.0.1",
            dest_ip="35.192.0.2",
            src_vpc={"vpc_name": "prod-vpc", "project_id": "proj-1"},
            dest_vpc={"vpc_name": "prod-vpc", "project_id": "proj-1"},
        ))
        assert result["metadata"]["is_internal"] is True

    def test_different_vpc_not_internal_with_public_ips(self, parser):
        result = parser.parse(_make_flow_event(
            src_ip="35.192.0.1",
            dest_ip="35.192.0.2",
            src_vpc={"vpc_name": "vpc-a", "project_id": "proj-1"},
            dest_vpc={"vpc_name": "vpc-b", "project_id": "proj-1"},
        ))
        assert result["metadata"]["is_internal"] is False

    def test_same_vpc_name_different_project(self, parser):
        """Same VPC name but different projects → not same VPC."""
        result = parser.parse(_make_flow_event(
            src_ip="35.192.0.1",
            dest_ip="35.192.0.2",
            src_vpc={"vpc_name": "default", "project_id": "proj-1"},
            dest_vpc={"vpc_name": "default", "project_id": "proj-2"},
        ))
        assert result["metadata"]["is_internal"] is False

    def test_rfc1918_boundary_172_15(self, parser):
        """172.15.x.x is NOT in the RFC 1918 172.16-31 range."""
        result = parser.parse(_make_flow_event(
            src_ip="172.15.0.1", dest_ip="172.15.0.2"
        ))
        assert result["metadata"]["is_internal"] is False

    def test_rfc1918_boundary_172_32(self, parser):
        """172.32.x.x is NOT in the RFC 1918 172.16-31 range."""
        result = parser.parse(_make_flow_event(
            src_ip="172.32.0.1", dest_ip="172.32.0.2"
        ))
        assert result["metadata"]["is_internal"] is False


class TestRFC1918:
    """Direct tests for the _is_rfc1918 static method."""

    def test_10_dot(self):
        assert GCPVPCFlowParser._is_rfc1918("10.0.0.1") is True
        assert GCPVPCFlowParser._is_rfc1918("10.255.255.255") is True

    def test_172_range(self):
        assert GCPVPCFlowParser._is_rfc1918("172.16.0.1") is True
        assert GCPVPCFlowParser._is_rfc1918("172.31.255.254") is True

    def test_192_168(self):
        assert GCPVPCFlowParser._is_rfc1918("192.168.0.1") is True
        assert GCPVPCFlowParser._is_rfc1918("192.168.255.255") is True

    def test_public_ip(self):
        assert GCPVPCFlowParser._is_rfc1918("8.8.8.8") is False

    def test_boundary_172_15(self):
        assert GCPVPCFlowParser._is_rfc1918("172.15.0.1") is False

    def test_boundary_172_32(self):
        assert GCPVPCFlowParser._is_rfc1918("172.32.0.1") is False

    def test_empty_string(self):
        assert GCPVPCFlowParser._is_rfc1918("") is False


class TestSafeInt:
    """Tests for _safe_int helper."""

    def test_integer_value(self):
        assert GCPVPCFlowParser._safe_int(42) == 42

    def test_string_value(self):
        assert GCPVPCFlowParser._safe_int("123") == 123

    def test_none_value(self):
        assert GCPVPCFlowParser._safe_int(None) is None

    def test_invalid_string(self):
        assert GCPVPCFlowParser._safe_int("abc") is None

    def test_float_value(self):
        assert GCPVPCFlowParser._safe_int(3.7) == 3


class TestParseTimestamp:
    """Tests for _parse_timestamp helper."""

    def test_rfc3339_with_z(self):
        dt = GCPVPCFlowParser._parse_timestamp("2025-06-15T10:00:00Z")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 15
        assert dt.tzinfo is not None

    def test_rfc3339_with_microseconds(self):
        dt = GCPVPCFlowParser._parse_timestamp("2025-06-15T10:00:00.123456Z")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_rfc3339_with_nanoseconds(self):
        """Nanoseconds are truncated to microseconds."""
        dt = GCPVPCFlowParser._parse_timestamp("2025-06-15T10:00:00.123456789Z")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_rfc3339_with_offset(self):
        dt = GCPVPCFlowParser._parse_timestamp("2025-06-15T10:00:00+05:30")
        assert dt is not None
        assert dt.utcoffset().total_seconds() == 5.5 * 3600

    def test_none_input(self):
        assert GCPVPCFlowParser._parse_timestamp(None) is None

    def test_empty_string(self):
        assert GCPVPCFlowParser._parse_timestamp("") is None

    def test_invalid_string(self):
        assert GCPVPCFlowParser._parse_timestamp("not-a-timestamp") is None

    def test_simple_iso_without_tz(self):
        dt = GCPVPCFlowParser._parse_timestamp("2025-06-15T10:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc


class TestComputeDuration:
    """Tests for _compute_duration helper."""

    def test_normal_duration(self):
        start = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 6, 15, 10, 5, 0, tzinfo=timezone.utc)
        assert GCPVPCFlowParser._compute_duration(start, end) == 300

    def test_zero_duration(self):
        dt = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert GCPVPCFlowParser._compute_duration(dt, dt) == 0

    def test_none_start(self):
        end = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert GCPVPCFlowParser._compute_duration(None, end) is None

    def test_none_end(self):
        start = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert GCPVPCFlowParser._compute_duration(start, None) is None

    def test_both_none(self):
        assert GCPVPCFlowParser._compute_duration(None, None) is None

    def test_negative_clamped_to_zero(self):
        """If end < start (clock skew), duration is clamped to 0."""
        start = datetime(2025, 6, 15, 10, 5, 0, tzinfo=timezone.utc)
        end = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert GCPVPCFlowParser._compute_duration(start, end) == 0


class TestFullEventIntegration:
    """Integration tests with fully populated events."""

    def test_full_flow_event(self, parser):
        """Parse a fully populated GCP VPC Flow Log event."""
        event = _make_flow_event(
            src_ip="10.128.0.5",
            dest_ip="35.190.0.1",
            src_port=54321,
            dest_port=443,
            protocol=6,
            bytes_sent=2048,
            packets_sent=20,
            start_time="2025-06-15T10:00:00.000000Z",
            end_time="2025-06-15T10:01:00.000000Z",
            reporter="SRC",
            src_instance={
                "vm_name": "web-1",
                "zone": "us-central1-a",
                "project_id": "my-project",
                "region": "us-central1",
            },
            dest_instance={
                "vm_name": "api-1",
                "zone": "us-east1-b",
                "project_id": "my-project",
                "region": "us-east1",
            },
            src_vpc={
                "vpc_name": "prod-vpc",
                "project_id": "my-project",
                "subnetwork_name": "subnet-a",
            },
            dest_vpc={
                "vpc_name": "prod-vpc",
                "project_id": "other-project",
                "subnetwork_name": "subnet-b",
            },
            src_location={
                "country": "US",
                "region": "Iowa",
                "city": "Council Bluffs",
                "continent": "North America",
            },
            dest_location={
                "country": "US",
                "region": "South Carolina",
                "city": "Moncks Corner",
                "continent": "North America",
            },
            dest_gke={
                "cluster_name": "prod-gke",
                "cluster_location": "us-east1",
                "pod_name": "api-pod-xyz",
                "pod_namespace": "api-ns",
                "service_name": "api-svc",
                "service_namespace": "api-ns",
            },
            rtt_msec=25,
        )

        result = parser.parse(event)
        m = result["metadata"]

        assert result["source_ip"] == "10.128.0.5"
        assert result["destination_ip"] == "35.190.0.1"
        assert result["action"] == "network_flow"
        assert result["service"] == "gcp_vpc"

        assert m["source_port"] == 54321
        assert m["destination_port"] == 443
        assert m["protocol"] == 6
        assert m["protocol_name"] == "TCP"
        assert m["bytes_transferred"] == 2048
        assert m["packets_sent"] == 20
        assert m["duration_seconds"] == 60
        assert m["reporter"] == "SRC"
        assert m["is_internal"] is False  # dest is public IP, diff VPC project
        assert m["rtt_msec"] == 25

        assert m["src_instance"]["vm_name"] == "web-1"
        assert m["dest_instance"]["vm_name"] == "api-1"
        assert m["src_vpc"]["vpc_name"] == "prod-vpc"
        assert m["dest_vpc"]["vpc_name"] == "prod-vpc"
        assert m["src_location"]["country"] == "US"
        assert m["dest_location"]["city"] == "Moncks Corner"
        assert m["dest_gke"]["cluster_name"] == "prod-gke"
        assert m["dest_gke"]["pod_name"] == "api-pod-xyz"

        assert "network" in m["tags"]

    def test_minimal_flow_event(self, parser):
        """Parse a minimal event with only connection info."""
        event = {
            "jsonPayload": {
                "connection": {
                    "src_ip": "1.2.3.4",
                    "src_port": 80,
                    "dest_ip": "5.6.7.8",
                    "dest_port": 443,
                    "protocol": 6,
                },
                "bytes_sent": 100,
                "packets_sent": 1,
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-01T00:00:01Z",
                "reporter": "SRC",
            }
        }

        result = parser.parse(event)
        assert result["source_ip"] == "1.2.3.4"
        assert result["destination_ip"] == "5.6.7.8"
        assert result["metadata"]["source_port"] == 80
        assert result["metadata"]["destination_port"] == 443
        assert result["metadata"]["bytes_transferred"] == 100
        assert result["metadata"]["duration_seconds"] == 1
        assert result["metadata"]["is_internal"] is False
        assert "network" in result["metadata"]["tags"]

    def test_empty_ip_addresses(self, parser):
        """Source/destination IP should be None when empty string."""
        event = _make_flow_event(src_ip="", dest_ip="")
        result = parser.parse(event)
        assert result["source_ip"] is None
        assert result["destination_ip"] is None

    def test_output_matches_parsed_event_to_dict_keys(self, parser):
        """Verify the output keys match ParsedEvent.to_dict()."""
        result = parser.parse(_make_flow_event())
        expected_keys = {
            "timestamp", "source_ip", "destination_ip", "user",
            "action", "result", "service", "metadata", "raw_event",
        }
        assert set(result.keys()) == expected_keys

    def test_icmp_flow(self, parser):
        """ICMP flows have no ports."""
        event = _make_flow_event(
            protocol=1,
            src_port=0,
            dest_port=0,
        )
        result = parser.parse(event)
        assert result["metadata"]["protocol_name"] == "ICMP"
        assert result["metadata"]["source_port"] == 0
        assert result["metadata"]["destination_port"] == 0
