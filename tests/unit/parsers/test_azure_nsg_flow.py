"""Unit tests for Azure NSG Flow Log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.azure_nsg_flow import AzureNSGFlowParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance (default: exclude continuing flows)."""
    return AzureNSGFlowParser()


@pytest.fixture
def parser_with_continuing():
    """Create parser instance that includes continuing flows."""
    return AzureNSGFlowParser(include_continuing=True)


def _make_flow_tuple(
    unix_ts=1706436000,
    src_ip="10.0.0.4",
    dest_ip="13.107.246.70",
    src_port=54321,
    dest_port=443,
    protocol="T",
    direction="O",
    decision="A",
    flow_state="B",
    packets_sent=5,
    bytes_sent=1024,
    packets_received=3,
    bytes_received=512,
):
    """Build a flow tuple string."""
    return (
        f"{unix_ts},{src_ip},{dest_ip},{src_port},{dest_port},"
        f"{protocol},{direction},{decision},{flow_state},"
        f"{packets_sent},{bytes_sent},{packets_received},{bytes_received}"
    )


def _make_v1_flow_tuple(
    unix_ts=1706436000,
    src_ip="10.0.0.4",
    dest_ip="13.107.246.70",
    src_port=54321,
    dest_port=443,
    protocol="T",
    direction="O",
    decision="A",
):
    """Build a v1 flow tuple string (8 fields, no state/bytes)."""
    return (
        f"{unix_ts},{src_ip},{dest_ip},{src_port},{dest_port},"
        f"{protocol},{direction},{decision}"
    )


def _make_nsg_record(
    flow_tuples=None,
    rule_name="DefaultRule_AllowInternetOutBound",
    time="2025-01-28T10:00:00Z",
    system_id="test-system-id",
    mac_address="00224DABCDEF",
    resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
    category="NetworkSecurityGroupFlowEvent",
    operation_name="NetworkSecurityGroupFlowEvents",
    version=2,
    extra_rules=None,
):
    """Build a synthetic Azure NSG Flow Log record."""
    if flow_tuples is None:
        flow_tuples = [_make_flow_tuple()]

    flows_inner = [{"mac": mac_address, "flowTuples": flow_tuples}]

    rule_flows = [{"rule": rule_name, "flows": flows_inner}]
    if extra_rules:
        rule_flows.extend(extra_rules)

    return {
        "time": time,
        "systemId": system_id,
        "macAddress": mac_address,
        "category": category,
        "resourceId": resource_id,
        "operationName": operation_name,
        "properties": {
            "Version": version,
            "flows": rule_flows,
        },
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestAzureNSGFlowParserInit:
    """Tests for parser initialisation."""

    def test_source_type(self, parser):
        assert parser.source_type == "azure_nsg_flow"

    def test_default_excludes_continuing(self, parser):
        assert parser._include_continuing is False

    def test_include_continuing_flag(self, parser_with_continuing):
        assert parser_with_continuing._include_continuing is True


class TestValidation:
    """Tests for event validation."""

    def test_valid_category(self, parser):
        event = {"category": "NetworkSecurityGroupFlowEvent"}
        assert parser.validate(event) is True

    def test_valid_operation_name(self, parser):
        event = {"operationName": "NetworkSecurityGroupFlowEvents"}
        assert parser.validate(event) is True

    def test_valid_properties_flows(self, parser):
        event = {
            "properties": {
                "flows": [{"rule": "test-rule", "flows": []}]
            }
        }
        assert parser.validate(event) is True

    def test_valid_resource_id_nsg(self, parser):
        event = {
            "resourceId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg"
        }
        assert parser.validate(event) is True

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_invalid_non_dict(self, parser):
        assert parser.validate("not a dict") is False

    def test_invalid_wrong_category(self, parser):
        event = {"category": "SomethingElse"}
        assert parser.validate(event) is False

    def test_invalid_empty_flows(self, parser):
        event = {"properties": {"flows": []}}
        assert parser.validate(event) is False

    def test_invalid_flows_no_rule(self, parser):
        event = {"properties": {"flows": [{"noRule": True}]}}
        assert parser.validate(event) is False


class TestFlowTupleParsing:
    """Tests for _parse_flow_tuple static method."""

    def test_v2_full_tuple(self):
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O,A,B,5,1024,3,512"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result is not None
        assert result["unix_timestamp"] == 1706436000
        assert result["src_ip"] == "10.0.0.4"
        assert result["dest_ip"] == "13.107.246.70"
        assert result["src_port"] == 54321
        assert result["dest_port"] == 443
        assert result["protocol"] == 6
        assert result["protocol_name"] == "TCP"
        assert result["direction"] == "outbound"
        assert result["decision"] == "allowed"
        assert result["flow_state"] == "B"
        assert result["packets_sent"] == 5
        assert result["bytes_sent"] == 1024
        assert result["packets_received"] == 3
        assert result["bytes_received"] == 512

    def test_v2_udp_inbound_denied(self):
        tuple_str = "1706436000,8.8.8.8,10.0.0.4,53,12345,U,I,D,B,0,0,0,0"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result["protocol"] == 17
        assert result["protocol_name"] == "UDP"
        assert result["direction"] == "inbound"
        assert result["decision"] == "denied"

    def test_v1_tuple_8_fields(self):
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O,A"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=1)
        assert result is not None
        assert result["flow_state"] == "B"  # default for v1
        assert result["packets_sent"] == 0
        assert result["bytes_sent"] == 0
        assert result["packets_received"] == 0
        assert result["bytes_received"] == 0

    def test_v2_continuing_state(self):
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O,A,C,10,2048,6,1024"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result["flow_state"] == "C"
        assert result["packets_sent"] == 10

    def test_v2_end_state(self):
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O,A,E,15,3072,9,1536"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result["flow_state"] == "E"

    def test_too_few_fields_returns_none(self):
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result is None

    def test_invalid_timestamp_returns_none(self):
        tuple_str = "notanumber,10.0.0.4,13.107.246.70,54321,443,T,O,A"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result is None

    def test_unknown_protocol_letter(self):
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,X,O,A,B,0,0,0,0"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result["protocol"] == 0
        assert result["protocol_name"] == "X"

    def test_v2_9_fields_state_only(self):
        """9 fields: has flow_state but no byte counts."""
        tuple_str = "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O,A,B"
        result = AzureNSGFlowParser._parse_flow_tuple(tuple_str, version=2)
        assert result is not None
        assert result["flow_state"] == "B"
        assert result["bytes_sent"] == 0


class TestFlowStateFiltering:
    """Tests for flow state B/C/E filtering."""

    def test_begin_included(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(flow_state="B"),
        ])
        events = parser.parse(record)
        assert len(events) == 1
        assert events[0]["metadata"]["flow_state"] == "B"

    def test_end_included(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(flow_state="E"),
        ])
        events = parser.parse(record)
        assert len(events) == 1
        assert events[0]["metadata"]["flow_state"] == "E"

    def test_continuing_excluded_by_default(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(flow_state="C"),
        ])
        events = parser.parse(record)
        assert len(events) == 0

    def test_continuing_included_when_flag_set(self, parser_with_continuing):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(flow_state="C"),
        ])
        events = parser_with_continuing.parse(record)
        assert len(events) == 1
        assert events[0]["metadata"]["flow_state"] == "C"

    def test_mixed_states_filters_continuing(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(flow_state="B", src_port=10001),
            _make_flow_tuple(flow_state="C", src_port=10001),
            _make_flow_tuple(flow_state="E", src_port=10001),
        ])
        events = parser.parse(record)
        assert len(events) == 2
        states = [e["metadata"]["flow_state"] for e in events]
        assert "B" in states
        assert "E" in states
        assert "C" not in states


class TestBasicParsing:
    """Tests for core parsing of a single flow event."""

    def test_action_allowed(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(decision="A"),
        ])
        events = parser.parse(record)
        assert events[0]["action"] == "network_accept"

    def test_action_denied(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(decision="D"),
        ])
        events = parser.parse(record)
        assert events[0]["action"] == "network_reject"

    def test_result_success(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(decision="A"),
        ])
        events = parser.parse(record)
        assert events[0]["result"] == "success"

    def test_result_failure(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(decision="D"),
        ])
        events = parser.parse(record)
        assert events[0]["result"] == "failure"

    def test_service(self, parser):
        record = _make_nsg_record()
        events = parser.parse(record)
        assert events[0]["service"] == "azure_nsg"

    def test_source_ip(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="192.168.1.5"),
        ])
        events = parser.parse(record)
        assert events[0]["source_ip"] == "192.168.1.5"

    def test_destination_ip(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(dest_ip="8.8.8.8"),
        ])
        events = parser.parse(record)
        assert events[0]["destination_ip"] == "8.8.8.8"

    def test_user_is_none(self, parser):
        record = _make_nsg_record()
        events = parser.parse(record)
        assert events[0]["user"] is None

    def test_timestamp_from_tuple(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(unix_ts=1706436000),
        ])
        events = parser.parse(record)
        ts = events[0]["timestamp"]
        assert "2024-01-28" in ts  # 1706436000 = 2024-01-28T10:00:00Z

    def test_raw_event_preserved(self, parser):
        record = _make_nsg_record()
        events = parser.parse(record)
        assert events[0]["raw_event"] is record


class TestConnectionMetadata:
    """Tests for connection-level metadata fields."""

    def test_source_port(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_port=12345),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["source_port"] == 12345

    def test_destination_port(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(dest_port=80),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["destination_port"] == 80

    def test_protocol_tcp(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(protocol="T"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["protocol"] == 6
        assert events[0]["metadata"]["protocol_name"] == "TCP"

    def test_protocol_udp(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(protocol="U"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["protocol"] == 17
        assert events[0]["metadata"]["protocol_name"] == "UDP"

    def test_bytes_transferred_total(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(bytes_sent=1024, bytes_received=512),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["bytes_transferred"] == 1536
        assert events[0]["metadata"]["bytes_sent"] == 1024
        assert events[0]["metadata"]["bytes_received"] == 512

    def test_packets(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(packets_sent=5, packets_received=3),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["packets_sent"] == 5
        assert events[0]["metadata"]["packets_received"] == 3
        assert events[0]["metadata"]["total_packets"] == 8

    def test_direction_outbound(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(direction="O"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["direction"] == "outbound"

    def test_direction_inbound(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(direction="I"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["direction"] == "inbound"


class TestNSGInfo:
    """Tests for NSG-specific metadata."""

    def test_rule_name(self, parser):
        record = _make_nsg_record(rule_name="AllowHTTPS")
        events = parser.parse(record)
        assert events[0]["metadata"]["rule_name"] == "AllowHTTPS"

    def test_mac_address(self, parser):
        record = _make_nsg_record(mac_address="AABBCCDDEEFF")
        events = parser.parse(record)
        assert events[0]["metadata"]["mac_address"] == "AABBCCDDEEFF"

    def test_nsg_name_from_resource_id(self, parser):
        record = _make_nsg_record(
            resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        )
        events = parser.parse(record)
        assert events[0]["metadata"]["nsg_name"] == "nsg-web"

    def test_resource_group_from_resource_id(self, parser):
        record = _make_nsg_record(
            resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        )
        events = parser.parse(record)
        assert events[0]["metadata"]["resource_group"] == "rg-prod"

    def test_subscription_id_from_resource_id(self, parser):
        record = _make_nsg_record(
            resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        )
        events = parser.parse(record)
        assert events[0]["metadata"]["subscription_id"] == "sub-123"

    def test_system_id(self, parser):
        record = _make_nsg_record(system_id="my-system-id")
        events = parser.parse(record)
        assert events[0]["metadata"]["system_id"] == "my-system-id"

    def test_version(self, parser):
        record = _make_nsg_record(version=2)
        events = parser.parse(record)
        assert events[0]["metadata"]["version"] == 2


class TestNDRTags:
    """Tests for NDR tagging."""

    def test_network_tag_present(self, parser):
        record = _make_nsg_record()
        events = parser.parse(record)
        assert "network" in events[0]["metadata"]["tags"]


class TestInternalTrafficDetection:
    """Tests for is_internal determination."""

    def test_both_rfc1918_10_dot(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="10.0.0.4", dest_ip="10.0.0.5"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is True

    def test_both_rfc1918_172_16(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="172.16.0.1", dest_ip="172.31.255.254"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is True

    def test_both_rfc1918_192_168(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="192.168.1.1", dest_ip="192.168.2.2"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is True

    def test_mixed_private_public(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="10.0.0.4", dest_ip="8.8.8.8"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is False

    def test_both_public(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="1.2.3.4", dest_ip="5.6.7.8"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is False

    def test_boundary_172_15_not_private(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="172.15.0.1", dest_ip="172.15.0.2"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is False

    def test_boundary_172_32_not_private(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip="172.32.0.1", dest_ip="172.32.0.2"),
        ])
        events = parser.parse(record)
        assert events[0]["metadata"]["is_internal"] is False


class TestRFC1918:
    """Direct tests for the _is_rfc1918 static method."""

    def test_10_dot(self):
        assert AzureNSGFlowParser._is_rfc1918("10.0.0.1") is True
        assert AzureNSGFlowParser._is_rfc1918("10.255.255.255") is True

    def test_172_range(self):
        assert AzureNSGFlowParser._is_rfc1918("172.16.0.1") is True
        assert AzureNSGFlowParser._is_rfc1918("172.31.255.254") is True

    def test_192_168(self):
        assert AzureNSGFlowParser._is_rfc1918("192.168.0.1") is True

    def test_public_ip(self):
        assert AzureNSGFlowParser._is_rfc1918("8.8.8.8") is False

    def test_empty_string(self):
        assert AzureNSGFlowParser._is_rfc1918("") is False


class TestSafeInt:
    """Tests for _safe_int helper."""

    def test_integer(self):
        assert AzureNSGFlowParser._safe_int(42) == 42

    def test_string(self):
        assert AzureNSGFlowParser._safe_int("123") == 123

    def test_none(self):
        assert AzureNSGFlowParser._safe_int(None) is None

    def test_invalid_string(self):
        assert AzureNSGFlowParser._safe_int("abc") is None


class TestParseResourceId:
    """Tests for _parse_resource_id helper."""

    def test_full_resource_id(self):
        rid = "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        result = AzureNSGFlowParser._parse_resource_id(rid)
        assert result["subscription_id"] == "sub-123"
        assert result["resource_group"] == "rg-prod"
        assert result["nsg_name"] == "nsg-web"

    def test_empty_resource_id(self):
        result = AzureNSGFlowParser._parse_resource_id("")
        assert result["subscription_id"] is None
        assert result["resource_group"] is None
        assert result["nsg_name"] is None

    def test_partial_resource_id(self):
        rid = "/subscriptions/sub-456"
        result = AzureNSGFlowParser._parse_resource_id(rid)
        assert result["subscription_id"] == "sub-456"
        assert result["resource_group"] is None
        assert result["nsg_name"] is None

    def test_case_insensitive_parsing(self):
        rid = "/SUBSCRIPTIONS/sub-789/RESOURCEGROUPS/rg-test/providers/Microsoft.Network/NETWORKSECURITYGROUPS/nsg-test"
        result = AzureNSGFlowParser._parse_resource_id(rid)
        assert result["subscription_id"] == "sub-789"
        assert result["resource_group"] == "rg-test"
        assert result["nsg_name"] == "nsg-test"


class TestMultipleFlowsAndRules:
    """Tests for records with multiple flow tuples and rules."""

    def test_multiple_tuples_in_one_rule(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_port=10001, flow_state="B"),
            _make_flow_tuple(src_port=10002, flow_state="B"),
            _make_flow_tuple(src_port=10003, flow_state="E"),
        ])
        events = parser.parse(record)
        assert len(events) == 3
        ports = sorted([e["metadata"]["source_port"] for e in events])
        assert ports == [10001, 10002, 10003]

    def test_multiple_rules(self, parser):
        record = _make_nsg_record(
            rule_name="AllowHTTPS",
            flow_tuples=[_make_flow_tuple(dest_port=443)],
            extra_rules=[
                {
                    "rule": "AllowSSH",
                    "flows": [
                        {
                            "mac": "00224DABCDEF",
                            "flowTuples": [
                                _make_flow_tuple(dest_port=22),
                            ],
                        }
                    ],
                }
            ],
        )
        events = parser.parse(record)
        assert len(events) == 2

        rules = {e["metadata"]["rule_name"] for e in events}
        assert rules == {"AllowHTTPS", "AllowSSH"}

        ports = sorted([e["metadata"]["destination_port"] for e in events])
        assert ports == [22, 443]

    def test_empty_flow_tuples(self, parser):
        record = _make_nsg_record(flow_tuples=[])
        events = parser.parse(record)
        assert len(events) == 0

    def test_empty_flows(self, parser):
        record = {
            "time": "2025-01-28T10:00:00Z",
            "category": "NetworkSecurityGroupFlowEvent",
            "properties": {"Version": 2, "flows": []},
        }
        events = parser.parse(record)
        assert len(events) == 0


class TestV1Records:
    """Tests for NSG Flow Log v1 records."""

    def test_v1_tuple_parsed(self, parser):
        record = _make_nsg_record(
            version=1,
            flow_tuples=[_make_v1_flow_tuple()],
        )
        events = parser.parse(record)
        assert len(events) == 1
        m = events[0]["metadata"]
        assert m["version"] == 1
        assert m["flow_state"] == "B"
        assert m["bytes_sent"] == 0
        assert m["bytes_received"] == 0
        assert m["bytes_transferred"] == 0


class TestOutputSchema:
    """Tests verifying the output matches ParsedEvent.to_dict() keys."""

    def test_output_keys(self, parser):
        record = _make_nsg_record()
        events = parser.parse(record)
        expected_keys = {
            "timestamp", "source_ip", "destination_ip", "user",
            "action", "result", "service", "metadata", "raw_event",
        }
        assert set(events[0].keys()) == expected_keys


class TestFullIntegration:
    """Integration tests with realistic NSG Flow Log data."""

    def test_realistic_nsg_record(self, parser):
        """Parse a realistic multi-rule NSG Flow Log record."""
        record = {
            "time": "2025-01-28T10:00:00Z",
            "systemId": "abc-123-def-456",
            "macAddress": "00224DABCDEF",
            "category": "NetworkSecurityGroupFlowEvent",
            "resourceId": "/subscriptions/sub-prod/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-frontend",
            "operationName": "NetworkSecurityGroupFlowEvents",
            "properties": {
                "Version": 2,
                "flows": [
                    {
                        "rule": "AllowHTTPS",
                        "flows": [
                            {
                                "mac": "00224DABCDEF",
                                "flowTuples": [
                                    "1706436000,10.0.0.4,52.184.123.45,54321,443,T,O,A,B,5,1024,3,512",
                                    "1706436060,10.0.0.4,52.184.123.45,54321,443,T,O,A,C,10,2048,6,1024",
                                    "1706436120,10.0.0.4,52.184.123.45,54321,443,T,O,A,E,15,3072,9,1536",
                                ],
                            }
                        ],
                    },
                    {
                        "rule": "DenySSH",
                        "flows": [
                            {
                                "mac": "00224DABCDEF",
                                "flowTuples": [
                                    "1706436030,203.0.113.50,10.0.0.4,45678,22,T,I,D,B,1,64,0,0",
                                ],
                            }
                        ],
                    },
                ],
            },
        }

        events = parser.parse(record)

        # C state filtered out, so 3 events (2 from HTTPS rule + 1 from SSH)
        assert len(events) == 3

        # Verify HTTPS begin
        https_begin = [e for e in events if e["metadata"]["rule_name"] == "AllowHTTPS" and e["metadata"]["flow_state"] == "B"][0]
        assert https_begin["source_ip"] == "10.0.0.4"
        assert https_begin["destination_ip"] == "52.184.123.45"
        assert https_begin["action"] == "network_accept"
        assert https_begin["result"] == "success"
        assert https_begin["metadata"]["destination_port"] == 443
        assert https_begin["metadata"]["protocol_name"] == "TCP"
        assert https_begin["metadata"]["direction"] == "outbound"
        assert https_begin["metadata"]["bytes_transferred"] == 1536  # 1024 + 512
        assert https_begin["metadata"]["is_internal"] is False
        assert "network" in https_begin["metadata"]["tags"]

        # Verify HTTPS end
        https_end = [e for e in events if e["metadata"]["rule_name"] == "AllowHTTPS" and e["metadata"]["flow_state"] == "E"][0]
        assert https_end["metadata"]["bytes_sent"] == 3072
        assert https_end["metadata"]["bytes_received"] == 1536

        # Verify SSH deny
        ssh_deny = [e for e in events if e["metadata"]["rule_name"] == "DenySSH"][0]
        assert ssh_deny["source_ip"] == "203.0.113.50"
        assert ssh_deny["destination_ip"] == "10.0.0.4"
        assert ssh_deny["action"] == "network_reject"
        assert ssh_deny["result"] == "failure"
        assert ssh_deny["metadata"]["destination_port"] == 22
        assert ssh_deny["metadata"]["direction"] == "inbound"
        assert ssh_deny["metadata"]["is_internal"] is False

        # Verify NSG metadata
        assert ssh_deny["metadata"]["nsg_name"] == "nsg-frontend"
        assert ssh_deny["metadata"]["resource_group"] == "rg-web"
        assert ssh_deny["metadata"]["subscription_id"] == "sub-prod"

    def test_all_internal_traffic(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(
                src_ip="10.0.0.4",
                dest_ip="10.0.0.5",
                direction="O",
                decision="A",
            ),
        ])
        events = parser.parse(record)
        assert len(events) == 1
        assert events[0]["metadata"]["is_internal"] is True

    def test_empty_source_ip(self, parser):
        record = _make_nsg_record(flow_tuples=[
            _make_flow_tuple(src_ip=""),
        ])
        events = parser.parse(record)
        assert events[0]["source_ip"] is None
        assert events[0]["metadata"]["is_internal"] is False
