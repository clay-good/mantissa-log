"""Unit tests for Unified Cloud Firewall Log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.cloud_firewall import CloudFirewallParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return CloudFirewallParser()


# ---------------------------------------------------------------------------
# Helpers — AWS Network Firewall
# ---------------------------------------------------------------------------

def _make_aws_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    proto="TCP",
    event_type="alert",
    alert_action="blocked",
    signature_id=2024897,
    signature="ET MALWARE Bad SSL Cert",
    alert_category="A Network Trojan was Detected",
    alert_severity=1,
    rule_group="",
    firewall_name="my-firewall",
    availability_zone="us-east-1a",
    event_timestamp="1718442000",
    timestamp="2025-06-15T10:00:00.000000+0000",
    app_proto="",
    flow=None,
    tls=None,
    http=None,
):
    """Build a synthetic AWS Network Firewall log event."""
    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
    }
    if alert_action or signature_id:
        event["alert"] = {
            "action": alert_action,
            "signature_id": signature_id,
            "rev": 1,
            "signature": signature,
            "category": alert_category,
            "severity": alert_severity,
        }
    if rule_group:
        event["rule_group"] = rule_group
    if app_proto:
        event["app_proto"] = app_proto
    if flow is not None:
        event["flow"] = flow
    if tls is not None:
        event["tls"] = tls
    if http is not None:
        event["http"] = http

    return {
        "firewall_name": firewall_name,
        "availability_zone": availability_zone,
        "event_timestamp": event_timestamp,
        "event": event,
    }


# ---------------------------------------------------------------------------
# Helpers — GCP VPC Firewall
# ---------------------------------------------------------------------------

def _make_gcp_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    protocol=6,
    disposition="ALLOWED",
    rule_reference="network:default/allow-https",
    rule_direction="EGRESS",
    rule_priority=1000,
    rule_action="ALLOW",
    source_range=None,
    destination_range=None,
    ip_port_info=None,
    vm_name="my-instance",
    vm_project_id="my-project",
    vm_region="us-central1",
    vm_zone="us-central1-a",
    vpc_name="default",
    vpc_project_id="my-project",
    subnetwork_name="default",
    remote_country="US",
    remote_region="California",
    remote_city="Los Angeles",
    timestamp="2025-06-15T10:00:00.000000Z",
):
    """Build a synthetic GCP VPC Firewall log event."""
    if source_range is None:
        source_range = ["10.0.0.0/8"]
    if destination_range is None:
        destination_range = ["0.0.0.0/0"]

    return {
        "insertId": "abc123",
        "resource": {
            "type": "gce_subnetwork",
            "labels": {
                "project_id": vm_project_id,
                "subnetwork_name": subnetwork_name,
                "subnetwork_id": "123456",
            },
        },
        "timestamp": timestamp,
        "jsonPayload": {
            "connection": {
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
            },
            "disposition": disposition,
            "rule_details": {
                "reference": rule_reference,
                "direction": rule_direction,
                "priority": rule_priority,
                "action": rule_action,
                "source_range": source_range,
                "destination_range": destination_range,
                "ip_port_info": ip_port_info or [],
            },
            "instance": {
                "project_id": vm_project_id,
                "vm_name": vm_name,
                "region": vm_region,
                "zone": vm_zone,
            },
            "vpc": {
                "vpc_name": vpc_name,
                "project_id": vpc_project_id,
                "subnetwork_name": subnetwork_name,
            },
            "remote_location": {
                "country": remote_country,
                "region": remote_region,
                "city": remote_city,
            },
        },
    }


# ---------------------------------------------------------------------------
# Helpers — Azure Firewall
# ---------------------------------------------------------------------------

def _make_azure_event(
    src_ip="10.0.0.4",
    src_port="54321",
    dest_ip="93.184.216.34",
    dest_port="443",
    protocol="TCP",
    action="Allow",
    rule_collection="AllowWeb",
    rule="AllowHTTPS",
    threat_intel="",
    policy="my-policy",
    msg="",
    time="2025-06-15T10:00:00.0000000Z",
    resource_id="/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/my-fw",
    category="AzureFirewallNetworkRule",
    operation_name="AzureFirewallNetworkRuleLog",
):
    """Build a synthetic Azure Firewall log event."""
    return {
        "category": category,
        "time": time,
        "resourceId": resource_id,
        "operationName": operation_name,
        "properties": {
            "msg": msg,
            "Protocol": protocol,
            "SourceIP": src_ip,
            "SourcePort": src_port,
            "DestinationIP": dest_ip,
            "DestinationPort": dest_port,
            "Action": action,
            "RuleCollection": rule_collection,
            "Rule": rule,
            "ThreatIntelligence": threat_intel,
            "Policy": policy,
        },
    }


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestCloudFirewallParserInit:
    """Tests for parser initialisation."""

    def test_source_type(self, parser):
        assert parser.source_type == "cloud_firewall"


class TestProviderDetection:
    """Tests for _detect_provider."""

    def test_aws_by_firewall_name(self, parser):
        event = {"firewall_name": "my-fw"}
        assert CloudFirewallParser._detect_provider(event) == "aws"

    def test_aws_by_event_type_alert(self, parser):
        event = {"event": {"event_type": "alert"}}
        assert CloudFirewallParser._detect_provider(event) == "aws"

    def test_aws_by_event_type_drop(self, parser):
        event = {"event": {"event_type": "drop"}}
        assert CloudFirewallParser._detect_provider(event) == "aws"

    def test_aws_by_event_type_flow(self, parser):
        event = {"event": {"event_type": "flow"}}
        assert CloudFirewallParser._detect_provider(event) == "aws"

    def test_gcp_by_disposition(self, parser):
        event = {"jsonPayload": {"disposition": "ALLOWED"}}
        assert CloudFirewallParser._detect_provider(event) == "gcp"

    def test_gcp_by_rule_details(self, parser):
        event = {"jsonPayload": {"rule_details": {}}}
        assert CloudFirewallParser._detect_provider(event) == "gcp"

    def test_azure_by_category(self, parser):
        event = {"category": "AzureFirewallNetworkRule"}
        assert CloudFirewallParser._detect_provider(event) == "azure"

    def test_azure_by_operation_name(self, parser):
        event = {"operationName": "AzureFirewallNetworkRuleLog"}
        assert CloudFirewallParser._detect_provider(event) == "azure"

    def test_azure_by_properties(self, parser):
        event = {"properties": {"Action": "Allow", "SourceIP": "10.0.0.1"}}
        assert CloudFirewallParser._detect_provider(event) == "azure"

    def test_azure_by_resource_id(self, parser):
        event = {
            "resourceId": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"
        }
        assert CloudFirewallParser._detect_provider(event) == "azure"

    def test_unknown_event(self, parser):
        assert CloudFirewallParser._detect_provider({"foo": "bar"}) is None

    def test_not_dict(self, parser):
        assert CloudFirewallParser._detect_provider("string") is None

    def test_none(self, parser):
        assert CloudFirewallParser._detect_provider(None) is None


class TestValidation:
    """Tests for validate()."""

    def test_valid_aws(self, parser):
        assert parser.validate(_make_aws_event()) is True

    def test_valid_gcp(self, parser):
        assert parser.validate(_make_gcp_event()) is True

    def test_valid_azure(self, parser):
        assert parser.validate(_make_azure_event()) is True

    def test_invalid_not_dict(self, parser):
        assert parser.validate("not a dict") is False

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_invalid_unrelated(self, parser):
        assert parser.validate({"foo": "bar"}) is False


# ===========================================================================
# AWS Network Firewall tests
# ===========================================================================


class TestAWSBasicParsing:
    """Tests for AWS Network Firewall basic parsing."""

    def test_returns_dict(self, parser):
        result = parser.parse(_make_aws_event())
        assert isinstance(result, dict)

    def test_service_name(self, parser):
        result = parser.parse(_make_aws_event())
        assert result["service"] == "aws_network_firewall"

    def test_source_ip(self, parser):
        result = parser.parse(_make_aws_event(src_ip="10.0.0.4"))
        assert result["source_ip"] == "10.0.0.4"

    def test_destination_ip(self, parser):
        result = parser.parse(_make_aws_event(dest_ip="93.184.216.34"))
        assert result["destination_ip"] == "93.184.216.34"

    def test_action_alert_blocked(self, parser):
        result = parser.parse(_make_aws_event(alert_action="blocked"))
        assert result["action"] == "firewall_deny"
        assert result["result"] == "blocked"

    def test_action_alert_allowed(self, parser):
        result = parser.parse(_make_aws_event(alert_action="allowed"))
        assert result["action"] == "firewall_allow"
        assert result["result"] == "allowed"

    def test_action_drop_event_type(self, parser):
        result = parser.parse(
            _make_aws_event(event_type="drop", alert_action="", signature_id=None)
        )
        assert result["action"] == "firewall_drop"

    def test_firewall_tag(self, parser):
        result = parser.parse(_make_aws_event())
        assert "firewall" in result["metadata"]["tags"]

    def test_cloud_provider(self, parser):
        result = parser.parse(_make_aws_event())
        assert result["metadata"]["cloud_provider"] == "aws"

    def test_raw_event_preserved(self, parser):
        event = _make_aws_event()
        result = parser.parse(event)
        assert result["raw_event"] == event


class TestAWSMetadata:
    """Tests for AWS-specific metadata fields."""

    def test_source_port(self, parser):
        result = parser.parse(_make_aws_event(src_port=54321))
        assert result["metadata"]["source_port"] == 54321

    def test_destination_port(self, parser):
        result = parser.parse(_make_aws_event(dest_port=443))
        assert result["metadata"]["destination_port"] == 443

    def test_protocol(self, parser):
        result = parser.parse(_make_aws_event(proto="TCP"))
        assert result["metadata"]["protocol"] == "TCP"

    def test_firewall_name(self, parser):
        result = parser.parse(_make_aws_event(firewall_name="my-fw"))
        assert result["metadata"]["firewall_name"] == "my-fw"

    def test_availability_zone(self, parser):
        result = parser.parse(_make_aws_event(availability_zone="us-east-1a"))
        assert result["metadata"]["availability_zone"] == "us-east-1a"

    def test_event_type(self, parser):
        result = parser.parse(_make_aws_event(event_type="alert"))
        assert result["metadata"]["event_type"] == "alert"

    def test_app_proto(self, parser):
        result = parser.parse(_make_aws_event(app_proto="tls"))
        assert result["metadata"]["app_proto"] == "tls"


class TestAWSSuricataAlert:
    """Tests for Suricata alert metadata."""

    def test_signature_id(self, parser):
        result = parser.parse(_make_aws_event(signature_id=2024897))
        assert result["metadata"]["signature_id"] == 2024897

    def test_signature(self, parser):
        result = parser.parse(_make_aws_event(signature="ET MALWARE Bad SSL Cert"))
        assert result["metadata"]["signature"] == "ET MALWARE Bad SSL Cert"

    def test_alert_severity(self, parser):
        result = parser.parse(_make_aws_event(alert_severity=1))
        assert result["metadata"]["alert_severity"] == 1

    def test_threat_category(self, parser):
        result = parser.parse(
            _make_aws_event(alert_category="A Network Trojan was Detected")
        )
        assert result["metadata"]["threat_category"] == "A Network Trojan was Detected"

    def test_firewall_rule_name_from_signature(self, parser):
        result = parser.parse(
            _make_aws_event(rule_group="", signature="ET TROJAN")
        )
        assert result["metadata"]["firewall_rule_name"] == "ET TROJAN"

    def test_firewall_rule_name_from_rule_group(self, parser):
        result = parser.parse(
            _make_aws_event(rule_group="my-rule-group", signature="")
        )
        assert result["metadata"]["firewall_rule_name"] == "my-rule-group"


class TestAWSTLSMetadata:
    """Tests for TLS metadata extraction."""

    def test_tls_sni(self, parser):
        event = _make_aws_event(
            tls={"sni": "example.com", "version": "TLS 1.3"}
        )
        result = parser.parse(event)
        assert result["metadata"]["tls_sni"] == "example.com"
        assert result["metadata"]["tls_version"] == "TLS 1.3"

    def test_tls_ja3(self, parser):
        event = _make_aws_event(
            tls={"sni": "example.com", "ja3": {"hash": "abc123"}}
        )
        result = parser.parse(event)
        assert result["metadata"]["tls_ja3_hash"] == "abc123"

    def test_no_tls(self, parser):
        result = parser.parse(_make_aws_event())
        assert "tls_sni" not in result["metadata"]


class TestAWSHTTPMetadata:
    """Tests for HTTP metadata extraction."""

    def test_http_fields(self, parser):
        event = _make_aws_event(
            http={
                "hostname": "example.com",
                "url": "/api/data",
                "http_method": "GET",
                "status": 200,
            }
        )
        result = parser.parse(event)
        assert result["metadata"]["http_hostname"] == "example.com"
        assert result["metadata"]["http_url"] == "/api/data"
        assert result["metadata"]["http_method"] == "GET"
        assert result["metadata"]["http_status"] == 200

    def test_no_http(self, parser):
        result = parser.parse(_make_aws_event())
        assert "http_hostname" not in result["metadata"]


class TestAWSTimestamp:
    """Tests for AWS timestamp parsing."""

    def test_suricata_timestamp(self, parser):
        event = _make_aws_event(
            timestamp="2025-06-15T10:00:00.000000+0000"
        )
        result = parser.parse(event)
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.year == 2025
        assert ts.month == 6

    def test_epoch_fallback(self, parser):
        event = _make_aws_event(timestamp="", event_timestamp="1718442000")
        result = parser.parse(event)
        assert "timestamp" in result

    def test_iso8601_z(self, parser):
        event = _make_aws_event(timestamp="2025-06-15T10:00:00Z")
        result = parser.parse(event)
        ts = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert ts.hour == 10


class TestAWSFlowStats:
    """Tests for flow statistics metadata."""

    def test_flow_stats(self, parser):
        event = _make_aws_event(
            flow={
                "bytes_toserver": 1234,
                "bytes_toclient": 5678,
                "pkts_toserver": 10,
                "pkts_toclient": 20,
            }
        )
        result = parser.parse(event)
        assert result["metadata"]["bytes_toserver"] == 1234
        assert result["metadata"]["bytes_toclient"] == 5678
        assert result["metadata"]["pkts_toserver"] == 10
        assert result["metadata"]["pkts_toclient"] == 20


# ===========================================================================
# GCP VPC Firewall tests
# ===========================================================================


class TestGCPBasicParsing:
    """Tests for GCP VPC Firewall basic parsing."""

    def test_returns_dict(self, parser):
        result = parser.parse(_make_gcp_event())
        assert isinstance(result, dict)

    def test_service_name(self, parser):
        result = parser.parse(_make_gcp_event())
        assert result["service"] == "gcp_vpc_firewall"

    def test_source_ip(self, parser):
        result = parser.parse(_make_gcp_event(src_ip="10.0.0.4"))
        assert result["source_ip"] == "10.0.0.4"

    def test_destination_ip(self, parser):
        result = parser.parse(_make_gcp_event(dest_ip="93.184.216.34"))
        assert result["destination_ip"] == "93.184.216.34"

    def test_action_allowed(self, parser):
        result = parser.parse(_make_gcp_event(disposition="ALLOWED"))
        assert result["action"] == "firewall_allow"
        assert result["result"] == "allowed"

    def test_action_denied(self, parser):
        result = parser.parse(_make_gcp_event(disposition="DENIED"))
        assert result["action"] == "firewall_deny"
        assert result["result"] == "blocked"

    def test_firewall_tag(self, parser):
        result = parser.parse(_make_gcp_event())
        assert "firewall" in result["metadata"]["tags"]

    def test_cloud_provider(self, parser):
        result = parser.parse(_make_gcp_event())
        assert result["metadata"]["cloud_provider"] == "gcp"


class TestGCPMetadata:
    """Tests for GCP-specific metadata fields."""

    def test_source_port(self, parser):
        result = parser.parse(_make_gcp_event(src_port=54321))
        assert result["metadata"]["source_port"] == 54321

    def test_destination_port(self, parser):
        result = parser.parse(_make_gcp_event(dest_port=443))
        assert result["metadata"]["destination_port"] == 443

    def test_protocol_tcp(self, parser):
        result = parser.parse(_make_gcp_event(protocol=6))
        assert result["metadata"]["protocol"] == "TCP"
        assert result["metadata"]["protocol_number"] == 6

    def test_protocol_udp(self, parser):
        result = parser.parse(_make_gcp_event(protocol=17))
        assert result["metadata"]["protocol"] == "UDP"

    def test_protocol_icmp(self, parser):
        result = parser.parse(_make_gcp_event(protocol=1))
        assert result["metadata"]["protocol"] == "ICMP"

    def test_firewall_rule_name(self, parser):
        result = parser.parse(
            _make_gcp_event(rule_reference="network:default/allow-https")
        )
        assert result["metadata"]["firewall_rule_name"] == "network:default/allow-https"

    def test_direction_egress(self, parser):
        result = parser.parse(_make_gcp_event(rule_direction="EGRESS"))
        assert result["metadata"]["direction"] == "outbound"

    def test_direction_ingress(self, parser):
        result = parser.parse(_make_gcp_event(rule_direction="INGRESS"))
        assert result["metadata"]["direction"] == "inbound"

    def test_disposition(self, parser):
        result = parser.parse(_make_gcp_event(disposition="ALLOWED"))
        assert result["metadata"]["disposition"] == "ALLOWED"

    def test_rule_priority(self, parser):
        result = parser.parse(_make_gcp_event(rule_priority=1000))
        assert result["metadata"]["rule_priority"] == 1000


class TestGCPInstance:
    """Tests for GCP instance metadata."""

    def test_vm_name(self, parser):
        result = parser.parse(_make_gcp_event(vm_name="my-vm"))
        assert result["metadata"]["instance_vm_name"] == "my-vm"

    def test_vm_project_id(self, parser):
        result = parser.parse(_make_gcp_event(vm_project_id="my-project"))
        assert result["metadata"]["instance_project_id"] == "my-project"

    def test_vm_region(self, parser):
        result = parser.parse(_make_gcp_event(vm_region="us-central1"))
        assert result["metadata"]["instance_region"] == "us-central1"

    def test_vpc_name(self, parser):
        result = parser.parse(_make_gcp_event(vpc_name="default"))
        assert result["metadata"]["vpc_name"] == "default"


class TestGCPRemoteLocation:
    """Tests for GCP remote location metadata."""

    def test_remote_country(self, parser):
        result = parser.parse(_make_gcp_event(remote_country="US"))
        assert result["metadata"]["remote_country"] == "US"

    def test_remote_region(self, parser):
        result = parser.parse(_make_gcp_event(remote_region="California"))
        assert result["metadata"]["remote_region"] == "California"

    def test_remote_city(self, parser):
        result = parser.parse(_make_gcp_event(remote_city="Los Angeles"))
        assert result["metadata"]["remote_city"] == "Los Angeles"


# ===========================================================================
# Azure Firewall tests
# ===========================================================================


class TestAzureBasicParsing:
    """Tests for Azure Firewall basic parsing."""

    def test_returns_dict(self, parser):
        result = parser.parse(_make_azure_event())
        assert isinstance(result, dict)

    def test_service_name(self, parser):
        result = parser.parse(_make_azure_event())
        assert result["service"] == "azure_firewall"

    def test_source_ip(self, parser):
        result = parser.parse(_make_azure_event(src_ip="10.0.0.4"))
        assert result["source_ip"] == "10.0.0.4"

    def test_destination_ip(self, parser):
        result = parser.parse(_make_azure_event(dest_ip="93.184.216.34"))
        assert result["destination_ip"] == "93.184.216.34"

    def test_action_allow(self, parser):
        result = parser.parse(_make_azure_event(action="Allow"))
        assert result["action"] == "firewall_allow"
        assert result["result"] == "allowed"

    def test_action_deny(self, parser):
        result = parser.parse(_make_azure_event(action="Deny"))
        assert result["action"] == "firewall_deny"
        assert result["result"] == "blocked"

    def test_action_drop(self, parser):
        result = parser.parse(_make_azure_event(action="Drop"))
        assert result["action"] == "firewall_drop"
        assert result["result"] == "blocked"

    def test_firewall_tag(self, parser):
        result = parser.parse(_make_azure_event())
        assert "firewall" in result["metadata"]["tags"]

    def test_cloud_provider(self, parser):
        result = parser.parse(_make_azure_event())
        assert result["metadata"]["cloud_provider"] == "azure"


class TestAzureMetadata:
    """Tests for Azure-specific metadata fields."""

    def test_source_port(self, parser):
        result = parser.parse(_make_azure_event(src_port="54321"))
        assert result["metadata"]["source_port"] == 54321

    def test_destination_port(self, parser):
        result = parser.parse(_make_azure_event(dest_port="443"))
        assert result["metadata"]["destination_port"] == 443

    def test_protocol(self, parser):
        result = parser.parse(_make_azure_event(protocol="TCP"))
        assert result["metadata"]["protocol"] == "TCP"

    def test_rule_collection(self, parser):
        result = parser.parse(_make_azure_event(rule_collection="AllowWeb"))
        assert result["metadata"]["rule_collection"] == "AllowWeb"

    def test_rule(self, parser):
        result = parser.parse(_make_azure_event(rule="AllowHTTPS"))
        assert result["metadata"]["rule"] == "AllowHTTPS"

    def test_firewall_rule_name_from_rule(self, parser):
        result = parser.parse(
            _make_azure_event(rule="AllowHTTPS", rule_collection="AllowWeb")
        )
        assert result["metadata"]["firewall_rule_name"] == "AllowHTTPS"

    def test_firewall_rule_name_fallback_to_collection(self, parser):
        result = parser.parse(
            _make_azure_event(rule="", rule_collection="AllowWeb")
        )
        assert result["metadata"]["firewall_rule_name"] == "AllowWeb"

    def test_policy(self, parser):
        result = parser.parse(_make_azure_event(policy="my-policy"))
        assert result["metadata"]["policy"] == "my-policy"

    def test_threat_intel(self, parser):
        result = parser.parse(
            _make_azure_event(threat_intel="Malware C2 Traffic")
        )
        assert result["metadata"]["threat_category"] == "Malware C2 Traffic"

    def test_threat_intel_empty_is_none(self, parser):
        result = parser.parse(_make_azure_event(threat_intel=""))
        assert result["metadata"]["threat_category"] is None

    def test_category(self, parser):
        result = parser.parse(
            _make_azure_event(category="AzureFirewallNetworkRule")
        )
        assert result["metadata"]["category"] == "AzureFirewallNetworkRule"


class TestAzureMsgParsing:
    """Tests for Azure Firewall msg string parsing."""

    def test_msg_extraction(self, parser):
        msg = "TCP request from 10.0.0.4:54321 to 93.184.216.34:443. Action: Allow. Rule Collection: AllowWeb. Rule: AllowHTTPS"
        event = _make_azure_event(
            src_ip="", dest_ip="", src_port="", dest_port="",
            protocol="", action="", rule_collection="", rule="",
            msg=msg,
        )
        result = parser.parse(event)
        assert result["source_ip"] == "10.0.0.4"
        assert result["metadata"]["source_port"] == 54321
        assert result["destination_ip"] == "93.184.216.34"
        assert result["metadata"]["destination_port"] == 443

    def test_msg_action_extraction(self, parser):
        msg = "TCP request from 10.0.0.4:54321 to 93.184.216.34:443. Action: Deny"
        event = _make_azure_event(
            src_ip="", dest_ip="", action="", msg=msg,
        )
        result = parser.parse(event)
        assert result["action"] == "firewall_deny"

    def test_structured_fields_take_precedence(self, parser):
        msg = "TCP request from 1.1.1.1:100 to 2.2.2.2:200. Action: Deny"
        event = _make_azure_event(
            src_ip="10.0.0.4", dest_ip="93.184.216.34", msg=msg,
        )
        result = parser.parse(event)
        # Structured fields should take precedence
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"


class TestAzureResourceId:
    """Tests for Azure Firewall resource ID parsing."""

    def test_full_resource_id(self, parser):
        result = parser.parse(_make_azure_event())
        assert result["metadata"]["subscription_id"] == "abc"
        assert result["metadata"]["resource_group"] == "rg"
        assert result["metadata"]["firewall_name"] == "my-fw"

    def test_empty_resource_id(self, parser):
        result = parser.parse(_make_azure_event(resource_id=""))
        assert result["metadata"]["subscription_id"] is None
        assert result["metadata"]["resource_group"] is None
        assert result["metadata"]["firewall_name"] is None


# ===========================================================================
# Cross-cloud normalised field tests
# ===========================================================================


class TestNormalisedAction:
    """Tests for action normalisation across clouds."""

    def test_aws_blocked(self):
        assert CloudFirewallParser._normalize_action("blocked") == "deny"

    def test_aws_allowed(self):
        assert CloudFirewallParser._normalize_action("allowed") == "allow"

    def test_aws_pass(self):
        assert CloudFirewallParser._normalize_action("pass") == "allow"

    def test_aws_drop(self):
        assert CloudFirewallParser._normalize_action("drop") == "drop"

    def test_aws_reject(self):
        assert CloudFirewallParser._normalize_action("reject") == "deny"

    def test_aws_alert(self):
        assert CloudFirewallParser._normalize_action("alert") == "alert"

    def test_gcp_allowed(self):
        assert CloudFirewallParser._normalize_action("ALLOWED") == "allow"

    def test_gcp_denied(self):
        assert CloudFirewallParser._normalize_action("DENIED") == "deny"

    def test_azure_allow(self):
        assert CloudFirewallParser._normalize_action("Allow") == "allow"

    def test_azure_deny(self):
        assert CloudFirewallParser._normalize_action("Deny") == "deny"

    def test_azure_drop(self):
        assert CloudFirewallParser._normalize_action("Drop") == "drop"

    def test_unknown(self):
        assert CloudFirewallParser._normalize_action("something") == "unknown"

    def test_empty(self):
        assert CloudFirewallParser._normalize_action("") == "unknown"

    def test_none(self):
        assert CloudFirewallParser._normalize_action(None) == "unknown"


class TestNormalisedDirection:
    """Tests for direction normalisation."""

    def test_egress(self):
        assert CloudFirewallParser._normalize_direction("EGRESS") == "outbound"

    def test_ingress(self):
        assert CloudFirewallParser._normalize_direction("INGRESS") == "inbound"

    def test_outbound(self):
        assert CloudFirewallParser._normalize_direction("outbound") == "outbound"

    def test_inbound(self):
        assert CloudFirewallParser._normalize_direction("inbound") == "inbound"

    def test_in(self):
        assert CloudFirewallParser._normalize_direction("in") == "inbound"

    def test_out(self):
        assert CloudFirewallParser._normalize_direction("out") == "outbound"

    def test_empty(self):
        assert CloudFirewallParser._normalize_direction("") is None

    def test_unknown(self):
        assert CloudFirewallParser._normalize_direction("lateral") is None


class TestDirectionInference:
    """Tests for direction inference from IPs."""

    def test_outbound(self):
        assert CloudFirewallParser._infer_direction(
            "10.0.0.4", "93.184.216.34"
        ) == "outbound"

    def test_inbound(self):
        assert CloudFirewallParser._infer_direction(
            "93.184.216.34", "10.0.0.4"
        ) == "inbound"

    def test_internal_both(self):
        assert CloudFirewallParser._infer_direction(
            "10.0.0.4", "10.0.0.5"
        ) is None

    def test_external_both(self):
        assert CloudFirewallParser._infer_direction(
            "8.8.8.8", "1.1.1.1"
        ) is None

    def test_empty_src(self):
        assert CloudFirewallParser._infer_direction("", "10.0.0.1") is None

    def test_empty_dest(self):
        assert CloudFirewallParser._infer_direction("10.0.0.1", "") is None


class TestProtocolResolution:
    """Tests for protocol number resolution."""

    def test_tcp(self):
        assert CloudFirewallParser._resolve_protocol(6) == "TCP"

    def test_udp(self):
        assert CloudFirewallParser._resolve_protocol(17) == "UDP"

    def test_icmp(self):
        assert CloudFirewallParser._resolve_protocol(1) == "ICMP"

    def test_gre(self):
        assert CloudFirewallParser._resolve_protocol(47) == "GRE"

    def test_unknown_number(self):
        assert CloudFirewallParser._resolve_protocol(999) == "PROTO999"

    def test_string_number(self):
        assert CloudFirewallParser._resolve_protocol("6") == "TCP"

    def test_string_name(self):
        assert CloudFirewallParser._resolve_protocol("tcp") == "TCP"

    def test_none(self):
        assert CloudFirewallParser._resolve_protocol(None) is None

    def test_empty_string(self):
        assert CloudFirewallParser._resolve_protocol("") is None


class TestInternalTraffic:
    """Tests for internal traffic detection."""

    def test_both_private(self):
        assert CloudFirewallParser._is_internal("10.0.0.1", "10.0.0.2") is True

    def test_src_private_dest_public(self):
        assert CloudFirewallParser._is_internal("10.0.0.1", "8.8.8.8") is False

    def test_both_public(self):
        assert CloudFirewallParser._is_internal("8.8.8.8", "1.1.1.1") is False

    def test_empty_src(self):
        assert CloudFirewallParser._is_internal("", "10.0.0.1") is False

    def test_empty_dest(self):
        assert CloudFirewallParser._is_internal("10.0.0.1", "") is False


class TestRFC1918:
    """Tests for RFC 1918 detection."""

    def test_10_network(self):
        assert CloudFirewallParser._is_rfc1918("10.0.0.1") is True

    def test_172_16(self):
        assert CloudFirewallParser._is_rfc1918("172.16.0.1") is True

    def test_192_168(self):
        assert CloudFirewallParser._is_rfc1918("192.168.1.1") is True

    def test_public(self):
        assert CloudFirewallParser._is_rfc1918("8.8.8.8") is False

    def test_172_15_not_private(self):
        assert CloudFirewallParser._is_rfc1918("172.15.0.1") is False


class TestSafeInt:
    """Tests for _safe_int helper."""

    def test_int(self):
        assert CloudFirewallParser._safe_int(42) == 42

    def test_string_number(self):
        assert CloudFirewallParser._safe_int("54321") == 54321

    def test_none(self):
        assert CloudFirewallParser._safe_int(None) is None

    def test_empty_string(self):
        assert CloudFirewallParser._safe_int("") is None

    def test_invalid(self):
        assert CloudFirewallParser._safe_int("abc") is None


class TestOutputSchema:
    """Verify the output matches ParsedEvent.to_dict() schema for all providers."""

    def _check_schema(self, result):
        required_keys = {
            "timestamp", "source_ip", "destination_ip", "user",
            "action", "result", "service", "raw_event", "metadata",
        }
        assert required_keys.issubset(result.keys())
        metadata = result["metadata"]
        normalised_keys = {
            "source_port", "destination_port", "protocol", "action",
            "firewall_rule_name", "direction", "threat_category",
            "is_internal", "cloud_provider", "tags",
        }
        assert normalised_keys.issubset(metadata.keys())

    def test_aws_schema(self, parser):
        self._check_schema(parser.parse(_make_aws_event()))

    def test_gcp_schema(self, parser):
        self._check_schema(parser.parse(_make_gcp_event()))

    def test_azure_schema(self, parser):
        self._check_schema(parser.parse(_make_azure_event()))


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_event_key_aws(self, parser):
        event = {"firewall_name": "fw"}
        result = parser.parse(event)
        assert isinstance(result, dict)
        assert result["service"] == "aws_network_firewall"

    def test_missing_json_payload_gcp(self, parser):
        event = {"jsonPayload": {"disposition": "ALLOWED"}}
        result = parser.parse(event)
        assert isinstance(result, dict)

    def test_non_dict_properties_azure(self, parser):
        event = {
            "category": "AzureFirewallNetworkRule",
            "properties": "not a dict",
        }
        result = parser.parse(event)
        assert isinstance(result, dict)

    def test_generic_fallback(self, parser):
        # Force generic parse by passing unrecognised event
        result = parser._parse_generic({"foo": "bar"})
        assert result["service"] == "cloud_firewall"
        assert result["action"] == "firewall_unknown"
        assert result["result"] == "unknown"

    def test_empty_aws_alert(self, parser):
        event = _make_aws_event(
            alert_action="", signature_id=None, signature="",
            alert_category="", alert_severity=None, event_type="flow",
        )
        result = parser.parse(event)
        assert result["action"] == "firewall_allow"

    def test_gcp_missing_connection(self, parser):
        event = {
            "jsonPayload": {"disposition": "DENIED"},
            "timestamp": "2025-06-15T10:00:00Z",
        }
        result = parser.parse(event)
        assert result["source_ip"] is None
        assert result["action"] == "firewall_deny"

    def test_azure_msg_only(self, parser):
        event = {
            "category": "AzureFirewallNetworkRule",
            "time": "2025-06-15T10:00:00Z",
            "properties": {
                "msg": "TCP request from 10.0.0.4:54321 to 93.184.216.34:443. Action: Allow",
            },
        }
        result = parser.parse(event)
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"


class TestFullIntegration:
    """End-to-end integration tests for each cloud provider."""

    def test_aws_alert_event(self, parser):
        event = _make_aws_event()
        result = parser.parse(event)
        assert result["action"] == "firewall_deny"
        assert result["result"] == "blocked"
        assert result["service"] == "aws_network_firewall"
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["metadata"]["source_port"] == 54321
        assert result["metadata"]["destination_port"] == 443
        assert result["metadata"]["protocol"] == "TCP"
        assert result["metadata"]["signature_id"] == 2024897
        assert result["metadata"]["threat_category"] == "A Network Trojan was Detected"
        assert result["metadata"]["cloud_provider"] == "aws"
        assert result["metadata"]["is_internal"] is False
        assert result["metadata"]["direction"] == "outbound"
        assert "firewall" in result["metadata"]["tags"]

    def test_gcp_allowed_event(self, parser):
        event = _make_gcp_event()
        result = parser.parse(event)
        assert result["action"] == "firewall_allow"
        assert result["result"] == "allowed"
        assert result["service"] == "gcp_vpc_firewall"
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["metadata"]["source_port"] == 54321
        assert result["metadata"]["destination_port"] == 443
        assert result["metadata"]["protocol"] == "TCP"
        assert result["metadata"]["firewall_rule_name"] == "network:default/allow-https"
        assert result["metadata"]["direction"] == "outbound"
        assert result["metadata"]["cloud_provider"] == "gcp"
        assert result["metadata"]["is_internal"] is False
        assert "firewall" in result["metadata"]["tags"]

    def test_gcp_denied_event(self, parser):
        event = _make_gcp_event(
            disposition="DENIED",
            rule_direction="INGRESS",
            rule_reference="network:default/deny-all",
            src_ip="93.184.216.34",
            dest_ip="10.0.0.4",
        )
        result = parser.parse(event)
        assert result["action"] == "firewall_deny"
        assert result["result"] == "blocked"
        assert result["metadata"]["direction"] == "inbound"

    def test_azure_allow_event(self, parser):
        event = _make_azure_event()
        result = parser.parse(event)
        assert result["action"] == "firewall_allow"
        assert result["result"] == "allowed"
        assert result["service"] == "azure_firewall"
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["metadata"]["source_port"] == 54321
        assert result["metadata"]["destination_port"] == 443
        assert result["metadata"]["protocol"] == "TCP"
        assert result["metadata"]["firewall_rule_name"] == "AllowHTTPS"
        assert result["metadata"]["rule_collection"] == "AllowWeb"
        assert result["metadata"]["cloud_provider"] == "azure"
        assert result["metadata"]["direction"] == "outbound"
        assert result["metadata"]["is_internal"] is False
        assert "firewall" in result["metadata"]["tags"]

    def test_azure_threat_intel_event(self, parser):
        event = _make_azure_event(
            action="Deny",
            threat_intel="Malware Command and Control",
        )
        result = parser.parse(event)
        assert result["action"] == "firewall_deny"
        assert result["metadata"]["threat_category"] == "Malware Command and Control"
