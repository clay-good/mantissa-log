"""Unit tests for Suricata EVE JSON Log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.suricata import (
    SuricataParser,
    _is_ip_address,
    _PROTOCOL_MAP,
    _SEVERITY_MAP,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return SuricataParser()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = "2024-06-15T10:00:00.000000+0000"


def _make_alert_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    proto="TCP",
    flow_id=1234567890,
    in_iface="eth0",
    alert_action="blocked",
    gid=1,
    signature_id=2024897,
    rev=1,
    signature="ET MALWARE Bad SSL Cert",
    category="A Network Trojan was Detected",
    severity=1,
    timestamp=_TS,
):
    """Build a synthetic Suricata alert event."""
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "in_iface": in_iface,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "action": alert_action,
            "gid": gid,
            "signature_id": signature_id,
            "rev": rev,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
    }


def _make_flow_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    proto="TCP",
    flow_id=1234567890,
    app_proto="tls",
    pkts_toserver=10,
    pkts_toclient=15,
    bytes_toserver=1024,
    bytes_toclient=4096,
    start="2024-06-15T09:59:00.000000+0000",
    end="2024-06-15T10:00:00.000000+0000",
    state="closed",
    reason="timeout",
    age=60,
    timestamp=_TS,
):
    """Build a synthetic Suricata flow event."""
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "app_proto": app_proto,
        "flow": {
            "pkts_toserver": pkts_toserver,
            "pkts_toclient": pkts_toclient,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "start": start,
            "end": end,
            "state": state,
            "reason": reason,
            "age": age,
        },
    }


def _make_dns_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="10.0.0.1",
    dest_port=53,
    flow_id=1234567890,
    dns_type="answer",
    rrname="example.com",
    rrtype="A",
    rdata="93.184.216.34",
    rcode="NOERROR",
    dns_id=12345,
    tx_id=0,
    answers=None,
    grouped=None,
    timestamp=_TS,
):
    """Build a synthetic Suricata DNS event."""
    dns = {
        "type": dns_type,
        "rrname": rrname,
        "rrtype": rrtype,
        "rdata": rdata,
        "rcode": rcode,
        "id": dns_id,
        "tx_id": tx_id,
    }
    if answers is not None:
        dns["answers"] = answers
    if grouped is not None:
        dns["grouped"] = grouped
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "dns",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "dns": dns,
    }


def _make_http_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=80,
    flow_id=1234567890,
    hostname="example.com",
    url="/index.html",
    http_user_agent="Mozilla/5.0",
    http_method="GET",
    protocol="HTTP/1.1",
    status=200,
    length=1234,
    http_content_type="text/html",
    http_refer="",
    timestamp=_TS,
):
    """Build a synthetic Suricata HTTP event."""
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "http",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "http": {
            "hostname": hostname,
            "url": url,
            "http_user_agent": http_user_agent,
            "http_method": http_method,
            "protocol": protocol,
            "status": status,
            "length": length,
            "http_content_type": http_content_type,
            "http_refer": http_refer,
        },
    }


def _make_tls_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    flow_id=1234567890,
    subject="CN=example.com",
    issuerdn="CN=Let's Encrypt,O=Let's Encrypt,C=US",
    serial="03:AB:CD:EF:01:23:45:67:89",
    fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
    sni="example.com",
    version="TLS 1.3",
    ja3_hash="e7d705a3286e19ea42f587b344ee6865",
    ja3_string="771,4865-4866-4867,0-23-65281,29-23-24,0",
    ja3s_hash="ec74a5c51106f0419184d0dd08fb22c5",
    ja3s_string="771,4865,23-65281",
    notbefore="2024-01-01T00:00:00",
    notafter="2025-01-01T00:00:00",
    timestamp=_TS,
):
    """Build a synthetic Suricata TLS event."""
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "tls",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "tls": {
            "subject": subject,
            "issuerdn": issuerdn,
            "serial": serial,
            "fingerprint": fingerprint,
            "sni": sni,
            "version": version,
            "notbefore": notbefore,
            "notafter": notafter,
            "ja3": {"hash": ja3_hash, "string": ja3_string},
            "ja3s": {"hash": ja3s_hash, "string": ja3s_string},
        },
    }


def _make_fileinfo_event(
    src_ip="93.184.216.34",
    src_port=80,
    dest_ip="10.0.0.4",
    dest_port=54321,
    flow_id=1234567890,
    app_proto="http",
    filename="malware.exe",
    size=1048576,
    state="CLOSED",
    md5="44d88612fea8a8f36de82e1278abb02f",
    sha1="",
    sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    magic="PE32 executable",
    stored=False,
    tx_id=0,
    gaps=False,
    timestamp=_TS,
):
    """Build a synthetic Suricata fileinfo event."""
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "event_type": "fileinfo",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "app_proto": app_proto,
        "fileinfo": {
            "filename": filename,
            "size": size,
            "state": state,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "magic": magic,
            "stored": stored,
            "tx_id": tx_id,
            "gaps": gaps,
        },
    }


# ===========================================================================
# Parser init
# ===========================================================================

class TestSuricataParserInit:
    """Initialization tests."""

    def test_source_type(self, parser):
        assert parser.source_type == "suricata"

    def test_instance_creation(self):
        p = SuricataParser()
        assert isinstance(p, SuricataParser)


# ===========================================================================
# Validation
# ===========================================================================

class TestValidation:
    """Validate method tests."""

    def test_valid_alert(self, parser):
        assert parser.validate(_make_alert_event()) is True

    def test_valid_flow(self, parser):
        assert parser.validate(_make_flow_event()) is True

    def test_valid_dns(self, parser):
        assert parser.validate(_make_dns_event()) is True

    def test_valid_http(self, parser):
        assert parser.validate(_make_http_event()) is True

    def test_valid_tls(self, parser):
        assert parser.validate(_make_tls_event()) is True

    def test_valid_fileinfo(self, parser):
        assert parser.validate(_make_fileinfo_event()) is True

    def test_invalid_no_event_type(self, parser):
        event = {"timestamp": _TS, "src_ip": "10.0.0.4"}
        assert parser.validate(event) is False

    def test_invalid_no_timestamp(self, parser):
        event = {"event_type": "alert", "src_ip": "10.0.0.4"}
        assert parser.validate(event) is False

    def test_invalid_not_dict(self, parser):
        assert parser.validate("not a dict") is False
        assert parser.validate(None) is False
        assert parser.validate(42) is False
        assert parser.validate([]) is False

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False

    def test_valid_unknown_event_type(self, parser):
        """Unknown event types still pass validation."""
        event = {"timestamp": _TS, "event_type": "stats"}
        assert parser.validate(event) is True


# ===========================================================================
# Event type detection
# ===========================================================================

class TestEventTypeDetection:
    """_detect_event_type tests."""

    def test_alert(self):
        assert SuricataParser._detect_event_type({"event_type": "alert"}) == "alert"

    def test_flow(self):
        assert SuricataParser._detect_event_type({"event_type": "flow"}) == "flow"

    def test_dns(self):
        assert SuricataParser._detect_event_type({"event_type": "dns"}) == "dns"

    def test_http(self):
        assert SuricataParser._detect_event_type({"event_type": "http"}) == "http"

    def test_tls(self):
        assert SuricataParser._detect_event_type({"event_type": "tls"}) == "tls"

    def test_fileinfo(self):
        assert SuricataParser._detect_event_type({"event_type": "fileinfo"}) == "fileinfo"

    def test_unknown(self):
        assert SuricataParser._detect_event_type({"event_type": "stats"}) == "stats"

    def test_empty(self):
        assert SuricataParser._detect_event_type({}) is None

    def test_empty_string(self):
        assert SuricataParser._detect_event_type({"event_type": ""}) is None


# ===========================================================================
# Alert parsing
# ===========================================================================

class TestAlertParsing:
    """Basic alert event parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_alert_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "suricata"
        assert result["metadata"]["suricata_event_type"] == "alert"

    def test_ports(self, parser):
        result = parser.parse(_make_alert_event())
        assert result["metadata"]["source_port"] == 54321
        assert result["metadata"]["destination_port"] == 443

    def test_protocol(self, parser):
        result = parser.parse(_make_alert_event(proto="TCP"))
        assert result["metadata"]["protocol"] == "TCP"

    def test_flow_id(self, parser):
        result = parser.parse(_make_alert_event(flow_id=999))
        assert result["metadata"]["flow_id"] == 999

    def test_in_iface(self, parser):
        result = parser.parse(_make_alert_event(in_iface="eth0"))
        assert result["metadata"]["in_iface"] == "eth0"

    def test_in_iface_empty(self, parser):
        result = parser.parse(_make_alert_event(in_iface=""))
        assert result["metadata"]["in_iface"] is None

    def test_tags(self, parser):
        result = parser.parse(_make_alert_event())
        assert result["metadata"]["tags"] == ["alert", "ids"]


class TestAlertDetails:
    """Alert-specific field parsing."""

    def test_signature_id(self, parser):
        result = parser.parse(_make_alert_event(signature_id=2024897))
        assert result["metadata"]["signature_id"] == 2024897

    def test_signature(self, parser):
        result = parser.parse(_make_alert_event(signature="ET MALWARE Bad SSL Cert"))
        assert result["metadata"]["signature"] == "ET MALWARE Bad SSL Cert"

    def test_category(self, parser):
        result = parser.parse(_make_alert_event(category="A Network Trojan was Detected"))
        assert result["metadata"]["category"] == "A Network Trojan was Detected"

    def test_gid(self, parser):
        result = parser.parse(_make_alert_event(gid=1))
        assert result["metadata"]["gid"] == 1

    def test_rev(self, parser):
        result = parser.parse(_make_alert_event(rev=3))
        assert result["metadata"]["rev"] == 3

    def test_empty_signature(self, parser):
        result = parser.parse(_make_alert_event(signature=""))
        assert result["metadata"]["signature"] is None

    def test_empty_category(self, parser):
        result = parser.parse(_make_alert_event(category=""))
        assert result["metadata"]["category"] is None


class TestAlertAction:
    """Alert action normalisation."""

    def test_blocked(self, parser):
        result = parser.parse(_make_alert_event(alert_action="blocked"))
        assert result["result"] == "blocked"
        assert result["metadata"]["alert_action"] == "blocked"
        assert result["action"] == "suricata_alert_blocked"

    def test_allowed(self, parser):
        result = parser.parse(_make_alert_event(alert_action="allowed"))
        assert result["result"] == "allowed"
        assert result["action"] == "suricata_alert_allowed"

    def test_drop(self, parser):
        result = parser.parse(_make_alert_event(alert_action="drop"))
        assert result["result"] == "blocked"
        assert result["action"] == "suricata_alert_drop"

    def test_empty_action(self, parser):
        result = parser.parse(_make_alert_event(alert_action=""))
        assert result["result"] == "alert"
        assert result["action"] == "suricata_alert"
        assert result["metadata"]["alert_action"] is None

    def test_unknown_action(self, parser):
        result = parser.parse(_make_alert_event(alert_action="custom"))
        assert result["result"] == "alert"
        assert result["action"] == "suricata_alert_custom"


class TestAlertSeverity:
    """Alert severity mapping."""

    def test_severity_1_critical(self, parser):
        result = parser.parse(_make_alert_event(severity=1))
        assert result["metadata"]["severity"] == 1
        assert result["metadata"]["severity_label"] == "critical"

    def test_severity_2_high(self, parser):
        result = parser.parse(_make_alert_event(severity=2))
        assert result["metadata"]["severity_label"] == "high"

    def test_severity_3_medium(self, parser):
        result = parser.parse(_make_alert_event(severity=3))
        assert result["metadata"]["severity_label"] == "medium"

    def test_severity_4_low(self, parser):
        result = parser.parse(_make_alert_event(severity=4))
        assert result["metadata"]["severity_label"] == "low"

    def test_severity_none(self, parser):
        result = parser.parse(_make_alert_event(severity=None))
        assert result["metadata"]["severity"] is None
        assert result["metadata"]["severity_label"] is None

    def test_severity_unknown(self, parser):
        result = parser.parse(_make_alert_event(severity=5))
        assert result["metadata"]["severity"] == 5
        assert result["metadata"]["severity_label"] is None

    def test_severity_map_complete(self):
        assert _SEVERITY_MAP == {1: "critical", 2: "high", 3: "medium", 4: "low"}


class TestAlertNonDictAlert:
    """Edge case: non-dict alert field."""

    def test_alert_not_dict(self, parser):
        event = _make_alert_event()
        event["alert"] = "not a dict"
        result = parser.parse(event)
        assert result["metadata"]["signature_id"] is None
        assert result["metadata"]["alert_action"] is None


# ===========================================================================
# Flow parsing
# ===========================================================================

class TestFlowParsing:
    """Basic flow event parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "suricata"
        assert result["metadata"]["suricata_event_type"] == "flow"

    def test_ports(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["source_port"] == 54321
        assert result["metadata"]["destination_port"] == 443

    def test_protocol(self, parser):
        result = parser.parse(_make_flow_event(proto="TCP"))
        assert result["metadata"]["protocol"] == "TCP"

    def test_app_proto(self, parser):
        result = parser.parse(_make_flow_event(app_proto="tls"))
        assert result["metadata"]["app_proto"] == "tls"

    def test_app_proto_empty(self, parser):
        result = parser.parse(_make_flow_event(app_proto=""))
        assert result["metadata"]["app_proto"] is None

    def test_tags(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["metadata"]["tags"] == ["network"]


class TestFlowStats:
    """Flow statistics."""

    def test_packet_counts(self, parser):
        result = parser.parse(_make_flow_event(pkts_toserver=10, pkts_toclient=15))
        assert result["metadata"]["pkts_toserver"] == 10
        assert result["metadata"]["pkts_toclient"] == 15
        assert result["metadata"]["packets_total"] == 25

    def test_byte_counts(self, parser):
        result = parser.parse(_make_flow_event(bytes_toserver=1024, bytes_toclient=4096))
        assert result["metadata"]["bytes_toserver"] == 1024
        assert result["metadata"]["bytes_toclient"] == 4096
        assert result["metadata"]["bytes_transferred"] == 5120

    def test_bytes_none(self, parser):
        result = parser.parse(_make_flow_event(bytes_toserver=None, bytes_toclient=None))
        assert result["metadata"]["bytes_transferred"] is None

    def test_packets_none(self, parser):
        result = parser.parse(_make_flow_event(pkts_toserver=None, pkts_toclient=None))
        assert result["metadata"]["packets_total"] is None


class TestFlowState:
    """Flow state and action."""

    def test_closed(self, parser):
        result = parser.parse(_make_flow_event(state="closed"))
        assert result["metadata"]["flow_state"] == "closed"
        assert result["action"] == "flow_closed"

    def test_new(self, parser):
        result = parser.parse(_make_flow_event(state="new"))
        assert result["action"] == "flow_new"

    def test_established(self, parser):
        result = parser.parse(_make_flow_event(state="established"))
        assert result["action"] == "flow_established"

    def test_empty_state(self, parser):
        result = parser.parse(_make_flow_event(state=""))
        assert result["metadata"]["flow_state"] is None
        assert result["action"] == "flow"

    def test_flow_reason(self, parser):
        result = parser.parse(_make_flow_event(reason="timeout"))
        assert result["metadata"]["flow_reason"] == "timeout"

    def test_result_always_success(self, parser):
        result = parser.parse(_make_flow_event())
        assert result["result"] == "success"


class TestFlowDuration:
    """Flow duration computation."""

    def test_duration_from_start_end(self, parser):
        result = parser.parse(_make_flow_event(
            start="2024-06-15T09:59:00.000000+0000",
            end="2024-06-15T10:00:00.000000+0000"
        ))
        assert result["metadata"]["duration_seconds"] == 60.0

    def test_duration_fallback_to_age(self, parser):
        result = parser.parse(_make_flow_event(start="", end="", age=120))
        assert result["metadata"]["duration_seconds"] == 120.0

    def test_duration_no_start_end_no_age(self, parser):
        result = parser.parse(_make_flow_event(start="", end="", age=None))
        assert result["metadata"]["duration_seconds"] is None

    def test_flow_start_end_timestamps(self, parser):
        result = parser.parse(_make_flow_event(
            start="2024-06-15T09:59:00.000000+0000",
            end="2024-06-15T10:00:00.000000+0000"
        ))
        assert result["metadata"]["flow_start"] == "2024-06-15T09:59:00.000000+0000"
        assert result["metadata"]["flow_end"] == "2024-06-15T10:00:00.000000+0000"


class TestFlowNonDictFlow:
    """Edge case: non-dict flow field."""

    def test_flow_not_dict(self, parser):
        event = _make_flow_event()
        event["flow"] = "not a dict"
        result = parser.parse(event)
        assert result["metadata"]["pkts_toserver"] is None
        assert result["metadata"]["bytes_transferred"] is None


# ===========================================================================
# DNS parsing
# ===========================================================================

class TestDNSParsing:
    """Basic DNS event parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "10.0.0.1"
        assert result["service"] == "suricata"
        assert result["metadata"]["suricata_event_type"] == "dns"

    def test_dns_type(self, parser):
        result = parser.parse(_make_dns_event(dns_type="answer"))
        assert result["metadata"]["dns_type"] == "answer"

    def test_query_name(self, parser):
        result = parser.parse(_make_dns_event(rrname="example.com."))
        assert result["metadata"]["query_name"] == "example.com"

    def test_query_type(self, parser):
        result = parser.parse(_make_dns_event(rrtype="AAAA"))
        assert result["metadata"]["query_type"] == "AAAA"

    def test_response_code(self, parser):
        result = parser.parse(_make_dns_event(rcode="NOERROR"))
        assert result["metadata"]["response_code"] == "NOERROR"

    def test_rdata(self, parser):
        result = parser.parse(_make_dns_event(rdata="93.184.216.34"))
        assert result["metadata"]["rdata"] == "93.184.216.34"

    def test_dns_id(self, parser):
        result = parser.parse(_make_dns_event(dns_id=12345))
        assert result["metadata"]["dns_id"] == 12345

    def test_tags(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["tags"] == ["dns"]


class TestDNSResult:
    """DNS result derivation."""

    def test_noerror_success(self, parser):
        result = parser.parse(_make_dns_event(rcode="NOERROR"))
        assert result["result"] == "success"

    def test_nxdomain_failure(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["result"] == "failure"

    def test_servfail_failure(self, parser):
        result = parser.parse(_make_dns_event(rcode="SERVFAIL"))
        assert result["result"] == "failure"

    def test_empty_rcode_answer_success(self, parser):
        result = parser.parse(_make_dns_event(dns_type="answer", rcode=""))
        assert result["result"] == "success"

    def test_empty_rcode_query_unknown(self, parser):
        result = parser.parse(_make_dns_event(dns_type="query", rcode=""))
        assert result["result"] == "unknown"


class TestDNSAction:
    """DNS action formatting."""

    def test_answer_a(self, parser):
        result = parser.parse(_make_dns_event(dns_type="answer", rrtype="A"))
        assert result["action"] == "dns_answer_a"

    def test_query_aaaa(self, parser):
        result = parser.parse(_make_dns_event(dns_type="query", rrtype="AAAA"))
        assert result["action"] == "dns_query_aaaa"

    def test_empty_type_rrtype(self, parser):
        result = parser.parse(_make_dns_event(dns_type="", rrtype="A"))
        assert result["action"] == "dns_query_a"

    def test_empty_rrtype(self, parser):
        result = parser.parse(_make_dns_event(dns_type="answer", rrtype=""))
        assert result["action"] == "dns_answer_query"


class TestDNSSubdomainAnalysis:
    """DNS subdomain entropy and count."""

    def test_simple_domain(self, parser):
        result = parser.parse(_make_dns_event(rrname="example.com"))
        assert result["metadata"]["subdomain_count"] == 2

    def test_subdomain(self, parser):
        result = parser.parse(_make_dns_event(rrname="mail.example.com"))
        assert result["metadata"]["subdomain_count"] == 3

    def test_high_entropy(self, parser):
        result = parser.parse(_make_dns_event(rrname="aB3kX9mQ.evil.com"))
        assert result["metadata"]["subdomain_entropy"] > 2.5

    def test_low_entropy(self, parser):
        result = parser.parse(_make_dns_event(rrname="www.example.com"))
        assert result["metadata"]["subdomain_entropy"] < 2.0

    def test_empty_rrname(self, parser):
        result = parser.parse(_make_dns_event(rrname=""))
        assert result["metadata"]["subdomain_count"] == 0
        assert result["metadata"]["subdomain_entropy"] == 0.0

    def test_domain_age_placeholder(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["domain_age_days"] is None


class TestDNSNXDomain:
    """NXDOMAIN detection."""

    def test_nxdomain(self, parser):
        result = parser.parse(_make_dns_event(rcode="NXDOMAIN"))
        assert result["metadata"]["is_nxdomain"] is True

    def test_not_nxdomain(self, parser):
        result = parser.parse(_make_dns_event(rcode="NOERROR"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_empty_rcode(self, parser):
        result = parser.parse(_make_dns_event(rcode=""))
        assert result["metadata"]["is_nxdomain"] is False


class TestDNSResolvedIPs:
    """DNS IP extraction."""

    def test_from_rdata(self, parser):
        result = parser.parse(_make_dns_event(rdata="93.184.216.34"))
        assert "93.184.216.34" in result["metadata"]["resolved_ips"]

    def test_from_answers(self, parser):
        answers = [
            {"rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"},
            {"rrname": "example.com", "rrtype": "A", "rdata": "10.0.0.5"},
        ]
        result = parser.parse(_make_dns_event(answers=answers, rdata=""))
        assert "93.184.216.34" in result["metadata"]["resolved_ips"]
        assert "10.0.0.5" in result["metadata"]["resolved_ips"]

    def test_from_grouped(self, parser):
        grouped = {"A": ["93.184.216.34", "10.0.0.5"], "AAAA": ["2001:db8::1"]}
        result = parser.parse(_make_dns_event(grouped=grouped, rdata=""))
        assert "93.184.216.34" in result["metadata"]["resolved_ips"]
        assert "2001:db8::1" in result["metadata"]["resolved_ips"]

    def test_non_ip_rdata(self, parser):
        result = parser.parse(_make_dns_event(rdata="cname.example.com"))
        assert result["metadata"]["resolved_ips"] == []

    def test_deduplication(self, parser):
        result = parser.parse(_make_dns_event(
            rdata="93.184.216.34",
            answers=[{"rdata": "93.184.216.34"}]
        ))
        assert result["metadata"]["resolved_ips"].count("93.184.216.34") == 1


class TestDNSExternalResolution:
    """DNS external resolution detection."""

    def test_external(self, parser):
        result = parser.parse(_make_dns_event(rdata="93.184.216.34"))
        assert result["metadata"]["is_external_resolution"] is True

    def test_internal(self, parser):
        result = parser.parse(_make_dns_event(rdata="10.0.0.5"))
        assert result["metadata"]["is_external_resolution"] is False

    def test_no_ips(self, parser):
        result = parser.parse(_make_dns_event(rdata=""))
        assert result["metadata"]["is_external_resolution"] is False


class TestDNSTransport:
    """DNS transport protocol detection."""

    def test_udp_53(self, parser):
        result = parser.parse(_make_dns_event(dest_port=53))
        assert result["metadata"]["transport"] == "UDP"

    def test_tcp_853(self, parser):
        result = parser.parse(_make_dns_event(dest_port=853))
        assert result["metadata"]["transport"] == "TCP"

    def test_other_port(self, parser):
        result = parser.parse(_make_dns_event(dest_port=5353))
        assert result["metadata"]["transport"] is None


class TestDNSNonDictDNS:
    """Edge case: non-dict dns field."""

    def test_dns_not_dict(self, parser):
        event = _make_dns_event()
        event["dns"] = "not a dict"
        result = parser.parse(event)
        assert result["metadata"]["query_name"] == ""
        assert result["metadata"]["dns_type"] is None


# ===========================================================================
# HTTP parsing
# ===========================================================================

class TestHTTPParsing:
    """Basic HTTP event parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_http_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "suricata"
        assert result["metadata"]["suricata_event_type"] == "http"

    def test_hostname(self, parser):
        result = parser.parse(_make_http_event(hostname="example.com"))
        assert result["metadata"]["http_hostname"] == "example.com"

    def test_url(self, parser):
        result = parser.parse(_make_http_event(url="/api/v1/users"))
        assert result["metadata"]["http_url"] == "/api/v1/users"

    def test_user_agent(self, parser):
        result = parser.parse(_make_http_event(http_user_agent="curl/7.68"))
        assert result["metadata"]["http_user_agent"] == "curl/7.68"

    def test_method(self, parser):
        result = parser.parse(_make_http_event(http_method="POST"))
        assert result["metadata"]["http_method"] == "POST"
        assert result["action"] == "http_post"

    def test_protocol(self, parser):
        result = parser.parse(_make_http_event(protocol="HTTP/1.1"))
        assert result["metadata"]["http_protocol"] == "HTTP/1.1"

    def test_status_200(self, parser):
        result = parser.parse(_make_http_event(status=200))
        assert result["metadata"]["http_status"] == 200
        assert result["result"] == "success"

    def test_status_404(self, parser):
        result = parser.parse(_make_http_event(status=404))
        assert result["result"] == "failure"

    def test_status_500(self, parser):
        result = parser.parse(_make_http_event(status=500))
        assert result["result"] == "failure"

    def test_status_none(self, parser):
        result = parser.parse(_make_http_event(status=None))
        assert result["result"] == "unknown"

    def test_length(self, parser):
        result = parser.parse(_make_http_event(length=1234))
        assert result["metadata"]["http_length"] == 1234

    def test_content_type(self, parser):
        result = parser.parse(_make_http_event(http_content_type="text/html"))
        assert result["metadata"]["http_content_type"] == "text/html"

    def test_referrer(self, parser):
        result = parser.parse(_make_http_event(http_refer="https://google.com"))
        assert result["metadata"]["http_refer"] == "https://google.com"

    def test_tags(self, parser):
        result = parser.parse(_make_http_event())
        assert result["metadata"]["tags"] == ["http"]

    def test_empty_method(self, parser):
        result = parser.parse(_make_http_event(http_method=""))
        assert result["action"] == "http_request"

    def test_empty_hostname(self, parser):
        result = parser.parse(_make_http_event(hostname=""))
        assert result["metadata"]["http_hostname"] is None

    def test_status_boundary_399(self, parser):
        result = parser.parse(_make_http_event(status=399))
        assert result["result"] == "success"

    def test_status_boundary_400(self, parser):
        result = parser.parse(_make_http_event(status=400))
        assert result["result"] == "failure"


class TestHTTPNonDictHTTP:
    """Edge case: non-dict http field."""

    def test_http_not_dict(self, parser):
        event = _make_http_event()
        event["http"] = "not a dict"
        result = parser.parse(event)
        assert result["metadata"]["http_hostname"] is None
        assert result["metadata"]["http_method"] is None


# ===========================================================================
# TLS parsing
# ===========================================================================

class TestTLSParsing:
    """Basic TLS event parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_tls_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "suricata"
        assert result["action"] == "tls_connection"
        assert result["result"] == "success"
        assert result["metadata"]["suricata_event_type"] == "tls"

    def test_subject(self, parser):
        result = parser.parse(_make_tls_event(subject="CN=example.com"))
        assert result["metadata"]["tls_subject"] == "CN=example.com"

    def test_issuerdn(self, parser):
        result = parser.parse(_make_tls_event(issuerdn="CN=Let's Encrypt"))
        assert result["metadata"]["tls_issuerdn"] == "CN=Let's Encrypt"

    def test_serial(self, parser):
        result = parser.parse(_make_tls_event(serial="03:AB:CD"))
        assert result["metadata"]["tls_serial"] == "03:AB:CD"

    def test_fingerprint(self, parser):
        result = parser.parse(_make_tls_event(fingerprint="aa:bb:cc"))
        assert result["metadata"]["tls_fingerprint"] == "aa:bb:cc"

    def test_sni(self, parser):
        result = parser.parse(_make_tls_event(sni="example.com"))
        assert result["metadata"]["tls_sni"] == "example.com"

    def test_version(self, parser):
        result = parser.parse(_make_tls_event(version="TLS 1.3"))
        assert result["metadata"]["tls_version"] == "TLS 1.3"

    def test_notbefore_notafter(self, parser):
        result = parser.parse(_make_tls_event(
            notbefore="2024-01-01T00:00:00",
            notafter="2025-01-01T00:00:00"
        ))
        assert result["metadata"]["tls_notbefore"] == "2024-01-01T00:00:00"
        assert result["metadata"]["tls_notafter"] == "2025-01-01T00:00:00"

    def test_tags(self, parser):
        result = parser.parse(_make_tls_event())
        assert result["metadata"]["tags"] == ["tls"]

    def test_empty_fields_are_none(self, parser):
        result = parser.parse(_make_tls_event(
            subject="", issuerdn="", serial="", fingerprint="",
            sni="", version=""
        ))
        assert result["metadata"]["tls_subject"] is None
        assert result["metadata"]["tls_issuerdn"] is None
        assert result["metadata"]["tls_serial"] is None
        assert result["metadata"]["tls_fingerprint"] is None
        assert result["metadata"]["tls_sni"] is None
        assert result["metadata"]["tls_version"] is None


class TestTLSJA3:
    """TLS JA3/JA3S fingerprint parsing."""

    def test_ja3_hash(self, parser):
        result = parser.parse(_make_tls_event(ja3_hash="e7d705a3286e19ea42f587b344ee6865"))
        assert result["metadata"]["ja3"] == "e7d705a3286e19ea42f587b344ee6865"

    def test_ja3_string(self, parser):
        result = parser.parse(_make_tls_event(
            ja3_string="771,4865-4866-4867,0-23-65281,29-23-24,0"
        ))
        assert result["metadata"]["ja3_string"] == "771,4865-4866-4867,0-23-65281,29-23-24,0"

    def test_ja3s_hash(self, parser):
        result = parser.parse(_make_tls_event(ja3s_hash="ec74a5c51106f0419184d0dd08fb22c5"))
        assert result["metadata"]["ja3s"] == "ec74a5c51106f0419184d0dd08fb22c5"

    def test_ja3s_string(self, parser):
        result = parser.parse(_make_tls_event(ja3s_string="771,4865,23-65281"))
        assert result["metadata"]["ja3s_string"] == "771,4865,23-65281"

    def test_ja3_flat_string(self, parser):
        """When ja3 is a flat string instead of a dict."""
        event = _make_tls_event()
        event["tls"]["ja3"] = "e7d705a3286e19ea42f587b344ee6865"
        result = parser.parse(event)
        assert result["metadata"]["ja3"] == "e7d705a3286e19ea42f587b344ee6865"

    def test_ja3s_flat_string(self, parser):
        """When ja3s is a flat string instead of a dict."""
        event = _make_tls_event()
        event["tls"]["ja3s"] = "ec74a5c51106f0419184d0dd08fb22c5"
        result = parser.parse(event)
        assert result["metadata"]["ja3s"] == "ec74a5c51106f0419184d0dd08fb22c5"

    def test_ja3_empty(self, parser):
        result = parser.parse(_make_tls_event(ja3_hash="", ja3s_hash=""))
        assert result["metadata"]["ja3"] is None
        assert result["metadata"]["ja3s"] is None


class TestTLSNonDictTLS:
    """Edge case: non-dict tls field."""

    def test_tls_not_dict(self, parser):
        event = _make_tls_event()
        event["tls"] = "not a dict"
        result = parser.parse(event)
        assert result["metadata"]["tls_subject"] is None
        assert result["metadata"]["ja3"] is None


# ===========================================================================
# Fileinfo parsing
# ===========================================================================

class TestFileinfoParsing:
    """Basic fileinfo event parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_fileinfo_event())
        assert result["source_ip"] == "93.184.216.34"
        assert result["destination_ip"] == "10.0.0.4"
        assert result["service"] == "suricata"
        assert result["action"] == "file_transfer"
        assert result["result"] == "success"
        assert result["metadata"]["suricata_event_type"] == "fileinfo"

    def test_filename(self, parser):
        result = parser.parse(_make_fileinfo_event(filename="malware.exe"))
        assert result["metadata"]["filename"] == "malware.exe"

    def test_size(self, parser):
        result = parser.parse(_make_fileinfo_event(size=1048576))
        assert result["metadata"]["file_size"] == 1048576

    def test_state(self, parser):
        result = parser.parse(_make_fileinfo_event(state="CLOSED"))
        assert result["metadata"]["file_state"] == "CLOSED"

    def test_hashes(self, parser):
        result = parser.parse(_make_fileinfo_event(
            md5="44d88612fea8a8f36de82e1278abb02f",
            sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        ))
        assert result["metadata"]["md5"] == "44d88612fea8a8f36de82e1278abb02f"
        assert result["metadata"]["sha256"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    def test_sha1(self, parser):
        result = parser.parse(_make_fileinfo_event(sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709"))
        assert result["metadata"]["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_magic(self, parser):
        result = parser.parse(_make_fileinfo_event(magic="PE32 executable"))
        assert result["metadata"]["file_magic"] == "PE32 executable"

    def test_app_proto(self, parser):
        result = parser.parse(_make_fileinfo_event(app_proto="http"))
        assert result["metadata"]["app_proto"] == "http"

    def test_stored(self, parser):
        result = parser.parse(_make_fileinfo_event(stored=True))
        assert result["metadata"]["stored"] is True

    def test_tx_id(self, parser):
        result = parser.parse(_make_fileinfo_event(tx_id=5))
        assert result["metadata"]["tx_id"] == 5

    def test_gaps(self, parser):
        result = parser.parse(_make_fileinfo_event(gaps=True))
        assert result["metadata"]["gaps"] is True

    def test_tags(self, parser):
        result = parser.parse(_make_fileinfo_event())
        assert result["metadata"]["tags"] == ["file"]

    def test_empty_filename(self, parser):
        result = parser.parse(_make_fileinfo_event(filename=""))
        assert result["metadata"]["filename"] is None

    def test_empty_hashes(self, parser):
        result = parser.parse(_make_fileinfo_event(md5="", sha1="", sha256=""))
        assert result["metadata"]["md5"] is None
        assert result["metadata"]["sha1"] is None
        assert result["metadata"]["sha256"] is None

    def test_empty_magic(self, parser):
        result = parser.parse(_make_fileinfo_event(magic=""))
        assert result["metadata"]["file_magic"] is None


class TestFileinfoNonDictFileinfo:
    """Edge case: non-dict fileinfo field."""

    def test_fileinfo_not_dict(self, parser):
        event = _make_fileinfo_event()
        event["fileinfo"] = "not a dict"
        result = parser.parse(event)
        assert result["metadata"]["filename"] is None
        assert result["metadata"]["md5"] is None


# ===========================================================================
# Generic / fallback parsing
# ===========================================================================

class TestGenericParsing:
    """Generic fallback parsing for unknown event types."""

    def test_stats_event(self, parser):
        event = {
            "timestamp": _TS,
            "event_type": "stats",
            "src_ip": "10.0.0.4",
            "dest_ip": "93.184.216.34",
            "flow_id": 123,
        }
        result = parser.parse(event)
        assert result["metadata"]["suricata_event_type"] == "stats"
        assert result["action"] == "suricata_stats"
        assert result["result"] == "unknown"
        assert result["metadata"]["tags"] == ["network"]

    def test_none_event_type(self, parser):
        event = {"timestamp": _TS, "event_type": ""}
        result = parser.parse(event)
        assert result["action"] == "suricata_unknown"


# ===========================================================================
# Timestamp parsing
# ===========================================================================

class TestTimestampParsing:
    """_parse_suricata_timestamp tests."""

    def test_suricata_format(self):
        dt = SuricataParser._parse_suricata_timestamp("2024-06-15T10:00:00.000000+0000")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 6
        assert dt.day == 15
        assert dt.hour == 10
        assert dt.tzinfo is not None

    def test_iso8601_z(self):
        dt = SuricataParser._parse_suricata_timestamp("2024-06-15T10:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_iso8601_offset(self):
        dt = SuricataParser._parse_suricata_timestamp("2024-06-15T10:00:00+00:00")
        assert dt is not None

    def test_iso8601_no_tz(self):
        dt = SuricataParser._parse_suricata_timestamp("2024-06-15T10:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_float_epoch(self):
        dt = SuricataParser._parse_suricata_timestamp(1718442000.0)
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_int_epoch(self):
        dt = SuricataParser._parse_suricata_timestamp(1718442000)
        assert dt is not None

    def test_string_epoch(self):
        dt = SuricataParser._parse_suricata_timestamp("1718442000")
        assert dt is not None

    def test_none(self):
        assert SuricataParser._parse_suricata_timestamp(None) is None

    def test_invalid_string(self):
        assert SuricataParser._parse_suricata_timestamp("not_a_timestamp") is None

    def test_negative_offset(self):
        dt = SuricataParser._parse_suricata_timestamp("2024-06-15T10:00:00.000000-0500")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_event_timestamp(self, parser):
        result = parser.parse(_make_alert_event())
        assert result["timestamp"] is not None
        ts = datetime.fromisoformat(result["timestamp"])
        assert ts.year == 2024


# ===========================================================================
# Protocol normalisation
# ===========================================================================

class TestProtocolNormalisation:
    """_normalise_protocol tests."""

    def test_tcp_string(self):
        assert SuricataParser._normalise_protocol("TCP") == "TCP"

    def test_tcp_lower(self):
        assert SuricataParser._normalise_protocol("tcp") == "TCP"

    def test_numeric_6(self):
        assert SuricataParser._normalise_protocol("6") == "TCP"

    def test_numeric_17(self):
        assert SuricataParser._normalise_protocol("17") == "UDP"

    def test_numeric_1(self):
        assert SuricataParser._normalise_protocol("1") == "ICMP"

    def test_none(self):
        assert SuricataParser._normalise_protocol(None) is None

    def test_empty(self):
        assert SuricataParser._normalise_protocol("") is None

    def test_unknown_proto(self):
        assert SuricataParser._normalise_protocol("sctp") == "SCTP"

    def test_protocol_map_complete(self):
        assert _PROTOCOL_MAP == {
            "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE",
            "50": "ESP", "51": "AH", "58": "ICMPv6", "132": "SCTP",
        }


# ===========================================================================
# Compute duration
# ===========================================================================

class TestComputeDuration:
    """_compute_duration tests."""

    def test_valid_duration(self):
        d = SuricataParser._compute_duration(
            "2024-06-15T09:59:00.000000+0000",
            "2024-06-15T10:00:00.000000+0000"
        )
        assert d == 60.0

    def test_zero_duration(self):
        d = SuricataParser._compute_duration(
            "2024-06-15T10:00:00.000000+0000",
            "2024-06-15T10:00:00.000000+0000"
        )
        assert d == 0.0

    def test_empty_start(self):
        assert SuricataParser._compute_duration("", "2024-06-15T10:00:00+0000") is None

    def test_empty_end(self):
        assert SuricataParser._compute_duration("2024-06-15T10:00:00+0000", "") is None

    def test_both_empty(self):
        assert SuricataParser._compute_duration("", "") is None

    def test_negative_duration(self):
        """End before start should return None."""
        d = SuricataParser._compute_duration(
            "2024-06-15T10:00:00.000000+0000",
            "2024-06-15T09:59:00.000000+0000"
        )
        assert d is None


# ===========================================================================
# RFC 1918 and internal traffic helpers
# ===========================================================================

class TestRFC1918:
    """RFC 1918 private address detection."""

    def test_10_network(self):
        assert SuricataParser._is_rfc1918("10.0.0.1") is True

    def test_172_network(self):
        assert SuricataParser._is_rfc1918("172.16.0.1") is True

    def test_172_non_private(self):
        assert SuricataParser._is_rfc1918("172.15.0.1") is False

    def test_192_network(self):
        assert SuricataParser._is_rfc1918("192.168.0.1") is True

    def test_public_ip(self):
        assert SuricataParser._is_rfc1918("93.184.216.34") is False

    def test_empty(self):
        assert SuricataParser._is_rfc1918("") is False


class TestInternalTraffic:
    """Internal traffic detection."""

    def test_both_internal(self):
        assert SuricataParser._is_internal("10.0.0.4", "192.168.1.1") is True

    def test_one_external(self):
        assert SuricataParser._is_internal("10.0.0.4", "93.184.216.34") is False

    def test_empty_src(self):
        assert SuricataParser._is_internal("", "10.0.0.4") is False


class TestDirectionInference:
    """Direction inference from IP addresses."""

    def test_outbound(self):
        assert SuricataParser._infer_direction("10.0.0.4", "93.184.216.34") == "outbound"

    def test_inbound(self):
        assert SuricataParser._infer_direction("93.184.216.34", "10.0.0.4") == "inbound"

    def test_both_private(self):
        assert SuricataParser._infer_direction("10.0.0.4", "192.168.1.1") is None

    def test_both_public(self):
        assert SuricataParser._infer_direction("8.8.8.8", "93.184.216.34") is None

    def test_empty(self):
        assert SuricataParser._infer_direction("", "10.0.0.4") is None


# ===========================================================================
# Safe int helper
# ===========================================================================

class TestSafeInt:
    """_safe_int helper tests."""

    def test_int(self):
        assert SuricataParser._safe_int(42) == 42

    def test_float(self):
        assert SuricataParser._safe_int(42.9) == 42

    def test_string(self):
        assert SuricataParser._safe_int("42") == 42

    def test_none(self):
        assert SuricataParser._safe_int(None) is None

    def test_empty(self):
        assert SuricataParser._safe_int("") is None

    def test_invalid(self):
        assert SuricataParser._safe_int("abc") is None


# ===========================================================================
# Module-level _is_ip_address
# ===========================================================================

class TestIsIPAddress:
    """_is_ip_address module-level helper tests."""

    def test_ipv4(self):
        assert _is_ip_address("10.0.0.1") is True
        assert _is_ip_address("93.184.216.34") is True

    def test_ipv6(self):
        assert _is_ip_address("2001:db8::1") is True
        assert _is_ip_address("::1") is True

    def test_not_ip(self):
        assert _is_ip_address("example.com") is False
        assert _is_ip_address("not-an-ip") is False

    def test_empty(self):
        assert _is_ip_address("") is False


# ===========================================================================
# Strip trailing dot
# ===========================================================================

class TestStripTrailingDot:
    """_strip_trailing_dot helper tests."""

    def test_with_dot(self):
        assert SuricataParser._strip_trailing_dot("example.com.") == "example.com"

    def test_without_dot(self):
        assert SuricataParser._strip_trailing_dot("example.com") == "example.com"

    def test_empty(self):
        assert SuricataParser._strip_trailing_dot("") == ""


# ===========================================================================
# Output schema
# ===========================================================================

class TestOutputSchema:
    """Verify output conforms to ParsedEvent.to_dict() shape."""

    REQUIRED_TOP_KEYS = {"timestamp", "source_ip", "destination_ip", "user",
                         "action", "result", "service", "raw_event", "metadata"}

    def test_alert_schema(self, parser):
        result = parser.parse(_make_alert_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)
        assert result["service"] == "suricata"

    def test_flow_schema(self, parser):
        result = parser.parse(_make_flow_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())

    def test_dns_schema(self, parser):
        result = parser.parse(_make_dns_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())

    def test_http_schema(self, parser):
        result = parser.parse(_make_http_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())

    def test_tls_schema(self, parser):
        result = parser.parse(_make_tls_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())

    def test_fileinfo_schema(self, parser):
        result = parser.parse(_make_fileinfo_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge cases and boundary tests."""

    def test_empty_ips(self, parser):
        result = parser.parse(_make_alert_event(src_ip="", dest_ip=""))
        assert result["source_ip"] is None
        assert result["destination_ip"] is None

    def test_raw_event_preserved(self, parser):
        event = _make_alert_event()
        result = parser.parse(event)
        assert result["raw_event"] == event

    def test_flow_zero_bytes(self, parser):
        result = parser.parse(_make_flow_event(bytes_toserver=0, bytes_toclient=0))
        assert result["metadata"]["bytes_transferred"] == 0

    def test_flow_large_bytes(self, parser):
        result = parser.parse(_make_flow_event(
            bytes_toserver=10**12, bytes_toclient=10**12
        ))
        assert result["metadata"]["bytes_transferred"] == 2 * 10**12

    def test_http_status_boundary_200(self, parser):
        result = parser.parse(_make_http_event(status=200))
        assert result["result"] == "success"

    def test_none_timestamp_defaults_to_now(self, parser):
        event = _make_alert_event(timestamp=None)
        event["timestamp"] = None
        result = parser.parse(event)
        assert result["timestamp"] is not None


# ===========================================================================
# Full integration tests
# ===========================================================================

class TestFullIntegration:
    """End-to-end integration tests with realistic Suricata events."""

    def test_malware_alert(self, parser):
        """IDS alert for malware detection."""
        event = {
            "timestamp": "2024-06-15T10:00:00.000000+0000",
            "flow_id": 1234567890,
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "gid": 1,
                "signature_id": 2024897,
                "rev": 1,
                "signature": "ET MALWARE Bad SSL Cert",
                "category": "A Network Trojan was Detected",
                "severity": 1,
            },
        }
        result = parser.parse(event)
        assert result["result"] == "blocked"
        assert result["metadata"]["severity_label"] == "critical"
        assert result["metadata"]["signature"] == "ET MALWARE Bad SSL Cert"
        assert result["metadata"]["direction"] == "outbound"
        assert result["metadata"]["tags"] == ["alert", "ids"]

    def test_dns_exfil_indicator(self, parser):
        """DNS query with high-entropy subdomain suggesting exfiltration."""
        event = {
            "timestamp": "2024-06-15T10:00:00.000000+0000",
            "flow_id": 9876543210,
            "event_type": "dns",
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "10.0.0.1",
            "dest_port": 53,
            "dns": {
                "type": "query",
                "rrname": "aB3kX9mQzW7nP4jL.evil.com",
                "rrtype": "TXT",
                "rcode": "",
                "id": 99999,
                "tx_id": 0,
            },
        }
        result = parser.parse(event)
        assert result["metadata"]["subdomain_entropy"] > 3.0
        assert result["metadata"]["subdomain_count"] == 3
        assert result["action"] == "dns_query_txt"

    def test_tls_c2_indicator(self, parser):
        """TLS connection with JA3 fingerprint for C2 detection."""
        event = {
            "timestamp": "2024-06-15T10:00:00.000000+0000",
            "flow_id": 1234567890,
            "event_type": "tls",
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "198.51.100.1",
            "dest_port": 443,
            "tls": {
                "subject": "CN=suspicious.example.com",
                "issuerdn": "CN=suspicious.example.com",
                "serial": "01",
                "fingerprint": "aa:bb:cc",
                "sni": "suspicious.example.com",
                "version": "TLS 1.2",
                "ja3": {"hash": "e7d705a3286e19ea42f587b344ee6865", "string": "771,4865"},
                "ja3s": {"hash": "ec74a5c51106f0419184d0dd08fb22c5", "string": "771,4865"},
            },
        }
        result = parser.parse(event)
        assert result["metadata"]["ja3"] == "e7d705a3286e19ea42f587b344ee6865"
        assert result["metadata"]["ja3s"] == "ec74a5c51106f0419184d0dd08fb22c5"
        assert result["metadata"]["tls_sni"] == "suspicious.example.com"
        assert result["metadata"]["tls_subject"] == result["metadata"]["tls_issuerdn"]

    def test_http_exfil(self, parser):
        """HTTP POST with large body to external host."""
        event = {
            "timestamp": "2024-06-15T10:00:00.000000+0000",
            "flow_id": 1234567890,
            "event_type": "http",
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "198.51.100.1",
            "dest_port": 443,
            "http": {
                "hostname": "upload.suspicious.com",
                "url": "/upload",
                "http_user_agent": "Python-urllib/3.11",
                "http_method": "POST",
                "protocol": "HTTP/1.1",
                "status": 200,
                "length": 10485760,
                "http_content_type": "application/octet-stream",
                "http_refer": "",
            },
        }
        result = parser.parse(event)
        assert result["action"] == "http_post"
        assert result["metadata"]["http_length"] == 10485760
        assert result["metadata"]["direction"] == "outbound"

    def test_file_download(self, parser):
        """Fileinfo event for executable download."""
        event = {
            "timestamp": "2024-06-15T10:00:00.000000+0000",
            "flow_id": 1234567890,
            "event_type": "fileinfo",
            "src_ip": "198.51.100.1",
            "src_port": 80,
            "dest_ip": "10.0.0.4",
            "dest_port": 54321,
            "app_proto": "http",
            "fileinfo": {
                "filename": "update.exe",
                "size": 2097152,
                "state": "CLOSED",
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "sha1": "",
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "magic": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly",
                "stored": True,
                "tx_id": 0,
                "gaps": False,
            },
        }
        result = parser.parse(event)
        assert result["action"] == "file_transfer"
        assert result["metadata"]["filename"] == "update.exe"
        assert result["metadata"]["file_magic"] == "PE32 executable (GUI) Intel 80386 Mono/.Net assembly"
        assert result["metadata"]["md5"] == "44d88612fea8a8f36de82e1278abb02f"
        assert result["metadata"]["direction"] == "inbound"

    def test_flow_summary(self, parser):
        """Flow event with full stats."""
        event = {
            "timestamp": "2024-06-15T10:00:00.000000+0000",
            "flow_id": 1234567890,
            "event_type": "flow",
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "flow": {
                "pkts_toserver": 100,
                "pkts_toclient": 150,
                "bytes_toserver": 10240,
                "bytes_toclient": 409600,
                "start": "2024-06-15T09:50:00.000000+0000",
                "end": "2024-06-15T10:00:00.000000+0000",
                "state": "closed",
                "reason": "timeout",
                "age": 600,
            },
        }
        result = parser.parse(event)
        assert result["metadata"]["bytes_transferred"] == 419840
        assert result["metadata"]["packets_total"] == 250
        assert result["metadata"]["duration_seconds"] == 600.0
        assert result["metadata"]["app_proto"] == "tls"
        assert result["action"] == "flow_closed"
