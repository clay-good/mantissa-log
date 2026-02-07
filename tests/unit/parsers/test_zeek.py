"""Unit tests for Zeek (formerly Bro) JSON Log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.zeek import ZeekParser, CONN_STATE_MAP, _RFC1918_RE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Create parser instance."""
    return ZeekParser()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conn_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    proto="tcp",
    service="ssl",
    duration=1.234,
    orig_bytes=1024,
    resp_bytes=4096,
    orig_pkts=10,
    resp_pkts=15,
    conn_state="SF",
    missed_bytes=0,
    history="ShADadFf",
    uid="CYFva94d3gVj3SXXX",
    ts=1718442000.000000,
    path="conn",
):
    """Build a synthetic Zeek conn.log event."""
    event = {"ts": ts, "uid": uid}
    if path is not None:
        event["_path"] = path
    event["id.orig_h"] = src_ip
    event["id.orig_p"] = src_port
    event["id.resp_h"] = dest_ip
    event["id.resp_p"] = dest_port
    event["proto"] = proto
    event["service"] = service
    event["duration"] = duration
    event["orig_bytes"] = orig_bytes
    event["resp_bytes"] = resp_bytes
    event["orig_pkts"] = orig_pkts
    event["resp_pkts"] = resp_pkts
    event["conn_state"] = conn_state
    event["missed_bytes"] = missed_bytes
    event["history"] = history
    return event


def _make_dns_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="10.0.0.1",
    dest_port=53,
    query="example.com",
    qtype_name="A",
    rcode_name="NOERROR",
    answers=None,
    rejected=False,
    ttls=None,
    trans_id=12345,
    uid="CYFva94d3gVj3SXXX",
    ts=1718442000.000000,
    path="dns",
):
    """Build a synthetic Zeek dns.log event."""
    event = {"ts": ts, "uid": uid}
    if path is not None:
        event["_path"] = path
    event["id.orig_h"] = src_ip
    event["id.orig_p"] = src_port
    event["id.resp_h"] = dest_ip
    event["id.resp_p"] = dest_port
    event["query"] = query
    event["qtype_name"] = qtype_name
    event["rcode_name"] = rcode_name
    event["answers"] = answers if answers is not None else []
    event["rejected"] = rejected
    event["TTLs"] = ttls if ttls is not None else []
    event["trans_id"] = trans_id
    return event


def _make_http_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=80,
    method="GET",
    host="example.com",
    uri="/index.html",
    user_agent="Mozilla/5.0",
    request_body_len=0,
    response_body_len=1234,
    status_code=200,
    resp_mime_types=None,
    referrer="",
    username="",
    password="",
    uid="CYFva94d3gVj3SXXX",
    ts=1718442000.000000,
    path="http",
):
    """Build a synthetic Zeek http.log event."""
    event = {"ts": ts, "uid": uid}
    if path is not None:
        event["_path"] = path
    event["id.orig_h"] = src_ip
    event["id.orig_p"] = src_port
    event["id.resp_h"] = dest_ip
    event["id.resp_p"] = dest_port
    event["method"] = method
    event["host"] = host
    event["uri"] = uri
    event["user_agent"] = user_agent
    event["request_body_len"] = request_body_len
    event["response_body_len"] = response_body_len
    event["status_code"] = status_code
    event["resp_mime_types"] = resp_mime_types if resp_mime_types is not None else []
    event["referrer"] = referrer
    event["username"] = username
    event["password"] = password
    return event


def _make_ssl_event(
    src_ip="10.0.0.4",
    src_port=54321,
    dest_ip="93.184.216.34",
    dest_port=443,
    version="TLSv13",
    server_name="example.com",
    subject="CN=example.com",
    issuer="CN=Let's Encrypt,O=Let's Encrypt,C=US",
    ja3="e7d705a3286e19ea42f587b344ee6865",
    ja3s="ec74a5c51106f0419184d0dd08fb22c5",
    established=True,
    validation_status="ok",
    cipher="TLS_AES_256_GCM_SHA384",
    curve="x25519",
    resumed=False,
    next_protocol="h2",
    uid="CYFva94d3gVj3SXXX",
    ts=1718442000.000000,
    path="ssl",
):
    """Build a synthetic Zeek ssl.log event."""
    event = {"ts": ts, "uid": uid}
    if path is not None:
        event["_path"] = path
    event["id.orig_h"] = src_ip
    event["id.orig_p"] = src_port
    event["id.resp_h"] = dest_ip
    event["id.resp_p"] = dest_port
    event["version"] = version
    event["server_name"] = server_name
    event["subject"] = subject
    event["issuer"] = issuer
    event["ja3"] = ja3
    event["ja3s"] = ja3s
    event["established"] = established
    event["validation_status"] = validation_status
    event["cipher"] = cipher
    event["curve"] = curve
    event["resumed"] = resumed
    event["next_protocol"] = next_protocol
    return event


def _make_files_event(
    fuid="FGhfj24bkl3SF",
    source="HTTP",
    mime_type="application/pdf",
    filename="report.pdf",
    total_bytes=51200,
    md5="d41d8cd98f00b204e9800998ecf8427e",
    sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    is_orig=False,
    conn_uids=None,
    tx_hosts=None,
    rx_hosts=None,
    ts=1718442000.000000,
    path="files",
):
    """Build a synthetic Zeek files.log event."""
    event = {"ts": ts}
    if path is not None:
        event["_path"] = path
    event["fuid"] = fuid
    event["source"] = source
    event["mime_type"] = mime_type
    event["filename"] = filename
    event["total_bytes"] = total_bytes
    event["md5"] = md5
    event["sha1"] = sha1
    event["sha256"] = sha256
    event["is_orig"] = is_orig
    event["conn_uids"] = conn_uids if conn_uids is not None else ["CYFva94d3gVj3SXXX"]
    event["tx_hosts"] = tx_hosts if tx_hosts is not None else ["93.184.216.34"]
    event["rx_hosts"] = rx_hosts if rx_hosts is not None else ["10.0.0.4"]
    return event


def _make_notice_event(
    note="Scan::Port_Scan",
    msg="10.0.0.4 scanned at least 15 unique ports of host 93.184.216.34",
    sub="",
    src="10.0.0.4",
    dst="93.184.216.34",
    p=443,
    actions=None,
    suppress_for=3600.0,
    uid="CYFva94d3gVj3SXXX",
    ts=1718442000.000000,
    path="notice",
):
    """Build a synthetic Zeek notice.log event."""
    event = {"ts": ts, "uid": uid}
    if path is not None:
        event["_path"] = path
    event["note"] = note
    event["msg"] = msg
    event["sub"] = sub
    event["src"] = src
    event["dst"] = dst
    event["p"] = p
    event["actions"] = actions if actions is not None else ["Notice::ACTION_LOG"]
    event["suppress_for"] = suppress_for
    return event


# ===========================================================================
# Parser init
# ===========================================================================

class TestZeekParserInit:
    """Initialization tests."""

    def test_source_type(self, parser):
        assert parser.source_type == "zeek"

    def test_instance_creation(self):
        p = ZeekParser()
        assert isinstance(p, ZeekParser)


# ===========================================================================
# Validation
# ===========================================================================

class TestValidation:
    """Validate method tests."""

    def test_valid_conn_event(self, parser):
        assert parser.validate(_make_conn_event()) is True

    def test_valid_dns_event(self, parser):
        assert parser.validate(_make_dns_event()) is True

    def test_valid_http_event(self, parser):
        assert parser.validate(_make_http_event()) is True

    def test_valid_ssl_event(self, parser):
        assert parser.validate(_make_ssl_event()) is True

    def test_valid_files_event(self, parser):
        assert parser.validate(_make_files_event()) is True

    def test_valid_notice_event(self, parser):
        assert parser.validate(_make_notice_event()) is True

    def test_invalid_no_ts(self, parser):
        event = _make_conn_event()
        del event["ts"]
        assert parser.validate(event) is False

    def test_invalid_not_dict(self, parser):
        assert parser.validate("not a dict") is False
        assert parser.validate(None) is False
        assert parser.validate(42) is False
        assert parser.validate([]) is False

    def test_valid_with_path_only(self, parser):
        event = {"ts": 1718442000.0, "_path": "conn"}
        assert parser.validate(event) is True

    def test_valid_with_uid_only(self, parser):
        event = {"ts": 1718442000.0, "uid": "abc123"}
        assert parser.validate(event) is True

    def test_valid_with_orig_h(self, parser):
        event = {"ts": 1718442000.0, "id.orig_h": "10.0.0.1"}
        assert parser.validate(event) is True

    def test_valid_with_resp_h(self, parser):
        event = {"ts": 1718442000.0, "id.resp_h": "10.0.0.1"}
        assert parser.validate(event) is True

    def test_valid_with_zeek_field_conn_state(self, parser):
        event = {"ts": 1718442000.0, "conn_state": "SF"}
        assert parser.validate(event) is True

    def test_valid_with_zeek_field_query(self, parser):
        event = {"ts": 1718442000.0, "query": "example.com"}
        assert parser.validate(event) is True

    def test_valid_with_zeek_field_server_name(self, parser):
        event = {"ts": 1718442000.0, "server_name": "example.com"}
        assert parser.validate(event) is True

    def test_valid_with_zeek_field_ja3(self, parser):
        event = {"ts": 1718442000.0, "ja3": "e7d705a3286e19ea42f587b344ee6865"}
        assert parser.validate(event) is True

    def test_valid_with_zeek_field_fuid(self, parser):
        event = {"ts": 1718442000.0, "fuid": "FGhfj24bkl3SF"}
        assert parser.validate(event) is True

    def test_valid_with_zeek_field_note(self, parser):
        event = {"ts": 1718442000.0, "note": "Scan::Port_Scan"}
        assert parser.validate(event) is True

    def test_invalid_ts_only(self, parser):
        event = {"ts": 1718442000.0}
        assert parser.validate(event) is False

    def test_invalid_empty_dict(self, parser):
        assert parser.validate({}) is False


# ===========================================================================
# Log type detection
# ===========================================================================

class TestLogTypeDetection:
    """_detect_log_type tests."""

    def test_detect_from_path_conn(self):
        assert ZeekParser._detect_log_type({"_path": "conn"}) == "conn"

    def test_detect_from_path_dns(self):
        assert ZeekParser._detect_log_type({"_path": "dns"}) == "dns"

    def test_detect_from_path_http(self):
        assert ZeekParser._detect_log_type({"_path": "http"}) == "http"

    def test_detect_from_path_ssl(self):
        assert ZeekParser._detect_log_type({"_path": "ssl"}) == "ssl"

    def test_detect_from_path_files(self):
        assert ZeekParser._detect_log_type({"_path": "files"}) == "files"

    def test_detect_from_path_notice(self):
        assert ZeekParser._detect_log_type({"_path": "notice"}) == "notice"

    def test_detect_conn_from_fields(self):
        assert ZeekParser._detect_log_type({"conn_state": "SF"}) == "conn"

    def test_detect_conn_from_history(self):
        assert ZeekParser._detect_log_type({"history": "ShADadFf"}) == "conn"

    def test_detect_dns_from_fields(self):
        assert ZeekParser._detect_log_type({"query": "x.com", "qtype_name": "A"}) == "dns"

    def test_detect_http_from_fields(self):
        assert ZeekParser._detect_log_type({"method": "GET", "uri": "/"}) == "http"

    def test_detect_ssl_from_server_name(self):
        assert ZeekParser._detect_log_type({"server_name": "example.com"}) == "ssl"

    def test_detect_ssl_from_ja3(self):
        assert ZeekParser._detect_log_type({"ja3": "abc123"}) == "ssl"

    def test_detect_files_from_fields(self):
        assert ZeekParser._detect_log_type({"fuid": "F1", "mime_type": "text/plain"}) == "files"

    def test_detect_notice_from_fields(self):
        assert ZeekParser._detect_log_type({"note": "Scan::Port_Scan", "msg": "scan"}) == "notice"

    def test_detect_unknown_path_fallback(self):
        """Non-standard _path values should be returned as-is."""
        assert ZeekParser._detect_log_type({"_path": "weird"}) == "weird"

    def test_detect_empty(self):
        assert ZeekParser._detect_log_type({}) is None

    def test_detect_path_priority_over_fields(self):
        """_path should take priority over field inference."""
        event = {"_path": "dns", "conn_state": "SF"}
        assert ZeekParser._detect_log_type(event) == "dns"

    def test_detect_dns_needs_both_fields(self):
        """DNS detection requires both query AND qtype_name."""
        assert ZeekParser._detect_log_type({"query": "x.com"}) is None


# ===========================================================================
# conn.log parsing
# ===========================================================================

class TestConnParsing:
    """Basic conn.log parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_conn_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "zeek"
        assert result["result"] == "success"
        assert result["metadata"]["zeek_log_type"] == "conn"

    def test_ports(self, parser):
        result = parser.parse(_make_conn_event())
        assert result["metadata"]["source_port"] == 54321
        assert result["metadata"]["destination_port"] == 443

    def test_protocol(self, parser):
        result = parser.parse(_make_conn_event(proto="tcp"))
        assert result["metadata"]["protocol"] == "TCP"

    def test_protocol_empty(self, parser):
        result = parser.parse(_make_conn_event(proto=""))
        assert result["metadata"]["protocol"] is None

    def test_duration(self, parser):
        result = parser.parse(_make_conn_event(duration=1.234))
        assert result["metadata"]["duration_seconds"] == 1.234

    def test_bytes(self, parser):
        result = parser.parse(_make_conn_event(orig_bytes=1024, resp_bytes=4096))
        assert result["metadata"]["orig_bytes"] == 1024
        assert result["metadata"]["resp_bytes"] == 4096
        assert result["metadata"]["bytes_transferred"] == 5120

    def test_bytes_none(self, parser):
        result = parser.parse(_make_conn_event(orig_bytes=None, resp_bytes=None))
        assert result["metadata"]["bytes_transferred"] is None

    def test_packets(self, parser):
        result = parser.parse(_make_conn_event(orig_pkts=10, resp_pkts=15))
        assert result["metadata"]["orig_pkts"] == 10
        assert result["metadata"]["resp_pkts"] == 15

    def test_uid(self, parser):
        result = parser.parse(_make_conn_event(uid="CYFva94d"))
        assert result["metadata"]["uid"] == "CYFva94d"

    def test_uid_empty(self, parser):
        result = parser.parse(_make_conn_event(uid=""))
        assert result["metadata"]["uid"] is None

    def test_service_field(self, parser):
        result = parser.parse(_make_conn_event(service="ssl"))
        assert result["metadata"]["detected_service"] == "ssl"

    def test_service_empty(self, parser):
        result = parser.parse(_make_conn_event(service=""))
        assert result["metadata"]["detected_service"] is None

    def test_missed_bytes(self, parser):
        result = parser.parse(_make_conn_event(missed_bytes=100))
        assert result["metadata"]["missed_bytes"] == 100

    def test_history(self, parser):
        result = parser.parse(_make_conn_event(history="ShADadFf"))
        assert result["metadata"]["history"] == "ShADadFf"

    def test_tags(self, parser):
        result = parser.parse(_make_conn_event())
        assert result["metadata"]["tags"] == ["network"]


class TestConnState:
    """Connection state mapping and result derivation."""

    def test_sf_normal_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="SF"))
        assert result["metadata"]["conn_state"] == "SF"
        assert result["metadata"]["conn_state_meaning"] == "normal"
        assert result["result"] == "success"
        assert result["action"] == "connection_sf"

    def test_s0_failure(self, parser):
        result = parser.parse(_make_conn_event(conn_state="S0"))
        assert result["metadata"]["conn_state_meaning"] == "syn_no_reply"
        assert result["result"] == "failure"

    def test_rej_failure(self, parser):
        result = parser.parse(_make_conn_event(conn_state="REJ"))
        assert result["metadata"]["conn_state_meaning"] == "rejected"
        assert result["result"] == "failure"

    def test_rsto_failure(self, parser):
        result = parser.parse(_make_conn_event(conn_state="RSTO"))
        assert result["metadata"]["conn_state_meaning"] == "reset_originator"
        assert result["result"] == "failure"

    def test_rstr_failure(self, parser):
        result = parser.parse(_make_conn_event(conn_state="RSTR"))
        assert result["metadata"]["conn_state_meaning"] == "reset_responder"
        assert result["result"] == "failure"

    def test_rstos0_failure(self, parser):
        result = parser.parse(_make_conn_event(conn_state="RSTOS0"))
        assert result["metadata"]["conn_state_meaning"] == "reset_originator_syn"
        assert result["result"] == "failure"

    def test_rstrh_failure(self, parser):
        result = parser.parse(_make_conn_event(conn_state="RSTRH"))
        assert result["metadata"]["conn_state_meaning"] == "reset_responder_established"
        assert result["result"] == "failure"

    def test_s1_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="S1"))
        assert result["metadata"]["conn_state_meaning"] == "established_no_reply"
        assert result["result"] == "success"

    def test_s2_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="S2"))
        assert result["metadata"]["conn_state_meaning"] == "established_originator_close"
        assert result["result"] == "success"

    def test_s3_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="S3"))
        assert result["metadata"]["conn_state_meaning"] == "established_responder_close"
        assert result["result"] == "success"

    def test_sh_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="SH"))
        assert result["metadata"]["conn_state_meaning"] == "syn_ack_no_fin"
        assert result["result"] == "success"

    def test_shr_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="SHR"))
        assert result["metadata"]["conn_state_meaning"] == "syn_ack_rejected"
        assert result["result"] == "success"

    def test_oth_success(self, parser):
        result = parser.parse(_make_conn_event(conn_state="OTH"))
        assert result["metadata"]["conn_state_meaning"] == "midstream"
        assert result["result"] == "success"

    def test_unknown_state(self, parser):
        result = parser.parse(_make_conn_event(conn_state="UNKNOWN"))
        assert result["metadata"]["conn_state"] == "UNKNOWN"
        assert result["metadata"]["conn_state_meaning"] is None
        assert result["result"] == "success"

    def test_empty_state(self, parser):
        result = parser.parse(_make_conn_event(conn_state=""))
        assert result["metadata"]["conn_state"] is None
        assert result["action"] == "connection"

    def test_all_conn_states_mapped(self):
        """Verify all CONN_STATE_MAP entries exist."""
        expected = {"S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR",
                    "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
        assert set(CONN_STATE_MAP.keys()) == expected


class TestConnDirection:
    """Direction inference for conn.log."""

    def test_outbound(self, parser):
        result = parser.parse(_make_conn_event(src_ip="10.0.0.4", dest_ip="93.184.216.34"))
        assert result["metadata"]["direction"] == "outbound"

    def test_inbound(self, parser):
        result = parser.parse(_make_conn_event(src_ip="93.184.216.34", dest_ip="10.0.0.4"))
        assert result["metadata"]["direction"] == "inbound"

    def test_internal(self, parser):
        result = parser.parse(_make_conn_event(src_ip="10.0.0.4", dest_ip="192.168.1.1"))
        assert result["metadata"]["direction"] is None
        assert result["metadata"]["is_internal"] is True

    def test_external(self, parser):
        result = parser.parse(_make_conn_event(src_ip="8.8.8.8", dest_ip="93.184.216.34"))
        assert result["metadata"]["direction"] is None
        assert result["metadata"]["is_internal"] is False


# ===========================================================================
# dns.log parsing
# ===========================================================================

class TestDNSParsing:
    """Basic dns.log parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "10.0.0.1"
        assert result["service"] == "zeek"
        assert result["result"] == "success"
        assert result["metadata"]["zeek_log_type"] == "dns"

    def test_query_name(self, parser):
        result = parser.parse(_make_dns_event(query="example.com."))
        assert result["metadata"]["query_name"] == "example.com"

    def test_query_type(self, parser):
        result = parser.parse(_make_dns_event(qtype_name="AAAA"))
        assert result["metadata"]["query_type"] == "AAAA"
        assert result["action"] == "dns_query_aaaa"

    def test_response_code(self, parser):
        result = parser.parse(_make_dns_event(rcode_name="NOERROR"))
        assert result["metadata"]["response_code"] == "NOERROR"

    def test_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=["93.184.216.34", "10.0.0.5"]))
        assert result["metadata"]["answers"] == ["93.184.216.34", "10.0.0.5"]

    def test_ttls(self, parser):
        result = parser.parse(_make_dns_event(ttls=[300, 600]))
        assert result["metadata"]["ttls"] == [300, 600]

    def test_trans_id(self, parser):
        result = parser.parse(_make_dns_event(trans_id=12345))
        assert result["metadata"]["trans_id"] == 12345

    def test_rejected_true(self, parser):
        result = parser.parse(_make_dns_event(rejected=True))
        assert result["metadata"]["rejected"] is True
        assert result["result"] == "failure"

    def test_rejected_false_noerror(self, parser):
        result = parser.parse(_make_dns_event(rejected=False, rcode_name="NOERROR"))
        assert result["result"] == "success"

    def test_nxdomain(self, parser):
        result = parser.parse(_make_dns_event(rcode_name="NXDOMAIN"))
        assert result["metadata"]["is_nxdomain"] is True
        assert result["result"] == "failure"

    def test_not_nxdomain(self, parser):
        result = parser.parse(_make_dns_event(rcode_name="NOERROR"))
        assert result["metadata"]["is_nxdomain"] is False

    def test_empty_rcode(self, parser):
        result = parser.parse(_make_dns_event(rcode_name=""))
        assert result["metadata"]["is_nxdomain"] is False
        assert result["result"] == "unknown"

    def test_tags(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["tags"] == ["dns"]

    def test_action_with_qtype(self, parser):
        result = parser.parse(_make_dns_event(qtype_name="MX"))
        assert result["action"] == "dns_query_mx"

    def test_action_empty_qtype(self, parser):
        result = parser.parse(_make_dns_event(qtype_name=""))
        assert result["action"] == "dns_query"


class TestDNSSubdomainAnalysis:
    """DNS subdomain entropy and count."""

    def test_simple_domain(self, parser):
        result = parser.parse(_make_dns_event(query="example.com"))
        assert result["metadata"]["subdomain_count"] == 2

    def test_subdomain_domain(self, parser):
        result = parser.parse(_make_dns_event(query="mail.example.com"))
        assert result["metadata"]["subdomain_count"] == 3

    def test_deep_subdomain(self, parser):
        result = parser.parse(_make_dns_event(query="a.b.c.d.example.com"))
        assert result["metadata"]["subdomain_count"] == 6

    def test_single_label(self, parser):
        result = parser.parse(_make_dns_event(query="localhost"))
        assert result["metadata"]["subdomain_count"] == 1

    def test_entropy_random_label(self, parser):
        result = parser.parse(_make_dns_event(query="aB3kX9mQ.evil.com"))
        assert result["metadata"]["subdomain_entropy"] > 2.5

    def test_entropy_simple_label(self, parser):
        result = parser.parse(_make_dns_event(query="www.example.com"))
        assert result["metadata"]["subdomain_entropy"] < 2.0

    def test_empty_query(self, parser):
        result = parser.parse(_make_dns_event(query=""))
        assert result["metadata"]["subdomain_count"] == 0
        assert result["metadata"]["subdomain_entropy"] == 0.0

    def test_trailing_dot_stripped(self, parser):
        result = parser.parse(_make_dns_event(query="example.com."))
        assert result["metadata"]["query_name"] == "example.com"
        assert result["metadata"]["subdomain_count"] == 2

    def test_domain_age_placeholder(self, parser):
        result = parser.parse(_make_dns_event())
        assert result["metadata"]["domain_age_days"] is None


class TestDNSResolvedIPs:
    """DNS IP extraction from answers."""

    def test_ipv4_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=["93.184.216.34", "10.0.0.5"]))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34", "10.0.0.5"]

    def test_ipv6_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=["2606:2800:220:1:248:1893:25c8:1946"]))
        assert result["metadata"]["resolved_ips"] == ["2606:2800:220:1:248:1893:25c8:1946"]

    def test_mixed_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=["93.184.216.34", "www.example.com"]))
        assert result["metadata"]["resolved_ips"] == ["93.184.216.34"]

    def test_cname_only(self, parser):
        result = parser.parse(_make_dns_event(answers=["www.example.com"]))
        assert result["metadata"]["resolved_ips"] == []

    def test_empty_answers(self, parser):
        result = parser.parse(_make_dns_event(answers=[]))
        assert result["metadata"]["resolved_ips"] == []

    def test_duplicate_ips(self, parser):
        result = parser.parse(_make_dns_event(answers=["10.0.0.1", "10.0.0.1"]))
        assert result["metadata"]["resolved_ips"] == ["10.0.0.1"]

    def test_non_list_answers(self, parser):
        result = parser.parse(_make_dns_event(answers="10.0.0.1"))
        assert result["metadata"]["resolved_ips"] == []

    def test_non_string_entries(self, parser):
        result = parser.parse(_make_dns_event(answers=[123, None, "10.0.0.1"]))
        assert result["metadata"]["resolved_ips"] == ["10.0.0.1"]


class TestDNSExternalResolution:
    """DNS external resolution detection."""

    def test_external_ip(self, parser):
        result = parser.parse(_make_dns_event(answers=["93.184.216.34"]))
        assert result["metadata"]["is_external_resolution"] is True

    def test_internal_ip(self, parser):
        result = parser.parse(_make_dns_event(answers=["10.0.0.1"]))
        assert result["metadata"]["is_external_resolution"] is False

    def test_mixed_external_internal(self, parser):
        result = parser.parse(_make_dns_event(answers=["10.0.0.1", "93.184.216.34"]))
        assert result["metadata"]["is_external_resolution"] is True

    def test_no_resolved_ips(self, parser):
        result = parser.parse(_make_dns_event(answers=[]))
        assert result["metadata"]["is_external_resolution"] is False

    def test_172_private(self, parser):
        result = parser.parse(_make_dns_event(answers=["172.16.0.1"]))
        assert result["metadata"]["is_external_resolution"] is False

    def test_192_private(self, parser):
        result = parser.parse(_make_dns_event(answers=["192.168.1.1"]))
        assert result["metadata"]["is_external_resolution"] is False


class TestDNSTransport:
    """DNS transport protocol detection."""

    def test_udp_port_53(self, parser):
        result = parser.parse(_make_dns_event(dest_port=53))
        assert result["metadata"]["transport"] == "UDP"

    def test_tcp_port_853(self, parser):
        result = parser.parse(_make_dns_event(dest_port=853))
        assert result["metadata"]["transport"] == "TCP"

    def test_other_port(self, parser):
        result = parser.parse(_make_dns_event(dest_port=5353))
        assert result["metadata"]["transport"] is None


# ===========================================================================
# http.log parsing
# ===========================================================================

class TestHTTPParsing:
    """Basic http.log parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_http_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "zeek"
        assert result["metadata"]["zeek_log_type"] == "http"

    def test_method(self, parser):
        result = parser.parse(_make_http_event(method="POST"))
        assert result["metadata"]["http_method"] == "POST"
        assert result["action"] == "http_post"

    def test_host(self, parser):
        result = parser.parse(_make_http_event(host="example.com"))
        assert result["metadata"]["http_host"] == "example.com"

    def test_uri(self, parser):
        result = parser.parse(_make_http_event(uri="/api/v1/users"))
        assert result["metadata"]["http_uri"] == "/api/v1/users"

    def test_user_agent(self, parser):
        result = parser.parse(_make_http_event(user_agent="curl/7.68"))
        assert result["metadata"]["http_user_agent"] == "curl/7.68"

    def test_status_code_200(self, parser):
        result = parser.parse(_make_http_event(status_code=200))
        assert result["metadata"]["http_status_code"] == 200
        assert result["result"] == "success"

    def test_status_code_301(self, parser):
        result = parser.parse(_make_http_event(status_code=301))
        assert result["result"] == "success"

    def test_status_code_404(self, parser):
        result = parser.parse(_make_http_event(status_code=404))
        assert result["result"] == "failure"

    def test_status_code_500(self, parser):
        result = parser.parse(_make_http_event(status_code=500))
        assert result["result"] == "failure"

    def test_status_code_none(self, parser):
        result = parser.parse(_make_http_event(status_code=None))
        assert result["metadata"]["http_status_code"] is None
        assert result["result"] == "unknown"

    def test_body_lengths(self, parser):
        result = parser.parse(_make_http_event(request_body_len=512, response_body_len=1024))
        assert result["metadata"]["request_body_len"] == 512
        assert result["metadata"]["response_body_len"] == 1024

    def test_resp_mime_types(self, parser):
        result = parser.parse(_make_http_event(resp_mime_types=["text/html"]))
        assert result["metadata"]["resp_mime_types"] == ["text/html"]

    def test_resp_mime_types_empty(self, parser):
        result = parser.parse(_make_http_event(resp_mime_types=[]))
        assert result["metadata"]["resp_mime_types"] is None

    def test_referrer(self, parser):
        result = parser.parse(_make_http_event(referrer="https://google.com"))
        assert result["metadata"]["http_referrer"] == "https://google.com"

    def test_referrer_empty(self, parser):
        result = parser.parse(_make_http_event(referrer=""))
        assert result["metadata"]["http_referrer"] is None

    def test_tags(self, parser):
        result = parser.parse(_make_http_event())
        assert result["metadata"]["tags"] == ["http"]

    def test_action_empty_method(self, parser):
        result = parser.parse(_make_http_event(method=""))
        assert result["action"] == "http_request"
        assert result["metadata"]["http_method"] is None

    def test_direction(self, parser):
        result = parser.parse(_make_http_event(src_ip="10.0.0.4", dest_ip="93.184.216.34"))
        assert result["metadata"]["direction"] == "outbound"

    def test_is_internal(self, parser):
        result = parser.parse(_make_http_event(src_ip="10.0.0.4", dest_ip="10.0.0.5"))
        assert result["metadata"]["is_internal"] is True


class TestHTTPCredentials:
    """HTTP credential detection."""

    def test_has_username(self, parser):
        result = parser.parse(_make_http_event(username="admin"))
        assert result["metadata"]["username"] == "admin"
        assert result["metadata"]["has_credentials"] is True
        assert result["user"] == "admin"

    def test_has_password_only(self, parser):
        result = parser.parse(_make_http_event(password="secret"))
        assert result["metadata"]["has_credentials"] is True

    def test_no_credentials(self, parser):
        result = parser.parse(_make_http_event(username="", password=""))
        assert result["metadata"]["has_credentials"] is False
        assert result["user"] is None


# ===========================================================================
# ssl.log parsing
# ===========================================================================

class TestSSLParsing:
    """Basic ssl.log parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_ssl_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "zeek"
        assert result["action"] == "tls_connection"
        assert result["metadata"]["zeek_log_type"] == "ssl"

    def test_tls_version(self, parser):
        result = parser.parse(_make_ssl_event(version="TLSv13"))
        assert result["metadata"]["tls_version"] == "TLSv13"

    def test_server_name(self, parser):
        result = parser.parse(_make_ssl_event(server_name="example.com"))
        assert result["metadata"]["server_name"] == "example.com"

    def test_subject_issuer(self, parser):
        result = parser.parse(_make_ssl_event(
            subject="CN=example.com",
            issuer="CN=Let's Encrypt"
        ))
        assert result["metadata"]["subject"] == "CN=example.com"
        assert result["metadata"]["issuer"] == "CN=Let's Encrypt"

    def test_ja3_fingerprints(self, parser):
        result = parser.parse(_make_ssl_event(
            ja3="e7d705a3286e19ea42f587b344ee6865",
            ja3s="ec74a5c51106f0419184d0dd08fb22c5"
        ))
        assert result["metadata"]["ja3"] == "e7d705a3286e19ea42f587b344ee6865"
        assert result["metadata"]["ja3s"] == "ec74a5c51106f0419184d0dd08fb22c5"

    def test_established_true(self, parser):
        result = parser.parse(_make_ssl_event(established=True))
        assert result["metadata"]["established"] is True
        assert result["result"] == "success"

    def test_established_false(self, parser):
        result = parser.parse(_make_ssl_event(established=False))
        assert result["metadata"]["established"] is False
        assert result["result"] == "failure"

    def test_established_none(self, parser):
        result = parser.parse(_make_ssl_event(established=None))
        assert result["metadata"]["established"] is None
        assert result["result"] == "unknown"

    def test_validation_status(self, parser):
        result = parser.parse(_make_ssl_event(validation_status="ok"))
        assert result["metadata"]["validation_status"] == "ok"

    def test_cipher(self, parser):
        result = parser.parse(_make_ssl_event(cipher="TLS_AES_256_GCM_SHA384"))
        assert result["metadata"]["cipher"] == "TLS_AES_256_GCM_SHA384"

    def test_curve(self, parser):
        result = parser.parse(_make_ssl_event(curve="x25519"))
        assert result["metadata"]["curve"] == "x25519"

    def test_resumed(self, parser):
        result = parser.parse(_make_ssl_event(resumed=True))
        assert result["metadata"]["resumed"] is True

    def test_next_protocol(self, parser):
        result = parser.parse(_make_ssl_event(next_protocol="h2"))
        assert result["metadata"]["next_protocol"] == "h2"

    def test_tags(self, parser):
        result = parser.parse(_make_ssl_event())
        assert result["metadata"]["tags"] == ["tls"]

    def test_empty_fields_are_none(self, parser):
        result = parser.parse(_make_ssl_event(
            version="", server_name="", subject="", issuer="",
            ja3="", ja3s="", validation_status="", cipher="", curve="",
            next_protocol=""
        ))
        assert result["metadata"]["tls_version"] is None
        assert result["metadata"]["server_name"] is None
        assert result["metadata"]["subject"] is None
        assert result["metadata"]["issuer"] is None
        assert result["metadata"]["ja3"] is None
        assert result["metadata"]["ja3s"] is None
        assert result["metadata"]["validation_status"] is None
        assert result["metadata"]["cipher"] is None
        assert result["metadata"]["curve"] is None
        assert result["metadata"]["next_protocol"] is None

    def test_direction(self, parser):
        result = parser.parse(_make_ssl_event(src_ip="10.0.0.4", dest_ip="93.184.216.34"))
        assert result["metadata"]["direction"] == "outbound"


# ===========================================================================
# files.log parsing
# ===========================================================================

class TestFilesParsing:
    """Basic files.log parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_files_event())
        assert result["service"] == "zeek"
        assert result["action"] == "file_transfer"
        assert result["result"] == "success"
        assert result["metadata"]["zeek_log_type"] == "files"

    def test_fuid(self, parser):
        result = parser.parse(_make_files_event(fuid="FGhfj24bkl3SF"))
        assert result["metadata"]["fuid"] == "FGhfj24bkl3SF"

    def test_source(self, parser):
        result = parser.parse(_make_files_event(source="HTTP"))
        assert result["metadata"]["file_source"] == "HTTP"

    def test_mime_type(self, parser):
        result = parser.parse(_make_files_event(mime_type="application/pdf"))
        assert result["metadata"]["mime_type"] == "application/pdf"

    def test_filename(self, parser):
        result = parser.parse(_make_files_event(filename="report.pdf"))
        assert result["metadata"]["filename"] == "report.pdf"

    def test_total_bytes(self, parser):
        result = parser.parse(_make_files_event(total_bytes=51200))
        assert result["metadata"]["total_bytes"] == 51200

    def test_hashes(self, parser):
        result = parser.parse(_make_files_event(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ))
        assert result["metadata"]["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert result["metadata"]["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert result["metadata"]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_is_orig(self, parser):
        result = parser.parse(_make_files_event(is_orig=True))
        assert result["metadata"]["is_orig"] is True

    def test_conn_uids(self, parser):
        result = parser.parse(_make_files_event(conn_uids=["CYFva94d", "CZ9va94d"]))
        assert result["metadata"]["conn_uids"] == ["CYFva94d", "CZ9va94d"]

    def test_conn_uids_empty(self, parser):
        result = parser.parse(_make_files_event(conn_uids=[]))
        assert result["metadata"]["conn_uids"] is None

    def test_source_ip_from_tx_hosts(self, parser):
        result = parser.parse(_make_files_event(tx_hosts=["93.184.216.34"]))
        assert result["source_ip"] == "93.184.216.34"

    def test_dest_ip_from_rx_hosts(self, parser):
        result = parser.parse(_make_files_event(rx_hosts=["10.0.0.4"]))
        assert result["destination_ip"] == "10.0.0.4"

    def test_no_hosts(self, parser):
        result = parser.parse(_make_files_event(tx_hosts=[], rx_hosts=[]))
        assert result["source_ip"] is None
        assert result["destination_ip"] is None

    def test_tags(self, parser):
        result = parser.parse(_make_files_event())
        assert result["metadata"]["tags"] == ["file"]

    def test_empty_fuid(self, parser):
        result = parser.parse(_make_files_event(fuid=""))
        assert result["metadata"]["fuid"] is None

    def test_empty_filename(self, parser):
        result = parser.parse(_make_files_event(filename=""))
        assert result["metadata"]["filename"] is None

    def test_empty_hashes(self, parser):
        result = parser.parse(_make_files_event(md5="", sha1="", sha256=""))
        assert result["metadata"]["md5"] is None
        assert result["metadata"]["sha1"] is None
        assert result["metadata"]["sha256"] is None


# ===========================================================================
# notice.log parsing
# ===========================================================================

class TestNoticeParsing:
    """Basic notice.log parsing."""

    def test_basic_fields(self, parser):
        result = parser.parse(_make_notice_event())
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"
        assert result["service"] == "zeek"
        assert result["result"] == "alert"
        assert result["metadata"]["zeek_log_type"] == "notice"

    def test_note(self, parser):
        result = parser.parse(_make_notice_event(note="Scan::Port_Scan"))
        assert result["metadata"]["note"] == "Scan::Port_Scan"

    def test_msg(self, parser):
        result = parser.parse(_make_notice_event(msg="Port scan detected"))
        assert result["metadata"]["notice_msg"] == "Port scan detected"

    def test_sub(self, parser):
        result = parser.parse(_make_notice_event(sub="additional details"))
        assert result["metadata"]["sub"] == "additional details"

    def test_port(self, parser):
        result = parser.parse(_make_notice_event(p=443))
        assert result["metadata"]["port"] == 443

    def test_actions(self, parser):
        result = parser.parse(_make_notice_event(actions=["Notice::ACTION_LOG", "Notice::ACTION_EMAIL"]))
        assert result["metadata"]["actions"] == ["Notice::ACTION_LOG", "Notice::ACTION_EMAIL"]

    def test_actions_empty(self, parser):
        result = parser.parse(_make_notice_event(actions=[]))
        assert result["metadata"]["actions"] is None

    def test_suppress_for(self, parser):
        result = parser.parse(_make_notice_event(suppress_for=3600.0))
        assert result["metadata"]["suppress_for"] == 3600.0

    def test_tags(self, parser):
        result = parser.parse(_make_notice_event())
        assert result["metadata"]["tags"] == ["alert"]

    def test_action_format(self, parser):
        result = parser.parse(_make_notice_event(note="Scan::Port_Scan"))
        assert result["action"] == "notice_scan_port_scan"

    def test_action_format_with_dots(self, parser):
        result = parser.parse(_make_notice_event(note="SSL::Invalid_Server_Cert"))
        assert result["action"] == "notice_ssl_invalid_server_cert"

    def test_action_empty_note(self, parser):
        result = parser.parse(_make_notice_event(note=""))
        assert result["action"] == "notice"
        assert result["metadata"]["note"] is None

    def test_src_from_src_field(self, parser):
        """Notice uses 'src' field for source IP."""
        result = parser.parse(_make_notice_event(src="192.168.1.10"))
        assert result["source_ip"] == "192.168.1.10"

    def test_dst_from_dst_field(self, parser):
        """Notice uses 'dst' field for destination IP."""
        result = parser.parse(_make_notice_event(dst="192.168.1.20"))
        assert result["destination_ip"] == "192.168.1.20"

    def test_uid(self, parser):
        result = parser.parse(_make_notice_event(uid="CYFva94d"))
        assert result["metadata"]["uid"] == "CYFva94d"

    def test_empty_sub(self, parser):
        result = parser.parse(_make_notice_event(sub=""))
        assert result["metadata"]["sub"] is None


# ===========================================================================
# Generic / fallback parsing
# ===========================================================================

class TestGenericParsing:
    """Generic fallback parsing for unknown log types."""

    def test_unknown_path(self, parser):
        event = {
            "ts": 1718442000.0,
            "_path": "weird_custom_log",
            "uid": "CYFva94d",
            "id.orig_h": "10.0.0.4",
            "id.resp_h": "93.184.216.34",
        }
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "weird_custom_log"
        assert result["action"] == "zeek_weird_custom_log"
        assert result["result"] == "unknown"
        assert result["metadata"]["tags"] == ["network"]
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"

    def test_no_path_no_match(self, parser):
        event = {"ts": 1718442000.0, "uid": "CYFva94d"}
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] is None
        assert result["action"] == "zeek_unknown"

    def test_generic_uid(self, parser):
        event = {"ts": 1718442000.0, "_path": "x509", "uid": "CYFva94d"}
        result = parser.parse(event)
        assert result["metadata"]["uid"] == "CYFva94d"


# ===========================================================================
# Timestamp parsing
# ===========================================================================

class TestTimestampParsing:
    """_parse_zeek_timestamp tests."""

    def test_float_epoch(self):
        dt = ZeekParser._parse_zeek_timestamp(1718442000.0)
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.year == 2024

    def test_int_epoch(self):
        dt = ZeekParser._parse_zeek_timestamp(1718442000)
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_string_epoch(self):
        dt = ZeekParser._parse_zeek_timestamp("1718442000.123456")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_iso8601(self):
        dt = ZeekParser._parse_zeek_timestamp("2024-06-15T10:00:00Z")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 6
        assert dt.day == 15

    def test_iso8601_with_offset(self):
        dt = ZeekParser._parse_zeek_timestamp("2024-06-15T10:00:00+00:00")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_iso8601_no_tz(self):
        dt = ZeekParser._parse_zeek_timestamp("2024-06-15T10:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_none_input(self):
        assert ZeekParser._parse_zeek_timestamp(None) is None

    def test_invalid_string(self):
        assert ZeekParser._parse_zeek_timestamp("not_a_timestamp") is None

    def test_invalid_type(self):
        assert ZeekParser._parse_zeek_timestamp([1, 2, 3]) is None

    def test_overflow_epoch(self):
        """Very large epoch should not crash."""
        result = ZeekParser._parse_zeek_timestamp(99999999999999.0)
        assert result is None

    def test_conn_timestamp(self, parser):
        result = parser.parse(_make_conn_event(ts=1718442000.000000))
        assert result["timestamp"] is not None
        ts = datetime.fromisoformat(result["timestamp"])
        assert ts.year == 2024

    def test_none_ts_defaults_to_now(self, parser):
        """When ts is None, falls back to current time."""
        event = _make_conn_event()
        event["ts"] = None
        result = parser.parse(event)
        assert result["timestamp"] is not None


# ===========================================================================
# RFC 1918 and internal traffic helpers
# ===========================================================================

class TestRFC1918:
    """RFC 1918 private address detection."""

    def test_10_network(self):
        assert ZeekParser._is_rfc1918("10.0.0.1") is True
        assert ZeekParser._is_rfc1918("10.255.255.255") is True

    def test_172_network(self):
        assert ZeekParser._is_rfc1918("172.16.0.1") is True
        assert ZeekParser._is_rfc1918("172.31.255.255") is True

    def test_172_non_private(self):
        assert ZeekParser._is_rfc1918("172.15.0.1") is False
        assert ZeekParser._is_rfc1918("172.32.0.1") is False

    def test_192_network(self):
        assert ZeekParser._is_rfc1918("192.168.0.1") is True
        assert ZeekParser._is_rfc1918("192.168.255.255") is True

    def test_public_ip(self):
        assert ZeekParser._is_rfc1918("93.184.216.34") is False
        assert ZeekParser._is_rfc1918("8.8.8.8") is False

    def test_empty_string(self):
        assert ZeekParser._is_rfc1918("") is False


class TestInternalTraffic:
    """Internal traffic detection."""

    def test_both_internal(self):
        assert ZeekParser._is_internal("10.0.0.4", "192.168.1.1") is True

    def test_one_external(self):
        assert ZeekParser._is_internal("10.0.0.4", "93.184.216.34") is False

    def test_both_external(self):
        assert ZeekParser._is_internal("8.8.8.8", "93.184.216.34") is False

    def test_empty_src(self):
        assert ZeekParser._is_internal("", "10.0.0.4") is False

    def test_empty_dest(self):
        assert ZeekParser._is_internal("10.0.0.4", "") is False

    def test_both_empty(self):
        assert ZeekParser._is_internal("", "") is False


class TestDirectionInference:
    """Direction inference from IP addresses."""

    def test_outbound(self):
        assert ZeekParser._infer_direction("10.0.0.4", "93.184.216.34") == "outbound"

    def test_inbound(self):
        assert ZeekParser._infer_direction("93.184.216.34", "10.0.0.4") == "inbound"

    def test_both_private(self):
        assert ZeekParser._infer_direction("10.0.0.4", "192.168.1.1") is None

    def test_both_public(self):
        assert ZeekParser._infer_direction("8.8.8.8", "93.184.216.34") is None

    def test_empty_src(self):
        assert ZeekParser._infer_direction("", "10.0.0.4") is None

    def test_empty_dest(self):
        assert ZeekParser._infer_direction("10.0.0.4", "") is None


# ===========================================================================
# Safe int helper
# ===========================================================================

class TestSafeInt:
    """_safe_int helper tests."""

    def test_int(self):
        assert ZeekParser._safe_int(42) == 42

    def test_float(self):
        assert ZeekParser._safe_int(42.9) == 42

    def test_string_int(self):
        assert ZeekParser._safe_int("42") == 42

    def test_none(self):
        assert ZeekParser._safe_int(None) is None

    def test_empty_string(self):
        assert ZeekParser._safe_int("") is None

    def test_invalid_string(self):
        assert ZeekParser._safe_int("abc") is None

    def test_list(self):
        assert ZeekParser._safe_int([1, 2]) is None


# ===========================================================================
# Strip trailing dot
# ===========================================================================

class TestStripTrailingDot:
    """_strip_trailing_dot helper tests."""

    def test_with_dot(self):
        assert ZeekParser._strip_trailing_dot("example.com.") == "example.com"

    def test_without_dot(self):
        assert ZeekParser._strip_trailing_dot("example.com") == "example.com"

    def test_empty(self):
        assert ZeekParser._strip_trailing_dot("") == ""

    def test_only_dot(self):
        assert ZeekParser._strip_trailing_dot(".") == ""


# ===========================================================================
# Extract IPs from answers
# ===========================================================================

class TestExtractIPsFromAnswers:
    """_extract_ips_from_answers helper tests."""

    def test_ipv4_list(self):
        assert ZeekParser._extract_ips_from_answers(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]

    def test_ipv6_list(self):
        result = ZeekParser._extract_ips_from_answers(["2001:db8::1"])
        assert result == ["2001:db8::1"]

    def test_mixed(self):
        result = ZeekParser._extract_ips_from_answers(["10.0.0.1", "cname.example.com", "::1"])
        assert "10.0.0.1" in result
        assert "::1" in result
        assert "cname.example.com" not in result

    def test_non_list(self):
        assert ZeekParser._extract_ips_from_answers("10.0.0.1") == []

    def test_empty_list(self):
        assert ZeekParser._extract_ips_from_answers([]) == []

    def test_none(self):
        assert ZeekParser._extract_ips_from_answers(None) == []

    def test_deduplication(self):
        result = ZeekParser._extract_ips_from_answers(["10.0.0.1", "10.0.0.1", "10.0.0.1"])
        assert result == ["10.0.0.1"]


# ===========================================================================
# Has external resolution
# ===========================================================================

class TestHasExternalResolution:
    """_has_external_resolution helper tests."""

    def test_public_ip(self):
        assert ZeekParser._has_external_resolution(["93.184.216.34"]) is True

    def test_private_ip(self):
        assert ZeekParser._has_external_resolution(["10.0.0.1"]) is False

    def test_mixed(self):
        assert ZeekParser._has_external_resolution(["10.0.0.1", "8.8.8.8"]) is True

    def test_empty(self):
        assert ZeekParser._has_external_resolution([]) is False


# ===========================================================================
# Output schema
# ===========================================================================

class TestOutputSchema:
    """Verify output conforms to ParsedEvent.to_dict() shape."""

    REQUIRED_TOP_KEYS = {"timestamp", "source_ip", "destination_ip", "user",
                         "action", "result", "service", "raw_event", "metadata"}

    def test_conn_schema(self, parser):
        result = parser.parse(_make_conn_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)
        assert result["service"] == "zeek"

    def test_dns_schema(self, parser):
        result = parser.parse(_make_dns_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)

    def test_http_schema(self, parser):
        result = parser.parse(_make_http_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)

    def test_ssl_schema(self, parser):
        result = parser.parse(_make_ssl_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)

    def test_files_schema(self, parser):
        result = parser.parse(_make_files_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)

    def test_notice_schema(self, parser):
        result = parser.parse(_make_notice_event())
        assert self.REQUIRED_TOP_KEYS.issubset(result.keys())
        assert isinstance(result["metadata"], dict)


# ===========================================================================
# Detection without _path field (field inference)
# ===========================================================================

class TestFieldInference:
    """Test log type detection without _path field."""

    def test_conn_without_path(self, parser):
        event = _make_conn_event(path=None)
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "conn"

    def test_dns_without_path(self, parser):
        event = _make_dns_event(path=None)
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "dns"

    def test_http_without_path(self, parser):
        event = _make_http_event(path=None)
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "http"

    def test_ssl_without_path(self, parser):
        event = _make_ssl_event(path=None)
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "ssl"

    def test_files_without_path(self, parser):
        event = _make_files_event(path=None)
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "files"

    def test_notice_without_path(self, parser):
        event = _make_notice_event(path=None)
        result = parser.parse(event)
        assert result["metadata"]["zeek_log_type"] == "notice"


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge cases and boundary tests."""

    def test_zero_duration(self, parser):
        result = parser.parse(_make_conn_event(duration=0))
        assert result["metadata"]["duration_seconds"] == 0

    def test_none_duration(self, parser):
        result = parser.parse(_make_conn_event(duration=None))
        assert result["metadata"]["duration_seconds"] is None

    def test_zero_bytes(self, parser):
        result = parser.parse(_make_conn_event(orig_bytes=0, resp_bytes=0))
        assert result["metadata"]["bytes_transferred"] == 0

    def test_large_bytes(self, parser):
        result = parser.parse(_make_conn_event(orig_bytes=10**12, resp_bytes=10**12))
        assert result["metadata"]["bytes_transferred"] == 2 * 10**12

    def test_empty_ips(self, parser):
        result = parser.parse(_make_conn_event(src_ip="", dest_ip=""))
        assert result["source_ip"] is None
        assert result["destination_ip"] is None

    def test_conn_with_no_service(self, parser):
        result = parser.parse(_make_conn_event(service=""))
        assert result["metadata"]["detected_service"] is None

    def test_http_status_boundary_200(self, parser):
        result = parser.parse(_make_http_event(status_code=200))
        assert result["result"] == "success"

    def test_http_status_boundary_399(self, parser):
        result = parser.parse(_make_http_event(status_code=399))
        assert result["result"] == "success"

    def test_http_status_boundary_400(self, parser):
        result = parser.parse(_make_http_event(status_code=400))
        assert result["result"] == "failure"

    def test_dns_with_trailing_dot_query(self, parser):
        result = parser.parse(_make_dns_event(query="sub.example.com."))
        assert result["metadata"]["query_name"] == "sub.example.com"

    def test_raw_event_preserved(self, parser):
        event = _make_conn_event()
        result = parser.parse(event)
        assert result["raw_event"] == event

    def test_files_with_multiple_tx_hosts(self, parser):
        """Only first tx_host is used as source_ip."""
        result = parser.parse(_make_files_event(tx_hosts=["1.2.3.4", "5.6.7.8"]))
        assert result["source_ip"] == "1.2.3.4"

    def test_notice_fallback_to_id_fields(self, parser):
        """When src/dst not present, notice falls back to id.orig_h/id.resp_h."""
        event = {
            "ts": 1718442000.0,
            "_path": "notice",
            "uid": "CYFva94d",
            "id.orig_h": "10.0.0.4",
            "id.resp_h": "93.184.216.34",
            "note": "SSL::Invalid_Server_Cert",
            "msg": "Invalid cert",
        }
        result = parser.parse(event)
        assert result["source_ip"] == "10.0.0.4"
        assert result["destination_ip"] == "93.184.216.34"


# ===========================================================================
# Full integration tests
# ===========================================================================

class TestFullIntegration:
    """End-to-end integration tests with realistic Zeek log entries."""

    def test_conn_scan(self, parser):
        """Port scan: SYN without response."""
        event = {
            "_path": "conn",
            "ts": 1718442000.0,
            "uid": "CYFva94d3gVj3SXXX",
            "id.orig_h": "10.0.0.100",
            "id.orig_p": 60123,
            "id.resp_h": "192.168.1.50",
            "id.resp_p": 22,
            "proto": "tcp",
            "service": "",
            "duration": None,
            "orig_bytes": 0,
            "resp_bytes": 0,
            "orig_pkts": 1,
            "resp_pkts": 0,
            "conn_state": "S0",
            "missed_bytes": 0,
            "history": "S",
        }
        result = parser.parse(event)
        assert result["result"] == "failure"
        assert result["metadata"]["conn_state_meaning"] == "syn_no_reply"
        assert result["action"] == "connection_s0"
        assert result["metadata"]["is_internal"] is True

    def test_dns_tunneling_indicator(self, parser):
        """High-entropy subdomain that might indicate DNS tunneling."""
        event = {
            "_path": "dns",
            "ts": 1718442000.0,
            "uid": "CYFva94d3gVj3SXXX",
            "id.orig_h": "10.0.0.4",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 53,
            "query": "aB3kX9mQzW7nP4jL.evil.com",
            "qtype_name": "TXT",
            "rcode_name": "NOERROR",
            "answers": [],
            "rejected": False,
            "TTLs": [60],
            "trans_id": 99999,
        }
        result = parser.parse(event)
        assert result["metadata"]["subdomain_entropy"] > 3.0
        assert result["metadata"]["subdomain_count"] == 3
        assert result["action"] == "dns_query_txt"

    def test_ssl_self_signed_cert(self, parser):
        """TLS connection with self-signed certificate."""
        event = {
            "_path": "ssl",
            "ts": 1718442000.0,
            "uid": "CYFva94d3gVj3SXXX",
            "id.orig_h": "10.0.0.4",
            "id.orig_p": 54321,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 443,
            "version": "TLSv12",
            "server_name": "suspicious.example.com",
            "subject": "CN=suspicious.example.com",
            "issuer": "CN=suspicious.example.com",
            "ja3": "e7d705a3286e19ea42f587b344ee6865",
            "ja3s": "ec74a5c51106f0419184d0dd08fb22c5",
            "established": True,
            "validation_status": "self signed certificate",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "curve": "secp256r1",
            "resumed": False,
            "next_protocol": "",
        }
        result = parser.parse(event)
        assert result["result"] == "success"
        assert result["metadata"]["validation_status"] == "self signed certificate"
        assert result["metadata"]["ja3"] is not None
        assert result["metadata"]["subject"] == result["metadata"]["issuer"]

    def test_http_post_with_credentials(self, parser):
        """HTTP POST with embedded credentials."""
        event = {
            "_path": "http",
            "ts": 1718442000.0,
            "uid": "CYFva94d3gVj3SXXX",
            "id.orig_h": "10.0.0.4",
            "id.orig_p": 54321,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "method": "POST",
            "host": "login.example.com",
            "uri": "/auth/login",
            "user_agent": "Mozilla/5.0",
            "request_body_len": 256,
            "response_body_len": 512,
            "status_code": 302,
            "resp_mime_types": ["text/html"],
            "referrer": "https://login.example.com/form",
            "username": "admin",
            "password": "p@ssw0rd",
        }
        result = parser.parse(event)
        assert result["action"] == "http_post"
        assert result["result"] == "success"
        assert result["user"] == "admin"
        assert result["metadata"]["has_credentials"] is True
        assert result["metadata"]["http_uri"] == "/auth/login"

    def test_malicious_file_transfer(self, parser):
        """File transfer with suspicious mime type."""
        event = {
            "_path": "files",
            "ts": 1718442000.0,
            "fuid": "FGhfj24bkl3SF",
            "source": "HTTP",
            "mime_type": "application/x-dosexec",
            "filename": "update.exe",
            "total_bytes": 1048576,
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "is_orig": False,
            "conn_uids": ["CYFva94d3gVj3SXXX"],
            "tx_hosts": ["93.184.216.34"],
            "rx_hosts": ["10.0.0.4"],
        }
        result = parser.parse(event)
        assert result["action"] == "file_transfer"
        assert result["metadata"]["mime_type"] == "application/x-dosexec"
        assert result["metadata"]["md5"] == "44d88612fea8a8f36de82e1278abb02f"
        assert result["metadata"]["sha256"] is not None
        assert result["source_ip"] == "93.184.216.34"
        assert result["destination_ip"] == "10.0.0.4"

    def test_notice_port_scan(self, parser):
        """Zeek-generated port scan alert."""
        event = {
            "_path": "notice",
            "ts": 1718442000.0,
            "uid": "CYFva94d3gVj3SXXX",
            "src": "10.0.0.100",
            "dst": "192.168.1.50",
            "p": 0,
            "note": "Scan::Port_Scan",
            "msg": "10.0.0.100 scanned at least 15 unique ports of host 192.168.1.50 in 0m5s",
            "sub": "local_orig",
            "actions": ["Notice::ACTION_LOG"],
            "suppress_for": 3600.0,
        }
        result = parser.parse(event)
        assert result["result"] == "alert"
        assert result["metadata"]["note"] == "Scan::Port_Scan"
        assert "scanned at least 15" in result["metadata"]["notice_msg"]
        assert result["source_ip"] == "10.0.0.100"
        assert result["destination_ip"] == "192.168.1.50"
