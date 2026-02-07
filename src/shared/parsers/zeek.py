"""Zeek (formerly Bro) JSON Log parser for NDR.

Parses Zeek structured JSON logs from various protocol analysers and
normalises them to the ``ParsedEvent``-compatible structure used across
all NDR parsers.

Supported Zeek log types:
  - **conn.log** — connection summaries (maps to VPC flow fields)
  - **dns.log** — DNS queries with answers
  - **http.log** — HTTP requests
  - **ssl.log** — TLS/SSL connections with JA3 fingerprints
  - **files.log** — file transfers with hashes
  - **notice.log** — Zeek-generated alerts

Each log type is detected by the ``_log_type`` field (set by Zeek's
JSON logger) or inferred from field presence.

Zeek JSON log reference:
  https://docs.zeek.org/en/current/log-formats.html

Example conn.log entry::

    {
        "_path": "conn",
        "ts": 1718442000.000000,
        "uid": "CYFva94d3gVj3SXXX",
        "id.orig_h": "10.0.0.4",
        "id.orig_p": 54321,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.234,
        "orig_bytes": 1024,
        "resp_bytes": 4096,
        "orig_pkts": 10,
        "resp_pkts": 15,
        "conn_state": "SF",
        "missed_bytes": 0,
        "history": "ShADadFf"
    }
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseParser, ParsedEvent
from .route53_dns import shannon_entropy

# Pre-compiled regex for RFC 1918 private address detection.
_RFC1918_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)

# Zeek connection state codes and their meanings.
CONN_STATE_MAP: Dict[str, str] = {
    "S0": "syn_no_reply",
    "S1": "established_no_reply",
    "SF": "normal",
    "REJ": "rejected",
    "S2": "established_originator_close",
    "S3": "established_responder_close",
    "RSTO": "reset_originator",
    "RSTR": "reset_responder",
    "RSTOS0": "reset_originator_syn",
    "RSTRH": "reset_responder_established",
    "SH": "syn_ack_no_fin",
    "SHR": "syn_ack_rejected",
    "OTH": "midstream",
}

# Supported Zeek log types.
_ZEEK_LOG_TYPES = {"conn", "dns", "http", "ssl", "files", "notice"}


class ZeekParser(BaseParser):
    """Parser for Zeek (formerly Bro) JSON logs.

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    uniformly across cloud and on-prem network data.
    """

    def __init__(self):
        super().__init__()
        self.source_type = "zeek"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek JSON log entry.

        Args:
            raw_event: Raw Zeek JSON log entry as a dictionary.

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``.
        """
        log_type = self._detect_log_type(raw_event)

        if log_type == "conn":
            return self._parse_conn(raw_event)
        elif log_type == "dns":
            return self._parse_dns(raw_event)
        elif log_type == "http":
            return self._parse_http(raw_event)
        elif log_type == "ssl":
            return self._parse_ssl(raw_event)
        elif log_type == "files":
            return self._parse_files(raw_event)
        elif log_type == "notice":
            return self._parse_notice(raw_event)

        return self._parse_generic(raw_event, log_type)

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like a Zeek JSON log entry.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid Zeek log.
        """
        if not isinstance(raw_event, dict):
            return False

        # Zeek logs always have a ts field
        if "ts" not in raw_event:
            return False

        # Check for _path (standard Zeek JSON field) or uid
        if "_path" in raw_event:
            return True
        if "uid" in raw_event:
            return True

        # Check for Zeek connection ID fields
        if "id.orig_h" in raw_event or "id.resp_h" in raw_event:
            return True

        # Check for known Zeek-specific fields
        zeek_fields = {"conn_state", "query", "qtype_name", "server_name",
                       "ja3", "fuid", "note"}
        if zeek_fields.intersection(raw_event.keys()):
            return True

        return False

    # ------------------------------------------------------------------
    # Log type detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_log_type(raw_event: Dict[str, Any]) -> Optional[str]:
        """Detect which Zeek log type this event belongs to.

        Returns:
            Log type name (e.g. ``"conn"``) or ``None``.
        """
        # Check _path field (standard in Zeek JSON output)
        path = raw_event.get("_path", "")
        if path and isinstance(path, str):
            if path in _ZEEK_LOG_TYPES:
                return path

        # Infer from field presence
        if "conn_state" in raw_event or "history" in raw_event:
            return "conn"
        if "query" in raw_event and "qtype_name" in raw_event:
            return "dns"
        if "method" in raw_event and "uri" in raw_event:
            return "http"
        if "server_name" in raw_event or "ja3" in raw_event:
            return "ssl"
        if "fuid" in raw_event and "mime_type" in raw_event:
            return "files"
        if "note" in raw_event and "msg" in raw_event:
            return "notice"

        # Fall back to _path for non-standard types
        if path:
            return path

        return None

    # ------------------------------------------------------------------
    # conn.log
    # ------------------------------------------------------------------

    def _parse_conn(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek conn.log entry."""
        src_ip = raw_event.get("id.orig_h", "")
        src_port = self._safe_int(raw_event.get("id.orig_p"))
        dest_ip = raw_event.get("id.resp_h", "")
        dest_port = self._safe_int(raw_event.get("id.resp_p"))
        proto = raw_event.get("proto", "")
        service = raw_event.get("service", "")
        duration = raw_event.get("duration")
        orig_bytes = raw_event.get("orig_bytes")
        resp_bytes = raw_event.get("resp_bytes")
        orig_pkts = raw_event.get("orig_pkts")
        resp_pkts = raw_event.get("resp_pkts")
        conn_state = raw_event.get("conn_state", "")
        missed_bytes = raw_event.get("missed_bytes")
        history = raw_event.get("history", "")
        uid = raw_event.get("uid", "")

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Compute total bytes
        total_bytes = None
        if orig_bytes is not None and resp_bytes is not None:
            total_bytes = orig_bytes + resp_bytes

        # Direction heuristic
        direction = self._infer_direction(src_ip, dest_ip)

        # Connection state meaning
        conn_state_meaning = CONN_STATE_MAP.get(conn_state)

        # Result from connection state
        result = "success"
        if conn_state in ("REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "S0"):
            result = "failure"

        metadata: Dict[str, Any] = {
            "zeek_log_type": "conn",
            "uid": uid or None,
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": proto.upper() if proto else None,
            "detected_service": service or None,
            "duration_seconds": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "bytes_transferred": total_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "conn_state": conn_state or None,
            "conn_state_meaning": conn_state_meaning,
            "missed_bytes": missed_bytes,
            "history": history or None,
            "direction": direction,
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["network"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"connection_{conn_state.lower()}" if conn_state else "connection",
            result=result,
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # dns.log
    # ------------------------------------------------------------------

    def _parse_dns(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek dns.log entry."""
        src_ip = raw_event.get("id.orig_h", "")
        src_port = self._safe_int(raw_event.get("id.orig_p"))
        dest_ip = raw_event.get("id.resp_h", "")
        dest_port = self._safe_int(raw_event.get("id.resp_p"))
        uid = raw_event.get("uid", "")

        query = raw_event.get("query", "")
        qtype_name = raw_event.get("qtype_name", "")
        rcode_name = raw_event.get("rcode_name", "")
        answers = raw_event.get("answers", [])
        rejected = raw_event.get("rejected", False)
        ttls = raw_event.get("TTLs", [])
        trans_id = raw_event.get("trans_id")

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Domain analysis
        clean_query = self._strip_trailing_dot(query)
        labels = clean_query.split(".") if clean_query else []
        subdomain_count = len(labels)
        leftmost_label = labels[0] if labels else ""
        subdomain_entropy = shannon_entropy(leftmost_label)

        # Extract IPs from answers
        resolved_ips = self._extract_ips_from_answers(answers)

        # NXDOMAIN / external resolution
        is_nxdomain = rcode_name.upper() == "NXDOMAIN" if rcode_name else False
        is_external = self._has_external_resolution(resolved_ips)

        # Result
        if rejected:
            result = "failure"
        elif rcode_name:
            result = "success" if rcode_name.upper() == "NOERROR" else "failure"
        else:
            result = "unknown"

        metadata: Dict[str, Any] = {
            "zeek_log_type": "dns",
            "uid": uid or None,
            "source_port": src_port,
            "destination_port": dest_port,
            # DNS fields
            "query_name": clean_query,
            "query_type": qtype_name,
            "response_code": rcode_name,
            "answers": answers if answers else [],
            "resolved_ips": resolved_ips,
            "rejected": rejected,
            "ttls": ttls if ttls else [],
            "trans_id": trans_id,
            # DNS analysis
            "is_nxdomain": is_nxdomain,
            "subdomain_count": subdomain_count,
            "subdomain_entropy": subdomain_entropy,
            "is_external_resolution": is_external,
            "domain_age_days": None,
            "transport": "UDP" if dest_port == 53 else "TCP" if dest_port == 853 else None,
            "tags": ["dns"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"dns_query_{qtype_name.lower()}" if qtype_name else "dns_query",
            result=result,
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # http.log
    # ------------------------------------------------------------------

    def _parse_http(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek http.log entry."""
        src_ip = raw_event.get("id.orig_h", "")
        src_port = self._safe_int(raw_event.get("id.orig_p"))
        dest_ip = raw_event.get("id.resp_h", "")
        dest_port = self._safe_int(raw_event.get("id.resp_p"))
        uid = raw_event.get("uid", "")

        method = raw_event.get("method", "")
        host = raw_event.get("host", "")
        uri = raw_event.get("uri", "")
        user_agent = raw_event.get("user_agent", "")
        request_body_len = raw_event.get("request_body_len")
        response_body_len = raw_event.get("response_body_len")
        status_code = self._safe_int(raw_event.get("status_code"))
        resp_mime_types = raw_event.get("resp_mime_types", [])
        referrer = raw_event.get("referrer", "")
        username = raw_event.get("username", "")
        password = raw_event.get("password", "")

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Result from status code
        if status_code is not None:
            if 200 <= status_code < 400:
                result = "success"
            else:
                result = "failure"
        else:
            result = "unknown"

        metadata: Dict[str, Any] = {
            "zeek_log_type": "http",
            "uid": uid or None,
            "source_port": src_port,
            "destination_port": dest_port,
            # HTTP fields
            "http_method": method or None,
            "http_host": host or None,
            "http_uri": uri or None,
            "http_user_agent": user_agent or None,
            "http_referrer": referrer or None,
            "http_status_code": status_code,
            "request_body_len": request_body_len,
            "response_body_len": response_body_len,
            "resp_mime_types": resp_mime_types if resp_mime_types else None,
            "username": username or None,
            "has_credentials": bool(username or password),
            "direction": self._infer_direction(src_ip, dest_ip),
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["http"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=username or None,
            action=f"http_{method.lower()}" if method else "http_request",
            result=result,
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # ssl.log
    # ------------------------------------------------------------------

    def _parse_ssl(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek ssl.log entry."""
        src_ip = raw_event.get("id.orig_h", "")
        src_port = self._safe_int(raw_event.get("id.orig_p"))
        dest_ip = raw_event.get("id.resp_h", "")
        dest_port = self._safe_int(raw_event.get("id.resp_p"))
        uid = raw_event.get("uid", "")

        version = raw_event.get("version", "")
        server_name = raw_event.get("server_name", "")
        subject = raw_event.get("subject", "")
        issuer = raw_event.get("issuer", "")
        ja3 = raw_event.get("ja3", "")
        ja3s = raw_event.get("ja3s", "")
        established = raw_event.get("established", None)
        validation_status = raw_event.get("validation_status", "")
        cipher = raw_event.get("cipher", "")
        curve = raw_event.get("curve", "")
        resumed = raw_event.get("resumed", None)
        next_protocol = raw_event.get("next_protocol", "")

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Result
        if established is True:
            result = "success"
        elif established is False:
            result = "failure"
        else:
            result = "unknown"

        metadata: Dict[str, Any] = {
            "zeek_log_type": "ssl",
            "uid": uid or None,
            "source_port": src_port,
            "destination_port": dest_port,
            # TLS fields
            "tls_version": version or None,
            "server_name": server_name or None,
            "subject": subject or None,
            "issuer": issuer or None,
            "ja3": ja3 or None,
            "ja3s": ja3s or None,
            "established": established,
            "validation_status": validation_status or None,
            "cipher": cipher or None,
            "curve": curve or None,
            "resumed": resumed,
            "next_protocol": next_protocol or None,
            "direction": self._infer_direction(src_ip, dest_ip),
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["tls"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action="tls_connection",
            result=result,
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # files.log
    # ------------------------------------------------------------------

    def _parse_files(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek files.log entry."""
        fuid = raw_event.get("fuid", "")
        source = raw_event.get("source", "")
        mime_type = raw_event.get("mime_type", "")
        filename = raw_event.get("filename", "")
        total_bytes = raw_event.get("total_bytes")
        md5 = raw_event.get("md5", "")
        sha1 = raw_event.get("sha1", "")
        sha256 = raw_event.get("sha256", "")
        is_orig = raw_event.get("is_orig")

        # files.log may include conn_uids linking to connections
        conn_uids = raw_event.get("conn_uids", [])

        # Extract source/dest from tx_hosts/rx_hosts if available
        tx_hosts = raw_event.get("tx_hosts", [])
        rx_hosts = raw_event.get("rx_hosts", [])
        src_ip = tx_hosts[0] if tx_hosts else ""
        dest_ip = rx_hosts[0] if rx_hosts else ""

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "zeek_log_type": "files",
            "fuid": fuid or None,
            "conn_uids": conn_uids if conn_uids else None,
            "file_source": source or None,
            "mime_type": mime_type or None,
            "filename": filename or None,
            "total_bytes": total_bytes,
            "md5": md5 or None,
            "sha1": sha1 or None,
            "sha256": sha256 or None,
            "is_orig": is_orig,
            "tags": ["file"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action="file_transfer",
            result="success",
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # notice.log
    # ------------------------------------------------------------------

    def _parse_notice(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Zeek notice.log entry."""
        src_ip = raw_event.get("src", raw_event.get("id.orig_h", ""))
        dest_ip = raw_event.get("dst", raw_event.get("id.resp_h", ""))
        uid = raw_event.get("uid", "")
        port = self._safe_int(raw_event.get("p"))
        note = raw_event.get("note", "")
        msg = raw_event.get("msg", "")
        sub = raw_event.get("sub", "")
        actions = raw_event.get("actions", [])
        suppress_for = raw_event.get("suppress_for")

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "zeek_log_type": "notice",
            "uid": uid or None,
            "note": note or None,
            "notice_msg": msg or None,
            "sub": sub or None,
            "port": port,
            "actions": actions if actions else None,
            "suppress_for": suppress_for,
            "tags": ["alert"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"notice_{note.lower().replace('::', '_').replace('.', '_')}" if note else "notice",
            result="alert",
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # Generic fallback
    # ------------------------------------------------------------------

    def _parse_generic(
        self, raw_event: Dict[str, Any], log_type: Optional[str]
    ) -> Dict[str, Any]:
        """Best-effort parse for unrecognised Zeek log types."""
        src_ip = raw_event.get("id.orig_h", "")
        dest_ip = raw_event.get("id.resp_h", "")
        uid = raw_event.get("uid", "")

        timestamp = self._parse_zeek_timestamp(raw_event.get("ts"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "zeek_log_type": log_type,
            "uid": uid or None,
            "tags": ["network"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"zeek_{log_type}" if log_type else "zeek_unknown",
            result="unknown",
            service="zeek",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_trailing_dot(name: str) -> str:
        """Strip the trailing dot from a DNS name if present."""
        if name and name.endswith("."):
            return name[:-1]
        return name

    @staticmethod
    def _extract_ips_from_answers(answers: Any) -> List[str]:
        """Extract IP addresses from Zeek DNS answer strings.

        Zeek dns.log answers are an array of strings, each being either
        an IP address or a CNAME/other record value.
        """
        ips: List[str] = []
        if not isinstance(answers, list):
            return ips
        for answer in answers:
            if not isinstance(answer, str):
                continue
            # Simple IPv4 check
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", answer):
                if answer not in ips:
                    ips.append(answer)
            # Simple IPv6 check
            elif re.match(r"^[0-9a-fA-F:]+$", answer) and ":" in answer:
                if answer not in ips:
                    ips.append(answer)
        return ips

    @staticmethod
    def _has_external_resolution(resolved_ips: List[str]) -> bool:
        """Return ``True`` if any resolved IP is public."""
        for ip in resolved_ips:
            if not _RFC1918_RE.match(ip):
                return True
        return False

    # ------------------------------------------------------------------
    # Internal traffic detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_rfc1918(ip: str) -> bool:
        """Return ``True`` if *ip* is an RFC 1918 private IPv4 address."""
        return bool(_RFC1918_RE.match(ip))

    @staticmethod
    def _is_internal(src_ip: str, dest_ip: str) -> bool:
        """Return ``True`` if both IPs are RFC 1918 private addresses."""
        if not src_ip or not dest_ip:
            return False
        return bool(_RFC1918_RE.match(src_ip) and _RFC1918_RE.match(dest_ip))

    @staticmethod
    def _infer_direction(src_ip: str, dest_ip: str) -> Optional[str]:
        """Infer traffic direction from IP addresses."""
        if not src_ip or not dest_ip:
            return None
        src_private = bool(_RFC1918_RE.match(src_ip))
        dest_private = bool(_RFC1918_RE.match(dest_ip))
        if src_private and not dest_private:
            return "outbound"
        if not src_private and dest_private:
            return "inbound"
        return None

    # ------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_zeek_timestamp(ts: Any) -> Optional[datetime]:
        """Parse a Zeek timestamp.

        Zeek timestamps are typically Unix epoch floats (e.g. ``1718442000.123456``),
        but may also be ISO 8601 strings in some configurations.

        Args:
            ts: Timestamp value (float, int, or string).

        Returns:
            ``datetime`` with UTC timezone or ``None``.
        """
        if ts is None:
            return None

        # Numeric epoch
        if isinstance(ts, (int, float)):
            try:
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None

        # String epoch
        if isinstance(ts, str):
            try:
                epoch = float(ts)
                return datetime.fromtimestamp(epoch, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                pass

            # Try ISO 8601
            normalized = ts
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

        return None

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert *value* to ``int`` if possible, else ``None``."""
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
