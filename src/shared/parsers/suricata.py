"""Suricata EVE JSON Log parser for NDR.

Parses Suricata's Extensible Event Format (EVE) JSON logs and normalises
them to the ``ParsedEvent``-compatible structure used across all NDR parsers.

Supported Suricata event types:
  - **alert** — IDS/IPS signature matches (allowed or blocked)
  - **flow** — connection/flow summaries with byte/packet counts
  - **dns** — DNS query and answer events
  - **http** — HTTP request/response metadata
  - **tls** — TLS handshake metadata with JA3 fingerprints
  - **fileinfo** — file transfer metadata with hashes

Event type is determined by the top-level ``event_type`` field that
Suricata always includes in EVE JSON output.

Suricata EVE JSON reference:
  https://docs.suricata.io/en/latest/output/eve/eve-json-output.html

Example alert event::

    {
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
            "severity": 1
        }
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

# Supported Suricata event types with dedicated parsers.
_SURICATA_EVENT_TYPES = {"alert", "flow", "dns", "http", "tls", "fileinfo"}

# Protocol number → name mapping for Suricata proto field.
_PROTOCOL_MAP: Dict[str, str] = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "132": "SCTP",
}

# Suricata alert severity (1=highest, 4=lowest) → normalised names.
_SEVERITY_MAP: Dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


class SuricataParser(BaseParser):
    """Parser for Suricata EVE JSON logs.

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    uniformly across cloud and on-prem network data.
    """

    def __init__(self):
        super().__init__()
        self.source_type = "suricata"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata EVE JSON event.

        Args:
            raw_event: Raw Suricata EVE JSON event as a dictionary.

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``.
        """
        event_type = self._detect_event_type(raw_event)

        if event_type == "alert":
            return self._parse_alert(raw_event)
        elif event_type == "flow":
            return self._parse_flow(raw_event)
        elif event_type == "dns":
            return self._parse_dns(raw_event)
        elif event_type == "http":
            return self._parse_http(raw_event)
        elif event_type == "tls":
            return self._parse_tls(raw_event)
        elif event_type == "fileinfo":
            return self._parse_fileinfo(raw_event)

        return self._parse_generic(raw_event, event_type)

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like a Suricata EVE JSON event.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid Suricata EVE log.
        """
        if not isinstance(raw_event, dict):
            return False

        # Suricata EVE always has event_type
        if "event_type" not in raw_event:
            return False

        # Must also have a timestamp
        if "timestamp" not in raw_event:
            return False

        return True

    # ------------------------------------------------------------------
    # Event type detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_event_type(raw_event: Dict[str, Any]) -> Optional[str]:
        """Detect which Suricata event type this event belongs to.

        Returns:
            Event type name (e.g. ``"alert"``) or ``None``.
        """
        event_type = raw_event.get("event_type", "")
        if event_type and isinstance(event_type, str):
            return event_type
        return None

    # ------------------------------------------------------------------
    # alert events
    # ------------------------------------------------------------------

    def _parse_alert(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata alert event."""
        src_ip = raw_event.get("src_ip", "")
        src_port = self._safe_int(raw_event.get("src_port"))
        dest_ip = raw_event.get("dest_ip", "")
        dest_port = self._safe_int(raw_event.get("dest_port"))
        proto = raw_event.get("proto", "")
        flow_id = raw_event.get("flow_id")
        in_iface = raw_event.get("in_iface", "")

        alert = raw_event.get("alert", {})
        if not isinstance(alert, dict):
            alert = {}

        alert_action = alert.get("action", "")
        signature_id = alert.get("signature_id")
        signature = alert.get("signature", "")
        category = alert.get("category", "")
        severity = self._safe_int(alert.get("severity"))
        gid = self._safe_int(alert.get("gid"))
        rev = self._safe_int(alert.get("rev"))

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Normalise alert action
        action_lower = alert_action.lower() if alert_action else ""
        if action_lower in ("blocked", "drop"):
            result = "blocked"
        elif action_lower == "allowed":
            result = "allowed"
        else:
            result = "alert"

        metadata: Dict[str, Any] = {
            "suricata_event_type": "alert",
            "flow_id": flow_id,
            "in_iface": in_iface or None,
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": self._normalise_protocol(proto),
            # Alert-specific
            "alert_action": alert_action or None,
            "signature_id": signature_id,
            "signature": signature or None,
            "category": category or None,
            "severity": severity,
            "severity_label": _SEVERITY_MAP.get(severity) if severity else None,
            "gid": gid,
            "rev": rev,
            "direction": self._infer_direction(src_ip, dest_ip),
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["alert", "ids"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"suricata_alert_{action_lower}" if action_lower else "suricata_alert",
            result=result,
            service="suricata",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # flow events
    # ------------------------------------------------------------------

    def _parse_flow(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata flow event."""
        src_ip = raw_event.get("src_ip", "")
        src_port = self._safe_int(raw_event.get("src_port"))
        dest_ip = raw_event.get("dest_ip", "")
        dest_port = self._safe_int(raw_event.get("dest_port"))
        proto = raw_event.get("proto", "")
        flow_id = raw_event.get("flow_id")
        app_proto = raw_event.get("app_proto", "")

        flow = raw_event.get("flow", {})
        if not isinstance(flow, dict):
            flow = {}

        pkts_toserver = flow.get("pkts_toserver")
        pkts_toclient = flow.get("pkts_toclient")
        bytes_toserver = flow.get("bytes_toserver")
        bytes_toclient = flow.get("bytes_toclient")
        flow_start = flow.get("start", "")
        flow_end = flow.get("end", "")
        flow_state = flow.get("state", "")
        flow_age = flow.get("age")
        flow_reason = flow.get("reason", "")

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Compute totals
        total_bytes = None
        if bytes_toserver is not None and bytes_toclient is not None:
            total_bytes = bytes_toserver + bytes_toclient
        total_pkts = None
        if pkts_toserver is not None and pkts_toclient is not None:
            total_pkts = pkts_toserver + pkts_toclient

        # Compute duration from start/end
        duration = self._compute_duration(flow_start, flow_end)
        if duration is None and flow_age is not None:
            duration = float(flow_age)

        metadata: Dict[str, Any] = {
            "suricata_event_type": "flow",
            "flow_id": flow_id,
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": self._normalise_protocol(proto),
            "app_proto": app_proto or None,
            # Flow stats
            "pkts_toserver": pkts_toserver,
            "pkts_toclient": pkts_toclient,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "bytes_transferred": total_bytes,
            "packets_total": total_pkts,
            "duration_seconds": duration,
            "flow_start": flow_start or None,
            "flow_end": flow_end or None,
            "flow_state": flow_state or None,
            "flow_reason": flow_reason or None,
            "direction": self._infer_direction(src_ip, dest_ip),
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["network"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"flow_{flow_state.lower()}" if flow_state else "flow",
            result="success",
            service="suricata",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # dns events
    # ------------------------------------------------------------------

    def _parse_dns(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata DNS event."""
        src_ip = raw_event.get("src_ip", "")
        src_port = self._safe_int(raw_event.get("src_port"))
        dest_ip = raw_event.get("dest_ip", "")
        dest_port = self._safe_int(raw_event.get("dest_port"))
        flow_id = raw_event.get("flow_id")

        dns = raw_event.get("dns", {})
        if not isinstance(dns, dict):
            dns = {}

        dns_type = dns.get("type", "")
        rrname = dns.get("rrname", "")
        rrtype = dns.get("rrtype", "")
        rdata = dns.get("rdata", "")
        rcode = dns.get("rcode", "")
        dns_id = dns.get("id")
        tx_id = dns.get("tx_id")

        # Suricata may also include grouped answers
        answers = dns.get("answers", [])
        grouped = dns.get("grouped", {})

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Domain analysis
        clean_query = self._strip_trailing_dot(rrname)
        labels = clean_query.split(".") if clean_query else []
        subdomain_count = len(labels)
        leftmost_label = labels[0] if labels else ""
        subdomain_entropy = shannon_entropy(leftmost_label)

        # Extract resolved IPs from answers or rdata
        resolved_ips = self._extract_dns_ips(answers, rdata, grouped)

        # NXDOMAIN detection
        is_nxdomain = rcode.upper() == "NXDOMAIN" if rcode else False

        # External resolution
        is_external = self._has_external_resolution(resolved_ips)

        # Result
        if rcode:
            result = "success" if rcode.upper() == "NOERROR" else "failure"
        elif dns_type == "answer" and not rcode:
            result = "success"
        else:
            result = "unknown"

        metadata: Dict[str, Any] = {
            "suricata_event_type": "dns",
            "flow_id": flow_id,
            "source_port": src_port,
            "destination_port": dest_port,
            # DNS fields
            "dns_type": dns_type or None,
            "query_name": clean_query,
            "query_type": rrtype or None,
            "response_code": rcode or None,
            "rdata": rdata or None,
            "answers": answers if answers else [],
            "resolved_ips": resolved_ips,
            "dns_id": dns_id,
            "tx_id": tx_id,
            # DNS analysis
            "is_nxdomain": is_nxdomain,
            "subdomain_count": subdomain_count,
            "subdomain_entropy": subdomain_entropy,
            "is_external_resolution": is_external,
            "domain_age_days": None,
            "transport": "UDP" if dest_port == 53 else "TCP" if dest_port == 853 else None,
            "tags": ["dns"],
        }

        action_suffix = rrtype.lower() if rrtype else "query"
        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"dns_{dns_type}_{action_suffix}" if dns_type else f"dns_query_{action_suffix}",
            result=result,
            service="suricata",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # http events
    # ------------------------------------------------------------------

    def _parse_http(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata HTTP event."""
        src_ip = raw_event.get("src_ip", "")
        src_port = self._safe_int(raw_event.get("src_port"))
        dest_ip = raw_event.get("dest_ip", "")
        dest_port = self._safe_int(raw_event.get("dest_port"))
        flow_id = raw_event.get("flow_id")

        http = raw_event.get("http", {})
        if not isinstance(http, dict):
            http = {}

        hostname = http.get("hostname", "")
        url = http.get("url", "")
        http_user_agent = http.get("http_user_agent", "")
        http_method = http.get("http_method", "")
        protocol = http.get("protocol", "")
        status = self._safe_int(http.get("status"))
        length = http.get("length")
        http_content_type = http.get("http_content_type", "")
        http_refer = http.get("http_refer", "")

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Result from status code
        if status is not None:
            if 200 <= status < 400:
                result = "success"
            else:
                result = "failure"
        else:
            result = "unknown"

        metadata: Dict[str, Any] = {
            "suricata_event_type": "http",
            "flow_id": flow_id,
            "source_port": src_port,
            "destination_port": dest_port,
            # HTTP fields
            "http_hostname": hostname or None,
            "http_url": url or None,
            "http_user_agent": http_user_agent or None,
            "http_method": http_method or None,
            "http_protocol": protocol or None,
            "http_status": status,
            "http_length": length,
            "http_content_type": http_content_type or None,
            "http_refer": http_refer or None,
            "direction": self._infer_direction(src_ip, dest_ip),
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["http"],
        }

        method_lower = http_method.lower() if http_method else "request"
        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"http_{method_lower}",
            result=result,
            service="suricata",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # tls events
    # ------------------------------------------------------------------

    def _parse_tls(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata TLS event."""
        src_ip = raw_event.get("src_ip", "")
        src_port = self._safe_int(raw_event.get("src_port"))
        dest_ip = raw_event.get("dest_ip", "")
        dest_port = self._safe_int(raw_event.get("dest_port"))
        flow_id = raw_event.get("flow_id")

        tls = raw_event.get("tls", {})
        if not isinstance(tls, dict):
            tls = {}

        subject = tls.get("subject", "")
        issuerdn = tls.get("issuerdn", "")
        serial = tls.get("serial", "")
        fingerprint = tls.get("fingerprint", "")
        sni = tls.get("sni", "")
        version = tls.get("version", "")
        notbefore = tls.get("notbefore", "")
        notafter = tls.get("notafter", "")

        # JA3 fingerprints — may be nested or flat
        ja3_obj = tls.get("ja3", {})
        ja3s_obj = tls.get("ja3s", {})
        if isinstance(ja3_obj, dict):
            ja3_hash = ja3_obj.get("hash", "")
            ja3_string = ja3_obj.get("string", "")
        else:
            ja3_hash = str(ja3_obj) if ja3_obj else ""
            ja3_string = ""
        if isinstance(ja3s_obj, dict):
            ja3s_hash = ja3s_obj.get("hash", "")
            ja3s_string = ja3s_obj.get("string", "")
        else:
            ja3s_hash = str(ja3s_obj) if ja3s_obj else ""
            ja3s_string = ""

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "suricata_event_type": "tls",
            "flow_id": flow_id,
            "source_port": src_port,
            "destination_port": dest_port,
            # TLS fields
            "tls_subject": subject or None,
            "tls_issuerdn": issuerdn or None,
            "tls_serial": serial or None,
            "tls_fingerprint": fingerprint or None,
            "tls_sni": sni or None,
            "tls_version": version or None,
            "tls_notbefore": notbefore or None,
            "tls_notafter": notafter or None,
            "ja3": ja3_hash or None,
            "ja3_string": ja3_string or None,
            "ja3s": ja3s_hash or None,
            "ja3s_string": ja3s_string or None,
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
            result="success",
            service="suricata",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # fileinfo events
    # ------------------------------------------------------------------

    def _parse_fileinfo(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata fileinfo event."""
        src_ip = raw_event.get("src_ip", "")
        src_port = self._safe_int(raw_event.get("src_port"))
        dest_ip = raw_event.get("dest_ip", "")
        dest_port = self._safe_int(raw_event.get("dest_port"))
        flow_id = raw_event.get("flow_id")
        app_proto = raw_event.get("app_proto", "")

        fileinfo = raw_event.get("fileinfo", {})
        if not isinstance(fileinfo, dict):
            fileinfo = {}

        filename = fileinfo.get("filename", "")
        size = fileinfo.get("size")
        state = fileinfo.get("state", "")
        md5 = fileinfo.get("md5", "")
        sha1 = fileinfo.get("sha1", "")
        sha256 = fileinfo.get("sha256", "")
        magic = fileinfo.get("magic", "")
        stored = fileinfo.get("stored")
        tx_id = fileinfo.get("tx_id")
        gaps = fileinfo.get("gaps")

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "suricata_event_type": "fileinfo",
            "flow_id": flow_id,
            "source_port": src_port,
            "destination_port": dest_port,
            "app_proto": app_proto or None,
            # File fields
            "filename": filename or None,
            "file_size": size,
            "file_state": state or None,
            "md5": md5 or None,
            "sha1": sha1 or None,
            "sha256": sha256 or None,
            "file_magic": magic or None,
            "stored": stored,
            "tx_id": tx_id,
            "gaps": gaps,
            "direction": self._infer_direction(src_ip, dest_ip),
            "is_internal": self._is_internal(src_ip, dest_ip),
            "tags": ["file"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action="file_transfer",
            result="success",
            service="suricata",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # Generic fallback
    # ------------------------------------------------------------------

    def _parse_generic(
        self, raw_event: Dict[str, Any], event_type: Optional[str]
    ) -> Dict[str, Any]:
        """Best-effort parse for unrecognised Suricata event types."""
        src_ip = raw_event.get("src_ip", "")
        dest_ip = raw_event.get("dest_ip", "")
        flow_id = raw_event.get("flow_id")

        timestamp = self._parse_suricata_timestamp(raw_event.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "suricata_event_type": event_type,
            "flow_id": flow_id,
            "tags": ["network"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"suricata_{event_type}" if event_type else "suricata_unknown",
            result="unknown",
            service="suricata",
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
    def _extract_dns_ips(
        answers: Any, rdata: str, grouped: Any
    ) -> List[str]:
        """Extract IP addresses from Suricata DNS answers, rdata, or grouped.

        Suricata DNS events may include resolved IPs in:
          - ``dns.answers[].rdata`` (list of answer dicts)
          - ``dns.rdata`` (single answer string)
          - ``dns.grouped.A`` / ``dns.grouped.AAAA`` (grouped answers)
        """
        ips: List[str] = []

        # From answers list (list of dicts with rdata field)
        if isinstance(answers, list):
            for answer in answers:
                if isinstance(answer, dict):
                    rd = answer.get("rdata", "")
                    if rd and isinstance(rd, str) and _is_ip_address(rd):
                        if rd not in ips:
                            ips.append(rd)
                elif isinstance(answer, str) and _is_ip_address(answer):
                    if answer not in ips:
                        ips.append(answer)

        # From rdata (single string)
        if rdata and isinstance(rdata, str) and _is_ip_address(rdata):
            if rdata not in ips:
                ips.append(rdata)

        # From grouped answers
        if isinstance(grouped, dict):
            for key in ("A", "AAAA"):
                group_ips = grouped.get(key, [])
                if isinstance(group_ips, list):
                    for ip in group_ips:
                        if isinstance(ip, str) and _is_ip_address(ip):
                            if ip not in ips:
                                ips.append(ip)

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
    # Protocol normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_protocol(proto: Any) -> Optional[str]:
        """Normalise protocol value to uppercase name.

        Handles both string names ("TCP") and numeric values ("6").
        """
        if not proto:
            return None
        proto_str = str(proto).strip()
        # Check if numeric
        if proto_str in _PROTOCOL_MAP:
            return _PROTOCOL_MAP[proto_str]
        # Already a name — uppercase it
        return proto_str.upper()

    # ------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_suricata_timestamp(ts: Any) -> Optional[datetime]:
        """Parse a Suricata EVE timestamp.

        Suricata timestamps are ISO 8601 strings, typically:
          ``2024-06-15T10:00:00.000000+0000``

        May also be epoch floats in some configurations.

        Args:
            ts: Timestamp value (string, float, or int).

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

        if isinstance(ts, str):
            # Suricata format: 2024-06-15T10:00:00.000000+0000
            # Python's fromisoformat needs +00:00 not +0000
            normalized = ts

            # Handle Z suffix
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"

            # Handle +0000 / -0000 (no colon) → +00:00 / -00:00
            # Match pattern: +HHMM or -HHMM at end of string
            tz_match = re.search(r"([+-])(\d{2})(\d{2})$", normalized)
            if tz_match:
                sign, hours, minutes = tz_match.groups()
                normalized = normalized[:tz_match.start()] + f"{sign}{hours}:{minutes}"

            try:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

            # Try as epoch string
            try:
                epoch = float(ts)
                return datetime.fromtimestamp(epoch, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                pass

        return None

    # ------------------------------------------------------------------
    # Flow duration helper
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_duration(start: str, end: str) -> Optional[float]:
        """Compute duration in seconds between two Suricata timestamps.

        Args:
            start: Flow start timestamp string.
            end: Flow end timestamp string.

        Returns:
            Duration in seconds or ``None``.
        """
        if not start or not end:
            return None
        start_dt = SuricataParser._parse_suricata_timestamp(start)
        end_dt = SuricataParser._parse_suricata_timestamp(end)
        if start_dt is None or end_dt is None:
            return None
        diff = (end_dt - start_dt).total_seconds()
        return diff if diff >= 0 else None

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


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def _is_ip_address(value: str) -> bool:
    """Return ``True`` if *value* looks like an IPv4 or IPv6 address."""
    if _IPV4_RE.match(value):
        return True
    if ":" in value and _IPV6_RE.match(value):
        return True
    return False
