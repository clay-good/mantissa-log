"""GCP Cloud DNS Query Log parser for NDR.

Parses GCP Cloud DNS query logs delivered through Cloud Logging and
normalises them to the ``ParsedEvent``-compatible structure used across
all NDR parsers.  Includes inline Shannon entropy computation for
subdomain analysis (DNS tunneling / DGA detection), matching the
Route 53 DNS parser output.

GCP Cloud DNS logs reference:
  https://cloud.google.com/dns/docs/monitoring

Example Cloud Logging entry for a DNS query::

    {
        "insertId": "abc123",
        "resource": {
            "type": "dns_query",
            "labels": {
                "project_id": "my-project",
                "target_name": "my-policy",
                "target_type": "policy",
                "source_type": "internet"
            }
        },
        "timestamp": "2025-06-15T10:00:00.000000Z",
        "jsonPayload": {
            "queryName": "api.example.com.",
            "queryType": "A",
            "responseCode": "NOERROR",
            "protocol": "UDP",
            "sourceIP": "10.0.0.4",
            "vmInstanceId": "123456789",
            "vmInstanceName": "my-instance",
            "vmInstanceIdString": "123456789",
            "vmProjectId": "my-project",
            "vmZoneName": "us-central1-a",
            "answers": [
                {
                    "name": "api.example.com.",
                    "type": "A",
                    "class": "IN",
                    "rdata": "93.184.216.34",
                    "ttl": 300
                }
            ],
            "serverLatency": "0.001s",
            "sourceNetwork": "default",
            "destinationIP": "8.8.8.8",
            "egressError": ""
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


class GCPCloudDNSParser(BaseParser):
    """Parser for GCP Cloud DNS Query Logs.

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    uniformly across AWS, GCP, and Azure DNS log data.
    """

    def __init__(self):
        super().__init__()
        self.source_type = "gcp_cloud_dns"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a GCP Cloud DNS query log entry.

        Args:
            raw_event: Raw Cloud DNS query log as a dictionary (Cloud
                Logging envelope).

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``.
        """
        payload = raw_event.get("jsonPayload", {})
        if not isinstance(payload, dict):
            payload = {}

        resource = raw_event.get("resource", {})
        if not isinstance(resource, dict):
            resource = {}
        resource_labels = resource.get("labels", {})
        if not isinstance(resource_labels, dict):
            resource_labels = {}

        # ----- Core fields -----
        query_name = payload.get("queryName", "")
        query_type = payload.get("queryType", "")
        response_code = payload.get("responseCode", "")
        protocol = payload.get("protocol", "")
        source_ip = payload.get("sourceIP", "")
        destination_ip = payload.get("destinationIP", "")

        # ----- VM context -----
        vm_instance_id = (
            payload.get("vmInstanceIdString", "")
            or payload.get("vmInstanceId", "")
        )
        vm_instance_name = payload.get("vmInstanceName", "")
        vm_project_id = payload.get("vmProjectId", "")
        vm_zone_name = payload.get("vmZoneName", "")

        # ----- Network context -----
        source_network = payload.get("sourceNetwork", "")
        egress_error = payload.get("egressError", "")

        # ----- Answers -----
        answers = payload.get("answers", [])
        resolved_ips = self._extract_resolved_ips(answers)

        # ----- Server latency -----
        server_latency_raw = payload.get("serverLatency", "")
        server_latency_ms = self._parse_latency(server_latency_raw)

        # ----- Resource labels -----
        project_id = resource_labels.get("project_id", "")
        target_name = resource_labels.get("target_name", "")
        target_type = resource_labels.get("target_type", "")
        source_type_label = resource_labels.get("source_type", "")

        # ----- Timestamp -----
        timestamp = self._parse_timestamp(raw_event.get("timestamp", ""))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # ----- Domain analysis -----
        clean_name = self._strip_trailing_dot(query_name)
        labels = clean_name.split(".") if clean_name else []
        subdomain_count = len(labels)
        leftmost_label = labels[0] if labels else ""
        subdomain_entropy = shannon_entropy(leftmost_label)

        # ----- Response analysis -----
        is_nxdomain = response_code.upper() == "NXDOMAIN" if response_code else False
        is_external = self._has_external_resolution(resolved_ips)

        # ----- Determine result -----
        if response_code:
            result = "success" if response_code.upper() == "NOERROR" else "failure"
        else:
            result = "unknown"

        # ----- Build metadata -----
        metadata: Dict[str, Any] = {
            # Query info
            "query_name": clean_name,
            "query_type": query_type,
            "response_code": response_code,
            "transport": protocol,
            # Answer info
            "answers": answers,
            "resolved_ips": resolved_ips,
            # DNS analysis
            "is_nxdomain": is_nxdomain,
            "subdomain_count": subdomain_count,
            "subdomain_entropy": subdomain_entropy,
            "is_external_resolution": is_external,
            "domain_age_days": None,  # Populated by enrichment pipeline
            # Server latency
            "server_latency_ms": server_latency_ms,
            # GCP context
            "project_id": project_id or vm_project_id or None,
            "vm_instance_id": vm_instance_id or None,
            "vm_instance_name": vm_instance_name or None,
            "vm_zone_name": vm_zone_name or None,
            "source_network": source_network or None,
            "destination_ip": destination_ip or None,
            "egress_error": egress_error or None,
            # Resource labels
            "target_name": target_name or None,
            "target_type": target_type or None,
            "source_type_label": source_type_label or None,
            # NDR tags
            "tags": ["dns"],
        }

        event = ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip or None,
            destination_ip=destination_ip or None,
            user=None,
            action=f"dns_query_{query_type.lower()}" if query_type else "dns_query",
            result=result,
            service="cloud_dns",
            raw_event=raw_event,
            metadata=metadata,
        )
        return event.to_dict()

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like a GCP Cloud DNS query log.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid GCP Cloud DNS log.
        """
        if not isinstance(raw_event, dict):
            return False

        # Check for resource.type == "dns_query"
        resource = raw_event.get("resource", {})
        if isinstance(resource, dict):
            if resource.get("type") == "dns_query":
                return True

        # Check jsonPayload for queryName (essential DNS field)
        payload = raw_event.get("jsonPayload", {})
        if isinstance(payload, dict) and "queryName" in payload:
            # Must also have at least one GCP Cloud DNS specific field
            gcp_dns_fields = {
                "responseCode", "queryType", "sourceIP", "protocol",
                "serverLatency",
            }
            if gcp_dns_fields.intersection(payload.keys()):
                return True

        return False

    # ------------------------------------------------------------------
    # Answer extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_resolved_ips(answers: List[Dict[str, Any]]) -> List[str]:
        """Extract IP addresses from DNS answer records.

        GCP Cloud DNS answers use lowercase field names: ``name``,
        ``type``, ``class``, ``rdata``, ``ttl``.

        Args:
            answers: List of answer record dicts.

        Returns:
            De-duplicated list of resolved IP addresses.
        """
        ips: List[str] = []
        if not isinstance(answers, list):
            return ips

        for answer in answers:
            if not isinstance(answer, dict):
                continue
            rdata = answer.get("rdata", answer.get("Rdata", ""))
            answer_type = answer.get("type", answer.get("Type", ""))
            if not rdata:
                continue

            if answer_type in ("A", "AAAA"):
                if rdata not in ips:
                    ips.append(rdata)
            elif not answer_type:
                # Try to detect IPs without explicit type
                if _is_ip_address(rdata):
                    if rdata not in ips:
                        ips.append(rdata)

        return ips

    # ------------------------------------------------------------------
    # Internal traffic / external resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _is_rfc1918(ip: str) -> bool:
        """Return ``True`` if *ip* is an RFC 1918 private IPv4 address."""
        return bool(_RFC1918_RE.match(ip))

    @staticmethod
    def _has_external_resolution(resolved_ips: List[str]) -> bool:
        """Return ``True`` if any resolved IP is public (non-RFC1918).

        Returns ``False`` if there are no resolved IPs.
        """
        for ip in resolved_ips:
            if not GCPCloudDNSParser._is_rfc1918(ip):
                return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_trailing_dot(name: str) -> str:
        """Strip the trailing dot from a DNS name if present."""
        if name and name.endswith("."):
            return name[:-1]
        return name

    @staticmethod
    def _parse_latency(latency_str: Any) -> Optional[float]:
        """Parse a GCP serverLatency value to milliseconds.

        GCP expresses latency as a Duration string, e.g. ``"0.001s"``
        or ``"0.000234s"``.  This converts to milliseconds.

        Args:
            latency_str: Latency string (e.g. ``"0.001s"``).

        Returns:
            Latency in milliseconds, or ``None`` if unparseable.
        """
        if not latency_str or not isinstance(latency_str, str):
            return None
        cleaned = latency_str.strip()
        if cleaned.endswith("s"):
            cleaned = cleaned[:-1]
        try:
            seconds = float(cleaned)
            return round(seconds * 1000, 4)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_timestamp(ts: Any) -> Optional[datetime]:
        """Parse a GCP Cloud Logging timestamp.

        GCP timestamps are RFC 3339 / ISO 8601 strings, often with
        nanosecond precision (e.g. ``"2025-06-15T10:00:00.000000000Z"``).

        Args:
            ts: Timestamp string or ``None``.

        Returns:
            ``datetime`` with UTC timezone or ``None`` if parsing fails.
        """
        if not ts or not isinstance(ts, str):
            return None

        normalized = ts
        # Replace trailing Z with +00:00
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        # Truncate nanosecond precision to microseconds
        # Match pattern: digits after decimal point before timezone offset
        nano_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)(.*)",
            normalized,
        )
        if nano_match:
            base = nano_match.group(1)
            frac = nano_match.group(2)[:6].ljust(6, "0")  # Truncate to 6 digits
            suffix = nano_match.group(3)
            normalized = f"{base}.{frac}{suffix}"

        try:
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass

        # Fallback formats
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        return None


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

# IPv4 pattern for extracting IPs from answer rdata.
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# IPv6 simplified detection (contains colons, no dots-only).
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def _is_ip_address(value: str) -> bool:
    """Return ``True`` if *value* looks like an IPv4 or IPv6 address."""
    return bool(_IPV4_RE.match(value) or _IPV6_RE.match(value))
