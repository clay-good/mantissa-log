"""Azure DNS Analytics Log parser for NDR.

Parses Azure DNS Analytics logs available through Azure Monitor and
normalises them to the ``ParsedEvent``-compatible structure used across
all NDR parsers.  Includes Shannon entropy computation for subdomain
analysis (DNS tunneling / DGA detection), matching the Route 53 and
GCP Cloud DNS parser output.

Azure DNS Analytics reference:
  https://learn.microsoft.com/en-us/azure/dns/dns-analytics

Example Azure DNS Analytics log entry::

    {
        "time": "2025-06-15T10:00:00.0000000Z",
        "resourceId": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.com",
        "operationName": "DnsQueryLog",
        "category": "DnsQueryLog",
        "properties": {
            "QueryName": "api.example.com.",
            "QueryType": 1,
            "RCODE": "NOERROR",
            "ClientIP": "10.0.0.4",
            "Answer": "93.184.216.34",
            "TimeTaken": 15,
            "QNAME": "api.example.com.",
            "Message": "R]3[api]7[example]3[com]0[ Q]1[A] C]IN]",
            "ClientSubnet": "10.0.0.0/24",
            "Zone": "example.com",
            "Server": "dns-server-01"
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

# DNS query type numeric to name mapping (common types).
_QUERY_TYPE_MAP: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
    99: "SPF",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}

# IPv4 pattern for extracting IPs from answer strings.
_IPV4_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# IPv6 simplified detection.
_IPV6_RE = re.compile(r"[0-9a-fA-F:]{3,}")

# Strict IPv4 for single-value validation.
_IPV4_STRICT_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Strict IPv6 for single-value validation.
_IPV6_STRICT_RE = re.compile(r"^[0-9a-fA-F:]+$")


class AzureDNSParser(BaseParser):
    """Parser for Azure DNS Analytics Logs.

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    uniformly across AWS, GCP, and Azure DNS log data.
    """

    def __init__(self):
        super().__init__()
        self.source_type = "azure_dns"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an Azure DNS Analytics log entry.

        Args:
            raw_event: Raw Azure DNS Analytics log as a dictionary.

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``.
        """
        properties = raw_event.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        # ----- Core fields -----
        # Azure uses both QueryName and QNAME; prefer QueryName
        query_name = (
            properties.get("QueryName", "")
            or properties.get("QNAME", "")
        )
        query_type_raw = properties.get("QueryType", "")
        rcode = properties.get("RCODE", "")
        client_ip = properties.get("ClientIP", "")
        answer_raw = properties.get("Answer", "")
        time_taken = properties.get("TimeTaken", None)
        message = properties.get("Message", "")

        # ----- Optional fields -----
        client_subnet = properties.get("ClientSubnet", "")
        zone = properties.get("Zone", "")
        server = properties.get("Server", "")

        # ----- Query type mapping -----
        query_type_name = self._resolve_query_type(query_type_raw)

        # ----- Answer extraction -----
        resolved_ips = self._extract_resolved_ips(answer_raw)

        # ----- Resource info -----
        resource_id = raw_event.get("resourceId", "")
        subscription_id, resource_group, dns_zone = self._parse_resource_id(
            resource_id
        )

        # ----- Timestamp -----
        timestamp = self._parse_timestamp(raw_event.get("time", ""))
        if timestamp is None:
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
        is_nxdomain = rcode.upper() == "NXDOMAIN" if rcode else False
        is_external = self._has_external_resolution(resolved_ips)

        # ----- Determine result -----
        if rcode:
            result = "success" if rcode.upper() == "NOERROR" else "failure"
        else:
            result = "unknown"

        # ----- Time taken to ms -----
        time_taken_ms = self._parse_time_taken(time_taken)

        # ----- Build metadata -----
        metadata: Dict[str, Any] = {
            # Query info
            "query_name": clean_name,
            "query_type": query_type_name,
            "query_type_id": self._safe_int(query_type_raw),
            "response_code": rcode,
            # Answer info
            "answer_raw": answer_raw if answer_raw else None,
            "resolved_ips": resolved_ips,
            # DNS analysis
            "is_nxdomain": is_nxdomain,
            "subdomain_count": subdomain_count,
            "subdomain_entropy": subdomain_entropy,
            "is_external_resolution": is_external,
            "domain_age_days": None,  # Populated by enrichment pipeline
            # Timing
            "time_taken_ms": time_taken_ms,
            # Azure context
            "subscription_id": subscription_id or None,
            "resource_group": resource_group or None,
            "dns_zone": dns_zone or zone or None,
            "server": server or None,
            "client_subnet": client_subnet or None,
            "message": message or None,
            "resource_id": resource_id or None,
            "operation_name": raw_event.get("operationName", None),
            "category": raw_event.get("category", None),
            # NDR tags
            "tags": ["dns"],
        }

        event = ParsedEvent(
            timestamp=timestamp,
            source_ip=client_ip or None,
            destination_ip=None,
            user=None,
            action=(
                f"dns_query_{query_type_name.lower()}"
                if query_type_name
                else "dns_query"
            ),
            result=result,
            service="azure_dns",
            raw_event=raw_event,
            metadata=metadata,
        )
        return event.to_dict()

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like an Azure DNS Analytics log.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid Azure DNS Analytics log.
        """
        if not isinstance(raw_event, dict):
            return False

        # Check category or operationName
        category = raw_event.get("category", "")
        if isinstance(category, str) and "dns" in category.lower():
            return True

        operation = raw_event.get("operationName", "")
        if isinstance(operation, str) and "dns" in operation.lower():
            return True

        # Check properties for DNS-specific fields
        properties = raw_event.get("properties", {})
        if isinstance(properties, dict):
            dns_fields = {"QueryName", "QNAME", "QueryType", "RCODE"}
            if dns_fields.intersection(properties.keys()):
                return True

        # Check resourceId for DNS zone pattern
        resource_id = raw_event.get("resourceId", "")
        if isinstance(resource_id, str) and "dnszones" in resource_id.lower():
            return True

        return False

    # ------------------------------------------------------------------
    # Query type resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_query_type(raw_value: Any) -> str:
        """Resolve a query type to its name.

        Azure DNS Analytics logs may provide the query type as a numeric
        value (e.g. ``1`` for ``A``) or as a string name.

        Args:
            raw_value: Numeric or string query type.

        Returns:
            Query type name (e.g. ``"A"``), or the raw string if not
            a known numeric type, or empty string if not resolvable.
        """
        if isinstance(raw_value, int):
            return _QUERY_TYPE_MAP.get(raw_value, f"TYPE{raw_value}")
        if isinstance(raw_value, str):
            if raw_value.isdigit():
                type_int = int(raw_value)
                return _QUERY_TYPE_MAP.get(type_int, f"TYPE{type_int}")
            return raw_value
        return ""

    # ------------------------------------------------------------------
    # Answer extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_resolved_ips(answer: Any) -> List[str]:
        """Extract IP addresses from the Azure DNS answer field.

        The Azure ``Answer`` field can be:
        - A single IP address string (e.g. ``"93.184.216.34"``)
        - A semicolon-separated list of IPs (e.g. ``"1.2.3.4;5.6.7.8"``)
        - A complex answer string containing IPs mixed with other data
        - A list of answer record dicts (less common)

        Args:
            answer: Raw answer field value.

        Returns:
            De-duplicated list of resolved IP addresses.
        """
        ips: List[str] = []
        if not answer:
            return ips

        if isinstance(answer, list):
            for item in answer:
                if isinstance(item, dict):
                    rdata = item.get("rdata", item.get("Rdata", ""))
                    if rdata and _is_ip_address(rdata):
                        if rdata not in ips:
                            ips.append(rdata)
                elif isinstance(item, str) and _is_ip_address(item):
                    if item not in ips:
                        ips.append(item)
            return ips

        if not isinstance(answer, str):
            return ips

        # Try semicolon-separated values first
        parts = answer.split(";")
        for part in parts:
            part = part.strip()
            if _is_ip_address(part):
                if part not in ips:
                    ips.append(part)

        # If no IPs found from splitting, try regex extraction
        if not ips:
            for match in _IPV4_RE.finditer(answer):
                ip = match.group()
                if ip not in ips:
                    ips.append(ip)

        return ips

    # ------------------------------------------------------------------
    # Resource ID parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_resource_id(
        resource_id: str,
    ) -> tuple:
        """Extract Azure resource details from a resource ID.

        Example resource ID::

            /subscriptions/abc-def/resourceGroups/my-rg/providers/
            Microsoft.Network/dnszones/example.com

        Args:
            resource_id: Azure resource ID string.

        Returns:
            Tuple of ``(subscription_id, resource_group, dns_zone)``.
        """
        subscription_id = ""
        resource_group = ""
        dns_zone = ""

        if not resource_id or not isinstance(resource_id, str):
            return subscription_id, resource_group, dns_zone

        parts = resource_id.strip("/").split("/")
        # Walk through key-value pairs in the path
        for i in range(len(parts) - 1):
            lower = parts[i].lower()
            if lower == "subscriptions":
                subscription_id = parts[i + 1]
            elif lower == "resourcegroups":
                resource_group = parts[i + 1]
            elif lower == "dnszones":
                dns_zone = parts[i + 1]

        return subscription_id, resource_group, dns_zone

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
            if not AzureDNSParser._is_rfc1918(ip):
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
    def _parse_time_taken(value: Any) -> Optional[float]:
        """Convert Azure TimeTaken to milliseconds.

        Azure DNS Analytics expresses TimeTaken in microseconds as an
        integer.

        Args:
            value: TimeTaken value (int or string, in microseconds).

        Returns:
            Time in milliseconds, or ``None`` if unparseable.
        """
        if value is None:
            return None
        try:
            microseconds = float(value)
            return round(microseconds / 1000, 4)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert *value* to ``int`` if possible, else ``None``."""
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_timestamp(ts: Any) -> Optional[datetime]:
        """Parse an Azure timestamp string.

        Azure timestamps are ISO 8601 strings, sometimes with
        7-digit fractional seconds (e.g. ``"...0000000Z"``).

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

        # Truncate excess fractional digits to microseconds (6 digits)
        frac_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)(.*)",
            normalized,
        )
        if frac_match:
            base = frac_match.group(1)
            frac = frac_match.group(2)[:6].ljust(6, "0")
            suffix = frac_match.group(3)
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


def _is_ip_address(value: str) -> bool:
    """Return ``True`` if *value* looks like an IPv4 or IPv6 address."""
    if not value or not isinstance(value, str):
        return False
    return bool(_IPV4_STRICT_RE.match(value) or _IPV6_STRICT_RE.match(value))
