"""AWS Route 53 Resolver DNS Query Log parser for NDR.

Parses Route 53 Resolver query logs delivered to CloudWatch Logs and
normalizes them to the ``ParsedEvent``-compatible structure used across
all NDR parsers.  Includes inline Shannon entropy computation for
subdomain analysis (DNS tunneling / DGA detection).

Route 53 Resolver query log reference:
  https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html

Example log entry::

    {
        "version": "1.100000",
        "account_id": "123456789012",
        "region": "us-east-1",
        "vpc_id": "vpc-abc123",
        "query_timestamp": "2025-06-15T10:00:00Z",
        "query_name": "api.example.com.",
        "query_type": "A",
        "query_class": "IN",
        "rcode": "NOERROR",
        "answers": [
            {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}
        ],
        "srcaddr": "10.0.0.4",
        "srcport": "54321",
        "transport": "UDP",
        "srcids": {"instance": "i-0abc123", "resolver_endpoint": "..."},
        "firewall_rule_group_id": "",
        "firewall_rule_action": "",
        "firewall_domain_list_id": ""
    }
"""

import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseParser, ParsedEvent

# Pre-compiled regex for RFC 1918 private address detection.
_RFC1918_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)

# IPv4 pattern for extracting IPs from answer rdata.
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# IPv6 simplified detection (contains colons, no dots-only).
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string.

    Calculates ``-sum(p * log2(p))`` for each unique character,
    where ``p`` is the frequency of that character.

    Args:
        s: Input string.

    Returns:
        Shannon entropy as a float.  Returns ``0.0`` for empty strings.
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class Route53DNSParser(BaseParser):
    """Parser for AWS Route 53 Resolver DNS Query Logs.

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    uniformly across AWS, GCP, and Azure DNS log data.
    """

    def __init__(self):
        super().__init__()
        self.source_type = "route53_dns"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Route 53 Resolver DNS query log entry.

        Args:
            raw_event: Raw Route 53 query log as a dictionary.

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``.
        """
        # ----- Core fields -----
        version = raw_event.get("version", "")
        account_id = raw_event.get("account_id", "")
        region = raw_event.get("region", "")
        vpc_id = raw_event.get("vpc_id", "")
        query_timestamp = raw_event.get("query_timestamp", "")
        query_name = raw_event.get("query_name", "")
        query_type = raw_event.get("query_type", "")
        query_class = raw_event.get("query_class", "IN")
        rcode = raw_event.get("rcode", "")
        transport = raw_event.get("transport", "")
        srcaddr = raw_event.get("srcaddr", "")
        srcport = raw_event.get("srcport", "")
        edns_client_subnet = raw_event.get("edns_client_subnet", "")

        # ----- Answers -----
        answers = raw_event.get("answers", [])
        resolved_ips = self._extract_resolved_ips(answers)

        # ----- Source IDs -----
        srcids = raw_event.get("srcids", {})
        instance_id = srcids.get("instance", "") if isinstance(srcids, dict) else ""
        resolver_endpoint = srcids.get("resolver_endpoint", "") if isinstance(srcids, dict) else ""

        # ----- Firewall info -----
        firewall_rule_group_id = raw_event.get("firewall_rule_group_id", "")
        firewall_rule_action = raw_event.get("firewall_rule_action", "")
        firewall_domain_list_id = raw_event.get("firewall_domain_list_id", "")

        # ----- Timestamp -----
        timestamp = self._parse_timestamp(query_timestamp)
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

        # ----- Build metadata -----
        metadata: Dict[str, Any] = {
            # Query info
            "query_name": clean_name,
            "query_type": query_type,
            "query_class": query_class,
            "response_code": rcode,
            "transport": transport,
            # Answer info
            "answers": answers,
            "resolved_ips": resolved_ips,
            # DNS analysis
            "is_nxdomain": is_nxdomain,
            "subdomain_count": subdomain_count,
            "subdomain_entropy": subdomain_entropy,
            "is_external_resolution": is_external,
            "domain_age_days": None,  # Populated by enrichment pipeline
            # Source info
            "source_port": self._safe_int(srcport),
            "edns_client_subnet": edns_client_subnet or None,
            # AWS context
            "version": version,
            "account_id": account_id,
            "region": region,
            "vpc_id": vpc_id,
            "instance_id": instance_id or None,
            "resolver_endpoint": resolver_endpoint or None,
            # Firewall info
            "firewall_rule_group_id": firewall_rule_group_id or None,
            "firewall_rule_action": firewall_rule_action or None,
            "firewall_domain_list_id": firewall_domain_list_id or None,
            # NDR tags
            "tags": ["dns"],
        }

        event = ParsedEvent(
            timestamp=timestamp,
            source_ip=srcaddr or None,
            destination_ip=None,
            user=None,
            action=f"dns_query_{query_type.lower()}" if query_type else "dns_query",
            result=result,
            service="route53",
            raw_event=raw_event,
            metadata=metadata,
        )
        return event.to_dict()

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like a Route 53 DNS query log.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid Route 53 query log.
        """
        if not isinstance(raw_event, dict):
            return False

        # Must have query_name — the essential DNS field
        if "query_name" not in raw_event:
            return False

        # Must have at least one of these Route 53 specific fields
        r53_fields = {"query_timestamp", "rcode", "query_type", "srcaddr"}
        if r53_fields.intersection(raw_event.keys()):
            return True

        return False

    # ------------------------------------------------------------------
    # Answer extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_resolved_ips(answers: List[Dict[str, Any]]) -> List[str]:
        """Extract IP addresses from DNS answer records.

        Looks for A and AAAA record types and extracts the rdata values
        that are valid IP addresses.

        Args:
            answers: List of answer record dicts with ``Rdata`` and ``Type``.

        Returns:
            De-duplicated list of resolved IP addresses.
        """
        ips: List[str] = []
        if not isinstance(answers, list):
            return ips

        for answer in answers:
            if not isinstance(answer, dict):
                continue
            rdata = answer.get("Rdata", answer.get("rdata", ""))
            answer_type = answer.get("Type", answer.get("type", ""))
            if not rdata:
                continue

            # Include A and AAAA records
            if answer_type in ("A", "AAAA"):
                if rdata not in ips:
                    ips.append(rdata)
            # Also detect IPs without explicit type
            elif not answer_type:
                if _IPV4_RE.match(rdata) or _IPV6_RE.match(rdata):
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
        """Return ``True`` if any resolved IP is a public (non-RFC1918) address.

        Returns ``False`` if there are no resolved IPs.
        """
        for ip in resolved_ips:
            if not Route53DNSParser._is_rfc1918(ip):
                return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_trailing_dot(name: str) -> str:
        """Strip the trailing dot from a DNS name if present.

        DNS names in logs are often FQDN-qualified with a trailing dot
        (e.g. ``"api.example.com."``).
        """
        if name and name.endswith("."):
            return name[:-1]
        return name

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
        """Parse a Route 53 timestamp string.

        Route 53 timestamps are RFC 3339 / ISO 8601 strings.

        Args:
            ts: Timestamp string or ``None``.

        Returns:
            ``datetime`` with timezone or ``None`` if parsing fails.
        """
        if not ts or not isinstance(ts, str):
            return None

        # Replace trailing Z with +00:00
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
