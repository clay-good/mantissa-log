"""Unified Cloud Firewall Log parser for NDR.

Parses firewall logs from AWS Network Firewall, GCP VPC Firewall Rules,
and Azure Firewall into a normalised ``ParsedEvent``-compatible structure
used across all NDR parsers.

Supported log formats:

- **AWS Network Firewall** (Suricata-based): JSON logs with event_type,
  src_ip/dest_ip, alert metadata, and TLS/HTTP/DNS event details.
- **GCP VPC Firewall Rules**: Cloud Logging JSON with connection tuple,
  rule reference, disposition (ALLOWED/DENIED), instance details.
- **Azure Firewall**: Azure Monitor JSON with msg, protocol, source/dest,
  action (Allow/Deny/Drop), rule collection, threat intelligence.

All three formats are normalised to the same output shape:
  - source_ip, destination_ip, source_port, destination_port
  - protocol, action (allow, deny, drop, alert)
  - firewall_rule_name, direction, threat_category
  - tags: ["firewall"]

Example AWS Network Firewall log::

    {
        "firewall_name": "my-firewall",
        "availability_zone": "us-east-1a",
        "event_timestamp": "1718442000",
        "event": {
            "timestamp": "2025-06-15T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "signature_id": 2024897,
                "rev": 1,
                "signature": "ET MALWARE Bad SSL Cert",
                "category": "A Network Trojan was Detected",
                "severity": 1
            }
        }
    }

Example GCP VPC Firewall log::

    {
        "insertId": "abc123",
        "resource": {
            "type": "gce_subnetwork",
            "labels": {
                "project_id": "my-project",
                "subnetwork_name": "default",
                "subnetwork_id": "123456"
            }
        },
        "timestamp": "2025-06-15T10:00:00.000000Z",
        "jsonPayload": {
            "connection": {
                "src_ip": "10.0.0.4",
                "src_port": 54321,
                "dest_ip": "93.184.216.34",
                "dest_port": 443,
                "protocol": 6
            },
            "disposition": "ALLOWED",
            "rule_details": {
                "reference": "network:default/allow-https",
                "direction": "EGRESS",
                "priority": 1000,
                "action": "ALLOW",
                "source_range": ["10.0.0.0/8"],
                "destination_range": ["0.0.0.0/0"],
                "ip_port_info": [{"ip_protocol": "TCP", "port_range": ["443"]}]
            },
            "instance": {
                "project_id": "my-project",
                "vm_name": "my-instance",
                "region": "us-central1",
                "zone": "us-central1-a"
            },
            "vpc": {
                "vpc_name": "default",
                "project_id": "my-project",
                "subnetwork_name": "default"
            },
            "remote_location": {
                "country": "US",
                "region": "California",
                "city": "Los Angeles"
            }
        }
    }

Example Azure Firewall log::

    {
        "category": "AzureFirewallNetworkRule",
        "time": "2025-06-15T10:00:00.0000000Z",
        "resourceId": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/my-fw",
        "operationName": "AzureFirewallNetworkRuleLog",
        "properties": {
            "msg": "TCP request from 10.0.0.4:54321 to 93.184.216.34:443. Action: Allow. Rule Collection: AllowWeb. Rule: AllowHTTPS",
            "Protocol": "TCP",
            "SourceIP": "10.0.0.4",
            "SourcePort": "54321",
            "DestinationIP": "93.184.216.34",
            "DestinationPort": "443",
            "Action": "Allow",
            "RuleCollection": "AllowWeb",
            "Rule": "AllowHTTPS",
            "ThreatIntelligence": "",
            "Policy": "my-policy"
        }
    }
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseParser, ParsedEvent

# Pre-compiled regex for RFC 1918 private address detection.
_RFC1918_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)

# Protocol number to name mapping.
_PROTOCOL_NUM_MAP: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    132: "SCTP",
}

# Normalised action mapping across clouds.
_ACTION_MAP: Dict[str, str] = {
    # AWS Network Firewall
    "allowed": "allow",
    "blocked": "deny",
    "pass": "allow",
    "drop": "drop",
    "reject": "deny",
    "alert": "alert",
    # GCP
    "allow": "allow",
    "deny": "deny",
    "allowed": "allow",
    "denied": "deny",
    # Azure
    "allow": "allow",
    "deny": "deny",
    "drop": "drop",
}

# Azure Firewall msg regex for extracting connection details.
_AZURE_MSG_RE = re.compile(
    r"(?P<proto>\w+)\s+request\s+from\s+"
    r"(?P<src_ip>[^:]+):(?P<src_port>\d+)\s+to\s+"
    r"(?P<dest_ip>[^:]+):(?P<dest_port>\d+)\."
    r"(?:\s+Action:\s*(?P<action>\w+))?"
    r"(?:\.\s*Rule\s+Collection:\s*(?P<rule_collection>[^.]+))?"
    r"(?:\.\s*Rule:\s*(?P<rule>[^.]+))?"
)


class CloudFirewallParser(BaseParser):
    """Unified parser for cloud firewall logs (AWS, GCP, Azure).

    Auto-detects the cloud provider from the log structure and
    normalises all three formats to the same ``ParsedEvent.to_dict()``
    output shape so NDR detection rules work uniformly.
    """

    def __init__(self):
        super().__init__()
        self.source_type = "cloud_firewall"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a cloud firewall log entry from any supported cloud.

        Args:
            raw_event: Raw firewall log as a dictionary.

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``.
        """
        provider = self._detect_provider(raw_event)

        if provider == "aws":
            return self._parse_aws(raw_event)
        elif provider == "gcp":
            return self._parse_gcp(raw_event)
        elif provider == "azure":
            return self._parse_azure(raw_event)

        # Unknown format — return best-effort parse
        return self._parse_generic(raw_event)

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like a cloud firewall log.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid firewall log.
        """
        if not isinstance(raw_event, dict):
            return False

        provider = self._detect_provider(raw_event)
        return provider is not None

    # ------------------------------------------------------------------
    # Provider detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_provider(raw_event: Dict[str, Any]) -> Optional[str]:
        """Detect which cloud provider generated this firewall log.

        Returns:
            ``"aws"``, ``"gcp"``, ``"azure"``, or ``None``.
        """
        if not isinstance(raw_event, dict):
            return None

        # AWS Network Firewall: has firewall_name or event.event_type
        if "firewall_name" in raw_event:
            return "aws"
        event = raw_event.get("event", {})
        if isinstance(event, dict) and event.get("event_type") in (
            "alert", "flow", "tls", "http", "dns", "drop", "netflow",
        ):
            return "aws"

        # GCP VPC Firewall: has jsonPayload with disposition or rule_details
        payload = raw_event.get("jsonPayload", {})
        if isinstance(payload, dict):
            if "disposition" in payload or "rule_details" in payload:
                return "gcp"

        # Azure Firewall: category contains "Firewall" or properties
        # with firewall-specific fields
        category = raw_event.get("category", "")
        if isinstance(category, str) and "firewall" in category.lower():
            return "azure"

        operation = raw_event.get("operationName", "")
        if isinstance(operation, str) and "firewall" in operation.lower():
            return "azure"

        properties = raw_event.get("properties", {})
        if isinstance(properties, dict):
            if "Action" in properties and (
                "SourceIP" in properties or "msg" in properties
            ):
                return "azure"

        # Check resourceId for azure firewall
        resource_id = raw_event.get("resourceId", "")
        if isinstance(resource_id, str) and "azurefirewalls" in resource_id.lower():
            return "azure"

        return None

    # ------------------------------------------------------------------
    # AWS Network Firewall
    # ------------------------------------------------------------------

    def _parse_aws(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an AWS Network Firewall log entry."""
        event = raw_event.get("event", {})
        if not isinstance(event, dict):
            event = {}

        # Connection info
        src_ip = event.get("src_ip", "")
        src_port = self._safe_int(event.get("src_port"))
        dest_ip = event.get("dest_ip", "")
        dest_port = self._safe_int(event.get("dest_port"))
        proto = event.get("proto", "")

        # Event type
        event_type = event.get("event_type", "")

        # Alert metadata (Suricata)
        alert = event.get("alert", {})
        if not isinstance(alert, dict):
            alert = {}
        alert_action = alert.get("action", "")
        signature_id = alert.get("signature_id")
        signature = alert.get("signature", "")
        alert_category = alert.get("category", "")
        alert_severity = alert.get("severity")

        # Rule group (AWS-specific)
        rule_group = event.get("rule_group", "")

        # Determine action
        if alert_action:
            action = self._normalize_action(alert_action)
        elif event_type == "alert":
            action = "alert"
        elif event_type == "drop":
            action = "drop"
        else:
            action = "allow"

        # Flow metadata
        flow = event.get("flow", {})
        if not isinstance(flow, dict):
            flow = {}

        # Timestamp
        timestamp = self._parse_aws_timestamp(
            event.get("timestamp", ""),
            raw_event.get("event_timestamp", ""),
        )
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Direction from flow or heuristic
        app_proto = event.get("app_proto", "")
        direction = self._infer_direction(src_ip, dest_ip)

        # Firewall context
        firewall_name = raw_event.get("firewall_name", "")
        availability_zone = raw_event.get("availability_zone", "")

        # Threat category from Suricata alert
        threat_category = alert_category or None

        # Build metadata
        metadata: Dict[str, Any] = {
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": proto.upper() if proto else None,
            "action": action,
            "firewall_rule_name": rule_group or signature or None,
            "direction": direction,
            "threat_category": threat_category,
            "is_internal": self._is_internal(src_ip, dest_ip),
            # AWS-specific
            "cloud_provider": "aws",
            "firewall_name": firewall_name or None,
            "availability_zone": availability_zone or None,
            "event_type": event_type or None,
            "app_proto": app_proto or None,
            # Suricata alert details
            "signature_id": signature_id,
            "signature": signature or None,
            "alert_severity": alert_severity,
            # Flow stats
            "bytes_toserver": flow.get("bytes_toserver"),
            "bytes_toclient": flow.get("bytes_toclient"),
            "pkts_toserver": flow.get("pkts_toserver"),
            "pkts_toclient": flow.get("pkts_toclient"),
            # NDR tags
            "tags": ["firewall"],
        }

        # TLS metadata if present
        tls = event.get("tls", {})
        if isinstance(tls, dict) and tls:
            metadata["tls_sni"] = tls.get("sni", None)
            metadata["tls_version"] = tls.get("version", None)
            metadata["tls_ja3_hash"] = tls.get("ja3", {}).get("hash", None) if isinstance(tls.get("ja3"), dict) else None

        # HTTP metadata if present
        http = event.get("http", {})
        if isinstance(http, dict) and http:
            metadata["http_hostname"] = http.get("hostname", None)
            metadata["http_url"] = http.get("url", None)
            metadata["http_method"] = http.get("http_method", None)
            metadata["http_status"] = http.get("status")

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"firewall_{action}",
            result="blocked" if action in ("deny", "drop", "alert") else "allowed",
            service="aws_network_firewall",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # GCP VPC Firewall Rules
    # ------------------------------------------------------------------

    def _parse_gcp(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a GCP VPC Firewall Rules log entry."""
        payload = raw_event.get("jsonPayload", {})
        if not isinstance(payload, dict):
            payload = {}

        # Connection info
        connection = payload.get("connection", {})
        if not isinstance(connection, dict):
            connection = {}
        src_ip = connection.get("src_ip", "")
        src_port = self._safe_int(connection.get("src_port"))
        dest_ip = connection.get("dest_ip", "")
        dest_port = self._safe_int(connection.get("dest_port"))
        proto_num = connection.get("protocol")
        protocol = self._resolve_protocol(proto_num)

        # Disposition / action
        disposition = payload.get("disposition", "")
        action = self._normalize_action(disposition)

        # Rule details
        rule_details = payload.get("rule_details", {})
        if not isinstance(rule_details, dict):
            rule_details = {}
        rule_reference = rule_details.get("reference", "")
        rule_direction = rule_details.get("direction", "")
        rule_priority = rule_details.get("priority")
        rule_action = rule_details.get("action", "")
        source_range = rule_details.get("source_range", [])
        destination_range = rule_details.get("destination_range", [])
        ip_port_info = rule_details.get("ip_port_info", [])

        # Direction
        direction = self._normalize_direction(rule_direction)

        # Instance details
        instance = payload.get("instance", {})
        if not isinstance(instance, dict):
            instance = {}

        # VPC details
        vpc = payload.get("vpc", {})
        if not isinstance(vpc, dict):
            vpc = {}

        # Remote location
        remote_location = payload.get("remote_location", {})
        if not isinstance(remote_location, dict):
            remote_location = {}

        # Resource labels
        resource = raw_event.get("resource", {})
        if not isinstance(resource, dict):
            resource = {}
        resource_labels = resource.get("labels", {})
        if not isinstance(resource_labels, dict):
            resource_labels = {}

        # Timestamp
        timestamp = self._parse_gcp_timestamp(raw_event.get("timestamp", ""))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        metadata: Dict[str, Any] = {
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": protocol,
            "protocol_number": self._safe_int(proto_num),
            "action": action,
            "firewall_rule_name": rule_reference or None,
            "direction": direction,
            "threat_category": None,
            "is_internal": self._is_internal(src_ip, dest_ip),
            # GCP-specific
            "cloud_provider": "gcp",
            "disposition": disposition or None,
            "rule_priority": rule_priority,
            "rule_action": rule_action or None,
            "source_range": source_range if source_range else None,
            "destination_range": destination_range if destination_range else None,
            "ip_port_info": ip_port_info if ip_port_info else None,
            # Instance
            "instance_project_id": instance.get("project_id") or None,
            "instance_vm_name": instance.get("vm_name") or None,
            "instance_region": instance.get("region") or None,
            "instance_zone": instance.get("zone") or None,
            # VPC
            "vpc_name": vpc.get("vpc_name") or None,
            "vpc_project_id": vpc.get("project_id") or None,
            "subnetwork_name": (
                vpc.get("subnetwork_name")
                or resource_labels.get("subnetwork_name")
                or None
            ),
            # Remote location
            "remote_country": remote_location.get("country") or None,
            "remote_region": remote_location.get("region") or None,
            "remote_city": remote_location.get("city") or None,
            # NDR tags
            "tags": ["firewall"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"firewall_{action}",
            result="blocked" if action in ("deny", "drop") else "allowed",
            service="gcp_vpc_firewall",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # Azure Firewall
    # ------------------------------------------------------------------

    def _parse_azure(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an Azure Firewall log entry."""
        properties = raw_event.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        # Try structured fields first
        src_ip = properties.get("SourceIP", "")
        src_port = self._safe_int(properties.get("SourcePort"))
        dest_ip = properties.get("DestinationIP", "")
        dest_port = self._safe_int(properties.get("DestinationPort"))
        protocol = properties.get("Protocol", "")
        action_raw = properties.get("Action", "")
        rule_collection = properties.get("RuleCollection", "")
        rule = properties.get("Rule", "")
        threat_intel = properties.get("ThreatIntelligence", "")
        policy = properties.get("Policy", "")
        msg = properties.get("msg", "")

        # Fall back to msg parsing if structured fields are missing
        if not src_ip and msg:
            parsed_msg = self._parse_azure_msg(msg)
            if parsed_msg:
                src_ip = src_ip or parsed_msg.get("src_ip", "")
                if src_port is None:
                    src_port = self._safe_int(parsed_msg.get("src_port"))
                dest_ip = dest_ip or parsed_msg.get("dest_ip", "")
                if dest_port is None:
                    dest_port = self._safe_int(parsed_msg.get("dest_port"))
                protocol = protocol or parsed_msg.get("proto", "")
                action_raw = action_raw or parsed_msg.get("action", "")
                rule_collection = rule_collection or parsed_msg.get(
                    "rule_collection", ""
                )
                rule = rule or parsed_msg.get("rule", "")

        # Normalize action
        action = self._normalize_action(action_raw)

        # Resource ID parsing
        resource_id = raw_event.get("resourceId", "")
        subscription_id, resource_group, firewall_name = (
            self._parse_azure_firewall_resource_id(resource_id)
        )

        # Timestamp
        timestamp = self._parse_azure_timestamp(raw_event.get("time", ""))
        if timestamp is None:
            timestamp = self._parse_azure_timestamp(
                raw_event.get("timestamp", "")
            )
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Direction heuristic
        direction = self._infer_direction(src_ip, dest_ip)

        # Threat category
        threat_category = threat_intel if threat_intel else None

        # Determine firewall rule name
        firewall_rule_name = rule or rule_collection or None

        metadata: Dict[str, Any] = {
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": protocol.upper() if protocol else None,
            "action": action,
            "firewall_rule_name": firewall_rule_name,
            "direction": direction,
            "threat_category": threat_category,
            "is_internal": self._is_internal(src_ip, dest_ip),
            # Azure-specific
            "cloud_provider": "azure",
            "rule_collection": rule_collection or None,
            "rule": rule or None,
            "policy": policy or None,
            "msg": msg or None,
            "subscription_id": subscription_id or None,
            "resource_group": resource_group or None,
            "firewall_name": firewall_name or None,
            "category": raw_event.get("category") or None,
            "operation_name": raw_event.get("operationName") or None,
            # NDR tags
            "tags": ["firewall"],
        }

        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=f"firewall_{action}",
            result="blocked" if action in ("deny", "drop", "alert") else "allowed",
            service="azure_firewall",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # Generic fallback
    # ------------------------------------------------------------------

    def _parse_generic(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Best-effort parse for unrecognised firewall log formats."""
        timestamp = datetime.now(timezone.utc)
        metadata: Dict[str, Any] = {
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "action": "unknown",
            "firewall_rule_name": None,
            "direction": None,
            "threat_category": None,
            "is_internal": False,
            "cloud_provider": "unknown",
            "tags": ["firewall"],
        }
        parsed = ParsedEvent(
            timestamp=timestamp,
            source_ip=None,
            destination_ip=None,
            user=None,
            action="firewall_unknown",
            result="unknown",
            service="cloud_firewall",
            raw_event=raw_event,
            metadata=metadata,
        )
        return parsed.to_dict()

    # ------------------------------------------------------------------
    # Action / direction normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_action(raw_action: Any) -> str:
        """Normalise a firewall action string.

        Returns one of: ``"allow"``, ``"deny"``, ``"drop"``, ``"alert"``,
        or ``"unknown"``.
        """
        if not raw_action or not isinstance(raw_action, str):
            return "unknown"
        key = raw_action.strip().lower()
        return _ACTION_MAP.get(key, "unknown")

    @staticmethod
    def _normalize_direction(raw_direction: str) -> Optional[str]:
        """Normalise a direction string to ``"inbound"`` or ``"outbound"``.

        Args:
            raw_direction: Direction string from the log.

        Returns:
            ``"inbound"``, ``"outbound"``, or ``None``.
        """
        if not raw_direction:
            return None
        lower = raw_direction.strip().lower()
        if lower in ("ingress", "inbound", "in", "i"):
            return "inbound"
        if lower in ("egress", "outbound", "out", "o"):
            return "outbound"
        return None

    @staticmethod
    def _infer_direction(src_ip: str, dest_ip: str) -> Optional[str]:
        """Infer traffic direction from source/destination IP addresses.

        Heuristic: if source is private and destination is public,
        it's outbound.  If source is public and destination is private,
        it's inbound.  Otherwise ``None``.
        """
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
    # Protocol resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_protocol(proto: Any) -> Optional[str]:
        """Resolve a protocol number or string to a name.

        Args:
            proto: Protocol number (int) or name (str).

        Returns:
            Protocol name or ``None``.
        """
        if isinstance(proto, int):
            return _PROTOCOL_NUM_MAP.get(proto, f"PROTO{proto}")
        if isinstance(proto, str):
            if proto.isdigit():
                return _PROTOCOL_NUM_MAP.get(int(proto), f"PROTO{proto}")
            return proto.upper() if proto else None
        return None

    # ------------------------------------------------------------------
    # Azure msg parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_azure_msg(msg: str) -> Optional[Dict[str, str]]:
        """Extract connection details from an Azure Firewall msg string.

        Example msg::

            TCP request from 10.0.0.4:54321 to 93.184.216.34:443.
            Action: Allow. Rule Collection: AllowWeb. Rule: AllowHTTPS

        Returns:
            Dictionary with parsed fields or ``None``.
        """
        if not msg:
            return None
        match = _AZURE_MSG_RE.search(msg)
        if not match:
            return None
        return {k: v for k, v in match.groupdict().items() if v}

    # ------------------------------------------------------------------
    # Azure resource ID parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_azure_firewall_resource_id(
        resource_id: str,
    ) -> Tuple[str, str, str]:
        """Extract Azure resource details from a firewall resource ID.

        Returns:
            Tuple of ``(subscription_id, resource_group, firewall_name)``.
        """
        subscription_id = ""
        resource_group = ""
        firewall_name = ""

        if not resource_id or not isinstance(resource_id, str):
            return subscription_id, resource_group, firewall_name

        parts = resource_id.strip("/").split("/")
        for i in range(len(parts) - 1):
            lower = parts[i].lower()
            if lower == "subscriptions":
                subscription_id = parts[i + 1]
            elif lower == "resourcegroups":
                resource_group = parts[i + 1]
            elif lower == "azurefirewalls":
                firewall_name = parts[i + 1]

        return subscription_id, resource_group, firewall_name

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

    # ------------------------------------------------------------------
    # Timestamp helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_aws_timestamp(
        event_ts: str, epoch_ts: str = ""
    ) -> Optional[datetime]:
        """Parse AWS Network Firewall timestamp.

        Tries the event-level ISO timestamp first, then falls back
        to the epoch timestamp at the envelope level.
        """
        if event_ts and isinstance(event_ts, str):
            # Suricata format: "2025-06-15T10:00:00.000000+0000"
            normalized = event_ts
            # Convert +0000 to +00:00
            offset_match = re.search(r"([+-])(\d{2})(\d{2})$", normalized)
            if offset_match:
                sign = offset_match.group(1)
                hh = offset_match.group(2)
                mm = offset_match.group(3)
                normalized = (
                    normalized[: offset_match.start()]
                    + f"{sign}{hh}:{mm}"
                )
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            # Truncate excess fractional digits
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

        # Try epoch timestamp
        if epoch_ts:
            try:
                epoch = float(epoch_ts)
                return datetime.fromtimestamp(epoch, tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                pass

        return None

    @staticmethod
    def _parse_gcp_timestamp(ts: Any) -> Optional[datetime]:
        """Parse a GCP Cloud Logging timestamp."""
        if not ts or not isinstance(ts, str):
            return None
        normalized = ts
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        # Truncate nanosecond precision
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
            return None

    @staticmethod
    def _parse_azure_timestamp(ts: Any) -> Optional[datetime]:
        """Parse an Azure timestamp with 7-digit fractional seconds."""
        if not ts or not isinstance(ts, str):
            return None
        normalized = ts
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
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
