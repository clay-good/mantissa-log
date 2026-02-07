"""Azure NSG Flow Log parser for NDR (Network Detection and Response).

Parses Azure Network Security Group (NSG) Flow Logs and normalizes them to
the same ``ParsedEvent``-compatible structure used by the AWS VPC Flow and
GCP VPC Flow parsers.  This allows NDR detection rules to operate uniformly
across all three cloud providers.

Azure NSG Flow Log reference:
  https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview

NSG Flow Log v2 record structure::

    {
        "records": [
            {
                "time": "2025-01-28T10:00:00Z",
                "systemId": "...",
                "macAddress": "00224DABCDEF",
                "category": "NetworkSecurityGroupFlowEvent",
                "resourceId": "/subscriptions/.../nsg-name",
                "operationName": "NetworkSecurityGroupFlowEvents",
                "properties": {
                    "Version": 2,
                    "flows": [
                        {
                            "rule": "DefaultRule_AllowInternetOutBound",
                            "flows": [
                                {
                                    "mac": "00224DABCDEF",
                                    "flowTuples": [
                                        "1706436000,10.0.0.4,13.107.246.70,54321,443,T,O,A,B,5,1024,3,512"
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }

Flow tuple format (comma-separated, 13 fields for v2)::

    Unix timestamp, source IP, dest IP, source port, dest port,
    protocol (T=TCP, U=UDP), direction (I=inbound, O=outbound),
    decision (A=allowed, D=denied), flow state (B=begin, C=continuing,
    E=end), packets sent, bytes sent, packets received, bytes received
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseParser, ParsedEvent

# Pre-compiled regex for RFC 1918 private address detection.
_RFC1918_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)

# Protocol letter to number/name mapping.
_PROTOCOL_LETTER = {"T": (6, "TCP"), "U": (17, "UDP")}


class AzureNSGFlowParser(BaseParser):
    """Parser for Azure NSG Flow Logs (v1 and v2).

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    identically across AWS, GCP, and Azure flow log data.

    The ``parse()`` method accepts a single NSG record (one element
    from the top-level ``records`` array).  It returns a list of
    normalised event dicts — one per flow tuple — because a single
    record can contain many flow tuples across multiple rules.
    """

    def __init__(self, include_continuing: bool = False):
        """Initialise the parser.

        Args:
            include_continuing: If ``True``, include flow state
                ``C`` (continuing) tuples in the output.  Defaults to
                ``False`` to avoid double-counting; only ``B`` (begin)
                and ``E`` (end) tuples are emitted.
        """
        super().__init__()
        self.source_type = "azure_nsg_flow"
        self._include_continuing = include_continuing

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse a single NSG Flow Log record into normalised events.

        Args:
            raw_event: One element from the ``records`` array of an
                Azure NSG Flow Log file.

        Returns:
            List of normalised event dictionaries matching
            ``ParsedEvent.to_dict()`` layout with NDR metadata.
            Empty list if no processable flow tuples are found.
        """
        record_time = raw_event.get("time", "")
        system_id = raw_event.get("systemId", "")
        mac_address = raw_event.get("macAddress", "")
        resource_id = raw_event.get("resourceId", "")
        category = raw_event.get("category", "")
        operation_name = raw_event.get("operationName", "")

        properties = raw_event.get("properties", {})
        version = properties.get("Version", 1)
        rule_flows = properties.get("flows", [])

        events: List[Dict[str, Any]] = []

        for rule_flow in rule_flows:
            rule_name = rule_flow.get("rule", "")

            for inner_flow in rule_flow.get("flows", []):
                flow_mac = inner_flow.get("mac", mac_address)

                for tuple_str in inner_flow.get("flowTuples", []):
                    parsed = self._parse_flow_tuple(
                        tuple_str, version
                    )
                    if parsed is None:
                        continue

                    # Filter by flow state
                    flow_state = parsed.get("flow_state", "")
                    if flow_state == "C" and not self._include_continuing:
                        continue

                    event = self._build_event(
                        parsed=parsed,
                        rule_name=rule_name,
                        mac=flow_mac,
                        system_id=system_id,
                        resource_id=resource_id,
                        record_time=record_time,
                        version=version,
                        raw_event=raw_event,
                    )
                    events.append(event)

        return events

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like an Azure NSG Flow Log record.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event appears to be a valid NSG Flow Log record.
        """
        if not isinstance(raw_event, dict):
            return False

        # Check category
        category = raw_event.get("category", "")
        if category == "NetworkSecurityGroupFlowEvent":
            return True

        # Check operationName
        op = raw_event.get("operationName", "")
        if op == "NetworkSecurityGroupFlowEvents":
            return True

        # Check for properties.flows structure
        properties = raw_event.get("properties", {})
        if isinstance(properties, dict) and "flows" in properties:
            flows = properties["flows"]
            if isinstance(flows, list) and len(flows) > 0:
                first = flows[0]
                if isinstance(first, dict) and "rule" in first:
                    return True

        # Check resourceId for NSG pattern
        resource_id = raw_event.get("resourceId", "")
        if "networksecuritygroups" in resource_id.lower():
            return True

        return False

    # ------------------------------------------------------------------
    # Flow tuple parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_flow_tuple(
        tuple_str: str, version: int = 2
    ) -> Optional[Dict[str, Any]]:
        """Parse a single comma-separated flow tuple string.

        v1 format (8 fields):
            timestamp, srcIP, dstIP, srcPort, dstPort, protocol,
            direction, decision

        v2 format (13 fields):
            ... + flow_state, packets_sent, bytes_sent,
            packets_received, bytes_received

        Args:
            tuple_str: Comma-separated flow tuple string.
            version: NSG Flow Log version (1 or 2).

        Returns:
            Parsed field dictionary or ``None`` if invalid.
        """
        parts = tuple_str.split(",")

        min_fields = 8
        if len(parts) < min_fields:
            return None

        try:
            unix_ts = int(parts[0])
        except (ValueError, TypeError):
            return None

        src_ip = parts[1]
        dest_ip = parts[2]

        src_port = AzureNSGFlowParser._safe_int(parts[3])
        dest_port = AzureNSGFlowParser._safe_int(parts[4])

        protocol_letter = parts[5]
        protocol_num, protocol_name = _PROTOCOL_LETTER.get(
            protocol_letter, (0, protocol_letter)
        )

        direction_letter = parts[6]
        direction = "inbound" if direction_letter == "I" else "outbound"

        decision_letter = parts[7]
        decision = "allowed" if decision_letter == "A" else "denied"

        result: Dict[str, Any] = {
            "unix_timestamp": unix_ts,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": src_port,
            "dest_port": dest_port,
            "protocol_letter": protocol_letter,
            "protocol": protocol_num,
            "protocol_name": protocol_name,
            "direction_letter": direction_letter,
            "direction": direction,
            "decision_letter": decision_letter,
            "decision": decision,
        }

        # v2 fields
        if len(parts) >= 9:
            result["flow_state"] = parts[8]
        else:
            result["flow_state"] = "B"  # treat v1 as begin

        if len(parts) >= 13:
            result["packets_sent"] = AzureNSGFlowParser._safe_int(parts[9]) or 0
            result["bytes_sent"] = AzureNSGFlowParser._safe_int(parts[10]) or 0
            result["packets_received"] = AzureNSGFlowParser._safe_int(parts[11]) or 0
            result["bytes_received"] = AzureNSGFlowParser._safe_int(parts[12]) or 0
        else:
            result["packets_sent"] = 0
            result["bytes_sent"] = 0
            result["packets_received"] = 0
            result["bytes_received"] = 0

        return result

    # ------------------------------------------------------------------
    # Event construction
    # ------------------------------------------------------------------

    def _build_event(
        self,
        parsed: Dict[str, Any],
        rule_name: str,
        mac: str,
        system_id: str,
        resource_id: str,
        record_time: str,
        version: int,
        raw_event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a normalised event dict from parsed tuple data."""
        unix_ts = parsed["unix_timestamp"]
        timestamp = datetime.fromtimestamp(unix_ts, tz=timezone.utc)

        src_ip = parsed["src_ip"]
        dest_ip = parsed["dest_ip"]
        decision = parsed["decision"]
        direction = parsed["direction"]

        total_bytes = parsed["bytes_sent"] + parsed["bytes_received"]
        total_packets = parsed["packets_sent"] + parsed["packets_received"]

        action_prefix = "network_accept" if decision == "allowed" else "network_reject"
        result = "success" if decision == "allowed" else "failure"

        is_internal = self._is_internal(src_ip, dest_ip)

        # Extract subscription, resource group, NSG name from resource ID
        nsg_info = self._parse_resource_id(resource_id)

        metadata: Dict[str, Any] = {
            # Connection info
            "source_port": parsed["src_port"],
            "destination_port": parsed["dest_port"],
            "protocol": parsed["protocol"],
            "protocol_name": parsed["protocol_name"],
            "bytes_transferred": total_bytes,
            "bytes_sent": parsed["bytes_sent"],
            "bytes_received": parsed["bytes_received"],
            "packets_sent": parsed["packets_sent"],
            "packets_received": parsed["packets_received"],
            "total_packets": total_packets,
            # Timestamps
            "start_time": timestamp.isoformat(),
            "end_time": None,
            "duration_seconds": None,
            # Direction & decision
            "direction": direction,
            "decision": decision,
            "flow_state": parsed["flow_state"],
            # NSG info
            "rule_name": rule_name,
            "mac_address": mac,
            "nsg_name": nsg_info.get("nsg_name"),
            "resource_group": nsg_info.get("resource_group"),
            "subscription_id": nsg_info.get("subscription_id"),
            "resource_id": resource_id,
            "system_id": system_id,
            "version": version,
            # Internality
            "is_internal": is_internal,
            # NDR tags
            "tags": ["network"],
        }

        event = ParsedEvent(
            timestamp=timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action=action_prefix,
            result=result,
            service="azure_nsg",
            raw_event=raw_event,
            metadata=metadata,
        )
        return event.to_dict()

    # ------------------------------------------------------------------
    # Internal traffic detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_rfc1918(ip: str) -> bool:
        """Return ``True`` if *ip* is an RFC 1918 private IPv4 address."""
        return bool(_RFC1918_RE.match(ip))

    @staticmethod
    def _is_internal(src_ip: str, dest_ip: str) -> bool:
        """Return ``True`` if both addresses are RFC 1918 private."""
        if not src_ip or not dest_ip:
            return False
        return (
            AzureNSGFlowParser._is_rfc1918(src_ip)
            and AzureNSGFlowParser._is_rfc1918(dest_ip)
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert *value* to ``int`` if possible, else ``None``."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_resource_id(resource_id: str) -> Dict[str, Optional[str]]:
        """Extract subscription, resource group and NSG name from an
        Azure resource ID string.

        Example resource ID::

            /subscriptions/xxx/resourceGroups/rg-name/providers/
            Microsoft.Network/networkSecurityGroups/my-nsg

        Returns:
            Dict with ``subscription_id``, ``resource_group``, and
            ``nsg_name`` keys (values may be ``None``).
        """
        result: Dict[str, Optional[str]] = {
            "subscription_id": None,
            "resource_group": None,
            "nsg_name": None,
        }
        if not resource_id:
            return result

        lower = resource_id.lower()
        parts = resource_id.split("/")

        # Find subscription ID
        for i, part in enumerate(parts):
            if part.lower() == "subscriptions" and i + 1 < len(parts):
                result["subscription_id"] = parts[i + 1]
                break

        # Find resource group
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                result["resource_group"] = parts[i + 1]
                break

        # Find NSG name
        for i, part in enumerate(parts):
            if part.lower() == "networksecuritygroups" and i + 1 < len(parts):
                result["nsg_name"] = parts[i + 1]
                break

        return result
