"""VPC Flow Logs parser.

Enhanced for NDR (Network Detection and Response) with support for VPC Flow
Log versions 2-5, TCP flag bitmask decoding, RFC 1918 internal-traffic
detection, and normalized fields required by network detection rules.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional

from .base import ParsedEvent, Parser, ParserError, handle_parse_errors, validate_required_fields
from .registry import register_parser

# Pre-compiled regex for RFC 1918 private address detection.
_RFC1918_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)


@register_parser
class VPCFlowLogsParser(Parser):
    """Parser for AWS VPC Flow Logs (versions 2-5).

    Produces ParsedEvent objects with NDR-ready metadata including parsed TCP
    flags, ``is_internal`` classification, ``duration_seconds``, and a
    ``"network"`` tag for easy filtering by detection rules.
    """

    PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
    }

    # TCP flag bitmask → flag name.  AWS encodes flags as an integer formed
    # by OR-ing the standard TCP flag bits.
    TCP_FLAGS = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
    }

    @property
    def log_type(self) -> str:
        return "vpc_flow_logs"

    @property
    def required_fields(self) -> List[str]:
        return ["srcaddr", "dstaddr", "start", "end", "action"]

    def validate(self, raw_event: str) -> bool:
        """Validate VPC Flow Log entry structure.

        Args:
            raw_event: Raw VPC Flow Log entry as space-delimited string

        Returns:
            True if valid VPC Flow Log entry
        """
        try:
            parts = raw_event.strip().split()
            if len(parts) < 14:
                return False

            try:
                int(parts[0])
                int(parts[5])
                int(parts[6])
            except (ValueError, IndexError):
                return False

            return True
        except Exception:
            return False

    @handle_parse_errors
    @validate_required_fields
    def parse(self, raw_event: str) -> ParsedEvent:
        """Parse VPC Flow Log entry into normalized format.

        Args:
            raw_event: Raw VPC Flow Log entry as space-delimited string

        Returns:
            ParsedEvent with normalized fields

        Raises:
            ParserError: If parsing fails
        """
        parts = raw_event.strip().split()

        if len(parts) < 14:
            raise ParserError(
                f"VPC Flow Log entry has insufficient fields: {len(parts)}",
                parser_name=self.log_type,
                raw_event=raw_event,
            )

        version = int(parts[0])

        if version == 2:
            return self._parse_v2(parts, raw_event)
        elif version in (3, 4, 5):
            return self._parse_v5(parts, raw_event)
        else:
            raise ParserError(
                f"Unsupported VPC Flow Log version: {version}",
                parser_name=self.log_type,
                raw_event=raw_event,
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tcp_flags(raw_value: Optional[str]) -> List[str]:
        """Decode a TCP flags integer bitmask into a list of flag names.

        Args:
            raw_value: String representation of the bitmask (e.g. ``"2"``
                for SYN, ``"18"`` for SYN+ACK).  ``"-"`` or ``None``
                means no flags available.

        Returns:
            Sorted list of flag name strings, e.g. ``["ACK", "SYN"]``.
        """
        if raw_value is None or raw_value == "-":
            return []
        try:
            bitmask = int(raw_value)
        except ValueError:
            return []
        flags = []
        for bit, name in VPCFlowLogsParser.TCP_FLAGS.items():
            if bitmask & bit:
                flags.append(name)
        flags.sort()
        return flags

    @staticmethod
    def _is_rfc1918(ip: str) -> bool:
        """Return True if *ip* is an RFC 1918 private IPv4 address."""
        return bool(_RFC1918_RE.match(ip))

    @staticmethod
    def _is_internal(srcaddr: str, dstaddr: str) -> bool:
        """Return True if both addresses are RFC 1918 private addresses."""
        return (
            VPCFlowLogsParser._is_rfc1918(srcaddr)
            and VPCFlowLogsParser._is_rfc1918(dstaddr)
        )

    @staticmethod
    def _safe_field(parts: List[str], index: int) -> Optional[str]:
        """Return ``parts[index]`` if present and not ``"-"``, else None."""
        if len(parts) > index:
            val = parts[index]
            return None if val == "-" else val
        return None

    # ------------------------------------------------------------------
    # Version-specific parse methods
    # ------------------------------------------------------------------

    def _parse_v2(self, parts: List[str], raw_event: str) -> ParsedEvent:
        """Parse VPC Flow Log version 2 format.

        Format: version account-id interface-id srcaddr dstaddr srcport dstport
                protocol packets bytes start end action log-status
        """
        try:
            version = int(parts[0])
            account_id = parts[1]
            interface_id = parts[2]
            srcaddr = parts[3]
            dstaddr = parts[4]
            srcport = int(parts[5])
            dstport = int(parts[6])
            protocol = int(parts[7])
            packets = int(parts[8])
            bytes_transferred = int(parts[9])
            start = int(parts[10])
            end = int(parts[11])
            action = parts[12]
            log_status = parts[13]
        except (ValueError, IndexError) as e:
            raise ParserError(
                f"Failed to parse VPC Flow Log fields: {e}",
                parser_name=self.log_type,
                original_error=e,
                raw_event=raw_event,
            )

        timestamp = datetime.fromtimestamp(start)
        end_timestamp = datetime.fromtimestamp(end)
        protocol_name = self.PROTOCOL_MAP.get(protocol, str(protocol))
        result = "success" if action == "ACCEPT" else "failure"
        duration = end - start

        metadata = {
            # Original fields (backward compatible)
            "version": version,
            "account_id": account_id,
            "interface_id": interface_id,
            "srcport": srcport,
            "dstport": dstport,
            "protocol": protocol,
            "protocol_name": protocol_name,
            "packets": packets,
            "bytes": bytes_transferred,
            "start": start,
            "end": end,
            "log_status": log_status,
            # NDR-normalized fields
            "source_port": srcport,
            "destination_port": dstport,
            "bytes_transferred": bytes_transferred,
            "tcp_flags": [],
            "flow_direction": None,
            "start_time": timestamp.isoformat(),
            "end_time": end_timestamp.isoformat(),
            "duration_seconds": duration,
            "is_internal": self._is_internal(srcaddr, dstaddr),
            "aws_service": None,
            "tags": ["network"],
        }

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=srcaddr,
            destination_ip=dstaddr,
            user=None,
            action=f"network_{action.lower()}",
            result=result,
            service="vpc",
            raw_event={"raw": raw_event},
            metadata=metadata,
        )

    def _parse_v5(self, parts: List[str], raw_event: str) -> ParsedEvent:
        """Parse VPC Flow Log version 3-5 format (extended fields).

        Indices 14-28 may be present depending on the configured log format.
        Missing or ``"-"`` values are normalised to ``None``.
        """
        try:
            version = int(parts[0])
            account_id = parts[1]
            interface_id = parts[2]
            srcaddr = parts[3]
            dstaddr = parts[4]
            srcport = int(parts[5])
            dstport = int(parts[6])
            protocol = int(parts[7])
            packets = int(parts[8])
            bytes_transferred = int(parts[9])
            start = int(parts[10])
            end = int(parts[11])
            action = parts[12]
            log_status = parts[13]

            # Extended fields (v3-v5, indices 14-28)
            vpc_id = self._safe_field(parts, 14)
            subnet_id = self._safe_field(parts, 15)
            instance_id = self._safe_field(parts, 16)
            tcp_flags_raw = self._safe_field(parts, 17)
            flow_type = self._safe_field(parts, 18)
            pkt_srcaddr = self._safe_field(parts, 19)
            pkt_dstaddr = self._safe_field(parts, 20)
            region = self._safe_field(parts, 21)
            az_id = self._safe_field(parts, 22)
            sublocation_type = self._safe_field(parts, 23)
            sublocation_id = self._safe_field(parts, 24)
            pkt_src_aws_service = self._safe_field(parts, 25)
            pkt_dst_aws_service = self._safe_field(parts, 26)
            flow_direction = self._safe_field(parts, 27)
            traffic_path = self._safe_field(parts, 28)

        except (ValueError, IndexError) as e:
            raise ParserError(
                f"Failed to parse VPC Flow Log fields: {e}",
                parser_name=self.log_type,
                original_error=e,
                raw_event=raw_event,
            )

        timestamp = datetime.fromtimestamp(start)
        end_timestamp = datetime.fromtimestamp(end)
        protocol_name = self.PROTOCOL_MAP.get(protocol, str(protocol))
        result = "success" if action == "ACCEPT" else "failure"
        duration = end - start
        parsed_flags = self._parse_tcp_flags(tcp_flags_raw)

        # Derive the aws_service value from either direction.
        aws_service = pkt_dst_aws_service or pkt_src_aws_service

        metadata = {
            # Original fields (backward compatible)
            "version": version,
            "account_id": account_id,
            "interface_id": interface_id,
            "srcport": srcport,
            "dstport": dstport,
            "protocol": protocol,
            "protocol_name": protocol_name,
            "packets": packets,
            "bytes": bytes_transferred,
            "start": start,
            "end": end,
            "log_status": log_status,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "instance_id": instance_id,
            "tcp_flags": parsed_flags,
            "tcp_flags_raw": tcp_flags_raw,
            "flow_type": flow_type,
            "pkt_srcaddr": pkt_srcaddr,
            "pkt_dstaddr": pkt_dstaddr,
            "region": region,
            "az_id": az_id,
            "sublocation_type": sublocation_type,
            "sublocation_id": sublocation_id,
            "pkt_src_aws_service": pkt_src_aws_service,
            "pkt_dst_aws_service": pkt_dst_aws_service,
            "flow_direction": flow_direction,
            "traffic_path": traffic_path,
            # NDR-normalized fields
            "source_port": srcport,
            "destination_port": dstport,
            "bytes_transferred": bytes_transferred,
            "start_time": timestamp.isoformat(),
            "end_time": end_timestamp.isoformat(),
            "duration_seconds": duration,
            "is_internal": self._is_internal(srcaddr, dstaddr),
            "aws_service": aws_service,
            "tags": ["network"],
        }

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=srcaddr,
            destination_ip=dstaddr,
            user=None,
            action=f"network_{action.lower()}",
            result=result,
            service="vpc",
            raw_event={"raw": raw_event},
            metadata=metadata,
        )
