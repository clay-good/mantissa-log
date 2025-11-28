"""VPC Flow Logs parser."""

from datetime import datetime
from typing import Dict, List

from .base import ParsedEvent, Parser, ParserError, handle_parse_errors, validate_required_fields
from .registry import register_parser


@register_parser
class VPCFlowLogsParser(Parser):
    """Parser for AWS VPC Flow Logs."""

    PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
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
        elif version == 3 or version == 4 or version == 5:
            return self._parse_v5(parts, raw_event)
        else:
            raise ParserError(
                f"Unsupported VPC Flow Log version: {version}",
                parser_name=self.log_type,
                raw_event=raw_event,
            )

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
        protocol_name = self.PROTOCOL_MAP.get(protocol, str(protocol))
        result = "success" if action == "ACCEPT" else "failure"

        metadata = {
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
        """Parse VPC Flow Log version 5 format (extended fields).

        Version 5 includes additional fields like vpc-id, subnet-id, instance-id, etc.
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

            vpc_id = parts[14] if len(parts) > 14 else None
            subnet_id = parts[15] if len(parts) > 15 else None
            instance_id = parts[16] if len(parts) > 16 else None
            tcp_flags = parts[17] if len(parts) > 17 else None
            flow_type = parts[18] if len(parts) > 18 else None
            pkt_srcaddr = parts[19] if len(parts) > 19 else None
            pkt_dstaddr = parts[20] if len(parts) > 20 else None
            region = parts[21] if len(parts) > 21 else None
            az_id = parts[22] if len(parts) > 22 else None

        except (ValueError, IndexError) as e:
            raise ParserError(
                f"Failed to parse VPC Flow Log fields: {e}",
                parser_name=self.log_type,
                original_error=e,
                raw_event=raw_event,
            )

        timestamp = datetime.fromtimestamp(start)
        protocol_name = self.PROTOCOL_MAP.get(protocol, str(protocol))
        result = "success" if action == "ACCEPT" else "failure"

        metadata = {
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
            "tcp_flags": tcp_flags,
            "flow_type": flow_type,
            "pkt_srcaddr": pkt_srcaddr,
            "pkt_dstaddr": pkt_dstaddr,
            "region": region,
            "az_id": az_id,
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
