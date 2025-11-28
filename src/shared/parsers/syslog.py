"""Syslog parser for traditional syslog format."""

import re
from datetime import datetime
from typing import Dict, List, Optional

from .base import ParsedEvent, Parser, ParserError, handle_parse_errors
from .registry import register_parser


@register_parser
class SyslogParser(Parser):
    """Parser for RFC 3164 and RFC 5424 syslog messages."""

    RFC3164_PATTERN = re.compile(
        r"^<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<tag>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )

    RFC5424_PATTERN = re.compile(
        r"^<(?P<priority>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+"
        r"(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+"
        r"(?P<msg_id>\S+)\s+(?P<structured_data>.*?)\s+(?P<message>.*)$"
    )

    SEVERITY_MAP = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFO",
        7: "DEBUG",
    }

    FACILITY_MAP = {
        0: "kernel",
        1: "user",
        2: "mail",
        3: "daemon",
        4: "auth",
        5: "syslog",
        6: "lpr",
        7: "news",
        8: "uucp",
        9: "cron",
        10: "authpriv",
        11: "ftp",
        16: "local0",
        17: "local1",
        18: "local2",
        19: "local3",
        20: "local4",
        21: "local5",
        22: "local6",
        23: "local7",
    }

    @property
    def log_type(self) -> str:
        return "syslog"

    @property
    def required_fields(self) -> List[str]:
        return ["priority", "timestamp", "message"]

    def validate(self, raw_event: str) -> bool:
        """Validate syslog message structure.

        Args:
            raw_event: Raw syslog message

        Returns:
            True if valid syslog message
        """
        return bool(
            self.RFC3164_PATTERN.match(raw_event)
            or self.RFC5424_PATTERN.match(raw_event)
        )

    @handle_parse_errors
    def parse(self, raw_event: str) -> ParsedEvent:
        """Parse syslog message into normalized format.

        Args:
            raw_event: Raw syslog message

        Returns:
            ParsedEvent with normalized fields

        Raises:
            ParserError: If parsing fails
        """
        match = self.RFC5424_PATTERN.match(raw_event)
        if match:
            return self._parse_rfc5424(match, raw_event)

        match = self.RFC3164_PATTERN.match(raw_event)
        if match:
            return self._parse_rfc3164(match, raw_event)

        raise ParserError(
            "Message does not match RFC3164 or RFC5424 format",
            parser_name=self.log_type,
            raw_event=raw_event,
        )

    def _parse_rfc3164(self, match: re.Match, raw_event: str) -> ParsedEvent:
        """Parse RFC 3164 format syslog message.

        Format: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MESSAGE
        """
        priority = int(match.group("priority"))
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        tag = match.group("tag")
        pid = match.group("pid")
        message = match.group("message")

        facility, severity = self._decode_priority(priority)
        timestamp = self._parse_rfc3164_timestamp(timestamp_str)

        source_ip = self.extract_ip(hostname) or self.extract_ip(message)

        metadata = {
            "priority": priority,
            "facility": facility,
            "severity": severity,
            "severity_name": self.SEVERITY_MAP.get(severity, "UNKNOWN"),
            "facility_name": self.FACILITY_MAP.get(facility, "unknown"),
            "hostname": hostname,
            "tag": tag,
            "pid": pid,
            "format": "RFC3164",
        }

        result = "failure" if severity <= 3 else "success"

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            user=None,
            action=tag,
            result=result,
            service="syslog",
            raw_event={"raw": raw_event},
            metadata=metadata,
        )

    def _parse_rfc5424(self, match: re.Match, raw_event: str) -> ParsedEvent:
        """Parse RFC 5424 format syslog message.

        Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        """
        priority = int(match.group("priority"))
        version = int(match.group("version"))
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        app_name = match.group("app_name")
        proc_id = match.group("proc_id")
        msg_id = match.group("msg_id")
        structured_data = match.group("structured_data")
        message = match.group("message")

        facility, severity = self._decode_priority(priority)
        timestamp = self.normalize_timestamp(timestamp_str)

        source_ip = self.extract_ip(hostname) or self.extract_ip(message)

        metadata = {
            "priority": priority,
            "facility": facility,
            "severity": severity,
            "severity_name": self.SEVERITY_MAP.get(severity, "UNKNOWN"),
            "facility_name": self.FACILITY_MAP.get(facility, "unknown"),
            "version": version,
            "hostname": hostname,
            "app_name": app_name,
            "proc_id": proc_id,
            "msg_id": msg_id,
            "structured_data": structured_data,
            "format": "RFC5424",
        }

        result = "failure" if severity <= 3 else "success"

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            user=None,
            action=app_name if app_name != "-" else "syslog",
            result=result,
            service="syslog",
            raw_event={"raw": raw_event},
            metadata=metadata,
        )

    def _decode_priority(self, priority: int) -> tuple:
        """Decode priority into facility and severity.

        Args:
            priority: Priority value from syslog message

        Returns:
            Tuple of (facility, severity)
        """
        facility = priority >> 3
        severity = priority & 0x07
        return facility, severity

    def _parse_rfc3164_timestamp(self, timestamp_str: str) -> datetime:
        """Parse RFC 3164 timestamp format.

        Format: Mmm dd hh:mm:ss

        Args:
            timestamp_str: Timestamp string

        Returns:
            datetime object
        """
        try:
            now = datetime.now()
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            return dt.replace(year=now.year)
        except ValueError:
            return datetime.now()
