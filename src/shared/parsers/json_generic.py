"""Generic JSON log parser for application logs."""

import json
from typing import Any, Dict, List

from .base import ParsedEvent, Parser, ParserError, handle_parse_errors
from .registry import register_parser


@register_parser
class GenericJSONParser(Parser):
    """Parser for generic JSON application logs.

    Expects logs in format:
    {
        "timestamp": "ISO8601 timestamp",
        "level": "ERROR|WARN|INFO|DEBUG",
        "message": "Log message",
        "service": "service-name",
        ...additional fields...
    }
    """

    @property
    def log_type(self) -> str:
        return "json_generic"

    @property
    def required_fields(self) -> List[str]:
        return ["timestamp", "message"]

    def validate(self, raw_event: str) -> bool:
        """Validate generic JSON log structure.

        Args:
            raw_event: Raw JSON log entry

        Returns:
            True if valid JSON with required fields
        """
        try:
            data = json.loads(raw_event)
            return all(field in data for field in self.required_fields)
        except (json.JSONDecodeError, TypeError):
            return False

    @handle_parse_errors
    def parse(self, raw_event: str) -> ParsedEvent:
        """Parse generic JSON log into normalized format.

        Args:
            raw_event: Raw JSON log entry

        Returns:
            ParsedEvent with normalized fields

        Raises:
            ParserError: If parsing fails
        """
        data = json.loads(raw_event)

        timestamp = self.normalize_timestamp(data["timestamp"])

        level = data.get("level", "INFO")
        message = data["message"]
        service = data.get("service", "unknown")

        source_ip = self._extract_ip_from_data(data)

        action = self._determine_action(data, level)
        result = self._determine_result(data, level)

        metadata = {
            "level": level,
            "message": message,
            "trace_id": data.get("trace_id"),
            "span_id": data.get("span_id"),
            "user_id": data.get("user_id"),
            "request_id": data.get("request_id"),
            "environment": data.get("environment"),
        }

        if "http" in data:
            metadata["http"] = data["http"]

        if "error" in data:
            metadata["error"] = data["error"]

        if "metadata" in data:
            metadata.update(data["metadata"])

        extra_fields = {
            k: v
            for k, v in data.items()
            if k
            not in [
                "timestamp",
                "level",
                "message",
                "service",
                "trace_id",
                "span_id",
                "user_id",
                "request_id",
                "environment",
                "http",
                "error",
                "metadata",
            ]
        }
        if extra_fields:
            metadata["extra"] = extra_fields

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            user=data.get("user_id"),
            action=action,
            result=result,
            service=service,
            raw_event=data,
            metadata=metadata,
        )

    def _extract_ip_from_data(self, data: Dict[str, Any]) -> str:
        """Extract IP address from various fields in log data.

        Args:
            data: Log data dictionary

        Returns:
            IP address string or None
        """
        if "source_ip" in data:
            return data["source_ip"]

        if "client_ip" in data:
            return data["client_ip"]

        if "http" in data and isinstance(data["http"], dict):
            http = data["http"]
            if "client_ip" in http:
                return http["client_ip"]
            if "remote_addr" in http:
                return http["remote_addr"]

        if "metadata" in data and isinstance(data["metadata"], dict):
            metadata = data["metadata"]
            if "ip" in metadata:
                return metadata["ip"]
            if "client_ip" in metadata:
                return metadata["client_ip"]

        return None

    def _determine_action(self, data: Dict[str, Any], level: str) -> str:
        """Determine action from log data.

        Args:
            data: Log data dictionary
            level: Log level

        Returns:
            Action string
        """
        if "action" in data:
            return data["action"]

        if "http" in data and isinstance(data["http"], dict):
            http = data["http"]
            method = http.get("method", "")
            path = http.get("path", "")
            if method and path:
                return f"{method} {path}"
            if method:
                return method

        if "error" in data:
            return "error"

        return level.lower()

    def _determine_result(self, data: Dict[str, Any], level: str) -> str:
        """Determine result from log data.

        Args:
            data: Log data dictionary
            level: Log level

        Returns:
            Result string (success/failure/unknown)
        """
        if level in ["ERROR", "FATAL", "CRITICAL"]:
            return "failure"

        if "error" in data:
            return "failure"

        if "http" in data and isinstance(data["http"], dict):
            status_code = data["http"].get("status_code")
            if status_code:
                if 200 <= status_code < 400:
                    return "success"
                else:
                    return "failure"

        if "result" in data:
            result = str(data["result"]).lower()
            if result in ["success", "ok", "true"]:
                return "success"
            if result in ["failure", "error", "false"]:
                return "failure"

        return "unknown"
