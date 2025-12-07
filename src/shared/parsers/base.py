"""Base classes and interfaces for log parsers."""

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ParsedEvent:
    """Normalized event structure across all log types."""

    timestamp: datetime
    action: str
    result: str
    service: str
    raw_event: Dict[str, Any]
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "action": self.action,
            "result": self.result,
            "service": self.service,
            "metadata": self.metadata,
            "raw_event": self.raw_event,
        }


class ParserError(Exception):
    """Exception raised when parsing fails."""

    def __init__(
        self,
        message: str,
        parser_name: str,
        original_error: Optional[Exception] = None,
        raw_event: Optional[str] = None,
    ):
        super().__init__(message)
        self.parser_name = parser_name
        self.original_error = original_error
        self.raw_event = raw_event[:500] if raw_event else None


class Parser(ABC):
    """Abstract base class for log parsers."""

    @property
    @abstractmethod
    def log_type(self) -> str:
        """Return the log type this parser handles."""
        pass

    @property
    @abstractmethod
    def required_fields(self) -> List[str]:
        """Return list of required fields for this log type."""
        pass

    @abstractmethod
    def parse(self, raw_event: str) -> ParsedEvent:
        """Parse raw event string into normalized ParsedEvent.

        Args:
            raw_event: Raw log event as string

        Returns:
            ParsedEvent with normalized fields

        Raises:
            ParserError: If parsing fails
        """
        pass

    @abstractmethod
    def validate(self, raw_event: str) -> bool:
        """Validate that raw event has required structure.

        Args:
            raw_event: Raw log event as string

        Returns:
            True if valid, False otherwise
        """
        pass

    def normalize_timestamp(self, ts: Any) -> datetime:
        """Normalize various timestamp formats to datetime object.

        Args:
            ts: Timestamp in various formats (string, int, float, datetime)

        Returns:
            datetime object in UTC

        Raises:
            ValueError: If timestamp cannot be parsed
        """
        if isinstance(ts, datetime):
            return ts

        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts)

        if isinstance(ts, str):
            formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ]

            for fmt in formats:
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue

            try:
                from dateutil import parser

                return parser.parse(ts)
            except (ImportError, ValueError):
                pass

        raise ValueError(f"Unable to parse timestamp: {ts}")

    def extract_ip(self, value: str) -> Optional[str]:
        """Extract IP address from string.

        Args:
            value: String potentially containing IP address

        Returns:
            IP address string or None if not found
        """
        if not value:
            return None

        ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"

        match = re.search(ipv4_pattern, value)
        if match:
            return match.group()

        match = re.search(ipv6_pattern, value)
        if match:
            return match.group()

        return None

    def safe_get(self, data: dict, path: str, default: Any = None) -> Any:
        """Safely get nested dictionary value using dot notation.

        Args:
            data: Dictionary to traverse
            path: Dot-separated path to value (e.g., 'user.name.first')
            default: Default value if path not found

        Returns:
            Value at path or default
        """
        keys = path.split(".")
        current = data

        for key in keys:
            if not isinstance(current, dict):
                return default
            current = current.get(key)
            if current is None:
                return default

        return current


def validate_required_fields(func):
    """Decorator to validate required fields before parsing.

    Args:
        func: Parse function to decorate

    Returns:
        Wrapped function
    """

    def wrapper(self, raw_event: str) -> ParsedEvent:
        if not self.validate(raw_event):
            raise ParserError(
                f"Event missing required fields for {self.log_type}",
                parser_name=self.log_type,
                raw_event=raw_event,
            )
        return func(self, raw_event)

    return wrapper


def handle_parse_errors(func):
    """Decorator to handle parsing errors consistently.

    Args:
        func: Parse function to decorate

    Returns:
        Wrapped function
    """

    def wrapper(self, raw_event: str) -> ParsedEvent:
        try:
            return func(self, raw_event)
        except ParserError:
            raise
        except Exception as e:
            raise ParserError(
                f"Failed to parse {self.log_type} event: {str(e)}",
                parser_name=self.log_type,
                original_error=e,
                raw_event=raw_event,
            )

    return wrapper


class BaseParser(ABC):
    """Abstract base class for log parsers that take dict input.

    This is an alternative interface for parsers that process JSON/dict events
    directly rather than raw strings.
    """

    def __init__(self):
        self.source_type = "unknown"

    @abstractmethod
    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse raw event dictionary into normalized format.

        Args:
            raw_event: Raw log event as dictionary

        Returns:
            Normalized event dictionary
        """
        pass

    def safe_get(self, data: dict, path: str, default: Any = None) -> Any:
        """Safely get nested dictionary value using dot notation.

        Args:
            data: Dictionary to traverse
            path: Dot-separated path to value (e.g., 'user.name.first')
            default: Default value if path not found

        Returns:
            Value at path or default
        """
        keys = path.split(".")
        current = data

        for key in keys:
            if not isinstance(current, dict):
                return default
            current = current.get(key)
            if current is None:
                return default

        return current

    def normalize_timestamp(self, ts: Any) -> Optional[str]:
        """Normalize various timestamp formats to ISO 8601 string.

        Args:
            ts: Timestamp in various formats (string, int, float, datetime)

        Returns:
            ISO 8601 formatted timestamp string
        """
        if ts is None:
            return None

        if isinstance(ts, datetime):
            return ts.isoformat()

        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts).isoformat()

        if isinstance(ts, str):
            # Already a string, validate and return
            formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ]

            for fmt in formats:
                try:
                    parsed = datetime.strptime(ts, fmt)
                    return parsed.isoformat()
                except ValueError:
                    continue

            # Return as-is if it looks like ISO format
            if "T" in ts and ("-" in ts or "+" in ts or "Z" in ts):
                return ts

        return None
