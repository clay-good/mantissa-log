"""Parser registry for managing and discovering log parsers."""

from typing import Dict, List, Optional, Type

from .base import Parser


class ParserRegistry:
    """Registry for managing parser instances."""

    def __init__(self):
        self._parsers: Dict[str, Parser] = {}

    def register(self, parser: Parser) -> None:
        """Register a parser instance.

        Args:
            parser: Parser instance to register
        """
        self._parsers[parser.log_type] = parser

    def get_parser(self, log_type: str) -> Optional[Parser]:
        """Get parser for a specific log type.

        Args:
            log_type: Type of log to parse

        Returns:
            Parser instance or None if not found
        """
        return self._parsers.get(log_type)

    def list_parsers(self) -> List[str]:
        """List all registered parser types.

        Returns:
            List of log type names
        """
        return list(self._parsers.keys())

    def auto_detect(self, raw_event: str) -> Optional[Parser]:
        """Attempt to auto-detect the correct parser for an event.

        Args:
            raw_event: Raw log event string

        Returns:
            Parser instance or None if no match found
        """
        for parser in self._parsers.values():
            if parser.validate(raw_event):
                return parser
        return None


_global_registry = ParserRegistry()


def register_parser(parser_class: Type[Parser]) -> Type[Parser]:
    """Decorator to automatically register a parser class.

    Args:
        parser_class: Parser class to register

    Returns:
        Original parser class
    """
    _global_registry.register(parser_class())
    return parser_class


def get_parser(log_type: str) -> Optional[Parser]:
    """Get parser from global registry.

    Args:
        log_type: Type of log to parse

    Returns:
        Parser instance or None if not found
    """
    return _global_registry.get_parser(log_type)


def list_parsers() -> List[str]:
    """List all registered parsers in global registry.

    Returns:
        List of log type names
    """
    return _global_registry.list_parsers()


def auto_detect_parser(raw_event: str) -> Optional[Parser]:
    """Auto-detect parser from global registry.

    Args:
        raw_event: Raw log event string

    Returns:
        Parser instance or None if no match found
    """
    return _global_registry.auto_detect(raw_event)
