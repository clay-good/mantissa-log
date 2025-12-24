"""OTLP parser - re-export from shared.parsers.otlp for package compatibility."""

from ..parsers.otlp import (
    OTLPMetricParser,
    OTLPTraceParser,
    parse_otlp_request,
)

# Create unified parser class that wraps both metric and trace parsers
class OTLPParser:
    """Unified OTLP parser that handles both metrics and traces."""

    def __init__(self):
        self.metric_parser = OTLPMetricParser()
        self.trace_parser = OTLPTraceParser()

    def parse_metrics(self, payload: dict) -> list:
        """Parse OTLP metrics payload."""
        return self.metric_parser.parse_otlp_metrics(payload)

    def parse_traces(self, payload: dict) -> list:
        """Parse OTLP traces payload."""
        return self.trace_parser.parse_otlp_traces(payload)

    def parse_request(self, payload: dict, content_type: str = "application/json"):
        """Parse OTLP request (auto-detect type)."""
        return parse_otlp_request(payload, content_type)


__all__ = [
    "OTLPParser",
    "OTLPMetricParser",
    "OTLPTraceParser",
    "parse_otlp_request",
]
