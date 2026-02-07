"""GCP VPC Flow Logs parser for NDR (Network Detection and Response).

Parses GCP VPC Flow Logs delivered via Cloud Logging in JSON format and
normalizes them to the same ``ParsedEvent``-compatible structure used by
the AWS VPC Flow Log parser.  This allows NDR detection rules to operate
uniformly across cloud providers.

GCP VPC Flow Log reference:
  https://cloud.google.com/vpc/docs/flow-logs#record_format
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseParser, ParsedEvent

# Pre-compiled regex for RFC 1918 private address detection.
_RFC1918_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)


class GCPVPCFlowParser(BaseParser):
    """Parser for GCP VPC Flow Logs (Cloud Logging JSON format).

    Produces normalised dictionaries with the same shape as
    ``ParsedEvent.to_dict()`` so NDR detection rules can work
    identically across AWS and GCP flow log data.
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

    def __init__(self):
        super().__init__()
        self.source_type = "gcp_vpc_flow"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a GCP VPC Flow Log entry.

        Args:
            raw_event: Raw GCP Cloud Logging entry with ``jsonPayload``
                containing VPC flow fields.

        Returns:
            Normalised event dictionary matching ``ParsedEvent.to_dict()``
            layout with NDR metadata.
        """
        json_payload = raw_event.get("jsonPayload", {})

        # ----- Connection info -----
        connection = json_payload.get("connection", {})
        src_ip = connection.get("src_ip", "")
        src_port = self._safe_int(connection.get("src_port"))
        dest_ip = connection.get("dest_ip", "")
        dest_port = self._safe_int(connection.get("dest_port"))
        protocol = self._safe_int(connection.get("protocol")) or 0
        protocol_name = self.PROTOCOL_MAP.get(protocol, str(protocol))

        # ----- Bytes / packets -----
        bytes_sent = self._safe_int(json_payload.get("bytes_sent")) or 0
        packets_sent = self._safe_int(json_payload.get("packets_sent")) or 0

        # ----- Timestamps -----
        start_time_str = json_payload.get("start_time", "")
        end_time_str = json_payload.get("end_time", "")
        start_dt = self._parse_timestamp(start_time_str)
        end_dt = self._parse_timestamp(end_time_str)
        duration = self._compute_duration(start_dt, end_dt)

        # Fall back to the Cloud Logging envelope timestamp if needed.
        event_timestamp = start_dt or self._parse_timestamp(
            raw_event.get("timestamp", "")
        )
        if event_timestamp is None:
            event_timestamp = datetime.now(timezone.utc)

        # ----- Reporter -----
        reporter = json_payload.get("reporter", "")

        # ----- Instance info -----
        src_instance = json_payload.get("src_instance", {})
        dest_instance = json_payload.get("dest_instance", {})

        # ----- VPC info -----
        src_vpc = json_payload.get("src_vpc", {})
        dest_vpc = json_payload.get("dest_vpc", {})

        # ----- Geolocation -----
        src_location = json_payload.get("src_location", {})
        dest_location = json_payload.get("dest_location", {})

        # ----- GKE info -----
        dest_gke = json_payload.get("dest_gke", {})
        src_gke = json_payload.get("src_gke", {})

        # ----- Resource labels (from Cloud Logging envelope) -----
        resource = raw_event.get("resource", {})
        resource_labels = resource.get("labels", {})

        # ----- Determine internality -----
        is_internal = self._is_internal(src_ip, dest_ip, src_vpc, dest_vpc)

        # ----- Build metadata -----
        metadata: Dict[str, Any] = {
            # Connection info
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": protocol,
            "protocol_name": protocol_name,
            "bytes_transferred": bytes_sent,
            "packets_sent": packets_sent,
            # Timestamps
            "start_time": start_dt.isoformat() if start_dt else None,
            "end_time": end_dt.isoformat() if end_dt else None,
            "duration_seconds": duration,
            # Reporter
            "reporter": reporter,
            # Internality
            "is_internal": is_internal,
            # Instance info
            "src_instance": {
                "vm_name": src_instance.get("vm_name"),
                "zone": src_instance.get("zone"),
                "project_id": src_instance.get("project_id"),
                "region": src_instance.get("region"),
            } if src_instance else None,
            "dest_instance": {
                "vm_name": dest_instance.get("vm_name"),
                "zone": dest_instance.get("zone"),
                "project_id": dest_instance.get("project_id"),
                "region": dest_instance.get("region"),
            } if dest_instance else None,
            # VPC info
            "src_vpc": {
                "vpc_name": src_vpc.get("vpc_name"),
                "project_id": src_vpc.get("project_id"),
                "subnetwork_name": src_vpc.get("subnetwork_name"),
            } if src_vpc else None,
            "dest_vpc": {
                "vpc_name": dest_vpc.get("vpc_name"),
                "project_id": dest_vpc.get("project_id"),
                "subnetwork_name": dest_vpc.get("subnetwork_name"),
            } if dest_vpc else None,
            # Geolocation
            "src_location": {
                "country": src_location.get("country"),
                "region": src_location.get("region"),
                "city": src_location.get("city"),
                "continent": src_location.get("continent"),
            } if src_location else None,
            "dest_location": {
                "country": dest_location.get("country"),
                "region": dest_location.get("region"),
                "city": dest_location.get("city"),
                "continent": dest_location.get("continent"),
            } if dest_location else None,
            # GKE info
            "dest_gke": {
                "cluster_name": dest_gke.get("cluster_name"),
                "cluster_location": dest_gke.get("cluster_location"),
                "pod_name": dest_gke.get("pod_name"),
                "pod_namespace": dest_gke.get("pod_namespace"),
                "service_name": dest_gke.get("service_name"),
                "service_namespace": dest_gke.get("service_namespace"),
            } if dest_gke else None,
            "src_gke": {
                "cluster_name": src_gke.get("cluster_name"),
                "cluster_location": src_gke.get("cluster_location"),
                "pod_name": src_gke.get("pod_name"),
                "pod_namespace": src_gke.get("pod_namespace"),
                "service_name": src_gke.get("service_name"),
                "service_namespace": src_gke.get("service_namespace"),
            } if src_gke else None,
            # Cloud Logging envelope
            "project_id": resource_labels.get("project_id"),
            "subnetwork_name": resource_labels.get("subnetwork_name"),
            "subnetwork_id": resource_labels.get("subnetwork_id"),
            "location": resource_labels.get("location"),
            # RTT if available
            "rtt_msec": json_payload.get("rtt_msec"),
            # NDR tags
            "tags": ["network"],
        }

        # Build the ParsedEvent and return its dict representation so
        # that consumers (detection rules, data lake writers) get the
        # same shape regardless of cloud provider.
        event = ParsedEvent(
            timestamp=event_timestamp,
            source_ip=src_ip or None,
            destination_ip=dest_ip or None,
            user=None,
            action="network_flow",
            result="success",
            service="gcp_vpc",
            raw_event=raw_event,
            metadata=metadata,
        )
        return event.to_dict()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Check whether *raw_event* looks like a GCP VPC Flow Log.

        Args:
            raw_event: Candidate event dictionary.

        Returns:
            ``True`` if the event is a valid GCP VPC Flow Log entry.
        """
        # Must be a dict
        if not isinstance(raw_event, dict):
            return False

        # Quick check: Cloud Logging log name
        log_name = raw_event.get("logName", "")
        if "vpc_flows" in log_name:
            return True

        # Check resource type
        resource = raw_event.get("resource", {})
        if resource.get("type") == "gce_subnetwork":
            json_payload = raw_event.get("jsonPayload", {})
            if "connection" in json_payload:
                return True

        # Direct jsonPayload with connection
        json_payload = raw_event.get("jsonPayload", {})
        if "connection" in json_payload and (
            "bytes_sent" in json_payload or "start_time" in json_payload
        ):
            return True

        return False

    # ------------------------------------------------------------------
    # Internal traffic detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_rfc1918(ip: str) -> bool:
        """Return ``True`` if *ip* is an RFC 1918 private IPv4 address."""
        return bool(_RFC1918_RE.match(ip))

    @staticmethod
    def _is_internal(
        src_ip: str,
        dest_ip: str,
        src_vpc: Dict[str, Any],
        dest_vpc: Dict[str, Any],
    ) -> bool:
        """Determine whether a flow represents internal traffic.

        Internal if:
        - Both IPs are RFC 1918 private addresses, OR
        - Both sides are within the same VPC (same vpc_name and project_id)
        """
        # Same-VPC check
        if src_vpc and dest_vpc:
            src_vpc_name = src_vpc.get("vpc_name")
            dest_vpc_name = dest_vpc.get("vpc_name")
            src_project = src_vpc.get("project_id")
            dest_project = dest_vpc.get("project_id")
            if (
                src_vpc_name
                and dest_vpc_name
                and src_vpc_name == dest_vpc_name
                and src_project == dest_project
            ):
                return True

        # RFC 1918 check
        if src_ip and dest_ip:
            return (
                GCPVPCFlowParser._is_rfc1918(src_ip)
                and GCPVPCFlowParser._is_rfc1918(dest_ip)
            )

        return False

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
    def _parse_timestamp(ts: Any) -> Optional[datetime]:
        """Parse a GCP timestamp string into a ``datetime`` object.

        Handles RFC 3339 timestamps with optional nanosecond precision and
        timezone offsets commonly emitted by Cloud Logging.

        Args:
            ts: Timestamp string or ``None``.

        Returns:
            ``datetime`` with timezone or ``None`` if parsing fails.
        """
        if not ts or not isinstance(ts, str):
            return None

        # Handle nanosecond precision by truncating to microseconds
        # GCP timestamps look like: 2025-01-28T10:30:00.123456789Z
        normalized = ts
        if "." in normalized:
            base, frac = normalized.split(".", 1)
            # Separate fractional seconds from timezone suffix
            tz_suffix = ""
            for i, ch in enumerate(frac):
                if ch in ("Z", "+", "-"):
                    tz_suffix = frac[i:]
                    frac = frac[:i]
                    break
            # Truncate to 6 digits (microseconds)
            frac = frac[:6].ljust(6, "0")
            normalized = f"{base}.{frac}{tz_suffix}"

        # Replace trailing Z with +00:00 for fromisoformat
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass

        # Fallback: try common formats
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

    @staticmethod
    def _compute_duration(
        start: Optional[datetime], end: Optional[datetime]
    ) -> Optional[int]:
        """Compute duration in seconds between two timestamps.

        Returns:
            Integer seconds or ``None`` if either timestamp is missing.
        """
        if start is None or end is None:
            return None
        delta = end - start
        return max(0, int(delta.total_seconds()))
