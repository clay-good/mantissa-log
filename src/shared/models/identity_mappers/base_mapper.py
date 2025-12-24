"""Base class for identity event mappers."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from ..identity_event import IdentityEvent, IdentityEventType, GeoLocation


class BaseIdentityMapper(ABC):
    """Abstract base class for provider-specific identity mappers.

    Each provider mapper must implement the map() method to convert
    provider-specific events to the unified IdentityEvent format.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name for this mapper."""
        pass

    @abstractmethod
    def map(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map a raw provider event to IdentityEvent.

        Args:
            raw_event: Raw event dictionary from the provider

        Returns:
            Normalized IdentityEvent
        """
        pass

    @abstractmethod
    def map_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Map provider-specific event type to IdentityEventType.

        Args:
            raw_event: Raw event dictionary

        Returns:
            Normalized IdentityEventType
        """
        pass

    def generate_event_id(self, raw_event: Dict[str, Any]) -> str:
        """Generate a unique event ID.

        Override in subclass if provider has a native event ID.

        Args:
            raw_event: Raw event dictionary

        Returns:
            Unique event ID string
        """
        return str(uuid.uuid4())

    def parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse various timestamp formats to datetime.

        Args:
            timestamp: Timestamp in various formats

        Returns:
            datetime object in UTC
        """
        if timestamp is None:
            return datetime.now(timezone.utc)

        if isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                return timestamp.replace(tzinfo=timezone.utc)
            return timestamp

        if isinstance(timestamp, (int, float)):
            # Unix timestamp
            if timestamp > 1e12:  # Milliseconds
                timestamp = timestamp / 1000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)

        if isinstance(timestamp, str):
            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ]

            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue

            # Try ISO format parsing
            try:
                if timestamp.endswith("Z"):
                    timestamp = timestamp.replace("Z", "+00:00")
                dt = datetime.fromisoformat(timestamp)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

        return datetime.now(timezone.utc)

    def extract_geo(self, geo_data: Optional[Dict[str, Any]]) -> Optional[GeoLocation]:
        """Extract geolocation from provider-specific geo data.

        Args:
            geo_data: Provider-specific geographic data

        Returns:
            GeoLocation object or None
        """
        if not geo_data:
            return None

        # Try common field names
        country = (
            geo_data.get("country")
            or geo_data.get("country_name")
            or geo_data.get("country_iso_code")
            or geo_data.get("countryOrRegion")
        )
        city = (
            geo_data.get("city")
            or geo_data.get("city_name")
        )
        region = (
            geo_data.get("region")
            or geo_data.get("region_name")
            or geo_data.get("state")
        )

        # Extract coordinates
        lat = None
        lon = None
        if "location" in geo_data and isinstance(geo_data["location"], dict):
            lat = geo_data["location"].get("lat") or geo_data["location"].get("latitude")
            lon = geo_data["location"].get("lon") or geo_data["location"].get("longitude")
        elif "geolocation" in geo_data and isinstance(geo_data["geolocation"], dict):
            lat = geo_data["geolocation"].get("lat")
            lon = geo_data["geolocation"].get("lon")
        else:
            lat = geo_data.get("lat") or geo_data.get("latitude")
            lon = geo_data.get("lon") or geo_data.get("longitude")

        if not any([country, city, lat, lon]):
            return None

        return GeoLocation(
            country=country,
            city=city,
            region=region,
            lat=lat,
            lon=lon,
            asn=geo_data.get("asn"),
            isp=geo_data.get("isp"),
        )

    def safe_get(self, data: Dict[str, Any], path: str, default: Any = None) -> Any:
        """Safely get nested dictionary value using dot notation.

        Args:
            data: Dictionary to traverse
            path: Dot-separated path to value
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

    def normalize_email(self, email: Optional[str]) -> str:
        """Normalize email address to lowercase.

        Args:
            email: Email address to normalize

        Returns:
            Lowercased email or empty string
        """
        if not email:
            return ""
        return email.lower().strip()

    def normalize_failure_reason(self, reason: Optional[str], code: Optional[str] = None) -> Optional[str]:
        """Normalize failure reason to a standard format.

        Args:
            reason: Failure reason text
            code: Error/failure code

        Returns:
            Normalized failure reason or None
        """
        if not reason and not code:
            return None

        parts = []
        if code:
            parts.append(f"[{code}]")
        if reason:
            parts.append(reason)

        return " ".join(parts) if parts else None
