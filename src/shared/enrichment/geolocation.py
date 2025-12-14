"""IP Geolocation Enrichment Service.

Provides IP geolocation using MaxMind GeoIP2 with fallback to free IP-API.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GeoLocation:
    """Geolocation data for an IP address."""

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    source: str = "unknown"
    cached: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "postal_code": self.postal_code,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "isp": self.isp,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_tor": self.is_tor,
            "is_datacenter": self.is_datacenter,
            "source": self.source,
            "cached": self.cached,
            "error": self.error,
        }


class GeoIPCache:
    """In-memory cache for geolocation results."""

    def __init__(self, ttl_hours: int = 24, max_size: int = 10000):
        """Initialize cache.

        Args:
            ttl_hours: Time-to-live in hours
            max_size: Maximum cache entries
        """
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
        self._cache: Dict[str, tuple] = {}  # ip -> (GeoLocation, timestamp)

    def get(self, ip: str) -> Optional[GeoLocation]:
        """Get cached geolocation."""
        if ip in self._cache:
            geo, timestamp = self._cache[ip]
            if datetime.utcnow() - timestamp < self.ttl:
                geo.cached = True
                return geo
            else:
                del self._cache[ip]
        return None

    def put(self, ip: str, geo: GeoLocation) -> None:
        """Cache geolocation result."""
        # Evict oldest entries if at capacity
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        self._cache[ip] = (geo, datetime.utcnow())

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()


class GeoIPService:
    """Geolocation service with multiple providers."""

    def __init__(
        self,
        maxmind_db_path: Optional[str] = None,
        maxmind_account_id: Optional[str] = None,
        maxmind_license_key: Optional[str] = None,
        ipinfo_token: Optional[str] = None,
        cache_ttl_hours: int = 24,
    ):
        """Initialize geolocation service.

        Args:
            maxmind_db_path: Path to MaxMind GeoIP2 database file
            maxmind_account_id: MaxMind account ID for web service
            maxmind_license_key: MaxMind license key
            ipinfo_token: IPInfo.io API token
            cache_ttl_hours: Cache TTL in hours
        """
        self.maxmind_db_path = maxmind_db_path or os.environ.get("MAXMIND_DB_PATH")
        self.maxmind_account_id = maxmind_account_id or os.environ.get("MAXMIND_ACCOUNT_ID")
        self.maxmind_license_key = maxmind_license_key or os.environ.get("MAXMIND_LICENSE_KEY")
        self.ipinfo_token = ipinfo_token or os.environ.get("IPINFO_TOKEN")

        self.cache = GeoIPCache(ttl_hours=cache_ttl_hours)
        self._maxmind_reader = None
        self._maxmind_client = None

        # Initialize MaxMind if available
        self._init_maxmind()

    def _init_maxmind(self) -> None:
        """Initialize MaxMind GeoIP2 reader or client."""
        # Try local database first
        if self.maxmind_db_path:
            try:
                import geoip2.database
                self._maxmind_reader = geoip2.database.Reader(self.maxmind_db_path)
                logger.info(f"Initialized MaxMind GeoIP2 database: {self.maxmind_db_path}")
            except ImportError:
                logger.warning("geoip2 package not installed - MaxMind database unavailable")
            except Exception as e:
                logger.warning(f"Failed to open MaxMind database: {e}")

        # Try web service if database not available
        if not self._maxmind_reader and self.maxmind_account_id and self.maxmind_license_key:
            try:
                import geoip2.webservice
                self._maxmind_client = geoip2.webservice.Client(
                    int(self.maxmind_account_id),
                    self.maxmind_license_key
                )
                logger.info("Initialized MaxMind GeoIP2 web service client")
            except ImportError:
                logger.warning("geoip2 package not installed - MaxMind web service unavailable")
            except Exception as e:
                logger.warning(f"Failed to initialize MaxMind web service: {e}")

    def lookup(self, ip: str) -> GeoLocation:
        """Lookup geolocation for IP address.

        Args:
            ip: IP address to lookup

        Returns:
            GeoLocation result
        """
        # Check cache first
        cached = self.cache.get(ip)
        if cached:
            return cached

        # Check for private/reserved IPs
        if self._is_private_ip(ip):
            geo = GeoLocation(
                ip=ip,
                country="Private",
                city="Internal Network",
                source="internal",
            )
            self.cache.put(ip, geo)
            return geo

        # Try MaxMind database
        if self._maxmind_reader:
            geo = self._lookup_maxmind_db(ip)
            if not geo.error:
                self.cache.put(ip, geo)
                return geo

        # Try MaxMind web service
        if self._maxmind_client:
            geo = self._lookup_maxmind_web(ip)
            if not geo.error:
                self.cache.put(ip, geo)
                return geo

        # Try IPInfo
        if self.ipinfo_token:
            geo = self._lookup_ipinfo(ip)
            if not geo.error:
                self.cache.put(ip, geo)
                return geo

        # Fallback to free IP-API
        geo = self._lookup_ipapi(ip)
        self.cache.put(ip, geo)
        return geo

    def lookup_batch(self, ips: List[str]) -> Dict[str, GeoLocation]:
        """Lookup geolocation for multiple IPs.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary of IP to GeoLocation
        """
        results = {}
        for ip in ips:
            results[ip] = self.lookup(ip)
        return results

    def _lookup_maxmind_db(self, ip: str) -> GeoLocation:
        """Lookup using MaxMind GeoIP2 database."""
        try:
            response = self._maxmind_reader.city(ip)

            return GeoLocation(
                ip=ip,
                country=response.country.name,
                country_code=response.country.iso_code,
                region=response.subdivisions.most_specific.name if response.subdivisions else None,
                city=response.city.name,
                postal_code=response.postal.code,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                timezone=response.location.time_zone,
                source="maxmind_db",
            )
        except Exception as e:
            logger.debug(f"MaxMind DB lookup failed for {ip}: {e}")
            return GeoLocation(ip=ip, error=str(e), source="maxmind_db")

    def _lookup_maxmind_web(self, ip: str) -> GeoLocation:
        """Lookup using MaxMind GeoIP2 web service."""
        try:
            response = self._maxmind_client.city(ip)

            return GeoLocation(
                ip=ip,
                country=response.country.name,
                country_code=response.country.iso_code,
                region=response.subdivisions.most_specific.name if response.subdivisions else None,
                city=response.city.name,
                postal_code=response.postal.code,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                timezone=response.location.time_zone,
                source="maxmind_web",
            )
        except Exception as e:
            logger.debug(f"MaxMind web lookup failed for {ip}: {e}")
            return GeoLocation(ip=ip, error=str(e), source="maxmind_web")

    def _lookup_ipinfo(self, ip: str) -> GeoLocation:
        """Lookup using IPInfo.io API."""
        import requests

        try:
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                headers={"Authorization": f"Bearer {self.ipinfo_token}"},
                timeout=5,
            )
            response.raise_for_status()
            data = response.json()

            # Parse location coordinates
            lat, lon = None, None
            if "loc" in data:
                parts = data["loc"].split(",")
                if len(parts) == 2:
                    lat, lon = float(parts[0]), float(parts[1])

            # Parse ASN from org field (e.g., "AS12345 Company Name")
            asn = None
            asn_org = data.get("org")
            if asn_org and asn_org.startswith("AS"):
                parts = asn_org.split(" ", 1)
                try:
                    asn = int(parts[0][2:])
                    asn_org = parts[1] if len(parts) > 1 else None
                except ValueError:
                    pass

            return GeoLocation(
                ip=ip,
                country=data.get("country"),
                country_code=data.get("country"),
                region=data.get("region"),
                city=data.get("city"),
                postal_code=data.get("postal"),
                latitude=lat,
                longitude=lon,
                timezone=data.get("timezone"),
                asn=asn,
                asn_org=asn_org,
                source="ipinfo",
            )
        except Exception as e:
            logger.debug(f"IPInfo lookup failed for {ip}: {e}")
            return GeoLocation(ip=ip, error=str(e), source="ipinfo")

    def _lookup_ipapi(self, ip: str) -> GeoLocation:
        """Lookup using free IP-API.com service."""
        import requests

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting",
                timeout=5,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "success":
                return GeoLocation(
                    ip=ip,
                    error=data.get("message", "Lookup failed"),
                    source="ip-api",
                )

            # Parse ASN from 'as' field (e.g., "AS12345 Company Name")
            asn = None
            as_field = data.get("as", "")
            if as_field.startswith("AS"):
                parts = as_field.split(" ", 1)
                try:
                    asn = int(parts[0][2:])
                except ValueError:
                    pass

            return GeoLocation(
                ip=ip,
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName"),
                city=data.get("city"),
                postal_code=data.get("zip"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                timezone=data.get("timezone"),
                asn=asn,
                asn_org=data.get("asname"),
                isp=data.get("isp"),
                is_proxy=data.get("proxy", False),
                is_datacenter=data.get("hosting", False),
                source="ip-api",
            )
        except Exception as e:
            logger.debug(f"IP-API lookup failed for {ip}: {e}")
            return GeoLocation(ip=ip, error=str(e), source="ip-api")

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/reserved range."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return False

            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.0.0.0/8
            if parts[0] == 127:
                return True
            # 169.254.0.0/16 (link-local)
            if parts[0] == 169 and parts[1] == 254:
                return True

            return False
        except (ValueError, IndexError):
            return False


def get_geolocation(ip: str, **kwargs) -> GeoLocation:
    """Convenience function to get geolocation for an IP.

    Args:
        ip: IP address
        **kwargs: Arguments passed to GeoIPService

    Returns:
        GeoLocation result
    """
    service = GeoIPService(**kwargs)
    return service.lookup(ip)
