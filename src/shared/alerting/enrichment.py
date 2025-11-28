"""Alert enrichment for adding context to security alerts."""

import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from ..detection.alert_generator import Alert


class AlertEnricher:
    """Enriches alerts with additional context."""

    def __init__(
        self,
        enable_ip_geolocation: bool = False,
        enable_threat_intel: bool = False,
        enable_related_alerts: bool = False,
        state_manager: Optional[Any] = None
    ):
        """Initialize alert enricher.

        Args:
            enable_ip_geolocation: Enable IP geolocation lookup
            enable_threat_intel: Enable threat intelligence lookup
            enable_related_alerts: Enable related alerts lookup
            state_manager: State manager for related alerts lookup
        """
        self.enable_ip_geolocation = enable_ip_geolocation
        self.enable_threat_intel = enable_threat_intel
        self.enable_related_alerts = enable_related_alerts
        self.state_manager = state_manager

    def enrich(self, alert: Alert) -> Alert:
        """Enrich alert with additional context.

        Args:
            alert: Alert to enrich

        Returns:
            Enriched alert
        """
        enrichment = {}

        # Extract IPs from results
        ips = self._extract_ips(alert)

        if ips:
            enrichment["ips_found"] = ips

            # Add IP geolocation
            if self.enable_ip_geolocation:
                enrichment["geolocation"] = self._get_geolocation(ips)

            # Add threat intelligence
            if self.enable_threat_intel:
                enrichment["threat_intel"] = self._get_threat_intel(ips)

        # Extract users from results
        users = self._extract_users(alert)
        if users:
            enrichment["users_found"] = users

        # Add related alerts
        if self.enable_related_alerts and self.state_manager:
            enrichment["related_alerts"] = self._get_related_alerts(alert)

        # Add enrichment to alert metadata
        if enrichment:
            if not alert.metadata:
                alert.metadata = {}
            alert.metadata["enrichment"] = enrichment

        return alert

    def _extract_ips(self, alert: Alert) -> List[str]:
        """Extract IP addresses from alert.

        Args:
            alert: Alert to extract IPs from

        Returns:
            List of unique IP addresses
        """
        ips = set()

        # IP regex pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

        # Check results for IP fields
        if alert.results:
            for result in alert.results:
                # Common IP field names
                ip_fields = ['source_ip', 'sourceipaddress', 'srcaddr', 'src_ip',
                            'destination_ip', 'dstaddr', 'dst_ip', 'ip', 'ip_address']

                for field in ip_fields:
                    if field in result and result[field]:
                        value = str(result[field])
                        if self._is_valid_ip(value):
                            ips.add(value)

                # Also search in string values
                for value in result.values():
                    if isinstance(value, str):
                        found_ips = re.findall(ip_pattern, value)
                        for ip in found_ips:
                            if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                                ips.add(ip)

        return list(ips)

    def _extract_users(self, alert: Alert) -> List[str]:
        """Extract usernames from alert.

        Args:
            alert: Alert to extract users from

        Returns:
            List of unique usernames
        """
        users = set()

        if alert.results:
            for result in alert.results:
                # Common user field names
                user_fields = ['user', 'username', 'user_name', 'principal_id',
                              'useridentity', 'identity', 'actor']

                for field in user_fields:
                    if field in result and result[field]:
                        users.add(str(result[field]))

        return list(users)

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address.

        Args:
            ip: String to check

        Returns:
            True if valid IP
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range.

        Args:
            ip: IP address

        Returns:
            True if private IP
        """
        parts = [int(p) for p in ip.split('.')]

        # 10.0.0.0/8
        if parts[0] == 10:
            return True

        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True

        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True

        # 127.0.0.0/8 (localhost)
        if parts[0] == 127:
            return True

        return False

    def _get_geolocation(self, ips: List[str]) -> Dict[str, Dict]:
        """Get geolocation data for IP addresses.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary of IP to geolocation data
        """
        geolocation = {}

        for ip in ips:
            if self._is_private_ip(ip):
                geolocation[ip] = {"type": "private", "location": "Internal Network"}
                continue

            try:
                geo_data = self._lookup_geolocation(ip)
                geolocation[ip] = geo_data
            except Exception as e:
                print(f"Error looking up geolocation for {ip}: {e}")
                geolocation[ip] = {"error": str(e)}

        return geolocation

    def _lookup_geolocation(self, ip: str) -> Dict:
        """Lookup geolocation for single IP.

        Args:
            ip: IP address

        Returns:
            Geolocation data
        """
        # Placeholder implementation
        # In production, integrate with MaxMind GeoIP2 or ip-api.com
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "source": "placeholder"
        }

    def _get_threat_intel(self, ips: List[str]) -> Dict[str, Dict]:
        """Get threat intelligence for IP addresses.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary of IP to threat intel data
        """
        threat_intel = {}

        for ip in ips:
            if self._is_private_ip(ip):
                threat_intel[ip] = {"type": "private", "reputation": "internal"}
                continue

            try:
                intel_data = self._lookup_threat_intel(ip)
                threat_intel[ip] = intel_data
            except Exception as e:
                print(f"Error looking up threat intel for {ip}: {e}")
                threat_intel[ip] = {"error": str(e)}

        return threat_intel

    def _lookup_threat_intel(self, ip: str) -> Dict:
        """Lookup threat intelligence for single IP.

        Args:
            ip: IP address

        Returns:
            Threat intelligence data
        """
        # Placeholder implementation
        # In production, integrate with:
        # - VirusTotal API
        # - AbuseIPDB
        # - AlienVault OTX
        # - Shodan
        return {
            "ip": ip,
            "reputation": "unknown",
            "malicious": False,
            "categories": [],
            "source": "placeholder"
        }

    def _get_related_alerts(self, alert: Alert) -> List[Dict]:
        """Get related alerts from history.

        Args:
            alert: Current alert

        Returns:
            List of related alerts
        """
        if not self.state_manager:
            return []

        related = []

        try:
            # Get IPs and users from current alert
            ips = self._extract_ips(alert)
            users = self._extract_users(alert)

            # Look for alerts with same IPs or users in last 24 hours
            for ip in ips[:5]:  # Limit to first 5 IPs
                history = self.state_manager.get_alert_history(
                    suppression_key=f"ip-{ip}",
                    limit=5
                )
                related.extend(history)

            for user in users[:5]:  # Limit to first 5 users
                history = self.state_manager.get_alert_history(
                    suppression_key=f"user-{user}",
                    limit=5
                )
                related.extend(history)

            # Remove duplicates and limit total
            seen = set()
            unique_related = []
            for item in related:
                if isinstance(item, dict):
                    alert_id = item.get('alert_id') or item.get('id')
                    if alert_id and alert_id != alert.id and alert_id not in seen:
                        seen.add(alert_id)
                        unique_related.append(item)

            return unique_related[:10]  # Return max 10 related alerts

        except Exception as e:
            print(f"Error getting related alerts: {e}")
            return []


class IPGeolocationService:
    """Service for IP geolocation lookup using external APIs."""

    def __init__(self, api_key: Optional[str] = None, provider: str = "ip-api"):
        """Initialize geolocation service.

        Args:
            api_key: API key for commercial providers
            provider: Provider name ('ip-api', 'maxmind', 'ipinfo')
        """
        self.api_key = api_key
        self.provider = provider

    def lookup(self, ip: str) -> Dict:
        """Lookup geolocation for IP address.

        Args:
            ip: IP address

        Returns:
            Geolocation data
        """
        if self.provider == "ip-api":
            return self._lookup_ipapi(ip)
        elif self.provider == "maxmind":
            return self._lookup_maxmind(ip)
        elif self.provider == "ipinfo":
            return self._lookup_ipinfo(ip)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _lookup_ipapi(self, ip: str) -> Dict:
        """Lookup using ip-api.com (free, no key required).

        Args:
            ip: IP address

        Returns:
            Geolocation data
        """
        import requests

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            response.raise_for_status()

            data = response.json()

            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "isp": data.get("isp"),
                    "source": "ip-api"
                }
            else:
                return {"ip": ip, "error": "Lookup failed", "source": "ip-api"}

        except Exception as e:
            return {"ip": ip, "error": str(e), "source": "ip-api"}

    def _lookup_maxmind(self, ip: str) -> Dict:
        """Lookup using MaxMind GeoIP2 (requires license).

        Args:
            ip: IP address

        Returns:
            Geolocation data
        """
        # Placeholder - requires maxminddb-geolite2 package
        return {
            "ip": ip,
            "error": "MaxMind integration not implemented",
            "source": "maxmind"
        }

    def _lookup_ipinfo(self, ip: str) -> Dict:
        """Lookup using ipinfo.io (requires API key).

        Args:
            ip: IP address

        Returns:
            Geolocation data
        """
        import requests

        if not self.api_key:
            return {"ip": ip, "error": "API key required", "source": "ipinfo"}

        try:
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=5
            )
            response.raise_for_status()

            data = response.json()
            loc = data.get("loc", "0,0").split(",")

            return {
                "ip": ip,
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": float(loc[0]) if len(loc) > 0 else 0.0,
                "longitude": float(loc[1]) if len(loc) > 1 else 0.0,
                "org": data.get("org"),
                "source": "ipinfo"
            }

        except Exception as e:
            return {"ip": ip, "error": str(e), "source": "ipinfo"}
