"""Threat Intelligence Enrichment Service.

Provides threat intelligence lookups via VirusTotal and AbuseIPDB APIs.
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Threat intelligence result for an indicator."""

    indicator: str
    indicator_type: str  # ip, domain, hash, url

    # Reputation scores
    reputation_score: Optional[float] = None  # 0-100, higher = more malicious
    is_malicious: bool = False
    confidence: float = 0.0  # 0-1

    # Categories and tags
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Detection stats (for hashes)
    detection_count: int = 0
    total_engines: int = 0

    # IP-specific
    abuse_score: Optional[int] = None  # AbuseIPDB confidence score (0-100)
    total_reports: int = 0
    last_reported: Optional[str] = None
    is_tor_exit: bool = False
    is_vpn: bool = False
    is_proxy: bool = False

    # Domain-specific
    registrar: Optional[str] = None
    creation_date: Optional[str] = None

    # Metadata
    sources: List[str] = field(default_factory=list)
    cached: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "reputation_score": self.reputation_score,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "categories": self.categories,
            "tags": self.tags,
            "detection_count": self.detection_count,
            "total_engines": self.total_engines,
            "abuse_score": self.abuse_score,
            "total_reports": self.total_reports,
            "last_reported": self.last_reported,
            "is_tor_exit": self.is_tor_exit,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "sources": self.sources,
            "cached": self.cached,
            "error": self.error,
        }


class ThreatIntelCache:
    """In-memory cache for threat intel results."""

    def __init__(self, ttl_hours: int = 24, max_size: int = 10000):
        """Initialize cache.

        Args:
            ttl_hours: Time-to-live in hours
            max_size: Maximum cache entries
        """
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
        self._cache: Dict[str, tuple] = {}  # key -> (result, timestamp)

    def _make_key(self, indicator: str, indicator_type: str) -> str:
        """Generate cache key."""
        return f"{indicator_type}:{indicator.lower()}"

    def get(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        """Get cached result."""
        key = self._make_key(indicator, indicator_type)
        if key in self._cache:
            result, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                result.cached = True
                return result
            else:
                del self._cache[key]
        return None

    def put(self, result: ThreatIntelResult) -> None:
        """Cache result."""
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        key = self._make_key(result.indicator, result.indicator_type)
        self._cache[key] = (result, datetime.utcnow())

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()


class ThreatIntelService:
    """Threat intelligence service with multiple providers."""

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        cache_ttl_hours: int = 24,
    ):
        """Initialize threat intel service.

        Args:
            virustotal_api_key: VirusTotal API key
            abuseipdb_api_key: AbuseIPDB API key
            cache_ttl_hours: Cache TTL in hours
        """
        self.vt_api_key = virustotal_api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self.abuseipdb_api_key = abuseipdb_api_key or os.environ.get("ABUSEIPDB_API_KEY")
        self.cache = ThreatIntelCache(ttl_hours=cache_ttl_hours)

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Lookup threat intel for an IP address.

        Args:
            ip: IP address to lookup

        Returns:
            ThreatIntelResult
        """
        # Check cache
        cached = self.cache.get(ip, "ip")
        if cached:
            return cached

        result = ThreatIntelResult(indicator=ip, indicator_type="ip")
        sources_used = []

        # Query AbuseIPDB
        if self.abuseipdb_api_key:
            abuse_result = self._lookup_abuseipdb(ip)
            if not abuse_result.error:
                result.abuse_score = abuse_result.abuse_score
                result.total_reports = abuse_result.total_reports
                result.last_reported = abuse_result.last_reported
                result.is_tor_exit = abuse_result.is_tor_exit
                result.categories.extend(abuse_result.categories)
                sources_used.append("abuseipdb")

                # Set malicious if high abuse score
                if result.abuse_score and result.abuse_score >= 50:
                    result.is_malicious = True
                    result.confidence = result.abuse_score / 100.0

        # Query VirusTotal
        if self.vt_api_key:
            vt_result = self._lookup_virustotal_ip(ip)
            if not vt_result.error:
                result.detection_count = vt_result.detection_count
                result.total_engines = vt_result.total_engines
                result.tags.extend(vt_result.tags)
                sources_used.append("virustotal")

                # Set malicious if detections found
                if vt_result.detection_count > 0:
                    result.is_malicious = True
                    vt_confidence = vt_result.detection_count / max(vt_result.total_engines, 1)
                    result.confidence = max(result.confidence, vt_confidence)

        # Calculate combined reputation score
        if result.abuse_score is not None or result.detection_count > 0:
            scores = []
            if result.abuse_score is not None:
                scores.append(result.abuse_score)
            if result.total_engines > 0:
                scores.append((result.detection_count / result.total_engines) * 100)
            result.reputation_score = sum(scores) / len(scores) if scores else 0

        result.sources = sources_used
        self.cache.put(result)
        return result

    def lookup_hash(self, file_hash: str) -> ThreatIntelResult:
        """Lookup threat intel for a file hash.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            ThreatIntelResult
        """
        # Normalize hash
        file_hash = file_hash.lower().strip()

        # Determine hash type
        hash_type = "hash"
        if len(file_hash) == 32:
            hash_type = "md5"
        elif len(file_hash) == 40:
            hash_type = "sha1"
        elif len(file_hash) == 64:
            hash_type = "sha256"

        # Check cache
        cached = self.cache.get(file_hash, "hash")
        if cached:
            return cached

        result = ThreatIntelResult(indicator=file_hash, indicator_type=hash_type)

        # Query VirusTotal
        if self.vt_api_key:
            vt_result = self._lookup_virustotal_hash(file_hash)
            if not vt_result.error:
                result.detection_count = vt_result.detection_count
                result.total_engines = vt_result.total_engines
                result.tags = vt_result.tags
                result.categories = vt_result.categories
                result.sources.append("virustotal")

                if vt_result.detection_count > 0:
                    result.is_malicious = True
                    result.confidence = vt_result.detection_count / max(vt_result.total_engines, 1)
                    result.reputation_score = result.confidence * 100

        self.cache.put(result)
        return result

    def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """Lookup threat intel for a domain.

        Args:
            domain: Domain name to lookup

        Returns:
            ThreatIntelResult
        """
        # Normalize domain
        domain = domain.lower().strip()

        # Check cache
        cached = self.cache.get(domain, "domain")
        if cached:
            return cached

        result = ThreatIntelResult(indicator=domain, indicator_type="domain")

        # Query VirusTotal
        if self.vt_api_key:
            vt_result = self._lookup_virustotal_domain(domain)
            if not vt_result.error:
                result.detection_count = vt_result.detection_count
                result.total_engines = vt_result.total_engines
                result.categories = vt_result.categories
                result.registrar = vt_result.registrar
                result.creation_date = vt_result.creation_date
                result.sources.append("virustotal")

                if vt_result.detection_count > 0:
                    result.is_malicious = True
                    result.confidence = vt_result.detection_count / max(vt_result.total_engines, 1)
                    result.reputation_score = result.confidence * 100

        self.cache.put(result)
        return result

    def _lookup_abuseipdb(self, ip: str) -> ThreatIntelResult:
        """Lookup IP in AbuseIPDB."""
        import requests

        result = ThreatIntelResult(indicator=ip, indicator_type="ip")

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                    "verbose": "",
                },
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            result.abuse_score = data.get("abuseConfidenceScore", 0)
            result.total_reports = data.get("totalReports", 0)
            result.last_reported = data.get("lastReportedAt")
            result.is_tor_exit = data.get("isTor", False)

            # Parse categories
            category_map = {
                1: "DNS Compromise",
                2: "DNS Poisoning",
                3: "Fraud Orders",
                4: "DDoS Attack",
                5: "FTP Brute-Force",
                6: "Ping of Death",
                7: "Phishing",
                8: "Fraud VoIP",
                9: "Open Proxy",
                10: "Web Spam",
                11: "Email Spam",
                12: "Blog Spam",
                13: "VPN IP",
                14: "Port Scan",
                15: "Hacking",
                16: "SQL Injection",
                17: "Spoofing",
                18: "Brute-Force",
                19: "Bad Web Bot",
                20: "Exploited Host",
                21: "Web App Attack",
                22: "SSH",
                23: "IoT Targeted",
            }

            for report in data.get("reports", [])[:10]:
                for cat_id in report.get("categories", []):
                    cat_name = category_map.get(cat_id, f"Category {cat_id}")
                    if cat_name not in result.categories:
                        result.categories.append(cat_name)

            return result

        except Exception as e:
            logger.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
            result.error = str(e)
            return result

    def _lookup_virustotal_ip(self, ip: str) -> ThreatIntelResult:
        """Lookup IP in VirusTotal."""
        import requests

        result = ThreatIntelResult(indicator=ip, indicator_type="ip")

        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_api_key},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})

            # Get last analysis stats
            stats = data.get("last_analysis_stats", {})
            result.detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            result.total_engines = sum(stats.values())

            # Get tags
            result.tags = data.get("tags", [])

            return result

        except Exception as e:
            logger.debug(f"VirusTotal IP lookup failed for {ip}: {e}")
            result.error = str(e)
            return result

    def _lookup_virustotal_hash(self, file_hash: str) -> ThreatIntelResult:
        """Lookup file hash in VirusTotal."""
        import requests

        result = ThreatIntelResult(indicator=file_hash, indicator_type="hash")

        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.vt_api_key},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})

            # Get last analysis stats
            stats = data.get("last_analysis_stats", {})
            result.detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            result.total_engines = sum(stats.values())

            # Get tags and categories
            result.tags = data.get("tags", [])
            result.categories = list(data.get("popular_threat_classification", {}).get("suggested_threat_label", []))

            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # Hash not found - not necessarily malicious
                return result
            logger.debug(f"VirusTotal hash lookup failed for {file_hash}: {e}")
            result.error = str(e)
            return result
        except Exception as e:
            logger.debug(f"VirusTotal hash lookup failed for {file_hash}: {e}")
            result.error = str(e)
            return result

    def _lookup_virustotal_domain(self, domain: str) -> ThreatIntelResult:
        """Lookup domain in VirusTotal."""
        import requests

        result = ThreatIntelResult(indicator=domain, indicator_type="domain")

        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.vt_api_key},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})

            # Get last analysis stats
            stats = data.get("last_analysis_stats", {})
            result.detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            result.total_engines = sum(stats.values())

            # Get categories
            result.categories = list(data.get("categories", {}).values())

            # Get WHOIS info
            result.registrar = data.get("registrar")
            result.creation_date = data.get("creation_date")

            return result

        except Exception as e:
            logger.debug(f"VirusTotal domain lookup failed for {domain}: {e}")
            result.error = str(e)
            return result


def lookup_ip_reputation(ip: str, **kwargs) -> ThreatIntelResult:
    """Convenience function to lookup IP reputation.

    Args:
        ip: IP address
        **kwargs: Arguments passed to ThreatIntelService

    Returns:
        ThreatIntelResult
    """
    service = ThreatIntelService(**kwargs)
    return service.lookup_ip(ip)


def lookup_hash(file_hash: str, **kwargs) -> ThreatIntelResult:
    """Convenience function to lookup file hash.

    Args:
        file_hash: File hash (MD5, SHA1, SHA256)
        **kwargs: Arguments passed to ThreatIntelService

    Returns:
        ThreatIntelResult
    """
    service = ThreatIntelService(**kwargs)
    return service.lookup_hash(file_hash)


def lookup_domain(domain: str, **kwargs) -> ThreatIntelResult:
    """Convenience function to lookup domain.

    Args:
        domain: Domain name
        **kwargs: Arguments passed to ThreatIntelService

    Returns:
        ThreatIntelResult
    """
    service = ThreatIntelService(**kwargs)
    return service.lookup_domain(domain)
