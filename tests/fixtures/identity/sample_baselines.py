"""
Sample baselines for different user types.

Provides pre-built baselines representing typical behavior patterns
for different user categories.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from src.shared.identity.baseline.user_baseline import UserBaseline
from src.shared.models.identity_event import GeoLocation

from .sample_events import (
    GEO_NYC,
    GEO_LONDON,
    GEO_TOKYO,
    GEO_SAN_FRANCISCO,
)


def create_office_worker_baseline(
    user_email: str = "office.worker@example.com",
    location: GeoLocation = None,
    tenure_days: int = 90,
) -> UserBaseline:
    """
    Create a baseline for a typical office worker.

    Characteristics:
    - Regular 9-5 working hours
    - Weekday logins only
    - Single office location
    - Limited applications
    - Standard devices
    """
    baseline = UserBaseline(user_email=user_email)
    location = location or GEO_NYC

    # Set maturity
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = tenure_days * 15  # ~15 events per day

    # Working hours: 8 AM - 6 PM
    baseline.typical_hours = list(range(8, 19))

    # Weekdays only
    baseline.typical_days = [0, 1, 2, 3, 4]  # Monday-Friday

    # Single office location
    baseline.known_locations = [location]

    # Known IPs
    baseline.known_ips = {
        "192.168.1.0/24",  # Office network
        f"10.0.0.{user_email.split('@')[0][-2:]}",  # VPN
    }

    # Standard device
    baseline.known_devices = [
        {
            "device_id": "office-desktop-001",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "device_type": "desktop",
            "first_seen": baseline.first_seen,
        }
    ]

    # Core applications
    baseline.typical_applications = {
        "Office365",
        "Salesforce",
        "Slack",
        "Jira",
    }

    # Standard auth methods
    baseline.auth_methods = {"password", "push"}

    # Volume statistics
    baseline.avg_events_per_day = 15.0
    baseline.events_std_dev = 4.5
    baseline.max_events_per_day = 30

    # Not a service account
    baseline.is_service_account = False
    baseline.is_privileged = False

    return baseline


def create_remote_worker_baseline(
    user_email: str = "remote.worker@example.com",
    home_location: GeoLocation = None,
    secondary_locations: list = None,
    tenure_days: int = 60,
) -> UserBaseline:
    """
    Create a baseline for a remote/hybrid worker.

    Characteristics:
    - Flexible hours (but mostly business hours)
    - Multiple locations (home, coffee shops, travel)
    - VPN usage
    - Multiple devices
    - Broader application access
    """
    baseline = UserBaseline(user_email=user_email)
    home = home_location or GEO_NYC

    # Set maturity
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = tenure_days * 20

    # Extended hours: 7 AM - 10 PM (flexible schedule)
    baseline.typical_hours = list(range(7, 23))

    # All days (occasional weekend work)
    baseline.typical_days = [0, 1, 2, 3, 4, 5, 6]

    # Multiple locations
    baseline.known_locations = [home]
    if secondary_locations:
        baseline.known_locations.extend(secondary_locations)
    else:
        # Add a couple default secondary locations
        baseline.known_locations.append(
            GeoLocation(country="US", city="Boston", latitude=42.3601, longitude=-71.0589)
        )

    # Multiple IPs (home, mobile, VPN)
    baseline.known_ips = {
        "home.dynamic.ip",
        "vpn.corporate.10.0.0.0/8",
        "mobile.carrier.ip",
    }

    # Multiple devices
    baseline.known_devices = [
        {
            "device_id": "laptop-work-001",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0.0.0",
            "device_type": "laptop",
            "first_seen": baseline.first_seen,
        },
        {
            "device_id": "mobile-personal-001",
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS) Safari/604.1",
            "device_type": "mobile",
            "first_seen": baseline.first_seen + timedelta(days=10),
        },
    ]

    # Broader application access
    baseline.typical_applications = {
        "Office365",
        "Slack",
        "Zoom",
        "GitHub",
        "Jira",
        "Confluence",
        "AWS Console",
    }

    # Auth methods including mobile
    baseline.auth_methods = {"password", "push", "totp"}

    # Higher volume due to multiple devices
    baseline.avg_events_per_day = 25.0
    baseline.events_std_dev = 8.0
    baseline.max_events_per_day = 50

    baseline.is_service_account = False
    baseline.is_privileged = False

    return baseline


def create_service_account_baseline(
    user_email: str = "svc-automation@example.com",
    tenure_days: int = 180,
) -> UserBaseline:
    """
    Create a baseline for a service account.

    Characteristics:
    - 24/7 activity
    - Single or few IPs
    - High volume, consistent patterns
    - Single application or API
    - No MFA (API keys/certificates)
    """
    baseline = UserBaseline(user_email=user_email)

    # Set maturity
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = tenure_days * 1000  # High volume

    # All hours (24/7 automation)
    baseline.typical_hours = list(range(24))

    # All days
    baseline.typical_days = [0, 1, 2, 3, 4, 5, 6]

    # Data center locations
    baseline.known_locations = [
        GeoLocation(country="US", city="Ashburn", latitude=39.0438, longitude=-77.4874),
        GeoLocation(country="US", city="San Jose", latitude=37.3382, longitude=-121.8863),
    ]

    # Fixed IPs (server IPs)
    baseline.known_ips = {
        "10.100.1.50",
        "10.100.1.51",
        "10.100.2.50",
    }

    # Server identity
    baseline.known_devices = [
        {
            "device_id": "automation-server-001",
            "user_agent": "python-requests/2.28.0",
            "device_type": "server",
            "first_seen": baseline.first_seen,
        }
    ]

    # Single application
    baseline.typical_applications = {"API Gateway", "Internal API"}

    # API authentication
    baseline.auth_methods = {"api_key", "certificate"}

    # Very high, consistent volume
    baseline.avg_events_per_day = 1000.0
    baseline.events_std_dev = 50.0
    baseline.max_events_per_day = 1500

    # Service account flag
    baseline.is_service_account = True
    baseline.is_privileged = True

    return baseline


def create_admin_user_baseline(
    user_email: str = "admin.user@example.com",
    tenure_days: int = 365,
) -> UserBaseline:
    """
    Create a baseline for an admin/IT user.

    Characteristics:
    - Extended hours (on-call)
    - Multiple locations (office, home, travel)
    - Admin console access
    - Multiple devices
    - Higher privileges
    """
    baseline = UserBaseline(user_email=user_email)

    # Set maturity (long tenure)
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = tenure_days * 30

    # Extended hours (includes on-call)
    baseline.typical_hours = list(range(6, 24))  # 6 AM - midnight

    # All days (on-call)
    baseline.typical_days = [0, 1, 2, 3, 4, 5, 6]

    # Multiple locations
    baseline.known_locations = [
        GEO_NYC,
        GEO_SAN_FRANCISCO,
        GeoLocation(country="US", city="Seattle", latitude=47.6062, longitude=-122.3321),
    ]

    # Multiple IPs
    baseline.known_ips = {
        "192.168.1.0/24",
        "10.0.0.0/8",
        "home.isp.range",
    }

    # Multiple devices
    baseline.known_devices = [
        {
            "device_id": "admin-laptop-001",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
            "device_type": "laptop",
            "first_seen": baseline.first_seen,
        },
        {
            "device_id": "admin-mobile-001",
            "user_agent": "Mozilla/5.0 (iPhone) Safari/604.1",
            "device_type": "mobile",
            "first_seen": baseline.first_seen + timedelta(days=30),
        },
    ]

    # Admin applications
    baseline.typical_applications = {
        "Office365",
        "Okta Admin",
        "Azure Portal",
        "AWS Console",
        "GitHub",
        "PagerDuty",
        "Splunk",
        "CrowdStrike",
    }

    # Multiple auth methods including hardware key
    baseline.auth_methods = {"password", "push", "totp", "hardware_key"}

    # Moderate volume
    baseline.avg_events_per_day = 40.0
    baseline.events_std_dev = 15.0
    baseline.max_events_per_day = 100

    baseline.is_service_account = False
    baseline.is_privileged = True
    baseline.is_admin = True

    return baseline


def create_executive_baseline(
    user_email: str = "ceo@example.com",
    tenure_days: int = 500,
) -> UserBaseline:
    """
    Create a baseline for an executive user.

    Characteristics:
    - Irregular hours (early/late)
    - Travel to many locations
    - Multiple devices including personal
    - High-value target (VIP)
    - Assistants may access account
    """
    baseline = UserBaseline(user_email=user_email)

    # Long tenure
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = tenure_days * 12

    # Irregular hours (early morning, late night)
    baseline.typical_hours = list(range(5, 24))  # 5 AM - midnight

    # All days
    baseline.typical_days = [0, 1, 2, 3, 4, 5, 6]

    # Many travel locations
    baseline.known_locations = [
        GEO_NYC,
        GEO_LONDON,
        GEO_TOKYO,
        GEO_SAN_FRANCISCO,
        GeoLocation(country="SG", city="Singapore", latitude=1.3521, longitude=103.8198),
        GeoLocation(country="AE", city="Dubai", latitude=25.2048, longitude=55.2708),
    ]

    # Various IPs
    baseline.known_ips = {
        "executive.office.ip",
        "executive.home.ip",
        "hotel.ip.range",
        "airport.lounge.ip.range",
    }

    # Multiple devices
    baseline.known_devices = [
        {
            "device_id": "exec-laptop-001",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/17.0",
            "device_type": "laptop",
            "first_seen": baseline.first_seen,
        },
        {
            "device_id": "exec-ipad-001",
            "user_agent": "Mozilla/5.0 (iPad; CPU OS) Safari/604.1",
            "device_type": "tablet",
            "first_seen": baseline.first_seen + timedelta(days=60),
        },
        {
            "device_id": "exec-iphone-001",
            "user_agent": "Mozilla/5.0 (iPhone) Safari/604.1",
            "device_type": "mobile",
            "first_seen": baseline.first_seen + timedelta(days=30),
        },
    ]

    # Executive applications
    baseline.typical_applications = {
        "Office365",
        "Salesforce",
        "Slack",
        "Zoom",
        "Board Portal",
        "DocuSign",
    }

    # Auth methods
    baseline.auth_methods = {"password", "push"}

    # Moderate volume
    baseline.avg_events_per_day = 15.0
    baseline.events_std_dev = 8.0
    baseline.max_events_per_day = 40

    baseline.is_service_account = False
    baseline.is_privileged = True
    baseline.is_executive = True
    baseline.is_vip = True

    return baseline


def create_new_employee_baseline(
    user_email: str = "new.employee@example.com",
    tenure_days: int = 7,
) -> UserBaseline:
    """
    Create a baseline for a new employee (immature baseline).

    Characteristics:
    - Very few days of history
    - Limited data
    - Low confidence
    - Learning period
    """
    baseline = UserBaseline(user_email=user_email)

    # Very short tenure
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = tenure_days * 10

    # Limited hours observed
    baseline.typical_hours = [9, 10, 11, 12, 13, 14, 15, 16, 17]

    # Only weekdays so far
    baseline.typical_days = [0, 1, 2, 3, 4]

    # Single location
    baseline.known_locations = [GEO_NYC]

    # Single IP
    baseline.known_ips = {"192.168.1.100"}

    # Single device
    baseline.known_devices = [
        {
            "device_id": "new-laptop-001",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
            "device_type": "laptop",
            "first_seen": baseline.first_seen,
        }
    ]

    # Limited applications
    baseline.typical_applications = {"Office365", "Slack"}

    # Basic auth
    baseline.auth_methods = {"password", "push"}

    # Low volume
    baseline.avg_events_per_day = 10.0
    baseline.events_std_dev = 3.0
    baseline.max_events_per_day = 20

    baseline.is_service_account = False
    baseline.is_privileged = False
    baseline.maturity_status = "learning"

    return baseline


def create_dormant_account_baseline(
    user_email: str = "former.employee@example.com",
    tenure_days: int = 365,
    dormant_days: int = 90,
) -> UserBaseline:
    """
    Create a baseline for a dormant account.

    Characteristics:
    - Long history but no recent activity
    - Should trigger alerts if suddenly active
    """
    baseline = UserBaseline(user_email=user_email)

    # Long history
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=tenure_days)
    # Last activity long ago
    baseline.last_updated = datetime.now(timezone.utc) - timedelta(days=dormant_days)
    baseline.event_count = (tenure_days - dormant_days) * 15

    # Historical patterns
    baseline.typical_hours = list(range(8, 18))
    baseline.typical_days = [0, 1, 2, 3, 4]
    baseline.known_locations = [GEO_NYC]
    baseline.known_ips = {"192.168.1.0/24"}

    baseline.known_devices = [
        {
            "device_id": "old-laptop-001",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/115.0.0.0",
            "device_type": "laptop",
            "first_seen": baseline.first_seen,
        }
    ]

    baseline.typical_applications = {"Office365", "Salesforce", "Slack"}
    baseline.auth_methods = {"password", "push"}

    baseline.avg_events_per_day = 15.0
    baseline.events_std_dev = 5.0
    baseline.max_events_per_day = 30

    baseline.is_service_account = False
    baseline.is_privileged = False
    baseline.is_dormant = True
    baseline.maturity_status = "stale"

    return baseline
