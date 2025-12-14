"""Behavioral baseline enrichment for security alerts.

Tracks normal behavior patterns per user/asset and flags deviations:
- Unusual login times (outside normal hours)
- New source IPs/locations
- Unusual data access patterns
- New applications/services accessed
- Anomalous activity volume
"""

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class DeviationType(Enum):
    """Types of behavioral deviations detected."""

    UNUSUAL_TIME = "unusual_time"
    NEW_SOURCE_IP = "new_source_ip"
    NEW_LOCATION = "new_location"
    NEW_DEVICE = "new_device"
    NEW_APPLICATION = "new_application"
    UNUSUAL_VOLUME = "unusual_volume"
    NEW_DATA_ACCESS = "new_data_access"
    FIRST_TIME_ACTIVITY = "first_time_activity"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class RiskLevel(Enum):
    """Risk level for behavioral deviations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehavioralDeviation:
    """Represents a detected behavioral deviation."""

    deviation_type: DeviationType
    risk_level: RiskLevel
    description: str
    expected_value: Optional[str] = None
    observed_value: Optional[str] = None
    confidence: float = 0.0  # 0.0 to 1.0
    first_seen: Optional[datetime] = None
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserBaseline:
    """Baseline behavior profile for a user."""

    user_id: str
    email: Optional[str] = None

    # Time patterns (hour of day, day of week)
    typical_login_hours: Set[int] = field(default_factory=set)  # 0-23
    typical_login_days: Set[int] = field(default_factory=set)  # 0-6 (Mon-Sun)

    # Location patterns
    known_source_ips: Set[str] = field(default_factory=set)
    known_countries: Set[str] = field(default_factory=set)
    known_cities: Set[str] = field(default_factory=set)

    # Device patterns
    known_devices: Set[str] = field(default_factory=set)
    known_user_agents: Set[str] = field(default_factory=set)

    # Application patterns
    known_applications: Set[str] = field(default_factory=set)
    known_services: Set[str] = field(default_factory=set)

    # Volume patterns
    avg_daily_events: float = 0.0
    std_daily_events: float = 0.0
    max_daily_events: int = 0

    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    baseline_period_days: int = 30
    last_updated: Optional[datetime] = None


@dataclass
class AssetBaseline:
    """Baseline behavior profile for an asset."""

    asset_id: str
    asset_type: str  # server, database, storage, etc.

    # Access patterns
    known_accessor_users: Set[str] = field(default_factory=set)
    known_accessor_ips: Set[str] = field(default_factory=set)
    known_accessor_roles: Set[str] = field(default_factory=set)

    # Time patterns
    typical_access_hours: Set[int] = field(default_factory=set)
    typical_access_days: Set[int] = field(default_factory=set)

    # Volume patterns
    avg_daily_accesses: float = 0.0
    std_daily_accesses: float = 0.0
    avg_data_volume_mb: float = 0.0
    std_data_volume_mb: float = 0.0

    # Operation patterns
    known_operations: Set[str] = field(default_factory=set)

    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    baseline_period_days: int = 30
    last_updated: Optional[datetime] = None


@dataclass
class BehavioralAnalysisResult:
    """Result of behavioral analysis on an event."""

    entity_type: str  # "user" or "asset"
    entity_id: str
    is_anomalous: bool
    deviations: List[BehavioralDeviation] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 to 100.0
    baseline_exists: bool = False
    baseline_age_days: int = 0
    confidence: float = 0.0  # 0.0 to 1.0 (based on baseline maturity)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for alert enrichment."""
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "is_anomalous": self.is_anomalous,
            "risk_score": self.risk_score,
            "baseline_exists": self.baseline_exists,
            "baseline_confidence": self.confidence,
            "deviations": [
                {
                    "type": d.deviation_type.value,
                    "risk_level": d.risk_level.value,
                    "description": d.description,
                    "expected": d.expected_value,
                    "observed": d.observed_value,
                    "confidence": d.confidence
                }
                for d in self.deviations
            ]
        }


class BaselineStore(ABC):
    """Abstract base class for baseline storage."""

    @abstractmethod
    def get_user_baseline(self, user_id: str) -> Optional[UserBaseline]:
        """Retrieve user baseline."""
        pass

    @abstractmethod
    def save_user_baseline(self, baseline: UserBaseline) -> None:
        """Save user baseline."""
        pass

    @abstractmethod
    def get_asset_baseline(self, asset_id: str) -> Optional[AssetBaseline]:
        """Retrieve asset baseline."""
        pass

    @abstractmethod
    def save_asset_baseline(self, baseline: AssetBaseline) -> None:
        """Save asset baseline."""
        pass

    @abstractmethod
    def list_user_baselines(self, limit: int = 1000) -> List[UserBaseline]:
        """List all user baselines."""
        pass

    @abstractmethod
    def list_asset_baselines(self, limit: int = 1000) -> List[AssetBaseline]:
        """List all asset baselines."""
        pass


class InMemoryBaselineStore(BaselineStore):
    """In-memory implementation of baseline storage for development/testing."""

    def __init__(self):
        self._user_baselines: Dict[str, UserBaseline] = {}
        self._asset_baselines: Dict[str, AssetBaseline] = {}

    def get_user_baseline(self, user_id: str) -> Optional[UserBaseline]:
        return self._user_baselines.get(user_id)

    def save_user_baseline(self, baseline: UserBaseline) -> None:
        self._user_baselines[baseline.user_id] = baseline

    def get_asset_baseline(self, asset_id: str) -> Optional[AssetBaseline]:
        return self._asset_baselines.get(asset_id)

    def save_asset_baseline(self, baseline: AssetBaseline) -> None:
        self._asset_baselines[baseline.asset_id] = baseline

    def list_user_baselines(self, limit: int = 1000) -> List[UserBaseline]:
        return list(self._user_baselines.values())[:limit]

    def list_asset_baselines(self, limit: int = 1000) -> List[AssetBaseline]:
        return list(self._asset_baselines.values())[:limit]


class DynamoDBBaselineStore(BaselineStore):
    """DynamoDB implementation of baseline storage for AWS deployments."""

    def __init__(
        self,
        table_name: str = "mantissa-baselines",
        region: str = "us-east-1"
    ):
        self.table_name = table_name
        self.region = region
        self._table = None

    def _get_table(self):
        """Lazy initialization of DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def get_user_baseline(self, user_id: str) -> Optional[UserBaseline]:
        try:
            response = self._get_table().get_item(
                Key={"pk": f"USER#{user_id}", "sk": "BASELINE"}
            )
            if "Item" not in response:
                return None
            return self._item_to_user_baseline(response["Item"])
        except Exception as e:
            logger.error(f"Error getting user baseline: {e}")
            return None

    def save_user_baseline(self, baseline: UserBaseline) -> None:
        try:
            item = self._user_baseline_to_item(baseline)
            self._get_table().put_item(Item=item)
        except Exception as e:
            logger.error(f"Error saving user baseline: {e}")

    def get_asset_baseline(self, asset_id: str) -> Optional[AssetBaseline]:
        try:
            response = self._get_table().get_item(
                Key={"pk": f"ASSET#{asset_id}", "sk": "BASELINE"}
            )
            if "Item" not in response:
                return None
            return self._item_to_asset_baseline(response["Item"])
        except Exception as e:
            logger.error(f"Error getting asset baseline: {e}")
            return None

    def save_asset_baseline(self, baseline: AssetBaseline) -> None:
        try:
            item = self._asset_baseline_to_item(baseline)
            self._get_table().put_item(Item=item)
        except Exception as e:
            logger.error(f"Error saving asset baseline: {e}")

    def list_user_baselines(self, limit: int = 1000) -> List[UserBaseline]:
        try:
            response = self._get_table().query(
                IndexName="gsi-type",
                KeyConditionExpression="entity_type = :type",
                ExpressionAttributeValues={":type": "USER"},
                Limit=limit
            )
            return [self._item_to_user_baseline(item) for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error listing user baselines: {e}")
            return []

    def list_asset_baselines(self, limit: int = 1000) -> List[AssetBaseline]:
        try:
            response = self._get_table().query(
                IndexName="gsi-type",
                KeyConditionExpression="entity_type = :type",
                ExpressionAttributeValues={":type": "ASSET"},
                Limit=limit
            )
            return [self._item_to_asset_baseline(item) for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error listing asset baselines: {e}")
            return []

    def _user_baseline_to_item(self, baseline: UserBaseline) -> Dict[str, Any]:
        return {
            "pk": f"USER#{baseline.user_id}",
            "sk": "BASELINE",
            "entity_type": "USER",
            "user_id": baseline.user_id,
            "email": baseline.email,
            "typical_login_hours": list(baseline.typical_login_hours),
            "typical_login_days": list(baseline.typical_login_days),
            "known_source_ips": list(baseline.known_source_ips),
            "known_countries": list(baseline.known_countries),
            "known_cities": list(baseline.known_cities),
            "known_devices": list(baseline.known_devices),
            "known_user_agents": list(baseline.known_user_agents),
            "known_applications": list(baseline.known_applications),
            "known_services": list(baseline.known_services),
            "avg_daily_events": str(baseline.avg_daily_events),
            "std_daily_events": str(baseline.std_daily_events),
            "max_daily_events": baseline.max_daily_events,
            "first_seen": baseline.first_seen.isoformat() if baseline.first_seen else None,
            "last_seen": baseline.last_seen.isoformat() if baseline.last_seen else None,
            "total_events": baseline.total_events,
            "baseline_period_days": baseline.baseline_period_days,
            "last_updated": datetime.utcnow().isoformat()
        }

    def _item_to_user_baseline(self, item: Dict[str, Any]) -> UserBaseline:
        return UserBaseline(
            user_id=item["user_id"],
            email=item.get("email"),
            typical_login_hours=set(item.get("typical_login_hours", [])),
            typical_login_days=set(item.get("typical_login_days", [])),
            known_source_ips=set(item.get("known_source_ips", [])),
            known_countries=set(item.get("known_countries", [])),
            known_cities=set(item.get("known_cities", [])),
            known_devices=set(item.get("known_devices", [])),
            known_user_agents=set(item.get("known_user_agents", [])),
            known_applications=set(item.get("known_applications", [])),
            known_services=set(item.get("known_services", [])),
            avg_daily_events=float(item.get("avg_daily_events", 0)),
            std_daily_events=float(item.get("std_daily_events", 0)),
            max_daily_events=int(item.get("max_daily_events", 0)),
            first_seen=datetime.fromisoformat(item["first_seen"]) if item.get("first_seen") else None,
            last_seen=datetime.fromisoformat(item["last_seen"]) if item.get("last_seen") else None,
            total_events=int(item.get("total_events", 0)),
            baseline_period_days=int(item.get("baseline_period_days", 30)),
            last_updated=datetime.fromisoformat(item["last_updated"]) if item.get("last_updated") else None
        )

    def _asset_baseline_to_item(self, baseline: AssetBaseline) -> Dict[str, Any]:
        return {
            "pk": f"ASSET#{baseline.asset_id}",
            "sk": "BASELINE",
            "entity_type": "ASSET",
            "asset_id": baseline.asset_id,
            "asset_type": baseline.asset_type,
            "known_accessor_users": list(baseline.known_accessor_users),
            "known_accessor_ips": list(baseline.known_accessor_ips),
            "known_accessor_roles": list(baseline.known_accessor_roles),
            "typical_access_hours": list(baseline.typical_access_hours),
            "typical_access_days": list(baseline.typical_access_days),
            "avg_daily_accesses": str(baseline.avg_daily_accesses),
            "std_daily_accesses": str(baseline.std_daily_accesses),
            "avg_data_volume_mb": str(baseline.avg_data_volume_mb),
            "std_data_volume_mb": str(baseline.std_data_volume_mb),
            "known_operations": list(baseline.known_operations),
            "first_seen": baseline.first_seen.isoformat() if baseline.first_seen else None,
            "last_seen": baseline.last_seen.isoformat() if baseline.last_seen else None,
            "total_events": baseline.total_events,
            "baseline_period_days": baseline.baseline_period_days,
            "last_updated": datetime.utcnow().isoformat()
        }

    def _item_to_asset_baseline(self, item: Dict[str, Any]) -> AssetBaseline:
        return AssetBaseline(
            asset_id=item["asset_id"],
            asset_type=item.get("asset_type", "unknown"),
            known_accessor_users=set(item.get("known_accessor_users", [])),
            known_accessor_ips=set(item.get("known_accessor_ips", [])),
            known_accessor_roles=set(item.get("known_accessor_roles", [])),
            typical_access_hours=set(item.get("typical_access_hours", [])),
            typical_access_days=set(item.get("typical_access_days", [])),
            avg_daily_accesses=float(item.get("avg_daily_accesses", 0)),
            std_daily_accesses=float(item.get("std_daily_accesses", 0)),
            avg_data_volume_mb=float(item.get("avg_data_volume_mb", 0)),
            std_data_volume_mb=float(item.get("std_data_volume_mb", 0)),
            known_operations=set(item.get("known_operations", [])),
            first_seen=datetime.fromisoformat(item["first_seen"]) if item.get("first_seen") else None,
            last_seen=datetime.fromisoformat(item["last_seen"]) if item.get("last_seen") else None,
            total_events=int(item.get("total_events", 0)),
            baseline_period_days=int(item.get("baseline_period_days", 30)),
            last_updated=datetime.fromisoformat(item["last_updated"]) if item.get("last_updated") else None
        )


class BehavioralAnalyzer:
    """Analyzes events against behavioral baselines to detect anomalies."""

    # Risk weights for different deviation types
    DEVIATION_RISK_WEIGHTS = {
        DeviationType.UNUSUAL_TIME: 0.3,
        DeviationType.NEW_SOURCE_IP: 0.5,
        DeviationType.NEW_LOCATION: 0.6,
        DeviationType.NEW_DEVICE: 0.4,
        DeviationType.NEW_APPLICATION: 0.3,
        DeviationType.UNUSUAL_VOLUME: 0.4,
        DeviationType.NEW_DATA_ACCESS: 0.5,
        DeviationType.FIRST_TIME_ACTIVITY: 0.2,
        DeviationType.IMPOSSIBLE_TRAVEL: 0.9,
        DeviationType.PRIVILEGE_ESCALATION: 0.8,
    }

    def __init__(
        self,
        store: BaselineStore,
        min_events_for_baseline: int = 10,
        min_days_for_baseline: int = 7,
        unusual_hour_threshold: float = 0.1,  # % of logins at this hour
        volume_std_threshold: float = 3.0,  # Number of std deviations
    ):
        self.store = store
        self.min_events_for_baseline = min_events_for_baseline
        self.min_days_for_baseline = min_days_for_baseline
        self.unusual_hour_threshold = unusual_hour_threshold
        self.volume_std_threshold = volume_std_threshold

    def analyze_user_event(
        self,
        user_id: str,
        event: Dict[str, Any],
        event_time: Optional[datetime] = None
    ) -> BehavioralAnalysisResult:
        """Analyze a user event against their baseline.

        Args:
            user_id: User identifier
            event: Event data with fields like source_ip, user_agent, application
            event_time: Event timestamp (defaults to now)

        Returns:
            BehavioralAnalysisResult with detected deviations
        """
        event_time = event_time or datetime.utcnow()
        baseline = self.store.get_user_baseline(user_id)

        if not baseline:
            # No baseline exists - this is first-time activity
            return BehavioralAnalysisResult(
                entity_type="user",
                entity_id=user_id,
                is_anomalous=True,
                deviations=[
                    BehavioralDeviation(
                        deviation_type=DeviationType.FIRST_TIME_ACTIVITY,
                        risk_level=RiskLevel.LOW,
                        description=f"First activity observed for user {user_id}",
                        confidence=1.0,
                        first_seen=event_time
                    )
                ],
                risk_score=20.0,
                baseline_exists=False,
                baseline_age_days=0,
                confidence=0.0
            )

        # Check baseline maturity
        baseline_age = (datetime.utcnow() - baseline.first_seen).days if baseline.first_seen else 0
        baseline_confidence = min(1.0, baseline.total_events / self.min_events_for_baseline) * \
                             min(1.0, baseline_age / self.min_days_for_baseline)

        deviations = []

        # Check time-based deviations
        time_deviation = self._check_time_deviation(event_time, baseline)
        if time_deviation:
            deviations.append(time_deviation)

        # Check source IP deviation
        source_ip = event.get("source_ip") or event.get("sourceIPAddress") or event.get("ip_address")
        if source_ip:
            ip_deviation = self._check_ip_deviation(source_ip, baseline)
            if ip_deviation:
                deviations.append(ip_deviation)

        # Check location deviation
        country = event.get("country") or event.get("geo_country")
        city = event.get("city") or event.get("geo_city")
        location_deviation = self._check_location_deviation(country, city, baseline)
        if location_deviation:
            deviations.append(location_deviation)

        # Check device deviation
        device = event.get("device") or event.get("device_type")
        user_agent = event.get("user_agent") or event.get("userAgent")
        device_deviation = self._check_device_deviation(device, user_agent, baseline)
        if device_deviation:
            deviations.append(device_deviation)

        # Check application deviation
        application = event.get("application") or event.get("app_name") or event.get("service")
        if application:
            app_deviation = self._check_application_deviation(application, baseline)
            if app_deviation:
                deviations.append(app_deviation)

        # Calculate risk score
        risk_score = self._calculate_risk_score(deviations, baseline_confidence)

        return BehavioralAnalysisResult(
            entity_type="user",
            entity_id=user_id,
            is_anomalous=len(deviations) > 0,
            deviations=deviations,
            risk_score=risk_score,
            baseline_exists=True,
            baseline_age_days=baseline_age,
            confidence=baseline_confidence
        )

    def analyze_asset_event(
        self,
        asset_id: str,
        asset_type: str,
        event: Dict[str, Any],
        event_time: Optional[datetime] = None
    ) -> BehavioralAnalysisResult:
        """Analyze an asset access event against its baseline.

        Args:
            asset_id: Asset identifier
            asset_type: Type of asset (server, database, storage, etc.)
            event: Event data with accessor info
            event_time: Event timestamp

        Returns:
            BehavioralAnalysisResult with detected deviations
        """
        event_time = event_time or datetime.utcnow()
        baseline = self.store.get_asset_baseline(asset_id)

        if not baseline:
            return BehavioralAnalysisResult(
                entity_type="asset",
                entity_id=asset_id,
                is_anomalous=True,
                deviations=[
                    BehavioralDeviation(
                        deviation_type=DeviationType.FIRST_TIME_ACTIVITY,
                        risk_level=RiskLevel.LOW,
                        description=f"First access observed for asset {asset_id}",
                        confidence=1.0,
                        first_seen=event_time
                    )
                ],
                risk_score=20.0,
                baseline_exists=False,
                baseline_age_days=0,
                confidence=0.0
            )

        baseline_age = (datetime.utcnow() - baseline.first_seen).days if baseline.first_seen else 0
        baseline_confidence = min(1.0, baseline.total_events / self.min_events_for_baseline) * \
                             min(1.0, baseline_age / self.min_days_for_baseline)

        deviations = []

        # Check accessor user
        accessor_user = event.get("user_id") or event.get("accessor") or event.get("principal")
        if accessor_user and accessor_user not in baseline.known_accessor_users:
            deviations.append(BehavioralDeviation(
                deviation_type=DeviationType.NEW_DATA_ACCESS,
                risk_level=RiskLevel.MEDIUM,
                description=f"New user accessing asset: {accessor_user}",
                observed_value=accessor_user,
                confidence=baseline_confidence
            ))

        # Check accessor IP
        accessor_ip = event.get("source_ip") or event.get("ip_address")
        if accessor_ip and accessor_ip not in baseline.known_accessor_ips:
            deviations.append(BehavioralDeviation(
                deviation_type=DeviationType.NEW_SOURCE_IP,
                risk_level=RiskLevel.MEDIUM,
                description=f"New IP accessing asset: {accessor_ip}",
                observed_value=accessor_ip,
                confidence=baseline_confidence
            ))

        # Check time-based deviation
        hour = event_time.hour
        day = event_time.weekday()
        if baseline.typical_access_hours and hour not in baseline.typical_access_hours:
            deviations.append(BehavioralDeviation(
                deviation_type=DeviationType.UNUSUAL_TIME,
                risk_level=RiskLevel.LOW,
                description=f"Access at unusual hour: {hour}:00",
                expected_value=f"Hours: {sorted(baseline.typical_access_hours)}",
                observed_value=str(hour),
                confidence=baseline_confidence
            ))

        # Check operation type
        operation = event.get("operation") or event.get("action") or event.get("event_type")
        if operation and operation not in baseline.known_operations:
            deviations.append(BehavioralDeviation(
                deviation_type=DeviationType.NEW_DATA_ACCESS,
                risk_level=RiskLevel.MEDIUM,
                description=f"New operation type: {operation}",
                observed_value=operation,
                confidence=baseline_confidence
            ))

        risk_score = self._calculate_risk_score(deviations, baseline_confidence)

        return BehavioralAnalysisResult(
            entity_type="asset",
            entity_id=asset_id,
            is_anomalous=len(deviations) > 0,
            deviations=deviations,
            risk_score=risk_score,
            baseline_exists=True,
            baseline_age_days=baseline_age,
            confidence=baseline_confidence
        )

    def update_user_baseline(
        self,
        user_id: str,
        event: Dict[str, Any],
        event_time: Optional[datetime] = None
    ) -> UserBaseline:
        """Update user baseline with new event data.

        Args:
            user_id: User identifier
            event: Event data
            event_time: Event timestamp

        Returns:
            Updated UserBaseline
        """
        event_time = event_time or datetime.utcnow()
        baseline = self.store.get_user_baseline(user_id) or UserBaseline(user_id=user_id)

        # Update time patterns
        baseline.typical_login_hours.add(event_time.hour)
        baseline.typical_login_days.add(event_time.weekday())

        # Update location patterns
        source_ip = event.get("source_ip") or event.get("sourceIPAddress") or event.get("ip_address")
        if source_ip:
            baseline.known_source_ips.add(source_ip)

        country = event.get("country") or event.get("geo_country")
        if country:
            baseline.known_countries.add(country)

        city = event.get("city") or event.get("geo_city")
        if city:
            baseline.known_cities.add(city)

        # Update device patterns
        device = event.get("device") or event.get("device_type")
        if device:
            baseline.known_devices.add(device)

        user_agent = event.get("user_agent") or event.get("userAgent")
        if user_agent:
            # Store hash of user agent to save space
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:16]
            baseline.known_user_agents.add(ua_hash)

        # Update application patterns
        application = event.get("application") or event.get("app_name") or event.get("service")
        if application:
            baseline.known_applications.add(application)

        email = event.get("email") or event.get("user_email")
        if email:
            baseline.email = email

        # Update metadata
        if not baseline.first_seen:
            baseline.first_seen = event_time
        baseline.last_seen = event_time
        baseline.total_events += 1
        baseline.last_updated = datetime.utcnow()

        self.store.save_user_baseline(baseline)
        return baseline

    def update_asset_baseline(
        self,
        asset_id: str,
        asset_type: str,
        event: Dict[str, Any],
        event_time: Optional[datetime] = None
    ) -> AssetBaseline:
        """Update asset baseline with new event data.

        Args:
            asset_id: Asset identifier
            asset_type: Type of asset
            event: Event data
            event_time: Event timestamp

        Returns:
            Updated AssetBaseline
        """
        event_time = event_time or datetime.utcnow()
        baseline = self.store.get_asset_baseline(asset_id) or AssetBaseline(
            asset_id=asset_id,
            asset_type=asset_type
        )

        # Update accessor patterns
        accessor_user = event.get("user_id") or event.get("accessor") or event.get("principal")
        if accessor_user:
            baseline.known_accessor_users.add(accessor_user)

        accessor_ip = event.get("source_ip") or event.get("ip_address")
        if accessor_ip:
            baseline.known_accessor_ips.add(accessor_ip)

        accessor_role = event.get("role") or event.get("iam_role")
        if accessor_role:
            baseline.known_accessor_roles.add(accessor_role)

        # Update time patterns
        baseline.typical_access_hours.add(event_time.hour)
        baseline.typical_access_days.add(event_time.weekday())

        # Update operation patterns
        operation = event.get("operation") or event.get("action") or event.get("event_type")
        if operation:
            baseline.known_operations.add(operation)

        # Update metadata
        if not baseline.first_seen:
            baseline.first_seen = event_time
        baseline.last_seen = event_time
        baseline.total_events += 1
        baseline.last_updated = datetime.utcnow()

        self.store.save_asset_baseline(baseline)
        return baseline

    def _check_time_deviation(
        self,
        event_time: datetime,
        baseline: UserBaseline
    ) -> Optional[BehavioralDeviation]:
        """Check if event time is unusual for this user."""
        hour = event_time.hour
        day = event_time.weekday()

        # Need enough data points for time analysis
        if len(baseline.typical_login_hours) < 3:
            return None

        if hour not in baseline.typical_login_hours:
            return BehavioralDeviation(
                deviation_type=DeviationType.UNUSUAL_TIME,
                risk_level=RiskLevel.LOW,
                description=f"Login at unusual hour: {hour}:00",
                expected_value=f"Typical hours: {sorted(baseline.typical_login_hours)}",
                observed_value=str(hour),
                confidence=min(1.0, baseline.total_events / 50)
            )

        return None

    def _check_ip_deviation(
        self,
        source_ip: str,
        baseline: UserBaseline
    ) -> Optional[BehavioralDeviation]:
        """Check if source IP is new for this user."""
        if source_ip not in baseline.known_source_ips:
            risk_level = RiskLevel.MEDIUM
            if len(baseline.known_source_ips) > 10:
                # User has diverse IPs, new ones are less concerning
                risk_level = RiskLevel.LOW

            return BehavioralDeviation(
                deviation_type=DeviationType.NEW_SOURCE_IP,
                risk_level=risk_level,
                description=f"Login from new IP address: {source_ip}",
                expected_value=f"Known IPs: {len(baseline.known_source_ips)}",
                observed_value=source_ip,
                confidence=min(1.0, baseline.total_events / 20)
            )

        return None

    def _check_location_deviation(
        self,
        country: Optional[str],
        city: Optional[str],
        baseline: UserBaseline
    ) -> Optional[BehavioralDeviation]:
        """Check if location is new for this user."""
        if country and country not in baseline.known_countries:
            return BehavioralDeviation(
                deviation_type=DeviationType.NEW_LOCATION,
                risk_level=RiskLevel.HIGH,
                description=f"Login from new country: {country}",
                expected_value=f"Known countries: {baseline.known_countries}",
                observed_value=country,
                confidence=min(1.0, baseline.total_events / 30)
            )

        if city and city not in baseline.known_cities:
            # New city in known country is less concerning
            return BehavioralDeviation(
                deviation_type=DeviationType.NEW_LOCATION,
                risk_level=RiskLevel.LOW,
                description=f"Login from new city: {city}",
                expected_value=f"Known cities: {len(baseline.known_cities)}",
                observed_value=city,
                confidence=min(1.0, baseline.total_events / 30)
            )

        return None

    def _check_device_deviation(
        self,
        device: Optional[str],
        user_agent: Optional[str],
        baseline: UserBaseline
    ) -> Optional[BehavioralDeviation]:
        """Check if device is new for this user."""
        if device and device not in baseline.known_devices:
            return BehavioralDeviation(
                deviation_type=DeviationType.NEW_DEVICE,
                risk_level=RiskLevel.MEDIUM,
                description=f"Login from new device type: {device}",
                observed_value=device,
                confidence=min(1.0, baseline.total_events / 20)
            )

        if user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:16]
            if ua_hash not in baseline.known_user_agents:
                return BehavioralDeviation(
                    deviation_type=DeviationType.NEW_DEVICE,
                    risk_level=RiskLevel.LOW,
                    description="Login from new browser/client",
                    observed_value=user_agent[:50] + "..." if len(user_agent) > 50 else user_agent,
                    confidence=min(1.0, baseline.total_events / 20)
                )

        return None

    def _check_application_deviation(
        self,
        application: str,
        baseline: UserBaseline
    ) -> Optional[BehavioralDeviation]:
        """Check if application is new for this user."""
        if application not in baseline.known_applications:
            return BehavioralDeviation(
                deviation_type=DeviationType.NEW_APPLICATION,
                risk_level=RiskLevel.LOW,
                description=f"Access to new application: {application}",
                observed_value=application,
                confidence=min(1.0, baseline.total_events / 30)
            )

        return None

    def _calculate_risk_score(
        self,
        deviations: List[BehavioralDeviation],
        baseline_confidence: float
    ) -> float:
        """Calculate overall risk score from deviations.

        Args:
            deviations: List of detected deviations
            baseline_confidence: Confidence in baseline maturity (0-1)

        Returns:
            Risk score from 0-100
        """
        if not deviations:
            return 0.0

        # Base score from deviation types and risk levels
        risk_level_scores = {
            RiskLevel.LOW: 15,
            RiskLevel.MEDIUM: 35,
            RiskLevel.HIGH: 60,
            RiskLevel.CRITICAL: 85
        }

        total_score = 0.0
        for deviation in deviations:
            base_score = risk_level_scores.get(deviation.risk_level, 25)
            weight = self.DEVIATION_RISK_WEIGHTS.get(deviation.deviation_type, 0.5)
            total_score += base_score * weight * deviation.confidence

        # Adjust by baseline confidence (immature baseline = less reliable)
        adjusted_score = total_score * (0.5 + 0.5 * baseline_confidence)

        # Cap at 100
        return min(100.0, adjusted_score)


# Convenience function for alert enrichment
def enrich_with_behavioral_analysis(
    event: Dict[str, Any],
    store: Optional[BaselineStore] = None
) -> Dict[str, Any]:
    """Enrich an event with behavioral analysis.

    Args:
        event: Event data
        store: Baseline store (defaults to in-memory)

    Returns:
        Event enriched with behavioral_analysis field
    """
    store = store or InMemoryBaselineStore()
    analyzer = BehavioralAnalyzer(store)

    enrichment = {}

    # Analyze user behavior if user_id present
    user_id = event.get("user_id") or event.get("userIdentity", {}).get("arn") or event.get("actor", {}).get("id")
    if user_id:
        result = analyzer.analyze_user_event(user_id, event)
        enrichment["user_behavior"] = result.to_dict()

    # Analyze asset behavior if asset_id present
    asset_id = event.get("resource_id") or event.get("asset_id") or event.get("target_resource")
    asset_type = event.get("resource_type") or event.get("asset_type") or "unknown"
    if asset_id:
        result = analyzer.analyze_asset_event(asset_id, asset_type, event)
        enrichment["asset_behavior"] = result.to_dict()

    return enrichment
