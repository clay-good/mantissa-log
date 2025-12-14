"""
False Positive Tracking System.

Provides functionality to:
- Mark alerts as false positives with reason
- Track FP rate per rule over time
- Auto-generate suppression recommendations
- Bulk FP marking for common patterns
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import Counter
from enum import Enum

logger = logging.getLogger(__name__)


class FPReason(Enum):
    """Standard reasons for false positive classification."""
    KNOWN_GOOD_ACTIVITY = "known_good_activity"
    SERVICE_ACCOUNT = "service_account"
    TESTING = "testing"
    SCHEDULED_JOB = "scheduled_job"
    INTERNAL_SCANNING = "internal_scanning"
    WHITELISTED_IP = "whitelisted_ip"
    WHITELISTED_USER = "whitelisted_user"
    RULE_TOO_BROAD = "rule_too_broad"
    DUPLICATE_ALERT = "duplicate"
    OTHER = "other"


@dataclass
class FalsePositiveRecord:
    """Record of a false positive marking."""

    alert_id: str
    rule_id: str
    rule_name: str
    marked_by: str
    marked_at: str
    reason: FPReason
    reason_details: Optional[str] = None

    # Alert context (for pattern detection)
    source_ip: Optional[str] = None
    user: Optional[str] = None
    asset_id: Optional[str] = None

    # Generated suppression
    suppression_pattern: Optional[Dict[str, Any]] = None
    applied_suppression: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "marked_by": self.marked_by,
            "marked_at": self.marked_at,
            "reason": self.reason.value,
            "reason_details": self.reason_details,
            "source_ip": self.source_ip,
            "user": self.user,
            "asset_id": self.asset_id,
            "suppression_pattern": self.suppression_pattern,
            "applied_suppression": self.applied_suppression,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FalsePositiveRecord":
        """Create from dictionary."""
        return cls(
            alert_id=data["alert_id"],
            rule_id=data["rule_id"],
            rule_name=data.get("rule_name", ""),
            marked_by=data["marked_by"],
            marked_at=data["marked_at"],
            reason=FPReason(data["reason"]),
            reason_details=data.get("reason_details"),
            source_ip=data.get("source_ip"),
            user=data.get("user"),
            asset_id=data.get("asset_id"),
            suppression_pattern=data.get("suppression_pattern"),
            applied_suppression=data.get("applied_suppression", False),
        )


@dataclass
class SuppressionRecommendation:
    """Auto-generated suppression recommendation based on FP patterns."""

    rule_id: str
    rule_name: str
    pattern_type: str  # "ip", "user", "asset", "combined"
    pattern_value: Dict[str, Any]

    # Statistics
    fp_count: int
    total_alerts: int
    fp_rate: float
    affected_alert_ids: List[str]

    # Sigma-format suppression
    sigma_filter: str

    # Recommendation metadata
    confidence: str  # "high", "medium", "low"
    recommendation_id: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "pattern_type": self.pattern_type,
            "pattern_value": self.pattern_value,
            "fp_count": self.fp_count,
            "total_alerts": self.total_alerts,
            "fp_rate": round(self.fp_rate, 4),
            "affected_alert_ids": self.affected_alert_ids[:10],  # Limit for response
            "sigma_filter": self.sigma_filter,
            "confidence": self.confidence,
            "recommendation_id": self.recommendation_id,
            "created_at": self.created_at,
        }


@dataclass
class FPStats:
    """False positive statistics for a rule."""

    rule_id: str
    rule_name: str
    period_days: int

    total_alerts: int
    fp_count: int
    fp_rate: float

    # Breakdown by reason
    fp_by_reason: Dict[str, int]

    # Top FP sources
    top_fp_ips: List[Dict[str, Any]]
    top_fp_users: List[Dict[str, Any]]

    # Trend
    fp_rate_trend: float  # Change vs previous period

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "period_days": self.period_days,
            "total_alerts": self.total_alerts,
            "fp_count": self.fp_count,
            "fp_rate": round(self.fp_rate, 4),
            "fp_by_reason": self.fp_by_reason,
            "top_fp_ips": self.top_fp_ips,
            "top_fp_users": self.top_fp_users,
            "fp_rate_trend": round(self.fp_rate_trend, 2),
        }


class FalsePositiveTracker:
    """Tracks false positives and generates suppression recommendations."""

    # Thresholds for suppression recommendations
    MIN_FP_COUNT = 5  # Minimum FPs before recommending suppression
    HIGH_FP_RATE = 0.70  # 70% FP rate = high confidence suppression
    MEDIUM_FP_RATE = 0.50  # 50% FP rate = medium confidence

    def __init__(self, store: Optional["FPStore"] = None):
        """
        Initialize FP tracker.

        Args:
            store: Storage backend for FP records
        """
        self.store = store

    def mark_false_positive(
        self,
        alert_id: str,
        rule_id: str,
        rule_name: str,
        marked_by: str,
        reason: FPReason,
        reason_details: Optional[str] = None,
        alert_data: Optional[Dict[str, Any]] = None
    ) -> FalsePositiveRecord:
        """
        Mark an alert as a false positive.

        Args:
            alert_id: Alert identifier
            rule_id: Rule identifier
            rule_name: Rule name
            marked_by: User who marked the FP
            reason: Reason for FP classification
            reason_details: Additional details
            alert_data: Full alert data for pattern extraction

        Returns:
            FalsePositiveRecord
        """
        now = datetime.utcnow().isoformat() + "Z"

        # Extract context from alert
        source_ip = None
        user = None
        asset_id = None

        if alert_data:
            source_ip = self._extract_field(alert_data, ["source_ip", "sourceIPAddress", "srcaddr"])
            user = self._extract_field(alert_data, ["user", "userName", "principal"])
            asset_id = self._extract_field(alert_data, ["asset_id", "resource_id", "instance_id"])

        record = FalsePositiveRecord(
            alert_id=alert_id,
            rule_id=rule_id,
            rule_name=rule_name,
            marked_by=marked_by,
            marked_at=now,
            reason=reason,
            reason_details=reason_details,
            source_ip=source_ip,
            user=user,
            asset_id=asset_id,
        )

        # Store record
        if self.store:
            self.store.save_fp_record(record)

        logger.info(f"Marked alert {alert_id} as false positive: {reason.value}")

        return record

    def mark_bulk_false_positives(
        self,
        alert_ids: List[str],
        rule_id: str,
        rule_name: str,
        marked_by: str,
        reason: FPReason,
        reason_details: Optional[str] = None,
        alerts_data: Optional[List[Dict[str, Any]]] = None
    ) -> List[FalsePositiveRecord]:
        """
        Mark multiple alerts as false positives.

        Args:
            alert_ids: List of alert identifiers
            rule_id: Rule identifier
            rule_name: Rule name
            marked_by: User who marked the FPs
            reason: Reason for FP classification
            reason_details: Additional details
            alerts_data: List of alert data (same order as alert_ids)

        Returns:
            List of FalsePositiveRecords
        """
        records = []

        for i, alert_id in enumerate(alert_ids):
            alert_data = alerts_data[i] if alerts_data and i < len(alerts_data) else None

            record = self.mark_false_positive(
                alert_id=alert_id,
                rule_id=rule_id,
                rule_name=rule_name,
                marked_by=marked_by,
                reason=reason,
                reason_details=reason_details,
                alert_data=alert_data
            )
            records.append(record)

        logger.info(f"Bulk marked {len(records)} alerts as false positives for rule {rule_id}")

        return records

    def get_fp_stats(
        self,
        rule_id: str,
        rule_name: str,
        days: int = 30,
        total_alerts: Optional[int] = None,
        previous_fp_rate: Optional[float] = None
    ) -> FPStats:
        """
        Get false positive statistics for a rule.

        Args:
            rule_id: Rule identifier
            rule_name: Rule name
            days: Number of days to analyze
            total_alerts: Total alerts for the rule (if known)
            previous_fp_rate: FP rate from previous period (for trend)

        Returns:
            FPStats
        """
        if not self.store:
            return FPStats(
                rule_id=rule_id,
                rule_name=rule_name,
                period_days=days,
                total_alerts=total_alerts or 0,
                fp_count=0,
                fp_rate=0.0,
                fp_by_reason={},
                top_fp_ips=[],
                top_fp_users=[],
                fp_rate_trend=0.0
            )

        # Get FP records
        fp_records = self.store.get_fp_records(rule_id, days)

        # Count by reason
        reason_counts = Counter()
        ip_counts = Counter()
        user_counts = Counter()

        for record in fp_records:
            reason_counts[record.reason.value] += 1

            if record.source_ip:
                ip_counts[record.source_ip] += 1
            if record.user:
                user_counts[record.user] += 1

        fp_count = len(fp_records)
        total = total_alerts if total_alerts is not None else fp_count

        fp_rate = fp_count / total if total > 0 else 0.0

        # Calculate trend
        fp_rate_trend = 0.0
        if previous_fp_rate is not None and previous_fp_rate > 0:
            fp_rate_trend = ((fp_rate - previous_fp_rate) / previous_fp_rate) * 100

        return FPStats(
            rule_id=rule_id,
            rule_name=rule_name,
            period_days=days,
            total_alerts=total,
            fp_count=fp_count,
            fp_rate=fp_rate,
            fp_by_reason=dict(reason_counts),
            top_fp_ips=[
                {"ip": ip, "count": count}
                for ip, count in ip_counts.most_common(5)
            ],
            top_fp_users=[
                {"user": user, "count": count}
                for user, count in user_counts.most_common(5)
            ],
            fp_rate_trend=fp_rate_trend
        )

    def generate_suppression_recommendations(
        self,
        rule_id: str,
        rule_name: str,
        days: int = 30,
        total_alerts: Optional[int] = None
    ) -> List[SuppressionRecommendation]:
        """
        Generate suppression recommendations based on FP patterns.

        Args:
            rule_id: Rule identifier
            rule_name: Rule name
            days: Number of days to analyze
            total_alerts: Total alerts for denominator

        Returns:
            List of SuppressionRecommendation
        """
        if not self.store:
            return []

        recommendations = []
        fp_records = self.store.get_fp_records(rule_id, days)

        if len(fp_records) < self.MIN_FP_COUNT:
            return recommendations

        total = total_alerts if total_alerts is not None else len(fp_records)
        now = datetime.utcnow().isoformat() + "Z"

        # Analyze IP patterns
        ip_counts = Counter()
        ip_alerts = {}
        for record in fp_records:
            if record.source_ip:
                ip_counts[record.source_ip] += 1
                if record.source_ip not in ip_alerts:
                    ip_alerts[record.source_ip] = []
                ip_alerts[record.source_ip].append(record.alert_id)

        for ip, count in ip_counts.most_common(10):
            if count >= self.MIN_FP_COUNT:
                fp_rate = count / total if total > 0 else 0.0
                confidence = self._get_confidence(fp_rate)

                if confidence:
                    rec_id = f"supp-{rule_id}-ip-{hash(ip) % 10000:04d}"
                    sigma_filter = self._generate_ip_filter(ip)

                    recommendations.append(SuppressionRecommendation(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        pattern_type="ip",
                        pattern_value={"source_ip": ip},
                        fp_count=count,
                        total_alerts=total,
                        fp_rate=fp_rate,
                        affected_alert_ids=ip_alerts[ip],
                        sigma_filter=sigma_filter,
                        confidence=confidence,
                        recommendation_id=rec_id,
                        created_at=now
                    ))

        # Analyze user patterns
        user_counts = Counter()
        user_alerts = {}
        for record in fp_records:
            if record.user:
                user_counts[record.user] += 1
                if record.user not in user_alerts:
                    user_alerts[record.user] = []
                user_alerts[record.user].append(record.alert_id)

        for user, count in user_counts.most_common(10):
            if count >= self.MIN_FP_COUNT:
                fp_rate = count / total if total > 0 else 0.0
                confidence = self._get_confidence(fp_rate)

                if confidence:
                    rec_id = f"supp-{rule_id}-user-{hash(user) % 10000:04d}"
                    sigma_filter = self._generate_user_filter(user)

                    recommendations.append(SuppressionRecommendation(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        pattern_type="user",
                        pattern_value={"user": user},
                        fp_count=count,
                        total_alerts=total,
                        fp_rate=fp_rate,
                        affected_alert_ids=user_alerts[user],
                        sigma_filter=sigma_filter,
                        confidence=confidence,
                        recommendation_id=rec_id,
                        created_at=now
                    ))

        # Analyze combined patterns (IP + User)
        combined_counts = Counter()
        combined_alerts = {}
        for record in fp_records:
            if record.source_ip and record.user:
                key = f"{record.source_ip}|{record.user}"
                combined_counts[key] += 1
                if key not in combined_alerts:
                    combined_alerts[key] = []
                combined_alerts[key].append(record.alert_id)

        for combo, count in combined_counts.most_common(5):
            if count >= self.MIN_FP_COUNT:
                ip, user = combo.split("|")
                fp_rate = count / total if total > 0 else 0.0
                confidence = self._get_confidence(fp_rate)

                if confidence:
                    rec_id = f"supp-{rule_id}-combo-{hash(combo) % 10000:04d}"
                    sigma_filter = self._generate_combined_filter(ip, user)

                    recommendations.append(SuppressionRecommendation(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        pattern_type="combined",
                        pattern_value={"source_ip": ip, "user": user},
                        fp_count=count,
                        total_alerts=total,
                        fp_rate=fp_rate,
                        affected_alert_ids=combined_alerts[combo],
                        sigma_filter=sigma_filter,
                        confidence=confidence,
                        recommendation_id=rec_id,
                        created_at=now
                    ))

        # Sort by confidence and FP rate
        recommendations.sort(
            key=lambda r: (
                0 if r.confidence == "high" else 1 if r.confidence == "medium" else 2,
                -r.fp_rate
            )
        )

        return recommendations

    def _extract_field(self, data: Dict[str, Any], field_names: List[str]) -> Optional[str]:
        """Extract a field value from data using multiple possible field names."""
        for field_name in field_names:
            if field_name in data and data[field_name]:
                value = data[field_name]
                if isinstance(value, dict):
                    return value.get("value") or value.get("name") or str(value)
                return str(value)
        return None

    def _get_confidence(self, fp_rate: float) -> Optional[str]:
        """Determine confidence level based on FP rate."""
        if fp_rate >= self.HIGH_FP_RATE:
            return "high"
        elif fp_rate >= self.MEDIUM_FP_RATE:
            return "medium"
        return None  # Don't recommend for low FP rates

    def _generate_ip_filter(self, ip: str) -> str:
        """Generate Sigma filter for IP exclusion."""
        return f"""filter:
    sourceIPAddress: '{ip}'"""

    def _generate_user_filter(self, user: str) -> str:
        """Generate Sigma filter for user exclusion."""
        # Escape special characters
        safe_user = user.replace("'", "\\'")
        return f"""filter:
    userName: '{safe_user}'"""

    def _generate_combined_filter(self, ip: str, user: str) -> str:
        """Generate Sigma filter for combined IP + user exclusion."""
        safe_user = user.replace("'", "\\'")
        return f"""filter:
    sourceIPAddress: '{ip}'
    userName: '{safe_user}'"""


class FPStore:
    """Abstract base class for FP storage."""

    def save_fp_record(self, record: FalsePositiveRecord) -> None:
        """Save FP record."""
        raise NotImplementedError

    def get_fp_records(self, rule_id: str, days: int = 30) -> List[FalsePositiveRecord]:
        """Get FP records for a rule."""
        raise NotImplementedError

    def update_alert_status(self, alert_id: str, status: str) -> None:
        """Update alert status to false_positive."""
        raise NotImplementedError


class DynamoDBFPStore(FPStore):
    """DynamoDB implementation of FP storage."""

    def __init__(
        self,
        fp_table_name: str,
        alerts_table_name: str,
        region: str = "us-east-1"
    ):
        """Initialize DynamoDB FP store."""
        self.fp_table_name = fp_table_name
        self.alerts_table_name = alerts_table_name
        self.region = region
        self._fp_table = None
        self._alerts_table = None

    @property
    def fp_table(self):
        """Lazy-load FP table."""
        if self._fp_table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._fp_table = dynamodb.Table(self.fp_table_name)
        return self._fp_table

    @property
    def alerts_table(self):
        """Lazy-load alerts table."""
        if self._alerts_table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._alerts_table = dynamodb.Table(self.alerts_table_name)
        return self._alerts_table

    def save_fp_record(self, record: FalsePositiveRecord) -> None:
        """Save FP record to DynamoDB."""
        try:
            item = {
                "pk": f"rule#{record.rule_id}",
                "sk": f"fp#{record.marked_at}#{record.alert_id}",
                **record.to_dict(),
                "ttl": int((datetime.utcnow() + timedelta(days=365)).timestamp())
            }
            self.fp_table.put_item(Item=item)

            # Also update alert status
            self.update_alert_status(record.alert_id, "false_positive")

        except Exception as e:
            logger.error(f"Failed to save FP record: {e}")

    def get_fp_records(self, rule_id: str, days: int = 30) -> List[FalsePositiveRecord]:
        """Get FP records for a rule from DynamoDB."""
        try:
            start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"

            response = self.fp_table.query(
                KeyConditionExpression="pk = :pk AND sk >= :sk_start",
                ExpressionAttributeValues={
                    ":pk": f"rule#{rule_id}",
                    ":sk_start": f"fp#{start_date}"
                },
                ScanIndexForward=False
            )

            records = []
            for item in response.get("Items", []):
                records.append(FalsePositiveRecord.from_dict(item))

            return records

        except Exception as e:
            logger.error(f"Failed to get FP records: {e}")
            return []

    def update_alert_status(self, alert_id: str, status: str) -> None:
        """Update alert status in alerts table."""
        try:
            self.alerts_table.update_item(
                Key={"id": alert_id},
                UpdateExpression="SET #status = :status, updated_at = :updated",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": status,
                    ":updated": datetime.utcnow().isoformat() + "Z"
                }
            )
        except Exception as e:
            logger.warning(f"Failed to update alert status: {e}")


def mark_false_positive(
    alert_id: str,
    rule_id: str,
    rule_name: str,
    marked_by: str,
    reason: str,
    reason_details: Optional[str] = None,
    store: Optional[FPStore] = None
) -> FalsePositiveRecord:
    """Convenience function to mark an alert as false positive."""
    tracker = FalsePositiveTracker(store=store)
    return tracker.mark_false_positive(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_name=rule_name,
        marked_by=marked_by,
        reason=FPReason(reason),
        reason_details=reason_details
    )
