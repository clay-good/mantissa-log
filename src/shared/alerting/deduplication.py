"""
Alert Deduplication and Suppression

Prevents alert fatigue by deduplicating identical alerts and suppressing
alerts during maintenance windows or based on configured rules.
"""

import os
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import boto3
from decimal import Decimal


class SuppressionReason(Enum):
    """Reasons for alert suppression."""
    DUPLICATE = "duplicate"
    MAINTENANCE_WINDOW = "maintenance_window"
    RATE_LIMIT = "rate_limit"
    MANUAL = "manual"


@dataclass
class DeduplicationConfig:
    """Configuration for alert deduplication."""
    enabled: bool = True
    window_minutes: int = 60  # Dedupe window
    fields_for_fingerprint: List[str] = None  # Fields to include in fingerprint
    max_alerts_per_window: int = 10  # Rate limit


@dataclass
class SuppressionRule:
    """Rule for suppressing alerts."""
    rule_id: str
    reason: SuppressionReason
    start_time: str
    end_time: Optional[str]
    rule_pattern: Optional[str]  # Regex pattern for rule names
    severity_levels: Optional[List[str]]  # Severities to suppress
    enabled: bool = True


class AlertDeduplicator:
    """
    Handles alert deduplication and suppression.

    Deduplication works by creating a fingerprint of the alert based on
    key fields (rule name, severity, etc.) and tracking recently sent alerts.
    """

    def __init__(
        self,
        config: Optional[DeduplicationConfig] = None,
        table_name: Optional[str] = None
    ):
        """
        Initialize deduplicator.

        Args:
            config: Deduplication configuration
            table_name: DynamoDB table for tracking alerts
        """
        self.config = config or DeduplicationConfig(
            fields_for_fingerprint=['rule_id', 'rule_name', 'severity']
        )
        self.table_name = table_name or os.environ.get(
            'ALERT_DEDUP_TABLE',
            'mantissa-log-alert-dedup'
        )
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)
        self.suppression_rules: List[SuppressionRule] = []

    def should_send_alert(
        self,
        user_id: str,
        alert_data: Dict[str, Any]
    ) -> tuple[bool, Optional[SuppressionReason]]:
        """
        Determine if alert should be sent or suppressed.

        Args:
            user_id: User ID
            alert_data: Alert data

        Returns:
            Tuple of (should_send, suppression_reason)
        """
        if not self.config.enabled:
            return True, None

        # Check suppression rules first
        suppression_reason = self._check_suppression_rules(alert_data)
        if suppression_reason:
            return False, suppression_reason

        # Check for duplicates
        if self._is_duplicate(user_id, alert_data):
            return False, SuppressionReason.DUPLICATE

        # Check rate limiting
        if self._exceeds_rate_limit(user_id, alert_data):
            return False, SuppressionReason.RATE_LIMIT

        # Alert should be sent
        return True, None

    def _check_suppression_rules(
        self,
        alert_data: Dict[str, Any]
    ) -> Optional[SuppressionReason]:
        """Check if alert matches any suppression rules."""
        import re

        current_time = datetime.utcnow()

        for rule in self.suppression_rules:
            if not rule.enabled:
                continue

            # Check time window
            start_time = datetime.fromisoformat(rule.start_time.replace('Z', '+00:00'))
            if rule.end_time:
                end_time = datetime.fromisoformat(rule.end_time.replace('Z', '+00:00'))
                if not (start_time <= current_time <= end_time):
                    continue
            else:
                # No end time means rule is always active
                if current_time < start_time:
                    continue

            # Check rule pattern
            if rule.rule_pattern:
                rule_name = alert_data.get('rule_name', '')
                if not re.search(rule.rule_pattern, rule_name):
                    continue

            # Check severity levels
            if rule.severity_levels:
                severity = alert_data.get('severity', '')
                if severity not in rule.severity_levels:
                    continue

            # All conditions matched
            return rule.reason

        return None

    def _is_duplicate(
        self,
        user_id: str,
        alert_data: Dict[str, Any]
    ) -> bool:
        """Check if alert is a duplicate of a recent alert."""
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(alert_data)

        # Check if this fingerprint was seen recently
        pk = f'user#{user_id}'
        sk = f'fingerprint#{fingerprint}'

        try:
            response = self.table.get_item(
                Key={'pk': pk, 'sk': sk}
            )

            if 'Item' in response:
                # Found recent alert with same fingerprint
                last_sent = response['Item'].get('last_sent')
                if last_sent:
                    last_sent_time = datetime.fromisoformat(last_sent.replace('Z', '+00:00'))
                    cutoff_time = datetime.utcnow() - timedelta(
                        minutes=self.config.window_minutes
                    )

                    if last_sent_time > cutoff_time:
                        # Duplicate within window
                        return True

            # Not a duplicate - record this alert
            self._record_alert(user_id, fingerprint, alert_data)
            return False

        except Exception as e:
            print(f'Error checking duplicate: {e}')
            # Fail open - send the alert
            return False

    def _exceeds_rate_limit(
        self,
        user_id: str,
        alert_data: Dict[str, Any]
    ) -> bool:
        """Check if sending this alert would exceed rate limits."""
        rule_id = alert_data.get('rule_id', 'unknown')

        # Count alerts for this rule in the current window
        pk = f'user#{user_id}#rule#{rule_id}'
        cutoff_time = (
            datetime.utcnow() - timedelta(minutes=self.config.window_minutes)
        ).isoformat() + 'Z'

        try:
            from boto3.dynamodb.conditions import Key

            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(pk) &
                    Key('sk').between(f'alert#{cutoff_time}', f'alert#9999-12-31')
            )

            alert_count = len(response.get('Items', []))

            return alert_count >= self.config.max_alerts_per_window

        except Exception as e:
            print(f'Error checking rate limit: {e}')
            # Fail open
            return False

    def _generate_fingerprint(self, alert_data: Dict[str, Any]) -> str:
        """
        Generate fingerprint for alert deduplication.

        Args:
            alert_data: Alert data

        Returns:
            Fingerprint hash
        """
        # Extract fields for fingerprinting
        fingerprint_data = {}
        for field in self.config.fields_for_fingerprint:
            if field in alert_data:
                fingerprint_data[field] = alert_data[field]

        # Create stable JSON representation
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True)

        # Hash to create fingerprint
        return hashlib.sha256(fingerprint_json.encode()).hexdigest()[:16]

    def _record_alert(
        self,
        user_id: str,
        fingerprint: str,
        alert_data: Dict[str, Any]
    ):
        """Record that an alert was sent."""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        rule_id = alert_data.get('rule_id', 'unknown')

        # Record fingerprint
        self.table.put_item(Item={
            'pk': f'user#{user_id}',
            'sk': f'fingerprint#{fingerprint}',
            'rule_id': rule_id,
            'last_sent': timestamp,
            'alert_data': json.dumps(alert_data),
            'ttl': int(datetime.utcnow().timestamp()) + (
                self.config.window_minutes * 60 * 2  # 2x window for buffer
            )
        })

        # Record in rule's timeline
        self.table.put_item(Item={
            'pk': f'user#{user_id}#rule#{rule_id}',
            'sk': f'alert#{timestamp}',
            'fingerprint': fingerprint,
            'timestamp': timestamp,
            'ttl': int(datetime.utcnow().timestamp()) + (
                self.config.window_minutes * 60 * 2
            )
        })

    def add_suppression_rule(self, rule: SuppressionRule):
        """Add a suppression rule."""
        self.suppression_rules.append(rule)

    def remove_suppression_rule(self, rule_id: str):
        """Remove a suppression rule."""
        self.suppression_rules = [
            r for r in self.suppression_rules if r.rule_id != rule_id
        ]

    def load_suppression_rules(self, user_id: str):
        """
        Load suppression rules from DynamoDB.

        Args:
            user_id: User ID
        """
        try:
            from boto3.dynamodb.conditions import Key

            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').begins_with('suppression#')
            )

            self.suppression_rules = []
            for item in response.get('Items', []):
                rule = SuppressionRule(
                    rule_id=item.get('rule_id', ''),
                    reason=SuppressionReason(item.get('reason', 'manual')),
                    start_time=item.get('start_time', ''),
                    end_time=item.get('end_time'),
                    rule_pattern=item.get('rule_pattern'),
                    severity_levels=item.get('severity_levels'),
                    enabled=item.get('enabled', True)
                )
                self.suppression_rules.append(rule)

        except Exception as e:
            print(f'Error loading suppression rules: {e}')

    def create_maintenance_window(
        self,
        user_id: str,
        start_time: datetime,
        duration_minutes: int,
        rule_pattern: Optional[str] = None,
        severity_levels: Optional[List[str]] = None
    ) -> str:
        """
        Create a maintenance window suppression rule.

        Args:
            user_id: User ID
            start_time: Start of maintenance window
            duration_minutes: Duration in minutes
            rule_pattern: Optional regex pattern for rule names to suppress
            severity_levels: Optional list of severities to suppress

        Returns:
            Rule ID
        """
        import uuid

        rule_id = f'maint-{uuid.uuid4().hex[:8]}'
        start_time_str = start_time.isoformat() + 'Z'
        end_time = start_time + timedelta(minutes=duration_minutes)
        end_time_str = end_time.isoformat() + 'Z'

        rule = SuppressionRule(
            rule_id=rule_id,
            reason=SuppressionReason.MAINTENANCE_WINDOW,
            start_time=start_time_str,
            end_time=end_time_str,
            rule_pattern=rule_pattern,
            severity_levels=severity_levels,
            enabled=True
        )

        # Store in DynamoDB
        self.table.put_item(Item={
            'pk': f'user#{user_id}',
            'sk': f'suppression#{rule_id}',
            'rule_id': rule_id,
            'reason': rule.reason.value,
            'start_time': start_time_str,
            'end_time': end_time_str,
            'rule_pattern': rule_pattern or '',
            'severity_levels': severity_levels or [],
            'enabled': True,
            'created_at': datetime.utcnow().isoformat() + 'Z'
        })

        # Add to active rules
        self.suppression_rules.append(rule)

        return rule_id

    def get_suppression_stats(
        self,
        user_id: str,
        hours: int = 24
    ) -> Dict[str, int]:
        """
        Get statistics on suppressed alerts.

        Args:
            user_id: User ID
            hours: Hours to look back

        Returns:
            Dictionary with suppression counts by reason
        """
        # This would query a separate suppression log table
        # For now, return placeholder
        return {
            'duplicate': 0,
            'maintenance_window': 0,
            'rate_limit': 0,
            'manual': 0,
            'total': 0
        }


def should_send_alert(
    user_id: str,
    alert_data: Dict[str, Any],
    config: Optional[DeduplicationConfig] = None
) -> tuple[bool, Optional[SuppressionReason]]:
    """
    Convenience function to check if alert should be sent.

    Args:
        user_id: User ID
        alert_data: Alert data
        config: Optional deduplication config

    Returns:
        Tuple of (should_send, suppression_reason)
    """
    deduplicator = AlertDeduplicator(config)
    deduplicator.load_suppression_rules(user_id)

    return deduplicator.should_send_alert(user_id, alert_data)
