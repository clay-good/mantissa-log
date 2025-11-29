"""
Feedback Tracker for Self-Learning Detection Engineer

Tracks Jira ticket resolutions to learn from user feedback and improve
future recommendations.
"""

import os
import logging
import requests
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class FeedbackType(Enum):
    """Types of feedback from ticket resolution."""
    ACCEPTED = "accepted"  # Recommendation was applied
    REJECTED = "rejected"  # Recommendation was declined
    IGNORED = "ignored"    # Ticket was closed without action (stale)


@dataclass
class FeedbackRecord:
    """Record of feedback for a recommendation."""
    recommendation_id: str
    rule_id: str
    recommendation_type: str
    feedback_type: FeedbackType
    jira_ticket_key: str
    resolution: Optional[str] = None
    resolution_comment: Optional[str] = None
    feedback_timestamp: str = ""
    created_at: str = ""

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        return {
            'pk': f'rule#{self.rule_id}',
            'sk': f'feedback#{self.recommendation_id}',
            'recommendation_id': self.recommendation_id,
            'rule_id': self.rule_id,
            'recommendation_type': self.recommendation_type,
            'feedback_type': self.feedback_type.value,
            'jira_ticket_key': self.jira_ticket_key,
            'resolution': self.resolution or '',
            'resolution_comment': self.resolution_comment or '',
            'feedback_timestamp': self.feedback_timestamp,
            'created_at': self.created_at,
            'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'FeedbackRecord':
        """Create from DynamoDB item."""
        return cls(
            recommendation_id=item['recommendation_id'],
            rule_id=item['rule_id'],
            recommendation_type=item['recommendation_type'],
            feedback_type=FeedbackType(item['feedback_type']),
            jira_ticket_key=item['jira_ticket_key'],
            resolution=item.get('resolution'),
            resolution_comment=item.get('resolution_comment'),
            feedback_timestamp=item.get('feedback_timestamp', ''),
            created_at=item.get('created_at', '')
        )


@dataclass
class SuppressionRecord:
    """Record of suppression for a rule/recommendation type."""
    rule_id: str
    recommendation_type: str
    suppressed_until: str
    permanent: bool = False
    rejection_count: int = 0
    reason: Optional[str] = None


class FeedbackTracker:
    """
    Tracks feedback from Jira ticket resolutions.

    Learning behavior:
    - ACCEPTED (Done/Fixed): Increases confidence for similar recommendations
    - REJECTED (Won't Do/Declined): Suppresses similar recommendations for 90 days
    - IGNORED (stale after 30 days): Does not re-create for 60 days
    - 3+ rejections for same pattern: Permanently suppress
    """

    def __init__(
        self,
        table_name: Optional[str] = None,
        jira_config: Optional[Dict[str, Any]] = None,
        suppress_rejected_days: int = 90,
        max_rejections_before_permanent: int = 3,
        stale_ticket_days: int = 30
    ):
        """
        Initialize feedback tracker.

        Args:
            table_name: DynamoDB table for feedback storage
            jira_config: Jira connection configuration
            suppress_rejected_days: Days to suppress after rejection
            max_rejections_before_permanent: Rejections before permanent suppression
            stale_ticket_days: Days before marking ticket as ignored
        """
        self.table_name = table_name or os.environ.get(
            'TUNING_FEEDBACK_TABLE',
            'mantissa-log-tuning-feedback'
        )
        self.jira_config = jira_config or {}
        self.suppress_rejected_days = suppress_rejected_days
        self.max_rejections_before_permanent = max_rejections_before_permanent
        self.stale_ticket_days = stale_ticket_days
        self._table = None
        self._suppressions_cache: Dict[str, SuppressionRecord] = {}

    @property
    def table(self):
        """Lazy-load DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource('dynamodb')
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def record_ticket_created(
        self,
        recommendation_id: str,
        rule_id: str,
        recommendation_type: str,
        jira_ticket_key: str
    ) -> None:
        """
        Record that a Jira ticket was created for a recommendation.

        Args:
            recommendation_id: Unique recommendation ID
            rule_id: Rule ID
            recommendation_type: Type of recommendation
            jira_ticket_key: Jira ticket key (e.g., "SECENG-123")
        """
        now = datetime.utcnow().isoformat() + 'Z'

        try:
            self.table.put_item(
                Item={
                    'pk': f'ticket#{jira_ticket_key}',
                    'sk': 'metadata',
                    'recommendation_id': recommendation_id,
                    'rule_id': rule_id,
                    'recommendation_type': recommendation_type,
                    'jira_ticket_key': jira_ticket_key,
                    'status': 'open',
                    'created_at': now,
                    'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
                }
            )
            logger.info(f"Recorded ticket creation: {jira_ticket_key} for {rule_id}")

        except Exception as e:
            logger.error(f"Failed to record ticket creation: {e}")

    def check_ticket_status(self, jira_ticket_key: str) -> Optional[Dict[str, Any]]:
        """
        Check the status of a Jira ticket.

        Args:
            jira_ticket_key: Jira ticket key

        Returns:
            Ticket status info or None if not found
        """
        if not self.jira_config:
            logger.warning("No Jira configuration provided")
            return None

        try:
            url = self.jira_config['url'].rstrip('/')
            email = self.jira_config['email']
            api_token = self.jira_config['api_token']

            response = requests.get(
                f'{url}/rest/api/3/issue/{jira_ticket_key}',
                auth=(email, api_token),
                timeout=10
            )

            if response.status_code == 404:
                return None

            response.raise_for_status()
            issue = response.json()

            return {
                'key': issue['key'],
                'status': issue['fields']['status']['name'],
                'status_category': issue['fields']['status']['statusCategory']['name'],
                'resolution': issue['fields'].get('resolution', {}).get('name') if issue['fields'].get('resolution') else None,
                'updated': issue['fields']['updated'],
                'created': issue['fields']['created']
            }

        except Exception as e:
            logger.error(f"Failed to check ticket status: {e}")
            return None

    def process_ticket_resolution(
        self,
        jira_ticket_key: str,
        status_info: Dict[str, Any]
    ) -> Optional[FeedbackRecord]:
        """
        Process a ticket resolution and record feedback.

        Args:
            jira_ticket_key: Jira ticket key
            status_info: Status info from check_ticket_status

        Returns:
            FeedbackRecord if feedback was recorded, None otherwise
        """
        # Get ticket metadata
        try:
            response = self.table.get_item(
                Key={
                    'pk': f'ticket#{jira_ticket_key}',
                    'sk': 'metadata'
                }
            )

            if 'Item' not in response:
                logger.warning(f"No metadata found for ticket {jira_ticket_key}")
                return None

            metadata = response['Item']

        except Exception as e:
            logger.error(f"Failed to get ticket metadata: {e}")
            return None

        # Determine feedback type
        status_category = status_info.get('status_category', '').lower()
        resolution = status_info.get('resolution', '')

        feedback_type = None

        if status_category == 'done':
            if resolution and resolution.lower() in ['done', 'fixed', 'resolved', 'completed']:
                feedback_type = FeedbackType.ACCEPTED
            elif resolution and resolution.lower() in ["won't do", "declined", "rejected", "duplicate", "cannot reproduce"]:
                feedback_type = FeedbackType.REJECTED
            else:
                # Default to accepted if done without rejection resolution
                feedback_type = FeedbackType.ACCEPTED

        # Check for stale tickets
        if not feedback_type and metadata.get('created_at'):
            try:
                created = datetime.fromisoformat(metadata['created_at'].replace('Z', ''))
                days_open = (datetime.utcnow() - created).days

                if days_open >= self.stale_ticket_days:
                    feedback_type = FeedbackType.IGNORED

            except (ValueError, TypeError):
                pass

        if not feedback_type:
            return None

        # Record feedback
        now = datetime.utcnow().isoformat() + 'Z'

        feedback = FeedbackRecord(
            recommendation_id=metadata['recommendation_id'],
            rule_id=metadata['rule_id'],
            recommendation_type=metadata['recommendation_type'],
            feedback_type=feedback_type,
            jira_ticket_key=jira_ticket_key,
            resolution=resolution,
            feedback_timestamp=now,
            created_at=metadata['created_at']
        )

        try:
            # Store feedback record
            self.table.put_item(Item=feedback.to_dynamodb_item())

            # Update ticket metadata
            self.table.update_item(
                Key={
                    'pk': f'ticket#{jira_ticket_key}',
                    'sk': 'metadata'
                },
                UpdateExpression='SET #status = :status, feedback_type = :feedback, resolved_at = :resolved',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'resolved',
                    ':feedback': feedback_type.value,
                    ':resolved': now
                }
            )

            # Apply suppression if rejected
            if feedback_type == FeedbackType.REJECTED:
                self._apply_rejection_suppression(
                    rule_id=metadata['rule_id'],
                    recommendation_type=metadata['recommendation_type'],
                    reason=f"Rejected via {jira_ticket_key}: {resolution}"
                )

            logger.info(f"Recorded feedback for {jira_ticket_key}: {feedback_type.value}")
            return feedback

        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
            return None

    def _apply_rejection_suppression(
        self,
        rule_id: str,
        recommendation_type: str,
        reason: Optional[str] = None
    ) -> None:
        """Apply suppression after a rejection."""
        suppression_key = f"{rule_id}:{recommendation_type}"

        try:
            # Get current rejection count
            response = self.table.get_item(
                Key={
                    'pk': f'suppression#{rule_id}',
                    'sk': f'type#{recommendation_type}'
                }
            )

            current_count = 0
            if 'Item' in response:
                current_count = response['Item'].get('rejection_count', 0)

            new_count = current_count + 1
            permanent = new_count >= self.max_rejections_before_permanent

            if permanent:
                suppressed_until = '9999-12-31T23:59:59Z'  # Effectively permanent
            else:
                suppressed_until = (
                    datetime.utcnow() + timedelta(days=self.suppress_rejected_days)
                ).isoformat() + 'Z'

            # Store suppression
            self.table.put_item(
                Item={
                    'pk': f'suppression#{rule_id}',
                    'sk': f'type#{recommendation_type}',
                    'rule_id': rule_id,
                    'recommendation_type': recommendation_type,
                    'suppressed_until': suppressed_until,
                    'permanent': permanent,
                    'rejection_count': new_count,
                    'reason': reason or '',
                    'updated_at': datetime.utcnow().isoformat() + 'Z',
                    'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
                }
            )

            # Update cache
            self._suppressions_cache[suppression_key] = SuppressionRecord(
                rule_id=rule_id,
                recommendation_type=recommendation_type,
                suppressed_until=suppressed_until,
                permanent=permanent,
                rejection_count=new_count,
                reason=reason
            )

            logger.info(
                f"Applied suppression for {rule_id}:{recommendation_type} "
                f"(count: {new_count}, permanent: {permanent})"
            )

        except Exception as e:
            logger.error(f"Failed to apply suppression: {e}")

    def is_rule_suppressed(self, rule_id: str, recommendation_type: Optional[str] = None) -> bool:
        """
        Check if a rule/recommendation type is suppressed.

        Args:
            rule_id: Rule ID
            recommendation_type: Optional specific recommendation type

        Returns:
            True if suppressed
        """
        try:
            if recommendation_type:
                # Check specific suppression
                response = self.table.get_item(
                    Key={
                        'pk': f'suppression#{rule_id}',
                        'sk': f'type#{recommendation_type}'
                    }
                )

                if 'Item' in response:
                    item = response['Item']
                    if item.get('permanent'):
                        return True

                    suppressed_until = item.get('suppressed_until', '')
                    if suppressed_until:
                        try:
                            until_dt = datetime.fromisoformat(suppressed_until.replace('Z', ''))
                            if datetime.utcnow() < until_dt:
                                return True
                        except ValueError:
                            pass

            else:
                # Check any suppression for this rule
                response = self.table.query(
                    KeyConditionExpression='pk = :pk',
                    ExpressionAttributeValues={':pk': f'suppression#{rule_id}'}
                )

                for item in response.get('Items', []):
                    if item.get('permanent'):
                        return True

                    suppressed_until = item.get('suppressed_until', '')
                    if suppressed_until:
                        try:
                            until_dt = datetime.fromisoformat(suppressed_until.replace('Z', ''))
                            if datetime.utcnow() < until_dt:
                                return True
                        except ValueError:
                            pass

            return False

        except Exception as e:
            logger.error(f"Failed to check suppression: {e}")
            return False

    def get_feedback_history(
        self,
        rule_id: str,
        limit: int = 50
    ) -> List[FeedbackRecord]:
        """
        Get feedback history for a rule.

        Args:
            rule_id: Rule ID
            limit: Maximum records to return

        Returns:
            List of feedback records
        """
        try:
            response = self.table.query(
                KeyConditionExpression='pk = :pk AND begins_with(sk, :sk_prefix)',
                ExpressionAttributeValues={
                    ':pk': f'rule#{rule_id}',
                    ':sk_prefix': 'feedback#'
                },
                ScanIndexForward=False,
                Limit=limit
            )

            return [
                FeedbackRecord.from_dynamodb_item(item)
                for item in response.get('Items', [])
            ]

        except Exception as e:
            logger.error(f"Failed to get feedback history: {e}")
            return []

    def get_open_tickets(self) -> List[Dict[str, Any]]:
        """
        Get all open tuning tickets that need status checks.

        Returns:
            List of open ticket metadata
        """
        try:
            # Scan for open tickets (in production, use a GSI)
            response = self.table.scan(
                FilterExpression='#status = :status AND begins_with(pk, :pk_prefix)',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'open',
                    ':pk_prefix': 'ticket#'
                }
            )

            return response.get('Items', [])

        except Exception as e:
            logger.error(f"Failed to get open tickets: {e}")
            return []

    def poll_and_process_tickets(self) -> Dict[str, int]:
        """
        Poll all open tickets and process resolutions.

        Returns:
            Dictionary with counts of processed tickets by feedback type
        """
        results = {
            'checked': 0,
            'accepted': 0,
            'rejected': 0,
            'ignored': 0,
            'still_open': 0,
            'errors': 0
        }

        open_tickets = self.get_open_tickets()
        results['checked'] = len(open_tickets)

        for ticket in open_tickets:
            jira_key = ticket.get('jira_ticket_key')
            if not jira_key:
                continue

            try:
                status_info = self.check_ticket_status(jira_key)
                if not status_info:
                    results['errors'] += 1
                    continue

                feedback = self.process_ticket_resolution(jira_key, status_info)

                if feedback:
                    if feedback.feedback_type == FeedbackType.ACCEPTED:
                        results['accepted'] += 1
                    elif feedback.feedback_type == FeedbackType.REJECTED:
                        results['rejected'] += 1
                    elif feedback.feedback_type == FeedbackType.IGNORED:
                        results['ignored'] += 1
                else:
                    results['still_open'] += 1

            except Exception as e:
                logger.error(f"Error processing ticket {jira_key}: {e}")
                results['errors'] += 1

        return results
