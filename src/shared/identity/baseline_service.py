"""Baseline builder service for ITDR module.

Continuously builds and updates user baselines from incoming identity events.
Can run as a scheduled Lambda/Cloud Function.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from ..models.identity_event import IdentityEvent, IdentityEventNormalizer
from .user_baseline import IdentityBaseline
from .baseline_calculator import BaselineCalculator
from .baseline_store import BaselineStore, InMemoryBaselineStore

logger = logging.getLogger(__name__)


class BaselineServiceConfig:
    """Configuration for BaselineService."""

    def __init__(
        self,
        learning_period_days: int = 14,
        min_events_for_confidence: int = 50,
        batch_size: int = 100,
        checkpoint_table: Optional[str] = None,
    ):
        self.learning_period_days = learning_period_days
        self.min_events_for_confidence = min_events_for_confidence
        self.batch_size = batch_size
        self.checkpoint_table = checkpoint_table

    @classmethod
    def from_environment(cls) -> "BaselineServiceConfig":
        """Create config from environment variables."""
        import os

        return cls(
            learning_period_days=int(os.environ.get("LEARNING_PERIOD_DAYS", "14")),
            min_events_for_confidence=int(os.environ.get("MIN_EVENTS_FOR_CONFIDENCE", "50")),
            batch_size=int(os.environ.get("BASELINE_BATCH_SIZE", "100")),
            checkpoint_table=os.environ.get("CHECKPOINT_TABLE"),
        )


class BaselineService:
    """Service for building and updating user identity baselines.

    Provides methods for:
    - Building baselines from historical data
    - Incrementally updating baselines from new events
    - Rebuilding all baselines (for backfill/repair)
    - Finding users needing baseline updates
    """

    def __init__(
        self,
        baseline_store: Optional[BaselineStore] = None,
        event_normalizer: Optional[IdentityEventNormalizer] = None,
        query_executor: Optional[Any] = None,
        config: Optional[BaselineServiceConfig] = None,
    ):
        """Initialize BaselineService.

        Args:
            baseline_store: Storage for baselines (defaults to InMemoryBaselineStore)
            event_normalizer: Normalizer for raw events to IdentityEvent
            query_executor: Executor for querying historical events from data lake
            config: Service configuration
        """
        self.baseline_store = baseline_store or InMemoryBaselineStore()
        self.event_normalizer = event_normalizer or IdentityEventNormalizer()
        self.query_executor = query_executor
        self.config = config or BaselineServiceConfig()
        self.calculator = BaselineCalculator(
            learning_period_days=self.config.learning_period_days,
            min_events_for_confidence=self.config.min_events_for_confidence,
        )

    def build_baseline_from_history(
        self,
        user_email: str,
        days: int = 14,
        provider: Optional[str] = None,
    ) -> IdentityBaseline:
        """Build a complete baseline from historical identity events.

        Queries the data lake for historical events and calculates a complete
        baseline for the user.

        Args:
            user_email: User's email address
            days: Number of days of history to analyze
            provider: Optional provider filter (okta, azure, etc.)

        Returns:
            Calculated IdentityBaseline
        """
        logger.info(f"Building baseline for {user_email} from {days} days of history")

        events = self._query_historical_events(user_email, days, provider)

        if not events:
            logger.warning(f"No historical events found for {user_email}")
            baseline = IdentityBaseline(
                user_id=user_email,
                email=user_email,
                baseline_start_date=datetime.now(timezone.utc),
            )
        else:
            baseline = self.calculator.calculate_baseline(user_email, events)

        # Save baseline
        self.baseline_store.save_baseline(user_email, baseline)

        logger.info(
            f"Built baseline for {user_email}: {baseline.event_count} events, "
            f"confidence={baseline.confidence_score:.2f}"
        )

        return baseline

    def process_new_events(
        self, events: List[IdentityEvent]
    ) -> Dict[str, IdentityBaseline]:
        """Process a batch of new identity events and update baselines.

        Groups events by user and updates each user's baseline incrementally.

        Args:
            events: List of IdentityEvents to process

        Returns:
            Dictionary of user_email -> updated IdentityBaseline
        """
        if not events:
            return {}

        # Group events by user
        events_by_user: Dict[str, List[IdentityEvent]] = defaultdict(list)
        for event in events:
            if event.user_email:
                events_by_user[event.user_email.lower()].append(event)

        updated_baselines: Dict[str, IdentityBaseline] = {}

        for user_email, user_events in events_by_user.items():
            try:
                baseline = self._update_user_baseline(user_email, user_events)
                updated_baselines[user_email] = baseline
            except Exception as e:
                logger.error(f"Error updating baseline for {user_email}: {e}")
                continue

        logger.info(
            f"Processed {len(events)} events, updated {len(updated_baselines)} baselines"
        )

        return updated_baselines

    def process_raw_events(
        self, raw_events: List[Dict[str, Any]], provider: str
    ) -> Dict[str, IdentityBaseline]:
        """Process raw events from a provider and update baselines.

        Normalizes raw events to IdentityEvent format before processing.

        Args:
            raw_events: List of raw event dictionaries
            provider: Provider name for normalization

        Returns:
            Dictionary of user_email -> updated IdentityBaseline
        """
        # Normalize events
        identity_events = []
        for raw_event in raw_events:
            try:
                event = self.event_normalizer.normalize(raw_event, provider)
                identity_events.append(event)
            except Exception as e:
                logger.warning(f"Error normalizing event: {e}")
                continue

        return self.process_new_events(identity_events)

    def rebuild_all_baselines(self, batch_size: Optional[int] = None) -> int:
        """Rebuild all user baselines from scratch.

        Used for backfill operations or repairing corrupt baselines.

        Args:
            batch_size: Number of users to process per batch

        Returns:
            Number of baselines rebuilt
        """
        batch_size = batch_size or self.config.batch_size

        logger.info("Starting full baseline rebuild")

        # Get all unique users from identity events
        users = self._get_all_users_with_events()

        rebuilt_count = 0
        total_users = len(users)

        for i in range(0, total_users, batch_size):
            batch = users[i:i + batch_size]

            for user_email in batch:
                try:
                    self.build_baseline_from_history(
                        user_email,
                        days=self.config.learning_period_days,
                    )
                    rebuilt_count += 1
                except Exception as e:
                    logger.error(f"Error rebuilding baseline for {user_email}: {e}")
                    continue

            logger.info(f"Rebuilt {rebuilt_count}/{total_users} baselines")

        logger.info(f"Baseline rebuild complete: {rebuilt_count} baselines rebuilt")
        return rebuilt_count

    def get_users_needing_baseline_update(
        self, hours_since_update: int = 24
    ) -> List[str]:
        """Find users who need their baselines updated.

        Returns users with:
        - Stale baselines (not updated recently)
        - No baseline but have events

        Args:
            hours_since_update: Hours since last update to consider stale

        Returns:
            List of user emails needing updates
        """
        users_needing_update = set()

        # Find stale baselines
        stale_days = max(1, hours_since_update // 24)
        stale_users = self.baseline_store.list_stale_baselines(days_since_update=stale_days)
        users_needing_update.update(stale_users)

        # Find users with events but no baseline
        users_with_events = self._get_users_with_recent_events(hours=hours_since_update)

        for user_email in users_with_events:
            baseline = self.baseline_store.get_baseline(user_email)
            if baseline is None:
                users_needing_update.add(user_email)

        return list(users_needing_update)

    def get_baseline_stats(self) -> Dict[str, Any]:
        """Get statistics about baselines in the system.

        Returns:
            Dictionary with baseline statistics
        """
        # This would need to be implemented based on store capabilities
        stats = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # If store supports listing, get counts
        if hasattr(self.baseline_store, "list_all_baselines"):
            baselines = self.baseline_store.list_all_baselines()
            mature_count = sum(1 for b in baselines if self.calculator.is_baseline_mature(b))
            stats["total_baselines"] = len(baselines)
            stats["mature_baselines"] = mature_count
            stats["immature_baselines"] = len(baselines) - mature_count

        return stats

    def _update_user_baseline(
        self, user_email: str, events: List[IdentityEvent]
    ) -> IdentityBaseline:
        """Update a single user's baseline with new events.

        Args:
            user_email: User's email
            events: New events for this user

        Returns:
            Updated IdentityBaseline
        """
        # Get existing baseline or create new
        baseline = self.baseline_store.get_baseline(user_email)

        if baseline is None:
            baseline = IdentityBaseline(
                user_id=user_email,
                email=user_email,
                baseline_start_date=datetime.now(timezone.utc),
            )

        # Sort events by timestamp
        events = sorted(events, key=lambda e: e.timestamp)

        # Update baseline incrementally with each event
        for event in events:
            baseline = self.calculator.update_baseline_incremental(baseline, event)

        # Save updated baseline
        self.baseline_store.save_baseline(user_email, baseline)

        return baseline

    def _query_historical_events(
        self,
        user_email: str,
        days: int,
        provider: Optional[str] = None,
    ) -> List[IdentityEvent]:
        """Query historical identity events from data lake.

        Args:
            user_email: User to query for
            days: Number of days of history
            provider: Optional provider filter

        Returns:
            List of IdentityEvents
        """
        if self.query_executor is None:
            logger.warning("No query executor configured, cannot query historical events")
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Build query for identity events
        # This query format will depend on the actual data lake schema
        provider_filter = f"AND provider = '{provider}'" if provider else ""

        query = f"""
            SELECT *
            FROM identity_events
            WHERE user_email = '{user_email.lower()}'
            AND event_timestamp >= '{cutoff_str}'
            {provider_filter}
            ORDER BY event_timestamp ASC
            LIMIT 10000
        """

        try:
            result = self.query_executor.execute_query(query)

            events = []
            for row in result.rows:
                try:
                    # Normalize each raw event
                    event = self.event_normalizer.normalize_auto(row)
                    if event:
                        events.append(event)
                except Exception as e:
                    logger.warning(f"Error normalizing historical event: {e}")
                    continue

            return events

        except Exception as e:
            logger.error(f"Error querying historical events: {e}")
            return []

    def _get_all_users_with_events(self) -> List[str]:
        """Get all unique users with identity events.

        Returns:
            List of user emails
        """
        if self.query_executor is None:
            return []

        query = """
            SELECT DISTINCT user_email
            FROM identity_events
            WHERE user_email IS NOT NULL
            LIMIT 100000
        """

        try:
            result = self.query_executor.execute_query(query)
            return [row.get("user_email", "").lower() for row in result.rows if row.get("user_email")]
        except Exception as e:
            logger.error(f"Error getting users with events: {e}")
            return []

    def _get_users_with_recent_events(self, hours: int = 24) -> List[str]:
        """Get users who have had events in the recent time window.

        Args:
            hours: Number of hours to look back

        Returns:
            List of user emails
        """
        if self.query_executor is None:
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT DISTINCT user_email
            FROM identity_events
            WHERE event_timestamp >= '{cutoff_str}'
            AND user_email IS NOT NULL
            LIMIT 10000
        """

        try:
            result = self.query_executor.execute_query(query)
            return [row.get("user_email", "").lower() for row in result.rows if row.get("user_email")]
        except Exception as e:
            logger.error(f"Error getting users with recent events: {e}")
            return []


class CheckpointManager:
    """Manages execution checkpoints for baseline builder.

    Stores last processed timestamp to enable incremental processing.
    """

    def __init__(self, table_name: str, region: str = "us-east-1"):
        """Initialize CheckpointManager.

        Args:
            table_name: DynamoDB table for checkpoints
            region: AWS region
        """
        self.table_name = table_name
        self.region = region
        self._table = None

    def _get_table(self):
        """Get DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def get_checkpoint(self, checkpoint_id: str = "baseline_builder") -> Optional[datetime]:
        """Get the last processed timestamp.

        Args:
            checkpoint_id: Identifier for this checkpoint

        Returns:
            Last processed timestamp or None if not set
        """
        try:
            response = self._get_table().get_item(
                Key={"pk": f"checkpoint#{checkpoint_id}", "sk": "latest"}
            )

            if "Item" not in response:
                return None

            timestamp_str = response["Item"].get("last_processed_timestamp")
            if timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

            return None

        except Exception as e:
            logger.error(f"Error getting checkpoint: {e}")
            return None

    def set_checkpoint(
        self,
        timestamp: datetime,
        checkpoint_id: str = "baseline_builder",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Set the checkpoint to a new timestamp.

        Args:
            timestamp: New checkpoint timestamp
            checkpoint_id: Identifier for this checkpoint
            metadata: Optional metadata about the run

        Returns:
            True if successful
        """
        try:
            item = {
                "pk": f"checkpoint#{checkpoint_id}",
                "sk": "latest",
                "last_processed_timestamp": timestamp.isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            if metadata:
                item["metadata"] = metadata

            self._get_table().put_item(Item=item)
            return True

        except Exception as e:
            logger.error(f"Error setting checkpoint: {e}")
            return False
