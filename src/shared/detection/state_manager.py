"""State management for alert deduplication and tracking."""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional
import json
import time


class StateManager:
    """Base class for managing detection state and alert deduplication."""

    def is_suppressed(self, suppression_key: str) -> bool:
        """Check if an alert is currently suppressed.

        Args:
            suppression_key: Unique key for alert suppression

        Returns:
            True if alert is suppressed
        """
        raise NotImplementedError("Subclasses must implement is_suppressed")

    def suppress_alert(self, suppression_key: str, duration: timedelta) -> None:
        """Suppress an alert for a specified duration.

        Args:
            suppression_key: Unique key for alert suppression
            duration: How long to suppress the alert
        """
        raise NotImplementedError("Subclasses must implement suppress_alert")

    def get_alert_history(self, suppression_key: str, limit: int = 10) -> list:
        """Get alert history for a suppression key.

        Args:
            suppression_key: Unique key for alert
            limit: Maximum number of historical alerts to return

        Returns:
            List of historical alert records
        """
        raise NotImplementedError("Subclasses must implement get_alert_history")

    def record_alert(self, suppression_key: str, alert_data: Dict[str, Any]) -> None:
        """Record an alert in history.

        Args:
            suppression_key: Unique key for alert
            alert_data: Alert metadata to store
        """
        raise NotImplementedError("Subclasses must implement record_alert")


class InMemoryStateManager(StateManager):
    """In-memory state manager for development and testing."""

    def __init__(self):
        """Initialize in-memory state manager."""
        self.suppression_cache: Dict[str, float] = {}
        self.alert_history: Dict[str, list] = {}

    def is_suppressed(self, suppression_key: str) -> bool:
        """Check if an alert is currently suppressed.

        Args:
            suppression_key: Unique key for alert suppression

        Returns:
            True if alert is suppressed
        """
        if suppression_key not in self.suppression_cache:
            return False

        # Check if suppression has expired
        expiry_time = self.suppression_cache[suppression_key]
        current_time = time.time()

        if current_time >= expiry_time:
            # Suppression expired, remove from cache
            del self.suppression_cache[suppression_key]
            return False

        return True

    def suppress_alert(self, suppression_key: str, duration: timedelta) -> None:
        """Suppress an alert for a specified duration.

        Args:
            suppression_key: Unique key for alert suppression
            duration: How long to suppress the alert
        """
        expiry_time = time.time() + duration.total_seconds()
        self.suppression_cache[suppression_key] = expiry_time

    def get_alert_history(self, suppression_key: str, limit: int = 10) -> list:
        """Get alert history for a suppression key.

        Args:
            suppression_key: Unique key for alert
            limit: Maximum number of historical alerts to return

        Returns:
            List of historical alert records
        """
        if suppression_key not in self.alert_history:
            return []

        # Return most recent alerts
        return self.alert_history[suppression_key][-limit:]

    def record_alert(self, suppression_key: str, alert_data: Dict[str, Any]) -> None:
        """Record an alert in history.

        Args:
            suppression_key: Unique key for alert
            alert_data: Alert metadata to store
        """
        if suppression_key not in self.alert_history:
            self.alert_history[suppression_key] = []

        # Add timestamp if not present
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.utcnow().isoformat()

        self.alert_history[suppression_key].append(alert_data)

        # Limit history size
        max_history = 100
        if len(self.alert_history[suppression_key]) > max_history:
            self.alert_history[suppression_key] = self.alert_history[suppression_key][-max_history:]

    def clear(self) -> None:
        """Clear all state (useful for testing)."""
        self.suppression_cache.clear()
        self.alert_history.clear()


class DynamoDBStateManager(StateManager):
    """DynamoDB-backed state manager for production use."""

    def __init__(
        self,
        table_name: str,
        region: str = "us-east-1",
        ttl_attribute: str = "ttl"
    ):
        """Initialize DynamoDB state manager.

        Args:
            table_name: DynamoDB table name
            region: AWS region
            ttl_attribute: Attribute name for TTL
        """
        self.table_name = table_name
        self.region = region
        self.ttl_attribute = ttl_attribute
        self.table = None
        self.dynamodb = None

    def _get_table(self):
        """Get or create DynamoDB table resource.

        Returns:
            DynamoDB table resource
        """
        if self.table is None:
            try:
                import boto3
                self.dynamodb = boto3.resource('dynamodb', region_name=self.region)
                self.table = self.dynamodb.Table(self.table_name)
            except ImportError:
                raise ImportError("boto3 is required for DynamoDB state manager")
        return self.table

    def is_suppressed(self, suppression_key: str) -> bool:
        """Check if an alert is currently suppressed.

        Args:
            suppression_key: Unique key for alert suppression

        Returns:
            True if alert is suppressed
        """
        table = self._get_table()

        try:
            response = table.get_item(
                Key={'pk': f"suppression#{suppression_key}", 'sk': 'current'}
            )

            if 'Item' not in response:
                return False

            # Check TTL
            item = response['Item']
            if self.ttl_attribute in item:
                ttl = item[self.ttl_attribute]
                if time.time() >= ttl:
                    return False

            return True

        except Exception as e:
            print(f"Error checking suppression: {e}")
            return False

    def suppress_alert(self, suppression_key: str, duration: timedelta) -> None:
        """Suppress an alert for a specified duration.

        Args:
            suppression_key: Unique key for alert suppression
            duration: How long to suppress the alert
        """
        table = self._get_table()

        ttl = int(time.time() + duration.total_seconds())

        try:
            table.put_item(
                Item={
                    'pk': f"suppression#{suppression_key}",
                    'sk': 'current',
                    self.ttl_attribute: ttl,
                    'created_at': datetime.utcnow().isoformat(),
                    'duration_seconds': int(duration.total_seconds())
                }
            )
        except Exception as e:
            print(f"Error suppressing alert: {e}")

    def get_alert_history(self, suppression_key: str, limit: int = 10) -> list:
        """Get alert history for a suppression key.

        Args:
            suppression_key: Unique key for alert
            limit: Maximum number of historical alerts to return

        Returns:
            List of historical alert records
        """
        table = self._get_table()

        try:
            response = table.query(
                KeyConditionExpression='pk = :pk AND begins_with(sk, :sk)',
                ExpressionAttributeValues={
                    ':pk': f"alert#{suppression_key}",
                    ':sk': 'history#'
                },
                ScanIndexForward=False,
                Limit=limit
            )

            items = response.get('Items', [])
            return [item.get('data', {}) for item in items]

        except Exception as e:
            print(f"Error getting alert history: {e}")
            return []

    def record_alert(self, suppression_key: str, alert_data: Dict[str, Any]) -> None:
        """Record an alert in history.

        Args:
            suppression_key: Unique key for alert
            alert_data: Alert metadata to store
        """
        table = self._get_table()

        timestamp = datetime.utcnow()
        timestamp_str = timestamp.isoformat()

        # Add timestamp if not present
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = timestamp_str

        try:
            table.put_item(
                Item={
                    'pk': f"alert#{suppression_key}",
                    'sk': f"history#{timestamp_str}",
                    'data': alert_data,
                    'created_at': timestamp_str
                }
            )
        except Exception as e:
            print(f"Error recording alert: {e}")


class RedisStateManager(StateManager):
    """Redis-backed state manager for high-performance deployments."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        key_prefix: str = "mantissa:"
    ):
        """Initialize Redis state manager.

        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            key_prefix: Prefix for all Redis keys
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.key_prefix = key_prefix
        self.redis_client = None

    def _get_client(self):
        """Get or create Redis client.

        Returns:
            Redis client
        """
        if self.redis_client is None:
            try:
                import redis
                self.redis_client = redis.Redis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    password=self.password,
                    decode_responses=True
                )
            except ImportError:
                raise ImportError("redis package is required for Redis state manager")
        return self.redis_client

    def is_suppressed(self, suppression_key: str) -> bool:
        """Check if an alert is currently suppressed.

        Args:
            suppression_key: Unique key for alert suppression

        Returns:
            True if alert is suppressed
        """
        client = self._get_client()
        key = f"{self.key_prefix}suppression:{suppression_key}"

        try:
            return client.exists(key) > 0
        except Exception as e:
            print(f"Error checking suppression: {e}")
            return False

    def suppress_alert(self, suppression_key: str, duration: timedelta) -> None:
        """Suppress an alert for a specified duration.

        Args:
            suppression_key: Unique key for alert suppression
            duration: How long to suppress the alert
        """
        client = self._get_client()
        key = f"{self.key_prefix}suppression:{suppression_key}"

        try:
            client.setex(
                key,
                int(duration.total_seconds()),
                datetime.utcnow().isoformat()
            )
        except Exception as e:
            print(f"Error suppressing alert: {e}")

    def get_alert_history(self, suppression_key: str, limit: int = 10) -> list:
        """Get alert history for a suppression key.

        Args:
            suppression_key: Unique key for alert
            limit: Maximum number of historical alerts to return

        Returns:
            List of historical alert records
        """
        client = self._get_client()
        key = f"{self.key_prefix}history:{suppression_key}"

        try:
            # Get most recent entries from list
            items = client.lrange(key, 0, limit - 1)
            return [json.loads(item) for item in items]
        except Exception as e:
            print(f"Error getting alert history: {e}")
            return []

    def record_alert(self, suppression_key: str, alert_data: Dict[str, Any]) -> None:
        """Record an alert in history.

        Args:
            suppression_key: Unique key for alert
            alert_data: Alert metadata to store
        """
        client = self._get_client()
        key = f"{self.key_prefix}history:{suppression_key}"

        # Add timestamp if not present
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.utcnow().isoformat()

        try:
            # Add to list (most recent first)
            client.lpush(key, json.dumps(alert_data))

            # Trim to max size
            client.ltrim(key, 0, 99)

            # Set expiry (30 days)
            client.expire(key, 30 * 24 * 60 * 60)
        except Exception as e:
            print(f"Error recording alert: {e}")
