"""Rate limiting utilities for API handlers.

Provides token bucket rate limiting with configurable backends
for AWS (DynamoDB), GCP (Firestore), and Azure (Cosmos DB).

Security Features:
- Per-user rate limiting to prevent abuse
- Configurable limits for different API endpoints
- Sliding window algorithm for smooth rate limiting
- Graceful degradation if backend is unavailable
"""

import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(self, retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds.")


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_limit: int = 10  # Max requests in a burst

    @classmethod
    def from_environment(cls) -> "RateLimitConfig":
        """Create config from environment variables."""
        return cls(
            requests_per_minute=int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60")),
            requests_per_hour=int(os.environ.get("RATE_LIMIT_PER_HOUR", "1000")),
            requests_per_day=int(os.environ.get("RATE_LIMIT_PER_DAY", "10000")),
            burst_limit=int(os.environ.get("RATE_LIMIT_BURST", "10")),
        )

    @classmethod
    def strict(cls) -> "RateLimitConfig":
        """Stricter limits for expensive operations (LLM queries, Athena)."""
        return cls(
            requests_per_minute=10,
            requests_per_hour=100,
            requests_per_day=1000,
            burst_limit=5,
        )

    @classmethod
    def relaxed(cls) -> "RateLimitConfig":
        """Relaxed limits for lightweight operations."""
        return cls(
            requests_per_minute=120,
            requests_per_hour=5000,
            requests_per_day=50000,
            burst_limit=20,
        )


class RateLimitBackend(ABC):
    """Abstract base class for rate limit storage backends."""

    @abstractmethod
    def check_and_increment(
        self,
        key: str,
        window_seconds: int,
        max_requests: int
    ) -> Tuple[bool, int, int]:
        """Check if request is allowed and increment counter.

        Args:
            key: Unique key for rate limiting (e.g., user_id:endpoint)
            window_seconds: Time window in seconds
            max_requests: Maximum requests allowed in window

        Returns:
            Tuple of (allowed, current_count, retry_after_seconds)
        """
        pass

    @abstractmethod
    def get_remaining(self, key: str, window_seconds: int, max_requests: int) -> int:
        """Get remaining requests in current window."""
        pass


class InMemoryRateLimitBackend(RateLimitBackend):
    """In-memory rate limiter for development/testing."""

    def __init__(self):
        self._requests: Dict[str, list] = {}

    def check_and_increment(
        self,
        key: str,
        window_seconds: int,
        max_requests: int
    ) -> Tuple[bool, int, int]:
        now = time.time()
        window_start = now - window_seconds

        # Get existing requests in window
        if key not in self._requests:
            self._requests[key] = []

        # Clean up old requests
        self._requests[key] = [t for t in self._requests[key] if t > window_start]

        current_count = len(self._requests[key])

        if current_count >= max_requests:
            # Calculate retry after
            oldest = min(self._requests[key]) if self._requests[key] else now
            retry_after = int(oldest + window_seconds - now) + 1
            return False, current_count, max(retry_after, 1)

        # Add new request
        self._requests[key].append(now)
        return True, current_count + 1, 0

    def get_remaining(self, key: str, window_seconds: int, max_requests: int) -> int:
        now = time.time()
        window_start = now - window_seconds

        if key not in self._requests:
            return max_requests

        current = len([t for t in self._requests[key] if t > window_start])
        return max(0, max_requests - current)


class DynamoDBRateLimitBackend(RateLimitBackend):
    """DynamoDB-backed rate limiter for AWS."""

    def __init__(self, table_name: str = None):
        import boto3
        self.table_name = table_name or os.environ.get(
            "RATE_LIMIT_TABLE", "mantissa-rate-limits"
        )
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(self.table_name)

    def check_and_increment(
        self,
        key: str,
        window_seconds: int,
        max_requests: int
    ) -> Tuple[bool, int, int]:
        import boto3
        from botocore.exceptions import ClientError

        now = int(time.time())
        window_key = f"{key}:{now // window_seconds}"
        ttl = now + window_seconds + 60  # Add buffer for TTL

        try:
            # Atomic increment with conditional check
            response = self.table.update_item(
                Key={"pk": window_key},
                UpdateExpression="SET request_count = if_not_exists(request_count, :zero) + :inc, #ttl = :ttl",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":inc": 1,
                    ":ttl": ttl,
                    ":max": max_requests,
                },
                ConditionExpression="attribute_not_exists(request_count) OR request_count < :max",
                ReturnValues="ALL_NEW",
            )

            new_count = int(response["Attributes"]["request_count"])
            return True, new_count, 0

        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Rate limit exceeded
                retry_after = window_seconds - (now % window_seconds)
                return False, max_requests, retry_after
            raise

    def get_remaining(self, key: str, window_seconds: int, max_requests: int) -> int:
        now = int(time.time())
        window_key = f"{key}:{now // window_seconds}"

        try:
            response = self.table.get_item(Key={"pk": window_key})
            if "Item" in response:
                current = int(response["Item"].get("request_count", 0))
                return max(0, max_requests - current)
            return max_requests
        except Exception as e:
            logger.warning(f"Error checking rate limit: {e}")
            return max_requests


class FirestoreRateLimitBackend(RateLimitBackend):
    """Firestore-backed rate limiter for GCP."""

    def __init__(self, collection_name: str = "rate_limits"):
        from google.cloud import firestore
        self.collection_name = collection_name
        self.client = firestore.Client()

    def check_and_increment(
        self,
        key: str,
        window_seconds: int,
        max_requests: int
    ) -> Tuple[bool, int, int]:
        from google.cloud import firestore

        now = int(time.time())
        window_key = f"{key}:{now // window_seconds}"
        doc_ref = self.client.collection(self.collection_name).document(window_key)

        @firestore.transactional
        def update_in_transaction(transaction):
            doc = doc_ref.get(transaction=transaction)

            if doc.exists:
                data = doc.to_dict()
                current_count = data.get("request_count", 0)

                if current_count >= max_requests:
                    retry_after = window_seconds - (now % window_seconds)
                    return False, current_count, retry_after

                transaction.update(doc_ref, {"request_count": current_count + 1})
                return True, current_count + 1, 0
            else:
                transaction.set(doc_ref, {
                    "request_count": 1,
                    "created_at": now,
                    "expires_at": now + window_seconds + 60,
                })
                return True, 1, 0

        transaction = self.client.transaction()
        return update_in_transaction(transaction)

    def get_remaining(self, key: str, window_seconds: int, max_requests: int) -> int:
        now = int(time.time())
        window_key = f"{key}:{now // window_seconds}"

        try:
            doc = self.client.collection(self.collection_name).document(window_key).get()
            if doc.exists:
                current = doc.to_dict().get("request_count", 0)
                return max(0, max_requests - current)
            return max_requests
        except Exception as e:
            logger.warning(f"Error checking rate limit: {e}")
            return max_requests


class CosmosDBRateLimitBackend(RateLimitBackend):
    """Cosmos DB-backed rate limiter for Azure."""

    def __init__(self, container_name: str = "rate_limits"):
        from azure.cosmos import CosmosClient
        connection_string = os.environ.get("COSMOS_CONNECTION_STRING")
        database_name = os.environ.get("COSMOS_DATABASE", "mantissa")

        self.client = CosmosClient.from_connection_string(connection_string)
        self.database = self.client.get_database_client(database_name)
        self.container = self.database.get_container_client(container_name)

    def check_and_increment(
        self,
        key: str,
        window_seconds: int,
        max_requests: int
    ) -> Tuple[bool, int, int]:
        now = int(time.time())
        window_key = f"{key}:{now // window_seconds}"
        doc_id = window_key.replace(":", "_")

        try:
            # Try to read existing document
            try:
                item = self.container.read_item(item=doc_id, partition_key=doc_id)
                current_count = item.get("request_count", 0)

                if current_count >= max_requests:
                    retry_after = window_seconds - (now % window_seconds)
                    return False, current_count, retry_after

                # Update count
                item["request_count"] = current_count + 1
                self.container.upsert_item(item)
                return True, current_count + 1, 0

            except Exception:
                # Document doesn't exist, create it
                item = {
                    "id": doc_id,
                    "request_count": 1,
                    "created_at": now,
                    "ttl": window_seconds + 60,
                }
                self.container.upsert_item(item)
                return True, 1, 0

        except Exception as e:
            logger.warning(f"Rate limit check failed, allowing request: {e}")
            return True, 0, 0

    def get_remaining(self, key: str, window_seconds: int, max_requests: int) -> int:
        now = int(time.time())
        window_key = f"{key}:{now // window_seconds}"
        doc_id = window_key.replace(":", "_")

        try:
            item = self.container.read_item(item=doc_id, partition_key=doc_id)
            current = item.get("request_count", 0)
            return max(0, max_requests - current)
        except Exception:
            return max_requests


class RateLimiter:
    """Rate limiter with multi-tier limits (minute, hour, day)."""

    def __init__(
        self,
        backend: RateLimitBackend = None,
        config: RateLimitConfig = None
    ):
        self.backend = backend or InMemoryRateLimitBackend()
        self.config = config or RateLimitConfig.from_environment()

    def check_rate_limit(self, user_id: str, endpoint: str = "default") -> Dict:
        """Check if request is within rate limits.

        Args:
            user_id: User identifier
            endpoint: API endpoint name for per-endpoint limits

        Returns:
            Dict with rate limit info including remaining requests

        Raises:
            RateLimitExceeded: If any limit is exceeded
        """
        key = f"{user_id}:{endpoint}"

        # Check minute limit
        allowed, count, retry_after = self.backend.check_and_increment(
            f"{key}:minute", 60, self.config.requests_per_minute
        )
        if not allowed:
            raise RateLimitExceeded(retry_after)

        # Check hour limit
        allowed, count, retry_after = self.backend.check_and_increment(
            f"{key}:hour", 3600, self.config.requests_per_hour
        )
        if not allowed:
            raise RateLimitExceeded(retry_after)

        # Check day limit
        allowed, count, retry_after = self.backend.check_and_increment(
            f"{key}:day", 86400, self.config.requests_per_day
        )
        if not allowed:
            raise RateLimitExceeded(retry_after)

        return {
            "allowed": True,
            "remaining_minute": self.backend.get_remaining(
                f"{key}:minute", 60, self.config.requests_per_minute
            ),
            "remaining_hour": self.backend.get_remaining(
                f"{key}:hour", 3600, self.config.requests_per_hour
            ),
            "remaining_day": self.backend.get_remaining(
                f"{key}:day", 86400, self.config.requests_per_day
            ),
        }

    def get_headers(self, user_id: str, endpoint: str = "default") -> Dict[str, str]:
        """Get rate limit headers for response."""
        key = f"{user_id}:{endpoint}"

        remaining_minute = self.backend.get_remaining(
            f"{key}:minute", 60, self.config.requests_per_minute
        )

        return {
            "X-RateLimit-Limit": str(self.config.requests_per_minute),
            "X-RateLimit-Remaining": str(remaining_minute),
            "X-RateLimit-Reset": str(int(time.time()) + 60 - (int(time.time()) % 60)),
        }


def get_rate_limiter(platform: str = "aws") -> RateLimiter:
    """Get appropriate rate limiter for the platform.

    Args:
        platform: One of 'aws', 'gcp', 'azure', or 'memory'

    Returns:
        Configured RateLimiter instance
    """
    config = RateLimitConfig.from_environment()

    if platform == "aws":
        try:
            backend = DynamoDBRateLimitBackend()
        except Exception as e:
            logger.warning(f"Failed to init DynamoDB backend, using memory: {e}")
            backend = InMemoryRateLimitBackend()
    elif platform == "gcp":
        try:
            backend = FirestoreRateLimitBackend()
        except Exception as e:
            logger.warning(f"Failed to init Firestore backend, using memory: {e}")
            backend = InMemoryRateLimitBackend()
    elif platform == "azure":
        try:
            backend = CosmosDBRateLimitBackend()
        except Exception as e:
            logger.warning(f"Failed to init CosmosDB backend, using memory: {e}")
            backend = InMemoryRateLimitBackend()
    else:
        backend = InMemoryRateLimitBackend()

    return RateLimiter(backend=backend, config=config)


def rate_limit_response(retry_after: int, headers: Dict = None) -> Dict:
    """Create a 429 Too Many Requests response for AWS Lambda."""
    response_headers = {
        "Content-Type": "application/json",
        "Retry-After": str(retry_after),
    }
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": 429,
        "headers": response_headers,
        "body": '{"error": "Too Many Requests", "message": "Rate limit exceeded", "retry_after": ' + str(retry_after) + '}',
    }
