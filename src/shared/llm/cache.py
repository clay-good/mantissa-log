"""
LLM Query Pattern Cache

Caches natural language to SQL translations to reduce LLM API calls and costs.
Uses DynamoDB for persistent storage with TTL-based expiration.
"""

import os
import re
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Common English stop words to normalize queries
STOP_WORDS = {
    'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
    'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been',
    'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
    'could', 'should', 'may', 'might', 'must', 'shall', 'can', 'need',
    'that', 'this', 'these', 'those', 'it', 'its', 'i', 'me', 'my', 'we',
    'our', 'you', 'your', 'he', 'she', 'they', 'them', 'their', 'what',
    'which', 'who', 'whom', 'when', 'where', 'why', 'how', 'all', 'each',
    'every', 'both', 'few', 'more', 'most', 'other', 'some', 'such', 'no',
    'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very',
    'just', 'also', 'now', 'here', 'there', 'then', 'once', 'if', 'any',
    'please', 'show', 'give', 'find', 'get', 'list', 'display', 'tell'
}

# Time-related patterns to normalize (these make queries unique but shouldn't affect caching)
TIME_PATTERNS = [
    (r'\blast\s+\d+\s+(?:day|days|hour|hours|minute|minutes|week|weeks|month|months)\b', 'LAST_N_TIMEUNITS'),
    (r'\bpast\s+\d+\s+(?:day|days|hour|hours|minute|minutes|week|weeks|month|months)\b', 'PAST_N_TIMEUNITS'),
    (r'\b\d{4}-\d{2}-\d{2}\b', 'DATE_YYYY_MM_DD'),
    (r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', 'DATE_MM_DD_YYYY'),
    (r'\byesterday\b', 'YESTERDAY'),
    (r'\btoday\b', 'TODAY'),
    (r'\bthis\s+(?:week|month|year)\b', 'THIS_TIMEPERIOD'),
]


@dataclass
class CachedQuery:
    """Represents a cached query result."""
    query_hash: str
    normalized_query: str
    original_query: str
    generated_sql: str
    explanation: Optional[str]
    schema_version: str
    created_at: str
    hit_count: int
    last_accessed: str
    ttl: int

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format."""
        return {
            'pk': f'cache#{self.query_hash}',
            'sk': 'query',
            'query_hash': self.query_hash,
            'normalized_query': self.normalized_query,
            'original_query': self.original_query,
            'generated_sql': self.generated_sql,
            'explanation': self.explanation or '',
            'schema_version': self.schema_version,
            'created_at': self.created_at,
            'hit_count': self.hit_count,
            'last_accessed': self.last_accessed,
            'ttl': self.ttl
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'CachedQuery':
        """Create from DynamoDB item."""
        return cls(
            query_hash=item['query_hash'],
            normalized_query=item['normalized_query'],
            original_query=item['original_query'],
            generated_sql=item['generated_sql'],
            explanation=item.get('explanation') or None,
            schema_version=item['schema_version'],
            created_at=item['created_at'],
            hit_count=item.get('hit_count', 0),
            last_accessed=item.get('last_accessed', item['created_at']),
            ttl=item.get('ttl', 0)
        )


@dataclass
class CacheStats:
    """Cache statistics."""
    total_entries: int
    hits: int
    misses: int
    hit_rate: float
    oldest_entry: Optional[str]
    newest_entry: Optional[str]


class QueryPatternCache:
    """
    Caches natural language to SQL translations.

    Features:
    - Normalizes queries to increase cache hit rate
    - DynamoDB-backed for persistence across Lambda invocations
    - TTL-based expiration (default 7 days)
    - Hit count tracking for analytics
    - Schema version tracking for cache invalidation
    """

    DEFAULT_TTL_DAYS = 7
    MAX_CACHE_ENTRIES_PER_USER = 1000

    def __init__(
        self,
        table_name: Optional[str] = None,
        ttl_days: int = DEFAULT_TTL_DAYS,
        schema_version: Optional[str] = None
    ):
        """
        Initialize query pattern cache.

        Args:
            table_name: DynamoDB table name for cache storage
            ttl_days: Time-to-live for cached entries in days
            schema_version: Schema version for cache invalidation
        """
        self.table_name = table_name or os.environ.get(
            'QUERY_CACHE_TABLE',
            'mantissa-log-query-cache'
        )
        self.ttl_days = ttl_days
        self.schema_version = schema_version or os.environ.get(
            'SCHEMA_VERSION',
            'v1'
        )
        self._table = None
        self._stats = {'hits': 0, 'misses': 0}

    @property
    def table(self):
        """Lazy-load DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource('dynamodb')
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def normalize_query(self, query: str) -> str:
        """
        Normalize a natural language query for cache key generation.

        Normalization steps:
        1. Convert to lowercase
        2. Remove punctuation except meaningful operators
        3. Replace time references with placeholders
        4. Remove stop words
        5. Sort remaining words alphabetically

        Args:
            query: Original natural language query

        Returns:
            Normalized query string
        """
        # Lowercase
        normalized = query.lower().strip()

        # Replace time patterns with placeholders
        for pattern, replacement in TIME_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)

        # Remove punctuation except meaningful chars
        normalized = re.sub(r'[^\w\s\-_]', ' ', normalized)

        # Split into words
        words = normalized.split()

        # Remove stop words
        words = [w for w in words if w not in STOP_WORDS and len(w) > 1]

        # Sort alphabetically for order-independent matching
        words.sort()

        return ' '.join(words)

    def generate_cache_key(self, query: str, user_id: Optional[str] = None) -> str:
        """
        Generate cache key for a query.

        Args:
            query: Natural language query
            user_id: Optional user ID for user-specific caching

        Returns:
            Cache key (hash)
        """
        normalized = self.normalize_query(query)

        # Include schema version in key to invalidate on schema changes
        key_parts = [normalized, self.schema_version]

        # Optionally include user_id for user-specific patterns
        # For now, we use global caching to maximize hit rate
        # if user_id:
        #     key_parts.append(user_id)

        key_string = '|'.join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    def get(self, query: str, user_id: Optional[str] = None) -> Optional[CachedQuery]:
        """
        Look up a query in the cache.

        Args:
            query: Natural language query
            user_id: Optional user ID

        Returns:
            CachedQuery if found, None otherwise
        """
        cache_key = self.generate_cache_key(query, user_id)

        try:
            response = self.table.get_item(
                Key={
                    'pk': f'cache#{cache_key}',
                    'sk': 'query'
                }
            )

            if 'Item' not in response:
                self._stats['misses'] += 1
                logger.debug(f"Cache miss for query: {query[:50]}...")
                return None

            item = response['Item']

            # Check schema version
            if item.get('schema_version') != self.schema_version:
                self._stats['misses'] += 1
                logger.debug(f"Cache miss (schema version mismatch)")
                return None

            cached = CachedQuery.from_dynamodb_item(item)

            # Update hit count and last accessed
            self._update_access_stats(cache_key)

            self._stats['hits'] += 1
            logger.debug(f"Cache hit for query: {query[:50]}...")

            return cached

        except Exception as e:
            logger.warning(f"Error reading from cache: {e}")
            self._stats['misses'] += 1
            return None

    def put(
        self,
        query: str,
        sql: str,
        explanation: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> CachedQuery:
        """
        Store a query result in the cache.

        Args:
            query: Original natural language query
            sql: Generated SQL
            explanation: Optional explanation
            user_id: Optional user ID

        Returns:
            CachedQuery that was stored
        """
        cache_key = self.generate_cache_key(query, user_id)
        normalized = self.normalize_query(query)
        now = datetime.utcnow()
        ttl = int((now + timedelta(days=self.ttl_days)).timestamp())

        cached = CachedQuery(
            query_hash=cache_key,
            normalized_query=normalized,
            original_query=query,
            generated_sql=sql,
            explanation=explanation,
            schema_version=self.schema_version,
            created_at=now.isoformat() + 'Z',
            hit_count=0,
            last_accessed=now.isoformat() + 'Z',
            ttl=ttl
        )

        try:
            self.table.put_item(Item=cached.to_dynamodb_item())
            logger.debug(f"Cached query: {query[:50]}...")
        except Exception as e:
            logger.warning(f"Error writing to cache: {e}")

        return cached

    def invalidate(self, query: str, user_id: Optional[str] = None) -> bool:
        """
        Invalidate a cached query.

        Args:
            query: Query to invalidate
            user_id: Optional user ID

        Returns:
            True if successfully invalidated
        """
        cache_key = self.generate_cache_key(query, user_id)

        try:
            self.table.delete_item(
                Key={
                    'pk': f'cache#{cache_key}',
                    'sk': 'query'
                }
            )
            logger.debug(f"Invalidated cache for query: {query[:50]}...")
            return True

        except Exception as e:
            logger.warning(f"Error invalidating cache: {e}")
            return False

    def invalidate_all(self) -> int:
        """
        Invalidate all cached queries (use with caution).

        Returns:
            Number of entries invalidated
        """
        count = 0

        try:
            # Scan for all cache entries
            response = self.table.scan(
                FilterExpression='begins_with(pk, :prefix)',
                ExpressionAttributeValues={':prefix': 'cache#'},
                ProjectionExpression='pk, sk'
            )

            # Delete in batches
            with self.table.batch_writer() as batch:
                for item in response.get('Items', []):
                    batch.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
                    count += 1

            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(
                    FilterExpression='begins_with(pk, :prefix)',
                    ExpressionAttributeValues={':prefix': 'cache#'},
                    ProjectionExpression='pk, sk',
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )

                with self.table.batch_writer() as batch:
                    for item in response.get('Items', []):
                        batch.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
                        count += 1

            logger.info(f"Invalidated {count} cache entries")

        except Exception as e:
            logger.warning(f"Error invalidating all cache entries: {e}")

        return count

    def get_stats(self) -> CacheStats:
        """
        Get cache statistics.

        Returns:
            CacheStats with current statistics
        """
        try:
            # Count total entries
            response = self.table.scan(
                FilterExpression='begins_with(pk, :prefix)',
                ExpressionAttributeValues={':prefix': 'cache#'},
                Select='COUNT'
            )

            total_entries = response.get('Count', 0)

            # Get oldest and newest entries
            oldest = None
            newest = None

            entries_response = self.table.scan(
                FilterExpression='begins_with(pk, :prefix)',
                ExpressionAttributeValues={':prefix': 'cache#'},
                ProjectionExpression='created_at'
            )

            items = entries_response.get('Items', [])
            if items:
                dates = [item.get('created_at', '') for item in items if item.get('created_at')]
                if dates:
                    dates.sort()
                    oldest = dates[0]
                    newest = dates[-1]

            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0.0

            return CacheStats(
                total_entries=total_entries,
                hits=self._stats['hits'],
                misses=self._stats['misses'],
                hit_rate=round(hit_rate, 2),
                oldest_entry=oldest,
                newest_entry=newest
            )

        except Exception as e:
            logger.warning(f"Error getting cache stats: {e}")
            return CacheStats(
                total_entries=0,
                hits=self._stats['hits'],
                misses=self._stats['misses'],
                hit_rate=0.0,
                oldest_entry=None,
                newest_entry=None
            )

    def get_top_queries(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top cached queries by hit count.

        Args:
            limit: Maximum number of queries to return

        Returns:
            List of top queries with hit counts
        """
        try:
            response = self.table.scan(
                FilterExpression='begins_with(pk, :prefix)',
                ExpressionAttributeValues={':prefix': 'cache#'},
                ProjectionExpression='original_query, hit_count, created_at, last_accessed'
            )

            items = response.get('Items', [])

            # Sort by hit count
            items.sort(key=lambda x: x.get('hit_count', 0), reverse=True)

            return [
                {
                    'query': item.get('original_query', ''),
                    'hit_count': item.get('hit_count', 0),
                    'created_at': item.get('created_at', ''),
                    'last_accessed': item.get('last_accessed', '')
                }
                for item in items[:limit]
            ]

        except Exception as e:
            logger.warning(f"Error getting top queries: {e}")
            return []

    def _update_access_stats(self, cache_key: str) -> None:
        """
        Update hit count and last accessed time for a cache entry.

        Args:
            cache_key: Cache key to update
        """
        try:
            self.table.update_item(
                Key={
                    'pk': f'cache#{cache_key}',
                    'sk': 'query'
                },
                UpdateExpression='SET hit_count = hit_count + :inc, last_accessed = :now',
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':now': datetime.utcnow().isoformat() + 'Z'
                }
            )
        except Exception as e:
            # Non-critical, don't fail the request
            logger.debug(f"Error updating cache stats: {e}")


class InMemoryQueryCache:
    """
    In-memory cache for local development and testing.

    Not suitable for production (no persistence across Lambda invocations).
    """

    def __init__(self, max_size: int = 100, ttl_seconds: int = 3600):
        """
        Initialize in-memory cache.

        Args:
            max_size: Maximum number of entries
            ttl_seconds: Time-to-live in seconds
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._stats = {'hits': 0, 'misses': 0}
        self.schema_version = 'v1'

    def normalize_query(self, query: str) -> str:
        """Normalize query (same as DynamoDB version)."""
        normalized = query.lower().strip()

        for pattern, replacement in TIME_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)

        normalized = re.sub(r'[^\w\s\-_]', ' ', normalized)
        words = normalized.split()
        words = [w for w in words if w not in STOP_WORDS and len(w) > 1]
        words.sort()

        return ' '.join(words)

    def generate_cache_key(self, query: str, user_id: Optional[str] = None) -> str:
        """Generate cache key."""
        normalized = self.normalize_query(query)
        key_string = f"{normalized}|{self.schema_version}"
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    def get(self, query: str, user_id: Optional[str] = None) -> Optional[CachedQuery]:
        """Look up query in cache."""
        cache_key = self.generate_cache_key(query, user_id)

        if cache_key not in self._cache:
            self._stats['misses'] += 1
            return None

        entry = self._cache[cache_key]

        # Check TTL
        created = datetime.fromisoformat(entry['created_at'].replace('Z', ''))
        if datetime.utcnow() - created > timedelta(seconds=self.ttl_seconds):
            del self._cache[cache_key]
            self._stats['misses'] += 1
            return None

        # Update stats
        entry['hit_count'] += 1
        entry['last_accessed'] = datetime.utcnow().isoformat() + 'Z'

        self._stats['hits'] += 1

        return CachedQuery(
            query_hash=cache_key,
            normalized_query=entry['normalized_query'],
            original_query=entry['original_query'],
            generated_sql=entry['generated_sql'],
            explanation=entry.get('explanation'),
            schema_version=entry['schema_version'],
            created_at=entry['created_at'],
            hit_count=entry['hit_count'],
            last_accessed=entry['last_accessed'],
            ttl=0
        )

    def put(
        self,
        query: str,
        sql: str,
        explanation: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> CachedQuery:
        """Store query in cache."""
        cache_key = self.generate_cache_key(query, user_id)
        normalized = self.normalize_query(query)
        now = datetime.utcnow()

        # Evict oldest entries if at capacity
        if len(self._cache) >= self.max_size:
            oldest_key = min(
                self._cache.keys(),
                key=lambda k: self._cache[k]['last_accessed']
            )
            del self._cache[oldest_key]

        entry = {
            'normalized_query': normalized,
            'original_query': query,
            'generated_sql': sql,
            'explanation': explanation,
            'schema_version': self.schema_version,
            'created_at': now.isoformat() + 'Z',
            'hit_count': 0,
            'last_accessed': now.isoformat() + 'Z'
        }

        self._cache[cache_key] = entry

        return CachedQuery(
            query_hash=cache_key,
            normalized_query=normalized,
            original_query=query,
            generated_sql=sql,
            explanation=explanation,
            schema_version=self.schema_version,
            created_at=entry['created_at'],
            hit_count=0,
            last_accessed=entry['last_accessed'],
            ttl=0
        )

    def invalidate(self, query: str, user_id: Optional[str] = None) -> bool:
        """Invalidate cached query."""
        cache_key = self.generate_cache_key(query, user_id)
        if cache_key in self._cache:
            del self._cache[cache_key]
            return True
        return False

    def invalidate_all(self) -> int:
        """Invalidate all cached queries."""
        count = len(self._cache)
        self._cache.clear()
        return count

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        total_requests = self._stats['hits'] + self._stats['misses']
        hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0.0

        dates = [
            self._cache[k]['created_at']
            for k in self._cache
        ]
        dates.sort()

        return CacheStats(
            total_entries=len(self._cache),
            hits=self._stats['hits'],
            misses=self._stats['misses'],
            hit_rate=round(hit_rate, 2),
            oldest_entry=dates[0] if dates else None,
            newest_entry=dates[-1] if dates else None
        )


def get_query_cache(use_dynamodb: bool = True) -> QueryPatternCache:
    """
    Factory function to get appropriate cache implementation.

    Args:
        use_dynamodb: Whether to use DynamoDB (True) or in-memory (False)

    Returns:
        Cache implementation
    """
    if use_dynamodb:
        return QueryPatternCache()
    else:
        return InMemoryQueryCache()
