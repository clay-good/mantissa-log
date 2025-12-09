"""
Multi-Cloud Query Pattern Cache Backends

Provides cloud-specific implementations for LLM query pattern caching:
- AWS: DynamoDB
- GCP: Firestore
- Azure: Cosmos DB
"""

import os
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from .cache import CachedQuery, CacheStats, STOP_WORDS, TIME_PATTERNS
import re
import hashlib

logger = logging.getLogger(__name__)


class CacheBackend(ABC):
    """Abstract base class for cache backends."""

    DEFAULT_TTL_DAYS = 7

    def __init__(self, schema_version: str = None, ttl_days: int = DEFAULT_TTL_DAYS):
        self.schema_version = schema_version or os.environ.get('SCHEMA_VERSION', 'v1')
        self.ttl_days = ttl_days
        self._stats = {'hits': 0, 'misses': 0}

    def normalize_query(self, query: str) -> str:
        """Normalize a natural language query for cache key generation."""
        normalized = query.lower().strip()

        for pattern, replacement in TIME_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)

        normalized = re.sub(r'[^\w\s\-_]', ' ', normalized)
        words = normalized.split()
        words = [w for w in words if w not in STOP_WORDS and len(w) > 1]
        words.sort()

        return ' '.join(words)

    def generate_cache_key(self, query: str, user_id: Optional[str] = None) -> str:
        """Generate cache key for a query."""
        normalized = self.normalize_query(query)
        key_parts = [normalized, self.schema_version]
        key_string = '|'.join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    @abstractmethod
    def get(self, query: str, user_id: Optional[str] = None) -> Optional[CachedQuery]:
        """Look up a query in the cache."""
        pass

    @abstractmethod
    def put(self, query: str, sql: str, explanation: Optional[str] = None,
            user_id: Optional[str] = None) -> CachedQuery:
        """Store a query result in the cache."""
        pass

    @abstractmethod
    def invalidate(self, query: str, user_id: Optional[str] = None) -> bool:
        """Invalidate a cached query."""
        pass

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        total_requests = self._stats['hits'] + self._stats['misses']
        hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0.0
        return CacheStats(
            total_entries=0,
            hits=self._stats['hits'],
            misses=self._stats['misses'],
            hit_rate=round(hit_rate, 2),
            oldest_entry=None,
            newest_entry=None
        )


class FirestoreCacheBackend(CacheBackend):
    """
    Google Cloud Firestore cache backend.

    Uses Firestore for persistent query pattern caching with TTL support.
    """

    def __init__(
        self,
        project_id: str = None,
        collection_name: str = "query_cache",
        database: str = "(default)",
        schema_version: str = None,
        ttl_days: int = CacheBackend.DEFAULT_TTL_DAYS
    ):
        super().__init__(schema_version, ttl_days)
        self.project_id = project_id or os.environ.get('GCP_PROJECT_ID')
        self.collection_name = collection_name
        self.database = database
        self._client = None

    @property
    def client(self):
        """Lazy-load Firestore client."""
        if self._client is None:
            from google.cloud import firestore
            self._client = firestore.Client(
                project=self.project_id,
                database=self.database
            )
        return self._client

    @property
    def collection(self):
        """Get cache collection reference."""
        return self.client.collection(self.collection_name)

    def get(self, query: str, user_id: Optional[str] = None) -> Optional[CachedQuery]:
        """Look up a query in Firestore cache."""
        cache_key = self.generate_cache_key(query, user_id)

        try:
            doc_ref = self.collection.document(cache_key)
            doc = doc_ref.get()

            if not doc.exists:
                self._stats['misses'] += 1
                logger.debug(f"Cache miss for query: {query[:50]}...")
                return None

            data = doc.to_dict()

            # Check schema version
            if data.get('schema_version') != self.schema_version:
                self._stats['misses'] += 1
                logger.debug("Cache miss (schema version mismatch)")
                return None

            # Check TTL
            created_at = data.get('created_at', '')
            if created_at:
                try:
                    created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if datetime.now(created.tzinfo) - created > timedelta(days=self.ttl_days):
                        # Entry expired, delete it
                        doc_ref.delete()
                        self._stats['misses'] += 1
                        return None
                except Exception:
                    pass

            # Update hit count and last accessed
            now = datetime.utcnow().isoformat() + 'Z'
            doc_ref.update({
                'hit_count': firestore.Increment(1),
                'last_accessed': now
            })

            self._stats['hits'] += 1
            logger.debug(f"Cache hit for query: {query[:50]}...")

            return CachedQuery(
                query_hash=cache_key,
                normalized_query=data.get('normalized_query', ''),
                original_query=data.get('original_query', ''),
                generated_sql=data.get('generated_sql', ''),
                explanation=data.get('explanation'),
                schema_version=data.get('schema_version', ''),
                created_at=data.get('created_at', ''),
                hit_count=data.get('hit_count', 0) + 1,
                last_accessed=now,
                ttl=0
            )

        except Exception as e:
            logger.warning(f"Error reading from Firestore cache: {e}")
            self._stats['misses'] += 1
            return None

    def put(self, query: str, sql: str, explanation: Optional[str] = None,
            user_id: Optional[str] = None) -> CachedQuery:
        """Store a query result in Firestore cache."""
        cache_key = self.generate_cache_key(query, user_id)
        normalized = self.normalize_query(query)
        now = datetime.utcnow().isoformat() + 'Z'

        data = {
            'query_hash': cache_key,
            'normalized_query': normalized,
            'original_query': query,
            'generated_sql': sql,
            'explanation': explanation or '',
            'schema_version': self.schema_version,
            'created_at': now,
            'hit_count': 0,
            'last_accessed': now
        }

        try:
            doc_ref = self.collection.document(cache_key)
            doc_ref.set(data)
            logger.debug(f"Cached query in Firestore: {query[:50]}...")
        except Exception as e:
            logger.warning(f"Error writing to Firestore cache: {e}")

        return CachedQuery(
            query_hash=cache_key,
            normalized_query=normalized,
            original_query=query,
            generated_sql=sql,
            explanation=explanation,
            schema_version=self.schema_version,
            created_at=now,
            hit_count=0,
            last_accessed=now,
            ttl=0
        )

    def invalidate(self, query: str, user_id: Optional[str] = None) -> bool:
        """Invalidate a cached query in Firestore."""
        cache_key = self.generate_cache_key(query, user_id)

        try:
            doc_ref = self.collection.document(cache_key)
            doc_ref.delete()
            logger.debug(f"Invalidated Firestore cache for query: {query[:50]}...")
            return True
        except Exception as e:
            logger.warning(f"Error invalidating Firestore cache: {e}")
            return False

    def get_stats(self) -> CacheStats:
        """Get Firestore cache statistics."""
        try:
            # Count total entries
            docs = self.collection.stream()
            entries = list(docs)
            total_entries = len(entries)

            dates = []
            for doc in entries:
                data = doc.to_dict()
                if 'created_at' in data:
                    dates.append(data['created_at'])

            dates.sort()

            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0.0

            return CacheStats(
                total_entries=total_entries,
                hits=self._stats['hits'],
                misses=self._stats['misses'],
                hit_rate=round(hit_rate, 2),
                oldest_entry=dates[0] if dates else None,
                newest_entry=dates[-1] if dates else None
            )
        except Exception as e:
            logger.warning(f"Error getting Firestore cache stats: {e}")
            return super().get_stats()


class CosmosDBCacheBackend(CacheBackend):
    """
    Azure Cosmos DB cache backend.

    Uses Cosmos DB for persistent query pattern caching with TTL support.
    """

    def __init__(
        self,
        connection_string: str = None,
        database_name: str = "mantissa",
        container_name: str = "query_cache",
        schema_version: str = None,
        ttl_days: int = CacheBackend.DEFAULT_TTL_DAYS
    ):
        super().__init__(schema_version, ttl_days)
        self.connection_string = connection_string or os.environ.get('COSMOS_CONNECTION_STRING')
        self.database_name = database_name
        self.container_name = container_name
        self._client = None
        self._container = None

    @property
    def container(self):
        """Lazy-load Cosmos DB container."""
        if self._container is None:
            from azure.cosmos import CosmosClient, PartitionKey

            self._client = CosmosClient.from_connection_string(self.connection_string)
            database = self._client.get_database_client(self.database_name)
            self._container = database.get_container_client(self.container_name)

        return self._container

    def get(self, query: str, user_id: Optional[str] = None) -> Optional[CachedQuery]:
        """Look up a query in Cosmos DB cache."""
        cache_key = self.generate_cache_key(query, user_id)

        try:
            item = self.container.read_item(item=cache_key, partition_key=cache_key)

            # Check schema version
            if item.get('schema_version') != self.schema_version:
                self._stats['misses'] += 1
                logger.debug("Cache miss (schema version mismatch)")
                return None

            # Check TTL
            created_at = item.get('created_at', '')
            if created_at:
                try:
                    created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if datetime.now(created.tzinfo) - created > timedelta(days=self.ttl_days):
                        # Entry expired, delete it
                        self.container.delete_item(item=cache_key, partition_key=cache_key)
                        self._stats['misses'] += 1
                        return None
                except Exception:
                    pass

            # Update hit count and last accessed
            now = datetime.utcnow().isoformat() + 'Z'
            item['hit_count'] = item.get('hit_count', 0) + 1
            item['last_accessed'] = now
            self.container.upsert_item(item)

            self._stats['hits'] += 1
            logger.debug(f"Cache hit for query: {query[:50]}...")

            return CachedQuery(
                query_hash=cache_key,
                normalized_query=item.get('normalized_query', ''),
                original_query=item.get('original_query', ''),
                generated_sql=item.get('generated_sql', ''),
                explanation=item.get('explanation'),
                schema_version=item.get('schema_version', ''),
                created_at=item.get('created_at', ''),
                hit_count=item['hit_count'],
                last_accessed=now,
                ttl=0
            )

        except Exception as e:
            # Item not found or other error
            if 'NotFound' not in str(type(e).__name__):
                logger.warning(f"Error reading from Cosmos DB cache: {e}")
            self._stats['misses'] += 1
            return None

    def put(self, query: str, sql: str, explanation: Optional[str] = None,
            user_id: Optional[str] = None) -> CachedQuery:
        """Store a query result in Cosmos DB cache."""
        cache_key = self.generate_cache_key(query, user_id)
        normalized = self.normalize_query(query)
        now = datetime.utcnow().isoformat() + 'Z'
        ttl_seconds = self.ttl_days * 24 * 60 * 60

        item = {
            'id': cache_key,
            'query_hash': cache_key,
            'normalized_query': normalized,
            'original_query': query,
            'generated_sql': sql,
            'explanation': explanation or '',
            'schema_version': self.schema_version,
            'created_at': now,
            'hit_count': 0,
            'last_accessed': now,
            'ttl': ttl_seconds  # Cosmos DB native TTL
        }

        try:
            self.container.upsert_item(item)
            logger.debug(f"Cached query in Cosmos DB: {query[:50]}...")
        except Exception as e:
            logger.warning(f"Error writing to Cosmos DB cache: {e}")

        return CachedQuery(
            query_hash=cache_key,
            normalized_query=normalized,
            original_query=query,
            generated_sql=sql,
            explanation=explanation,
            schema_version=self.schema_version,
            created_at=now,
            hit_count=0,
            last_accessed=now,
            ttl=ttl_seconds
        )

    def invalidate(self, query: str, user_id: Optional[str] = None) -> bool:
        """Invalidate a cached query in Cosmos DB."""
        cache_key = self.generate_cache_key(query, user_id)

        try:
            self.container.delete_item(item=cache_key, partition_key=cache_key)
            logger.debug(f"Invalidated Cosmos DB cache for query: {query[:50]}...")
            return True
        except Exception as e:
            logger.warning(f"Error invalidating Cosmos DB cache: {e}")
            return False

    def get_stats(self) -> CacheStats:
        """Get Cosmos DB cache statistics."""
        try:
            # Query all items
            query = "SELECT c.created_at FROM c"
            items = list(self.container.query_items(query=query, enable_cross_partition_query=True))

            dates = [item['created_at'] for item in items if 'created_at' in item]
            dates.sort()

            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0.0

            return CacheStats(
                total_entries=len(items),
                hits=self._stats['hits'],
                misses=self._stats['misses'],
                hit_rate=round(hit_rate, 2),
                oldest_entry=dates[0] if dates else None,
                newest_entry=dates[-1] if dates else None
            )
        except Exception as e:
            logger.warning(f"Error getting Cosmos DB cache stats: {e}")
            return super().get_stats()


def get_cache_backend(cloud_provider: str = None) -> CacheBackend:
    """
    Factory function to get appropriate cache backend for the cloud provider.

    Args:
        cloud_provider: Cloud provider name ("aws", "gcp", "azure")
                       If not specified, detects from environment

    Returns:
        CacheBackend implementation for the specified cloud
    """
    if cloud_provider is None:
        # Auto-detect cloud provider
        if os.environ.get('AWS_REGION') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
            cloud_provider = 'aws'
        elif os.environ.get('GCP_PROJECT_ID') or os.environ.get('GOOGLE_CLOUD_PROJECT'):
            cloud_provider = 'gcp'
        elif os.environ.get('AZURE_FUNCTIONS_ENVIRONMENT') or os.environ.get('COSMOS_CONNECTION_STRING'):
            cloud_provider = 'azure'
        else:
            cloud_provider = 'aws'  # Default

    cloud_provider = cloud_provider.lower()

    if cloud_provider == 'aws':
        from .cache import QueryPatternCache
        return QueryPatternCache()
    elif cloud_provider == 'gcp':
        return FirestoreCacheBackend()
    elif cloud_provider == 'azure':
        return CosmosDBCacheBackend()
    else:
        raise ValueError(f"Unknown cloud provider: {cloud_provider}")
