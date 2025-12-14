"""Lazy initialization utilities for cold start optimization.

This module provides patterns for deferring expensive initialization
until first use, reducing Lambda/Cloud Function cold start times.

Key patterns:
- LazyClient: Lazy initialization wrapper for SDK clients
- cached_client: Decorator for singleton client creation
- lazy_import: Deferred module import
"""

import functools
import logging
import threading
from typing import Any, Callable, Dict, Generic, Optional, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class LazyClient(Generic[T]):
    """Lazy initialization wrapper for SDK clients.

    Defers client creation until first access, reducing cold start time.
    Thread-safe for concurrent access.

    Example:
        # Instead of:
        s3_client = boto3.client('s3')  # Created at import time

        # Use:
        _s3_client = LazyClient(lambda: boto3.client('s3'))

        def get_s3_client():
            return _s3_client.get()  # Created on first call
    """

    def __init__(self, factory: Callable[[], T], name: str = "client"):
        """Initialize lazy client wrapper.

        Args:
            factory: Callable that creates the client when invoked
            name: Name for logging purposes
        """
        self._factory = factory
        self._name = name
        self._instance: Optional[T] = None
        self._lock = threading.Lock()

    def get(self) -> T:
        """Get or create the client instance.

        Thread-safe singleton pattern.

        Returns:
            The client instance
        """
        if self._instance is None:
            with self._lock:
                # Double-check pattern
                if self._instance is None:
                    logger.debug(f"Initializing lazy client: {self._name}")
                    self._instance = self._factory()
        return self._instance

    def reset(self) -> None:
        """Reset the client instance (useful for testing)."""
        with self._lock:
            self._instance = None


# Global client cache for cached_client decorator
_client_cache: Dict[str, Any] = {}
_client_cache_lock = threading.Lock()


def cached_client(name: str) -> Callable[[Callable[[], T]], Callable[[], T]]:
    """Decorator for creating cached singleton clients.

    Use this decorator to ensure a client is only created once
    and reused across all invocations within the same Lambda instance.

    Example:
        @cached_client('dynamodb')
        def get_dynamodb_resource():
            return boto3.resource('dynamodb')

        # First call creates the resource, subsequent calls return cached
        table = get_dynamodb_resource().Table('my-table')
    """
    def decorator(factory: Callable[[], T]) -> Callable[[], T]:
        @functools.wraps(factory)
        def wrapper() -> T:
            if name not in _client_cache:
                with _client_cache_lock:
                    if name not in _client_cache:
                        logger.debug(f"Creating cached client: {name}")
                        _client_cache[name] = factory()
            return _client_cache[name]
        return wrapper
    return decorator


def clear_client_cache() -> None:
    """Clear all cached clients (useful for testing)."""
    global _client_cache
    with _client_cache_lock:
        _client_cache = {}


class LazyModule:
    """Lazy module loader that defers import until first attribute access.

    Example:
        # Instead of:
        import heavy_module  # Loaded at import time

        # Use:
        heavy_module = LazyModule('heavy_module')
        # Module only loaded when you actually use it:
        heavy_module.some_function()
    """

    def __init__(self, module_name: str):
        """Initialize lazy module.

        Args:
            module_name: Full module name to import
        """
        self._module_name = module_name
        self._module: Any = None

    def _load(self) -> Any:
        """Load the module on first access."""
        if self._module is None:
            import importlib
            logger.debug(f"Lazy loading module: {self._module_name}")
            self._module = importlib.import_module(self._module_name)
        return self._module

    def __getattr__(self, name: str) -> Any:
        """Forward attribute access to the loaded module."""
        return getattr(self._load(), name)


def lazy_import(module_name: str) -> LazyModule:
    """Create a lazy-loading module reference.

    Args:
        module_name: Full module name to import

    Returns:
        LazyModule that loads on first attribute access
    """
    return LazyModule(module_name)


# Pre-configured lazy clients for common AWS services
class AWSClients:
    """Lazy-initialized AWS clients for common services.

    Usage:
        from shared.utils.lazy_init import aws_clients

        # Clients are only created when accessed
        s3 = aws_clients.s3
        dynamodb = aws_clients.dynamodb
    """

    def __init__(self):
        self._clients: Dict[str, LazyClient] = {}

    def _get_boto3(self):
        """Lazy import boto3."""
        import boto3
        return boto3

    @property
    def s3(self):
        """Get lazy-initialized S3 client."""
        if 's3' not in self._clients:
            self._clients['s3'] = LazyClient(
                lambda: self._get_boto3().client('s3'),
                name='s3'
            )
        return self._clients['s3'].get()

    @property
    def dynamodb(self):
        """Get lazy-initialized DynamoDB resource."""
        if 'dynamodb' not in self._clients:
            self._clients['dynamodb'] = LazyClient(
                lambda: self._get_boto3().resource('dynamodb'),
                name='dynamodb'
            )
        return self._clients['dynamodb'].get()

    @property
    def secrets_manager(self):
        """Get lazy-initialized Secrets Manager client."""
        if 'secretsmanager' not in self._clients:
            self._clients['secretsmanager'] = LazyClient(
                lambda: self._get_boto3().client('secretsmanager'),
                name='secretsmanager'
            )
        return self._clients['secretsmanager'].get()

    @property
    def athena(self):
        """Get lazy-initialized Athena client."""
        if 'athena' not in self._clients:
            self._clients['athena'] = LazyClient(
                lambda: self._get_boto3().client('athena'),
                name='athena'
            )
        return self._clients['athena'].get()

    @property
    def sns(self):
        """Get lazy-initialized SNS client."""
        if 'sns' not in self._clients:
            self._clients['sns'] = LazyClient(
                lambda: self._get_boto3().client('sns'),
                name='sns'
            )
        return self._clients['sns'].get()

    @property
    def sqs(self):
        """Get lazy-initialized SQS client."""
        if 'sqs' not in self._clients:
            self._clients['sqs'] = LazyClient(
                lambda: self._get_boto3().client('sqs'),
                name='sqs'
            )
        return self._clients['sqs'].get()


# Global instance for convenience
aws_clients = AWSClients()


class GCPClients:
    """Lazy-initialized GCP clients for common services.

    Usage:
        from shared.utils.lazy_init import gcp_clients

        # Clients are only created when accessed
        storage = gcp_clients.storage
        firestore = gcp_clients.firestore
    """

    def __init__(self):
        self._clients: Dict[str, LazyClient] = {}

    @property
    def storage(self):
        """Get lazy-initialized Cloud Storage client."""
        if 'storage' not in self._clients:
            def create():
                from google.cloud import storage
                return storage.Client()
            self._clients['storage'] = LazyClient(create, name='storage')
        return self._clients['storage'].get()

    @property
    def firestore(self):
        """Get lazy-initialized Firestore client."""
        if 'firestore' not in self._clients:
            def create():
                from google.cloud import firestore
                return firestore.Client()
            self._clients['firestore'] = LazyClient(create, name='firestore')
        return self._clients['firestore'].get()

    @property
    def bigquery(self):
        """Get lazy-initialized BigQuery client."""
        if 'bigquery' not in self._clients:
            def create():
                from google.cloud import bigquery
                return bigquery.Client()
            self._clients['bigquery'] = LazyClient(create, name='bigquery')
        return self._clients['bigquery'].get()

    @property
    def secret_manager(self):
        """Get lazy-initialized Secret Manager client."""
        if 'secretmanager' not in self._clients:
            def create():
                from google.cloud import secretmanager
                return secretmanager.SecretManagerServiceClient()
            self._clients['secretmanager'] = LazyClient(create, name='secretmanager')
        return self._clients['secretmanager'].get()

    @property
    def pubsub_publisher(self):
        """Get lazy-initialized Pub/Sub publisher client."""
        if 'pubsub_publisher' not in self._clients:
            def create():
                from google.cloud import pubsub_v1
                return pubsub_v1.PublisherClient()
            self._clients['pubsub_publisher'] = LazyClient(create, name='pubsub_publisher')
        return self._clients['pubsub_publisher'].get()


# Global instance for convenience
gcp_clients = GCPClients()


class AzureClients:
    """Lazy-initialized Azure clients for common services.

    Usage:
        from shared.utils.lazy_init import azure_clients

        # Clients are only created when accessed
        credential = azure_clients.credential
        blob_service = azure_clients.get_blob_service(account_url)
    """

    def __init__(self):
        self._credential: Optional[Any] = None
        self._credential_lock = threading.Lock()
        self._clients: Dict[str, LazyClient] = {}

    @property
    def credential(self):
        """Get cached DefaultAzureCredential.

        This is the most expensive initialization, so we cache it globally.
        """
        if self._credential is None:
            with self._credential_lock:
                if self._credential is None:
                    from azure.identity import DefaultAzureCredential
                    logger.debug("Initializing DefaultAzureCredential")
                    self._credential = DefaultAzureCredential()
        return self._credential

    def get_blob_service(self, account_url: str):
        """Get BlobServiceClient for the specified account."""
        cache_key = f'blob_{account_url}'
        if cache_key not in self._clients:
            def create():
                from azure.storage.blob import BlobServiceClient
                return BlobServiceClient(account_url, credential=self.credential)
            self._clients[cache_key] = LazyClient(create, name=cache_key)
        return self._clients[cache_key].get()

    def get_secret_client(self, vault_url: str):
        """Get SecretClient for the specified Key Vault."""
        cache_key = f'keyvault_{vault_url}'
        if cache_key not in self._clients:
            def create():
                from azure.keyvault.secrets import SecretClient
                return SecretClient(vault_url=vault_url, credential=self.credential)
            self._clients[cache_key] = LazyClient(create, name=cache_key)
        return self._clients[cache_key].get()


# Global instance for convenience
azure_clients = AzureClients()
