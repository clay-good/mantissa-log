"""Persistent storage backends for network traffic baselines.

Provides an abstract interface and cloud-specific implementations
(DynamoDB, Firestore, Cosmos DB) plus an in-memory implementation
for development and testing.

Follows the same multi-cloud pattern used by
``src/shared/identity/baseline_store.py`` and
``src/shared/health/health_state_store.py``.

Two entity types are stored:

1. **Host baselines** — keyed by ``(tenant_id, host_ip)``.
   Each document is the full ``NetworkHostBaseline.to_dict()`` output.

2. **Network baselines** — keyed by ``tenant_id`` (one per tenant).
   Each document is the full ``NetworkBaseline.to_dict()`` output.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .network_baseline import NetworkBaseline, NetworkHostBaseline

logger = logging.getLogger(__name__)

# Default TTL for stored baselines: 90 days.
_DEFAULT_TTL_SECONDS = 90 * 24 * 60 * 60


class NetworkBaselineStore(ABC):
    """Abstract base class for network baseline persistence.

    Implementations must provide five methods covering host-level
    baselines and a single network-wide baseline per tenant.
    """

    # ------------------------------------------------------------------
    # Host baselines
    # ------------------------------------------------------------------

    @abstractmethod
    def save_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
        baseline: NetworkHostBaseline,
    ) -> bool:
        """Persist a host baseline.

        Args:
            host_ip: Host IP address.
            tenant_id: Tenant identifier.
            baseline: NetworkHostBaseline to save.

        Returns:
            True if the write succeeded.
        """
        pass

    @abstractmethod
    def get_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
    ) -> Optional[NetworkHostBaseline]:
        """Retrieve a single host baseline.

        Args:
            host_ip: Host IP address.
            tenant_id: Tenant identifier.

        Returns:
            NetworkHostBaseline or None if not found.
        """
        pass

    @abstractmethod
    def list_host_baselines(
        self,
        tenant_id: str,
    ) -> List[NetworkHostBaseline]:
        """Retrieve all host baselines for a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            List of NetworkHostBaseline (may be empty).
        """
        pass

    # ------------------------------------------------------------------
    # Network-wide baseline
    # ------------------------------------------------------------------

    @abstractmethod
    def save_network_baseline(
        self,
        tenant_id: str,
        baseline: NetworkBaseline,
    ) -> bool:
        """Persist the network-wide baseline for a tenant.

        Args:
            tenant_id: Tenant identifier.
            baseline: NetworkBaseline to save.

        Returns:
            True if the write succeeded.
        """
        pass

    @abstractmethod
    def get_network_baseline(
        self,
        tenant_id: str,
    ) -> Optional[NetworkBaseline]:
        """Retrieve the network-wide baseline for a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            NetworkBaseline or None if not found.
        """
        pass


# ======================================================================
# In-Memory Implementation (development / testing)
# ======================================================================


class InMemoryNetworkBaselineStore(NetworkBaselineStore):
    """In-memory network baseline store for development and unit tests."""

    def __init__(self) -> None:
        # Keyed by (tenant_id, host_ip)
        self._host_baselines: Dict[Tuple[str, str], NetworkHostBaseline] = {}
        # Keyed by tenant_id
        self._network_baselines: Dict[str, NetworkBaseline] = {}

    # -- Host baselines ------------------------------------------------

    def save_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
        baseline: NetworkHostBaseline,
    ) -> bool:
        baseline.host_ip = host_ip
        baseline.tenant_id = tenant_id
        baseline.last_updated = datetime.now(timezone.utc)
        self._host_baselines[(tenant_id, host_ip)] = baseline
        return True

    def get_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
    ) -> Optional[NetworkHostBaseline]:
        return self._host_baselines.get((tenant_id, host_ip))

    def list_host_baselines(
        self,
        tenant_id: str,
    ) -> List[NetworkHostBaseline]:
        return [
            b for (tid, _), b in self._host_baselines.items()
            if tid == tenant_id
        ]

    # -- Network-wide baseline ----------------------------------------

    def save_network_baseline(
        self,
        tenant_id: str,
        baseline: NetworkBaseline,
    ) -> bool:
        baseline.tenant_id = tenant_id
        baseline.last_updated = datetime.now(timezone.utc)
        self._network_baselines[tenant_id] = baseline
        return True

    def get_network_baseline(
        self,
        tenant_id: str,
    ) -> Optional[NetworkBaseline]:
        return self._network_baselines.get(tenant_id)

    # -- Helpers (test-only) -------------------------------------------

    def clear(self) -> None:
        """Remove all stored baselines (useful in tests)."""
        self._host_baselines.clear()
        self._network_baselines.clear()


# ======================================================================
# DynamoDB Implementation (AWS)
# ======================================================================


class DynamoDBNetworkBaselineStore(NetworkBaselineStore):
    """DynamoDB-backed network baseline store for AWS deployments.

    Table schema
    ------------
    Partition key: ``tenant_id``  (String)
    Sort key:      ``sk``         (String)
    TTL attribute: ``ttl``        (Number, epoch seconds)

    Host baselines use ``sk = "HOST#<host_ip>"``.
    Network baselines use ``sk = "NETWORK"``.

    Follows the lazy-init pattern from ``DynamoDBBaselineStore``.
    """

    def __init__(
        self,
        table_name: str = "mantissa-network-baselines",
        region: str = "us-east-1",
        ttl_attribute: str = "ttl",
    ) -> None:
        self.table_name = table_name
        self.region = region
        self.ttl_attribute = ttl_attribute
        self._table = None

    def _get_table(self):
        """Lazy initialization of the DynamoDB Table resource."""
        if self._table is None:
            import boto3

            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    @staticmethod
    def _host_sk(host_ip: str) -> str:
        """Build the sort key for a host baseline."""
        return f"HOST#{host_ip}"

    @staticmethod
    def _network_sk() -> str:
        """Build the sort key for the network baseline."""
        return "NETWORK"

    def _serialize_host(
        self,
        baseline: NetworkHostBaseline,
        ttl_epoch: int,
    ) -> Dict[str, Any]:
        """Convert a NetworkHostBaseline to a DynamoDB item."""
        from decimal import Decimal

        data = baseline.to_dict()
        data["tenant_id"] = baseline.tenant_id
        data["sk"] = self._host_sk(baseline.host_ip)
        data["entity_type"] = "NETWORK_HOST_BASELINE"
        data["ttl"] = ttl_epoch
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        # DynamoDB cannot store sets directly in all SDKs; use JSON
        # strings for the complex nested structures.
        data["normal_external_destinations"] = json.dumps(
            data["normal_external_destinations"]
        )
        data["normal_internal_partners"] = json.dumps(
            data["normal_internal_partners"]
        )
        data["normal_destination_ports"] = json.dumps(
            data["normal_destination_ports"]
        )
        data["top_queried_domains"] = json.dumps(
            data["top_queried_domains"]
        )
        data["day_of_week_profile"] = json.dumps(
            data["day_of_week_profile"]
        )
        data["hour_of_day_profile"] = json.dumps(
            data["hour_of_day_profile"]
        )

        # Convert floats to Decimal for DynamoDB
        for key in (
            "hourly_outbound_bytes_mean",
            "hourly_outbound_bytes_stddev",
            "hourly_inbound_bytes_mean",
            "hourly_inbound_bytes_stddev",
            "hourly_connection_count_mean",
            "hourly_connection_count_stddev",
            "hourly_dns_query_count_mean",
            "hourly_dns_query_count_stddev",
            "confidence_score",
        ):
            if key in data:
                data[key] = Decimal(str(data[key]))

        return data

    @staticmethod
    def _deserialize_host(item: Dict[str, Any]) -> NetworkHostBaseline:
        """Convert a DynamoDB item to a NetworkHostBaseline."""
        # Deserialize JSON strings back
        for key in (
            "normal_external_destinations",
            "normal_internal_partners",
            "normal_destination_ports",
            "top_queried_domains",
            "day_of_week_profile",
            "hour_of_day_profile",
        ):
            val = item.get(key)
            if isinstance(val, str):
                item[key] = json.loads(val)

        # Convert Decimal back to float
        for key in (
            "hourly_outbound_bytes_mean",
            "hourly_outbound_bytes_stddev",
            "hourly_inbound_bytes_mean",
            "hourly_inbound_bytes_stddev",
            "hourly_connection_count_mean",
            "hourly_connection_count_stddev",
            "hourly_dns_query_count_mean",
            "hourly_dns_query_count_stddev",
            "confidence_score",
        ):
            val = item.get(key)
            if val is not None:
                item[key] = float(val)

        return NetworkHostBaseline.from_dict(item)

    def _serialize_network(
        self,
        baseline: NetworkBaseline,
        ttl_epoch: int,
    ) -> Dict[str, Any]:
        """Convert a NetworkBaseline to a DynamoDB item."""
        from decimal import Decimal

        data = baseline.to_dict()
        data["tenant_id"] = baseline.tenant_id
        data["sk"] = self._network_sk()
        data["entity_type"] = "NETWORK_BASELINE"
        data["ttl"] = ttl_epoch
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Serialize complex structures as JSON strings
        data["top_external_destinations"] = json.dumps(
            data["top_external_destinations"]
        )
        data["top_internal_pairs"] = json.dumps(
            data["top_internal_pairs"]
        )
        data["port_distribution"] = json.dumps(
            data["port_distribution"]
        )

        # Convert floats to Decimal
        for key in (
            "hourly_total_bytes_mean",
            "hourly_total_bytes_stddev",
            "hourly_total_connections_mean",
            "hourly_total_connections_stddev",
            "hourly_dns_query_volume_mean",
            "hourly_dns_query_volume_stddev",
            "hourly_nxdomain_rate_mean",
            "hourly_nxdomain_rate_stddev",
        ):
            if key in data:
                data[key] = Decimal(str(data[key]))

        return data

    @staticmethod
    def _deserialize_network(item: Dict[str, Any]) -> NetworkBaseline:
        """Convert a DynamoDB item to a NetworkBaseline."""
        for key in (
            "top_external_destinations",
            "top_internal_pairs",
            "port_distribution",
        ):
            val = item.get(key)
            if isinstance(val, str):
                item[key] = json.loads(val)

        for key in (
            "hourly_total_bytes_mean",
            "hourly_total_bytes_stddev",
            "hourly_total_connections_mean",
            "hourly_total_connections_stddev",
            "hourly_dns_query_volume_mean",
            "hourly_dns_query_volume_stddev",
            "hourly_nxdomain_rate_mean",
            "hourly_nxdomain_rate_stddev",
        ):
            val = item.get(key)
            if val is not None:
                item[key] = float(val)

        return NetworkBaseline.from_dict(item)

    # -- Host baselines ------------------------------------------------

    def save_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
        baseline: NetworkHostBaseline,
    ) -> bool:
        try:
            baseline.host_ip = host_ip
            baseline.tenant_id = tenant_id
            baseline.last_updated = datetime.now(timezone.utc)
            ttl_epoch = int(time.time()) + _DEFAULT_TTL_SECONDS
            item = self._serialize_host(baseline, ttl_epoch)
            self._get_table().put_item(Item=item)
            return True
        except Exception as e:
            logger.error(
                "Error saving host baseline for %s: %s", host_ip, e
            )
            return False

    def get_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
    ) -> Optional[NetworkHostBaseline]:
        try:
            response = self._get_table().get_item(
                Key={
                    "tenant_id": tenant_id,
                    "sk": self._host_sk(host_ip),
                }
            )
            if "Item" not in response:
                return None
            return self._deserialize_host(response["Item"])
        except Exception as e:
            logger.error(
                "Error getting host baseline for %s: %s", host_ip, e
            )
            return None

    def list_host_baselines(
        self,
        tenant_id: str,
    ) -> List[NetworkHostBaseline]:
        try:
            response = self._get_table().query(
                KeyConditionExpression=(
                    "tenant_id = :tid AND begins_with(sk, :prefix)"
                ),
                ExpressionAttributeValues={
                    ":tid": tenant_id,
                    ":prefix": "HOST#",
                },
            )
            results = [
                self._deserialize_host(item)
                for item in response.get("Items", [])
            ]

            # Handle pagination
            while "LastEvaluatedKey" in response:
                response = self._get_table().query(
                    KeyConditionExpression=(
                        "tenant_id = :tid AND begins_with(sk, :prefix)"
                    ),
                    ExpressionAttributeValues={
                        ":tid": tenant_id,
                        ":prefix": "HOST#",
                    },
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                results.extend(
                    self._deserialize_host(item)
                    for item in response.get("Items", [])
                )

            return results
        except Exception as e:
            logger.error(
                "Error listing host baselines for %s: %s", tenant_id, e
            )
            return []

    # -- Network-wide baseline ----------------------------------------

    def save_network_baseline(
        self,
        tenant_id: str,
        baseline: NetworkBaseline,
    ) -> bool:
        try:
            baseline.tenant_id = tenant_id
            baseline.last_updated = datetime.now(timezone.utc)
            ttl_epoch = int(time.time()) + _DEFAULT_TTL_SECONDS
            item = self._serialize_network(baseline, ttl_epoch)
            self._get_table().put_item(Item=item)
            return True
        except Exception as e:
            logger.error(
                "Error saving network baseline for %s: %s", tenant_id, e
            )
            return False

    def get_network_baseline(
        self,
        tenant_id: str,
    ) -> Optional[NetworkBaseline]:
        try:
            response = self._get_table().get_item(
                Key={
                    "tenant_id": tenant_id,
                    "sk": self._network_sk(),
                }
            )
            if "Item" not in response:
                return None
            return self._deserialize_network(response["Item"])
        except Exception as e:
            logger.error(
                "Error getting network baseline for %s: %s", tenant_id, e
            )
            return None


# ======================================================================
# Firestore Implementation (GCP)
# ======================================================================


class FirestoreNetworkBaselineStore(NetworkBaselineStore):
    """Firestore-backed network baseline store for GCP deployments.

    Collection structure
    --------------------
    Host baselines:    ``network_baselines/{tenant_id}##HOST##{host_ip}``
    Network baselines: ``network_baselines/{tenant_id}##NETWORK``

    Uses the same composite document ID pattern as
    ``FirestoreHealthStateStore``.
    """

    def __init__(
        self,
        collection_name: str = "network_baselines",
        project_id: Optional[str] = None,
    ) -> None:
        self.collection_name = collection_name
        self.project_id = project_id
        self._db = None

    def _get_db(self):
        """Lazy initialization of Firestore client."""
        if self._db is None:
            from google.cloud import firestore

            if self.project_id:
                self._db = firestore.Client(project=self.project_id)
            else:
                self._db = firestore.Client()
        return self._db

    def _get_collection(self):
        """Get the baselines collection."""
        return self._get_db().collection(self.collection_name)

    @staticmethod
    def _host_doc_id(tenant_id: str, host_ip: str) -> str:
        """Build document ID for a host baseline."""
        return f"{tenant_id}##HOST##{host_ip}"

    @staticmethod
    def _network_doc_id(tenant_id: str) -> str:
        """Build document ID for the network baseline."""
        return f"{tenant_id}##NETWORK"

    # -- Host baselines ------------------------------------------------

    def save_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
        baseline: NetworkHostBaseline,
    ) -> bool:
        try:
            baseline.host_ip = host_ip
            baseline.tenant_id = tenant_id
            baseline.last_updated = datetime.now(timezone.utc)

            doc_id = self._host_doc_id(tenant_id, host_ip)
            data = baseline.to_dict()
            data["entity_type"] = "NETWORK_HOST_BASELINE"
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._get_collection().document(doc_id).set(data)
            return True
        except Exception as e:
            logger.error(
                "Error saving host baseline for %s: %s", host_ip, e
            )
            return False

    def get_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
    ) -> Optional[NetworkHostBaseline]:
        try:
            doc_id = self._host_doc_id(tenant_id, host_ip)
            doc = self._get_collection().document(doc_id).get()
            if not doc.exists:
                return None
            return NetworkHostBaseline.from_dict(doc.to_dict())
        except Exception as e:
            logger.error(
                "Error getting host baseline for %s: %s", host_ip, e
            )
            return None

    def list_host_baselines(
        self,
        tenant_id: str,
    ) -> List[NetworkHostBaseline]:
        try:
            query = self._get_collection().where(
                "tenant_id", "==", tenant_id
            ).where(
                "entity_type", "==", "NETWORK_HOST_BASELINE"
            )
            return [
                NetworkHostBaseline.from_dict(doc.to_dict())
                for doc in query.stream()
            ]
        except Exception as e:
            logger.error(
                "Error listing host baselines for %s: %s", tenant_id, e
            )
            return []

    # -- Network-wide baseline ----------------------------------------

    def save_network_baseline(
        self,
        tenant_id: str,
        baseline: NetworkBaseline,
    ) -> bool:
        try:
            baseline.tenant_id = tenant_id
            baseline.last_updated = datetime.now(timezone.utc)

            doc_id = self._network_doc_id(tenant_id)
            data = baseline.to_dict()
            data["entity_type"] = "NETWORK_BASELINE"
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._get_collection().document(doc_id).set(data)
            return True
        except Exception as e:
            logger.error(
                "Error saving network baseline for %s: %s", tenant_id, e
            )
            return False

    def get_network_baseline(
        self,
        tenant_id: str,
    ) -> Optional[NetworkBaseline]:
        try:
            doc_id = self._network_doc_id(tenant_id)
            doc = self._get_collection().document(doc_id).get()
            if not doc.exists:
                return None
            return NetworkBaseline.from_dict(doc.to_dict())
        except Exception as e:
            logger.error(
                "Error getting network baseline for %s: %s", tenant_id, e
            )
            return None


# ======================================================================
# Cosmos DB Implementation (Azure)
# ======================================================================


class CosmosNetworkBaselineStore(NetworkBaselineStore):
    """Cosmos DB-backed network baseline store for Azure deployments.

    Container schema
    ----------------
    Container name: ``network_baselines``
    Partition key:  ``/tenant_id``
    id:             ``HOST#<host_ip>`` for host baselines,
                    ``NETWORK`` for network baselines.
    TTL:            Enabled on the container (``ttl`` field, seconds).

    Follows the lazy-init pattern from ``CosmosBaselineStore``.
    """

    def __init__(
        self,
        endpoint: str,
        key: str,
        database_name: str = "mantissa",
        container_name: str = "network_baselines",
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self.endpoint = endpoint
        self.key = key
        self.database_name = database_name
        self.container_name = container_name
        self.ttl_seconds = ttl_seconds
        self._container = None

    def _get_container(self):
        """Lazy initialization of the Cosmos DB container client."""
        if self._container is None:
            from azure.cosmos import CosmosClient

            client = CosmosClient(self.endpoint, credential=self.key)
            database = client.get_database_client(self.database_name)
            self._container = database.get_container_client(
                self.container_name
            )
        return self._container

    @staticmethod
    def _host_id(host_ip: str) -> str:
        """Build item ID for a host baseline."""
        return f"HOST#{host_ip}"

    @staticmethod
    def _network_id() -> str:
        """Build item ID for the network baseline."""
        return "NETWORK"

    # -- Host baselines ------------------------------------------------

    def save_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
        baseline: NetworkHostBaseline,
    ) -> bool:
        try:
            baseline.host_ip = host_ip
            baseline.tenant_id = tenant_id
            baseline.last_updated = datetime.now(timezone.utc)

            doc = baseline.to_dict()
            doc["id"] = self._host_id(host_ip)
            doc["entity_type"] = "NETWORK_HOST_BASELINE"
            doc["ttl"] = self.ttl_seconds
            doc["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._get_container().upsert_item(body=doc)
            return True
        except Exception as e:
            logger.error(
                "Error saving host baseline for %s: %s", host_ip, e
            )
            return False

    def get_host_baseline(
        self,
        host_ip: str,
        tenant_id: str,
    ) -> Optional[NetworkHostBaseline]:
        try:
            doc = self._get_container().read_item(
                item=self._host_id(host_ip),
                partition_key=tenant_id,
            )
            return NetworkHostBaseline.from_dict(doc)
        except Exception:
            return None

    def list_host_baselines(
        self,
        tenant_id: str,
    ) -> List[NetworkHostBaseline]:
        try:
            query = (
                "SELECT * FROM c "
                "WHERE c.tenant_id = @tid "
                "AND c.entity_type = 'NETWORK_HOST_BASELINE'"
            )
            parameters = [{"name": "@tid", "value": tenant_id}]
            items = list(
                self._get_container().query_items(
                    query=query,
                    parameters=parameters,
                    partition_key=tenant_id,
                )
            )
            return [NetworkHostBaseline.from_dict(item) for item in items]
        except Exception as e:
            logger.error(
                "Error listing host baselines for %s: %s", tenant_id, e
            )
            return []

    # -- Network-wide baseline ----------------------------------------

    def save_network_baseline(
        self,
        tenant_id: str,
        baseline: NetworkBaseline,
    ) -> bool:
        try:
            baseline.tenant_id = tenant_id
            baseline.last_updated = datetime.now(timezone.utc)

            doc = baseline.to_dict()
            doc["id"] = self._network_id()
            doc["entity_type"] = "NETWORK_BASELINE"
            doc["ttl"] = self.ttl_seconds
            doc["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._get_container().upsert_item(body=doc)
            return True
        except Exception as e:
            logger.error(
                "Error saving network baseline for %s: %s", tenant_id, e
            )
            return False

    def get_network_baseline(
        self,
        tenant_id: str,
    ) -> Optional[NetworkBaseline]:
        try:
            doc = self._get_container().read_item(
                item=self._network_id(),
                partition_key=tenant_id,
            )
            return NetworkBaseline.from_dict(doc)
        except Exception:
            return None
