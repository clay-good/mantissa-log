"""Persistent storage backends for log source health state.

Provides an abstract interface and cloud-specific implementations
(DynamoDB, Firestore, Cosmos DB) plus an in-memory implementation
for development and testing.

Follows the same multi-cloud pattern used by
``src/shared/identity/baseline_store.py`` and
``src/shared/detection/state_manager.py``.
"""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .log_source_health import LogSourceHealthState, LogSourceStatus

logger = logging.getLogger(__name__)

# Default TTL for state entries: 90 days.  Entries that have not been
# updated within this window are automatically cleaned up by the backend.
_DEFAULT_TTL_SECONDS = 90 * 24 * 60 * 60


class HealthStateStore(ABC):
    """Abstract base class for health state persistence.

    Every cloud-specific implementation must provide the six methods below.
    The partition key is ``tenant_id`` and the sort key is ``source_type``,
    giving O(1) access to any single source's state and efficient scans
    across all sources for a tenant.
    """

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    @abstractmethod
    def save_state(
        self,
        source_type: str,
        tenant_id: str,
        state: LogSourceHealthState,
    ) -> bool:
        """Persist (upsert) the full health state for a source.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.
            state: Complete health state to save.

        Returns:
            True if the write succeeded.
        """
        pass

    @abstractmethod
    def get_state(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[LogSourceHealthState]:
        """Retrieve the health state for a single source.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.

        Returns:
            LogSourceHealthState or None if no state exists yet.
        """
        pass

    @abstractmethod
    def get_all_states(
        self,
        tenant_id: str,
    ) -> List[LogSourceHealthState]:
        """Retrieve health states for every source belonging to a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            List of LogSourceHealthState (may be empty).
        """
        pass

    # ------------------------------------------------------------------
    # Lightweight incremental updates (called from collectors)
    # ------------------------------------------------------------------

    @abstractmethod
    def update_event_count(
        self,
        source_type: str,
        tenant_id: str,
        count_increment: int,
        latest_timestamp: datetime,
    ) -> bool:
        """Atomically increment the event count and update the latest timestamp.

        Called by collectors after each successful batch write so the
        health-check engine has near-real-time counts without needing to
        query the data lake.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.
            count_increment: Number of events in this batch.
            latest_timestamp: Timestamp of the newest event in the batch.

        Returns:
            True if the update succeeded.
        """
        pass

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    @abstractmethod
    def save_baseline(
        self,
        source_type: str,
        tenant_id: str,
        hourly_volume: float,
        hourly_stddev: float,
    ) -> bool:
        """Store the computed baseline statistics for a source.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.
            hourly_volume: Mean events per hour over the learning period.
            hourly_stddev: Standard deviation of hourly event counts.

        Returns:
            True if the write succeeded.
        """
        pass

    @abstractmethod
    def get_baseline(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[Tuple[float, float]]:
        """Retrieve the baseline statistics for a source.

        Args:
            source_type: Log source identifier.
            tenant_id: Tenant identifier.

        Returns:
            Tuple of (hourly_volume, hourly_stddev) or None if no
            baseline has been computed yet.
        """
        pass


# ======================================================================
# In-Memory Implementation (development / testing)
# ======================================================================


class InMemoryHealthStateStore(HealthStateStore):
    """In-memory health state store for development and unit tests."""

    def __init__(self) -> None:
        # Keyed by (tenant_id, source_type)
        self._states: Dict[Tuple[str, str], LogSourceHealthState] = {}
        self._baselines: Dict[Tuple[str, str], Tuple[float, float]] = {}

    # -- Core CRUD -----------------------------------------------------

    def save_state(
        self,
        source_type: str,
        tenant_id: str,
        state: LogSourceHealthState,
    ) -> bool:
        state.source_type = source_type
        state.tenant_id = tenant_id
        self._states[(tenant_id, source_type)] = state
        return True

    def get_state(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[LogSourceHealthState]:
        return self._states.get((tenant_id, source_type))

    def get_all_states(
        self,
        tenant_id: str,
    ) -> List[LogSourceHealthState]:
        return [
            s for (tid, _), s in self._states.items()
            if tid == tenant_id
        ]

    # -- Incremental updates -------------------------------------------

    def update_event_count(
        self,
        source_type: str,
        tenant_id: str,
        count_increment: int,
        latest_timestamp: datetime,
    ) -> bool:
        key = (tenant_id, source_type)
        state = self._states.get(key)
        if state is None:
            state = LogSourceHealthState(
                source_type=source_type,
                tenant_id=tenant_id,
            )
            self._states[key] = state

        state.event_count_current_window += count_increment

        if (
            state.last_event_timestamp is None
            or latest_timestamp > state.last_event_timestamp
        ):
            state.last_event_timestamp = latest_timestamp

        return True

    # -- Baselines -----------------------------------------------------

    def save_baseline(
        self,
        source_type: str,
        tenant_id: str,
        hourly_volume: float,
        hourly_stddev: float,
    ) -> bool:
        self._baselines[(tenant_id, source_type)] = (
            hourly_volume,
            hourly_stddev,
        )
        # Also update the state object if it exists
        state = self._states.get((tenant_id, source_type))
        if state is not None:
            state.baseline_hourly_volume = hourly_volume
            state.baseline_hourly_stddev = hourly_stddev
        return True

    def get_baseline(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[Tuple[float, float]]:
        return self._baselines.get((tenant_id, source_type))

    # -- Helpers (test-only) -------------------------------------------

    def clear(self) -> None:
        """Remove all stored state (useful in tests)."""
        self._states.clear()
        self._baselines.clear()


# ======================================================================
# DynamoDB Implementation (AWS)
# ======================================================================


class DynamoDBHealthStateStore(HealthStateStore):
    """DynamoDB-backed health state store for AWS deployments.

    Table schema
    ------------
    Partition key: ``tenant_id``  (String)
    Sort key:      ``source_type`` (String)
    TTL attribute: ``ttl`` (Number, epoch seconds)

    Follows the lazy-init pattern from ``DynamoDBStateManager`` and
    ``DynamoDBBaselineStore``.
    """

    def __init__(
        self,
        table_name: str = "mantissa-log-source-health",
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
    def _state_to_item(state: LogSourceHealthState, ttl_epoch: int) -> Dict[str, Any]:
        """Convert a LogSourceHealthState to a DynamoDB item dict."""
        item = state.to_dict()
        # DynamoDB keys
        item["tenant_id"] = state.tenant_id
        item["source_type"] = state.source_type
        item["ttl"] = ttl_epoch
        item["updated_at"] = datetime.now(timezone.utc).isoformat()
        # Serialize gap_windows as JSON string for DynamoDB compatibility
        # (DynamoDB does not support nested lists of lists natively in all SDKs)
        item["gap_windows"] = json.dumps(item["gap_windows"])
        return item

    @staticmethod
    def _item_to_state(item: Dict[str, Any]) -> LogSourceHealthState:
        """Convert a DynamoDB item dict back to a LogSourceHealthState."""
        # Deserialize gap_windows from JSON string
        gw = item.get("gap_windows", "[]")
        if isinstance(gw, str):
            item["gap_windows"] = json.loads(gw)
        return LogSourceHealthState.from_dict(item)

    # -- Core CRUD -----------------------------------------------------

    def save_state(
        self,
        source_type: str,
        tenant_id: str,
        state: LogSourceHealthState,
    ) -> bool:
        try:
            state.source_type = source_type
            state.tenant_id = tenant_id
            ttl_epoch = int(time.time()) + _DEFAULT_TTL_SECONDS
            item = self._state_to_item(state, ttl_epoch)
            self._get_table().put_item(Item=item)
            return True
        except Exception as e:
            logger.error("Error saving health state for %s: %s", source_type, e)
            return False

    def get_state(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[LogSourceHealthState]:
        try:
            response = self._get_table().get_item(
                Key={"tenant_id": tenant_id, "source_type": source_type}
            )
            if "Item" not in response:
                return None
            return self._item_to_state(response["Item"])
        except Exception as e:
            logger.error("Error getting health state for %s: %s", source_type, e)
            return None

    def get_all_states(
        self,
        tenant_id: str,
    ) -> List[LogSourceHealthState]:
        try:
            response = self._get_table().query(
                KeyConditionExpression="tenant_id = :tid",
                ExpressionAttributeValues={":tid": tenant_id},
            )
            return [
                self._item_to_state(item) for item in response.get("Items", [])
            ]
        except Exception as e:
            logger.error("Error listing health states: %s", e)
            return []

    # -- Incremental updates -------------------------------------------

    def update_event_count(
        self,
        source_type: str,
        tenant_id: str,
        count_increment: int,
        latest_timestamp: datetime,
    ) -> bool:
        try:
            ts_iso = latest_timestamp.isoformat()
            ttl_epoch = int(time.time()) + _DEFAULT_TTL_SECONDS
            self._get_table().update_item(
                Key={"tenant_id": tenant_id, "source_type": source_type},
                UpdateExpression=(
                    "ADD event_count_current_window :inc "
                    "SET last_event_timestamp = if_not_exists(last_event_timestamp, :ts), "
                    "    #ttl_attr = :ttl, "
                    "    updated_at = :now"
                ),
                ConditionExpression=(
                    "attribute_not_exists(last_event_timestamp) OR "
                    "last_event_timestamp < :ts"
                ),
                ExpressionAttributeNames={
                    "#ttl_attr": self.ttl_attribute,
                },
                ExpressionAttributeValues={
                    ":inc": count_increment,
                    ":ts": ts_iso,
                    ":ttl": ttl_epoch,
                    ":now": datetime.now(timezone.utc).isoformat(),
                },
            )
            return True
        except Exception as e:
            # If the condition fails (timestamp not newer), that is expected;
            # we still want to increment the count.
            try:
                self._get_table().update_item(
                    Key={"tenant_id": tenant_id, "source_type": source_type},
                    UpdateExpression=(
                        "ADD event_count_current_window :inc "
                        "SET #ttl_attr = :ttl, "
                        "    updated_at = :now"
                    ),
                    ExpressionAttributeNames={
                        "#ttl_attr": self.ttl_attribute,
                    },
                    ExpressionAttributeValues={
                        ":inc": count_increment,
                        ":ttl": int(time.time()) + _DEFAULT_TTL_SECONDS,
                        ":now": datetime.now(timezone.utc).isoformat(),
                    },
                )
                return True
            except Exception as e2:
                logger.error(
                    "Error updating event count for %s: %s", source_type, e2
                )
                return False

    # -- Baselines -----------------------------------------------------

    def save_baseline(
        self,
        source_type: str,
        tenant_id: str,
        hourly_volume: float,
        hourly_stddev: float,
    ) -> bool:
        try:
            from decimal import Decimal

            ttl_epoch = int(time.time()) + _DEFAULT_TTL_SECONDS
            self._get_table().update_item(
                Key={"tenant_id": tenant_id, "source_type": source_type},
                UpdateExpression=(
                    "SET baseline_hourly_volume = :vol, "
                    "    baseline_hourly_stddev = :std, "
                    "    baseline_updated_at = :now, "
                    "    #ttl_attr = :ttl"
                ),
                ExpressionAttributeNames={
                    "#ttl_attr": self.ttl_attribute,
                },
                ExpressionAttributeValues={
                    ":vol": Decimal(str(hourly_volume)),
                    ":std": Decimal(str(hourly_stddev)),
                    ":now": datetime.now(timezone.utc).isoformat(),
                    ":ttl": ttl_epoch,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "Error saving baseline for %s: %s", source_type, e
            )
            return False

    def get_baseline(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[Tuple[float, float]]:
        try:
            response = self._get_table().get_item(
                Key={"tenant_id": tenant_id, "source_type": source_type},
                ProjectionExpression="baseline_hourly_volume, baseline_hourly_stddev",
            )
            item = response.get("Item")
            if item is None:
                return None

            vol = item.get("baseline_hourly_volume")
            std = item.get("baseline_hourly_stddev")
            if vol is None or std is None:
                return None

            return (float(vol), float(std))
        except Exception as e:
            logger.error(
                "Error getting baseline for %s: %s", source_type, e
            )
            return None


# ======================================================================
# Firestore Implementation (GCP)
# ======================================================================


class FirestoreHealthStateStore(HealthStateStore):
    """Firestore-backed health state store for GCP deployments.

    Collection structure
    --------------------
    ``log_source_health/{tenant_id}##{source_type}``

    Each document stores the full ``LogSourceHealthState.to_dict()``
    output plus a ``document_id`` composite key.

    Follows the lazy-init pattern from ``FirestoreBaselineStore``.
    """

    def __init__(
        self,
        collection_name: str = "log_source_health",
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
        """Get the health state collection."""
        return self._get_db().collection(self.collection_name)

    @staticmethod
    def _doc_id(tenant_id: str, source_type: str) -> str:
        """Build a deterministic document ID from the composite key."""
        return f"{tenant_id}##{source_type}"

    # -- Core CRUD -----------------------------------------------------

    def save_state(
        self,
        source_type: str,
        tenant_id: str,
        state: LogSourceHealthState,
    ) -> bool:
        try:
            state.source_type = source_type
            state.tenant_id = tenant_id
            doc_id = self._doc_id(tenant_id, source_type)
            data = state.to_dict()
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._get_collection().document(doc_id).set(data)
            return True
        except Exception as e:
            logger.error("Error saving health state for %s: %s", source_type, e)
            return False

    def get_state(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[LogSourceHealthState]:
        try:
            doc_id = self._doc_id(tenant_id, source_type)
            doc = self._get_collection().document(doc_id).get()
            if not doc.exists:
                return None
            return LogSourceHealthState.from_dict(doc.to_dict())
        except Exception as e:
            logger.error("Error getting health state for %s: %s", source_type, e)
            return None

    def get_all_states(
        self,
        tenant_id: str,
    ) -> List[LogSourceHealthState]:
        try:
            query = self._get_collection().where(
                "tenant_id", "==", tenant_id
            )
            return [
                LogSourceHealthState.from_dict(doc.to_dict())
                for doc in query.stream()
            ]
        except Exception as e:
            logger.error("Error listing health states: %s", e)
            return []

    # -- Incremental updates -------------------------------------------

    def update_event_count(
        self,
        source_type: str,
        tenant_id: str,
        count_increment: int,
        latest_timestamp: datetime,
    ) -> bool:
        try:
            from google.cloud.firestore_v1 import transforms

            doc_id = self._doc_id(tenant_id, source_type)
            doc_ref = self._get_collection().document(doc_id)
            doc = doc_ref.get()

            ts_iso = latest_timestamp.isoformat()

            if doc.exists:
                updates: Dict[str, Any] = {
                    "event_count_current_window": transforms.Increment(
                        count_increment
                    ),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                existing = doc.to_dict()
                existing_ts = existing.get("last_event_timestamp")
                if existing_ts is None or ts_iso > existing_ts:
                    updates["last_event_timestamp"] = ts_iso
                doc_ref.update(updates)
            else:
                # First write for this source — create the document
                doc_ref.set({
                    "source_type": source_type,
                    "tenant_id": tenant_id,
                    "event_count_current_window": count_increment,
                    "last_event_timestamp": ts_iso,
                    "status": LogSourceStatus.UNKNOWN.value,
                    "consecutive_failures": 0,
                    "event_count_previous_window": 0,
                    "gap_windows": [],
                    "metadata": {},
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })

            return True
        except Exception as e:
            logger.error(
                "Error updating event count for %s: %s", source_type, e
            )
            return False

    # -- Baselines -----------------------------------------------------

    def save_baseline(
        self,
        source_type: str,
        tenant_id: str,
        hourly_volume: float,
        hourly_stddev: float,
    ) -> bool:
        try:
            doc_id = self._doc_id(tenant_id, source_type)
            self._get_collection().document(doc_id).set(
                {
                    "baseline_hourly_volume": hourly_volume,
                    "baseline_hourly_stddev": hourly_stddev,
                    "baseline_updated_at": datetime.now(timezone.utc).isoformat(),
                },
                merge=True,
            )
            return True
        except Exception as e:
            logger.error("Error saving baseline for %s: %s", source_type, e)
            return False

    def get_baseline(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[Tuple[float, float]]:
        try:
            doc_id = self._doc_id(tenant_id, source_type)
            doc = self._get_collection().document(doc_id).get()
            if not doc.exists:
                return None
            data = doc.to_dict()
            vol = data.get("baseline_hourly_volume")
            std = data.get("baseline_hourly_stddev")
            if vol is None or std is None:
                return None
            return (float(vol), float(std))
        except Exception as e:
            logger.error("Error getting baseline for %s: %s", source_type, e)
            return None


# ======================================================================
# Cosmos DB Implementation (Azure)
# ======================================================================


class CosmosHealthStateStore(HealthStateStore):
    """Cosmos DB-backed health state store for Azure deployments.

    Container schema
    ----------------
    Container name: ``log_source_health``
    Partition key:  ``/tenant_id``
    id:             ``{source_type}``  (unique within partition)
    TTL:            Enabled on the container (``ttl`` field, seconds).

    Follows the lazy-init pattern from ``CosmosBaselineStore``.
    """

    def __init__(
        self,
        endpoint: str,
        key: str,
        database_name: str = "mantissa",
        container_name: str = "log_source_health",
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
            self._container = database.get_container_client(self.container_name)
        return self._container

    # -- Core CRUD -----------------------------------------------------

    def save_state(
        self,
        source_type: str,
        tenant_id: str,
        state: LogSourceHealthState,
    ) -> bool:
        try:
            state.source_type = source_type
            state.tenant_id = tenant_id
            doc = state.to_dict()
            doc["id"] = source_type
            doc["ttl"] = self.ttl_seconds
            doc["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._get_container().upsert_item(body=doc)
            return True
        except Exception as e:
            logger.error("Error saving health state for %s: %s", source_type, e)
            return False

    def get_state(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[LogSourceHealthState]:
        try:
            doc = self._get_container().read_item(
                item=source_type,
                partition_key=tenant_id,
            )
            return LogSourceHealthState.from_dict(doc)
        except Exception:
            # read_item raises if item does not exist
            return None

    def get_all_states(
        self,
        tenant_id: str,
    ) -> List[LogSourceHealthState]:
        try:
            query = "SELECT * FROM c WHERE c.tenant_id = @tid"
            parameters = [{"name": "@tid", "value": tenant_id}]
            items = list(
                self._get_container().query_items(
                    query=query,
                    parameters=parameters,
                    partition_key=tenant_id,
                )
            )
            return [LogSourceHealthState.from_dict(item) for item in items]
        except Exception as e:
            logger.error("Error listing health states: %s", e)
            return []

    # -- Incremental updates -------------------------------------------

    def update_event_count(
        self,
        source_type: str,
        tenant_id: str,
        count_increment: int,
        latest_timestamp: datetime,
    ) -> bool:
        try:
            ts_iso = latest_timestamp.isoformat()
            now_iso = datetime.now(timezone.utc).isoformat()

            # Try to read-modify-write; create if missing.
            try:
                doc = self._get_container().read_item(
                    item=source_type,
                    partition_key=tenant_id,
                )
            except Exception:
                doc = None

            if doc is not None:
                doc["event_count_current_window"] = (
                    doc.get("event_count_current_window", 0) + count_increment
                )
                existing_ts = doc.get("last_event_timestamp")
                if existing_ts is None or ts_iso > existing_ts:
                    doc["last_event_timestamp"] = ts_iso
                doc["updated_at"] = now_iso
                doc["ttl"] = self.ttl_seconds
                self._get_container().replace_item(item=doc["id"], body=doc)
            else:
                doc = {
                    "id": source_type,
                    "source_type": source_type,
                    "tenant_id": tenant_id,
                    "event_count_current_window": count_increment,
                    "event_count_previous_window": 0,
                    "last_event_timestamp": ts_iso,
                    "status": LogSourceStatus.UNKNOWN.value,
                    "consecutive_failures": 0,
                    "gap_windows": [],
                    "metadata": {},
                    "ttl": self.ttl_seconds,
                    "updated_at": now_iso,
                }
                self._get_container().create_item(body=doc)

            return True
        except Exception as e:
            logger.error(
                "Error updating event count for %s: %s", source_type, e
            )
            return False

    # -- Baselines -----------------------------------------------------

    def save_baseline(
        self,
        source_type: str,
        tenant_id: str,
        hourly_volume: float,
        hourly_stddev: float,
    ) -> bool:
        try:
            now_iso = datetime.now(timezone.utc).isoformat()

            # Patch if document exists, otherwise create a minimal one.
            try:
                doc = self._get_container().read_item(
                    item=source_type,
                    partition_key=tenant_id,
                )
                doc["baseline_hourly_volume"] = hourly_volume
                doc["baseline_hourly_stddev"] = hourly_stddev
                doc["baseline_updated_at"] = now_iso
                doc["ttl"] = self.ttl_seconds
                self._get_container().replace_item(item=doc["id"], body=doc)
            except Exception:
                doc = {
                    "id": source_type,
                    "source_type": source_type,
                    "tenant_id": tenant_id,
                    "baseline_hourly_volume": hourly_volume,
                    "baseline_hourly_stddev": hourly_stddev,
                    "baseline_updated_at": now_iso,
                    "status": LogSourceStatus.UNKNOWN.value,
                    "consecutive_failures": 0,
                    "event_count_current_window": 0,
                    "event_count_previous_window": 0,
                    "gap_windows": [],
                    "metadata": {},
                    "ttl": self.ttl_seconds,
                    "updated_at": now_iso,
                }
                self._get_container().upsert_item(body=doc)

            return True
        except Exception as e:
            logger.error("Error saving baseline for %s: %s", source_type, e)
            return False

    def get_baseline(
        self,
        source_type: str,
        tenant_id: str,
    ) -> Optional[Tuple[float, float]]:
        try:
            doc = self._get_container().read_item(
                item=source_type,
                partition_key=tenant_id,
            )
            vol = doc.get("baseline_hourly_volume")
            std = doc.get("baseline_hourly_stddev")
            if vol is None or std is None:
                return None
            return (float(vol), float(std))
        except Exception:
            return None
