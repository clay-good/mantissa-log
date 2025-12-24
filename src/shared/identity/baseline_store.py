"""Baseline storage for identity baselines.

Provides abstract interface and cloud implementations for storing
user behavioral baselines.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


class BaselineStore(ABC):
    """Abstract base class for baseline storage.

    Implementations should handle persistence to DynamoDB, Firestore, Cosmos DB, etc.
    """

    @abstractmethod
    def save_baseline(self, user_email: str, baseline: IdentityBaseline) -> bool:
        """Save a baseline for a user.

        Args:
            user_email: User's email address
            baseline: IdentityBaseline to save

        Returns:
            True if save successful
        """
        pass

    @abstractmethod
    def get_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get baseline for a user.

        Args:
            user_email: User's email address

        Returns:
            IdentityBaseline if found, None otherwise
        """
        pass

    @abstractmethod
    def get_baselines_for_peer_group(
        self, peer_group_id: str
    ) -> List[IdentityBaseline]:
        """Get all baselines for a peer group.

        Args:
            peer_group_id: Peer group identifier (department/team)

        Returns:
            List of baselines in the peer group
        """
        pass

    @abstractmethod
    def delete_baseline(self, user_email: str) -> bool:
        """Delete a user's baseline.

        Args:
            user_email: User's email address

        Returns:
            True if deletion successful
        """
        pass

    @abstractmethod
    def list_stale_baselines(self, days_since_update: int = 30) -> List[str]:
        """List baselines that haven't been updated recently.

        Args:
            days_since_update: Number of days since last update

        Returns:
            List of user emails with stale baselines
        """
        pass


class InMemoryBaselineStore(BaselineStore):
    """In-memory implementation of baseline storage for development/testing."""

    def __init__(self):
        self._baselines: Dict[str, IdentityBaseline] = {}

    def save_baseline(self, user_email: str, baseline: IdentityBaseline) -> bool:
        """Save a baseline for a user."""
        email = user_email.lower()
        baseline.email = email
        baseline.last_updated = datetime.now(timezone.utc)
        self._baselines[email] = baseline
        logger.debug(f"Saved baseline for {email}")
        return True

    def get_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get baseline for a user."""
        return self._baselines.get(user_email.lower())

    def get_baselines_for_peer_group(
        self, peer_group_id: str
    ) -> List[IdentityBaseline]:
        """Get all baselines for a peer group."""
        return [
            b for b in self._baselines.values()
            if b.peer_group_id == peer_group_id
        ]

    def delete_baseline(self, user_email: str) -> bool:
        """Delete a user's baseline."""
        email = user_email.lower()
        if email in self._baselines:
            del self._baselines[email]
            logger.debug(f"Deleted baseline for {email}")
            return True
        return False

    def list_stale_baselines(self, days_since_update: int = 30) -> List[str]:
        """List baselines that haven't been updated recently."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_since_update)
        stale = []

        for email, baseline in self._baselines.items():
            if baseline.last_updated:
                last = baseline.last_updated
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last < cutoff:
                    stale.append(email)
            else:
                stale.append(email)

        return stale

    def list_all_baselines(self, limit: int = 1000) -> List[IdentityBaseline]:
        """List all baselines (for testing/debugging)."""
        return list(self._baselines.values())[:limit]


class DynamoDBBaselineStore(BaselineStore):
    """DynamoDB implementation of baseline storage for AWS deployments."""

    def __init__(
        self,
        table_name: str = "mantissa-identity-baselines",
        region: str = "us-east-1",
    ):
        self.table_name = table_name
        self.region = region
        self._table = None

    def _get_table(self):
        """Lazy initialization of DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def _baseline_to_item(self, baseline: IdentityBaseline) -> Dict[str, Any]:
        """Convert IdentityBaseline to DynamoDB item."""
        data = baseline.to_dict()

        # Add DynamoDB-specific fields
        data["pk"] = baseline.email.lower()
        data["sk"] = "BASELINE"
        data["entity_type"] = "IDENTITY_BASELINE"

        # Add peer group GSI key
        if baseline.peer_group_id:
            data["gsi_peer_group"] = baseline.peer_group_id

        return data

    def _item_to_baseline(self, item: Dict[str, Any]) -> IdentityBaseline:
        """Convert DynamoDB item to IdentityBaseline."""
        return IdentityBaseline.from_dict(item)

    def save_baseline(self, user_email: str, baseline: IdentityBaseline) -> bool:
        """Save a baseline for a user."""
        try:
            baseline.email = user_email.lower()
            baseline.last_updated = datetime.now(timezone.utc)
            item = self._baseline_to_item(baseline)
            self._get_table().put_item(Item=item)
            logger.debug(f"Saved baseline for {user_email}")
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
            return False

    def get_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get baseline for a user."""
        try:
            response = self._get_table().get_item(
                Key={"pk": user_email.lower(), "sk": "BASELINE"}
            )

            if "Item" not in response:
                return None

            return self._item_to_baseline(response["Item"])
        except Exception as e:
            logger.error(f"Error getting baseline: {e}")
            return None

    def get_baselines_for_peer_group(
        self, peer_group_id: str
    ) -> List[IdentityBaseline]:
        """Get all baselines for a peer group."""
        try:
            response = self._get_table().query(
                IndexName="peer-group-index",
                KeyConditionExpression="gsi_peer_group = :pg",
                ExpressionAttributeValues={":pg": peer_group_id},
            )

            return [
                self._item_to_baseline(item)
                for item in response.get("Items", [])
            ]
        except Exception as e:
            logger.error(f"Error getting peer group baselines: {e}")
            return []

    def delete_baseline(self, user_email: str) -> bool:
        """Delete a user's baseline."""
        try:
            self._get_table().delete_item(
                Key={"pk": user_email.lower(), "sk": "BASELINE"}
            )
            logger.debug(f"Deleted baseline for {user_email}")
            return True
        except Exception as e:
            logger.error(f"Error deleting baseline: {e}")
            return False

    def list_stale_baselines(self, days_since_update: int = 30) -> List[str]:
        """List baselines that haven't been updated recently."""
        try:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(days=days_since_update)
            ).isoformat()

            response = self._get_table().scan(
                FilterExpression="last_updated < :cutoff",
                ExpressionAttributeValues={":cutoff": cutoff},
                ProjectionExpression="pk",
            )

            return [item["pk"] for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error listing stale baselines: {e}")
            return []


class FirestoreBaselineStore(BaselineStore):
    """Firestore implementation of baseline storage for GCP deployments."""

    def __init__(
        self,
        collection_name: str = "identity_baselines",
        project_id: Optional[str] = None,
    ):
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

    def save_baseline(self, user_email: str, baseline: IdentityBaseline) -> bool:
        """Save a baseline for a user."""
        try:
            baseline.email = user_email.lower()
            baseline.last_updated = datetime.now(timezone.utc)
            doc_ref = self._get_collection().document(user_email.lower())
            doc_ref.set(baseline.to_dict())
            logger.debug(f"Saved baseline for {user_email}")
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
            return False

    def get_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get baseline for a user."""
        try:
            doc_ref = self._get_collection().document(user_email.lower())
            doc = doc_ref.get()

            if not doc.exists:
                return None

            return IdentityBaseline.from_dict(doc.to_dict())
        except Exception as e:
            logger.error(f"Error getting baseline: {e}")
            return None

    def get_baselines_for_peer_group(
        self, peer_group_id: str
    ) -> List[IdentityBaseline]:
        """Get all baselines for a peer group."""
        try:
            query = self._get_collection().where(
                "peer_group_id", "==", peer_group_id
            )

            return [
                IdentityBaseline.from_dict(doc.to_dict())
                for doc in query.stream()
            ]
        except Exception as e:
            logger.error(f"Error getting peer group baselines: {e}")
            return []

    def delete_baseline(self, user_email: str) -> bool:
        """Delete a user's baseline."""
        try:
            self._get_collection().document(user_email.lower()).delete()
            logger.debug(f"Deleted baseline for {user_email}")
            return True
        except Exception as e:
            logger.error(f"Error deleting baseline: {e}")
            return False

    def list_stale_baselines(self, days_since_update: int = 30) -> List[str]:
        """List baselines that haven't been updated recently."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days_since_update)

            query = self._get_collection().where("last_updated", "<", cutoff)

            return [doc.id for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error listing stale baselines: {e}")
            return []


class CosmosBaselineStore(BaselineStore):
    """Azure Cosmos DB implementation of baseline storage."""

    def __init__(
        self,
        endpoint: str,
        key: str,
        database_name: str = "mantissa",
        container_name: str = "identity_baselines",
    ):
        self.endpoint = endpoint
        self.key = key
        self.database_name = database_name
        self.container_name = container_name
        self._container = None

    def _get_container(self):
        """Lazy initialization of Cosmos DB container."""
        if self._container is None:
            from azure.cosmos import CosmosClient

            client = CosmosClient(self.endpoint, credential=self.key)
            database = client.get_database_client(self.database_name)
            self._container = database.get_container_client(self.container_name)
        return self._container

    def save_baseline(self, user_email: str, baseline: IdentityBaseline) -> bool:
        """Save a baseline for a user."""
        try:
            baseline.email = user_email.lower()
            baseline.last_updated = datetime.now(timezone.utc)

            doc = baseline.to_dict()
            doc["id"] = user_email.lower()

            self._get_container().upsert_item(body=doc)
            logger.debug(f"Saved baseline for {user_email}")
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
            return False

    def get_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get baseline for a user."""
        try:
            doc = self._get_container().read_item(
                item=user_email.lower(),
                partition_key=user_email.lower(),
            )
            return IdentityBaseline.from_dict(doc)
        except Exception:
            # Item not found
            return None

    def get_baselines_for_peer_group(
        self, peer_group_id: str
    ) -> List[IdentityBaseline]:
        """Get all baselines for a peer group."""
        try:
            query = "SELECT * FROM c WHERE c.peer_group_id = @pg"
            parameters = [{"name": "@pg", "value": peer_group_id}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
            ))

            return [IdentityBaseline.from_dict(item) for item in items]
        except Exception as e:
            logger.error(f"Error getting peer group baselines: {e}")
            return []

    def delete_baseline(self, user_email: str) -> bool:
        """Delete a user's baseline."""
        try:
            self._get_container().delete_item(
                item=user_email.lower(),
                partition_key=user_email.lower(),
            )
            logger.debug(f"Deleted baseline for {user_email}")
            return True
        except Exception as e:
            logger.error(f"Error deleting baseline: {e}")
            return False

    def list_stale_baselines(self, days_since_update: int = 30) -> List[str]:
        """List baselines that haven't been updated recently."""
        try:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(days=days_since_update)
            ).isoformat()

            query = "SELECT c.email FROM c WHERE c.last_updated < @cutoff"
            parameters = [{"name": "@cutoff", "value": cutoff}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
            ))

            return [item["email"] for item in items]
        except Exception as e:
            logger.error(f"Error listing stale baselines: {e}")
            return []
