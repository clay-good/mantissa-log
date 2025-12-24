"""Azure Cosmos DB implementation of session store for Azure deployments."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .session_store import SessionStore, UserSession

logger = logging.getLogger(__name__)


class CosmosSessionStore(SessionStore):
    """Azure Cosmos DB implementation of session storage.

    Container structure:
    - Container: identity_sessions
    - Partition key: /user_email
    - TTL enabled for automatic cleanup
    """

    def __init__(
        self,
        endpoint: str,
        key: str,
        database_name: str = "mantissa",
        container_name: str = "identity_sessions",
        ttl_seconds: int = 86400,  # 24 hours
    ):
        self.endpoint = endpoint
        self.key = key
        self.database_name = database_name
        self.container_name = container_name
        self.ttl_seconds = ttl_seconds
        self._container = None

    def _get_container(self):
        """Lazy initialization of Cosmos DB container."""
        if self._container is None:
            from azure.cosmos import CosmosClient, PartitionKey

            client = CosmosClient(self.endpoint, credential=self.key)
            database = client.get_database_client(self.database_name)
            self._container = database.get_container_client(self.container_name)
        return self._container

    def _session_to_doc(self, session: UserSession) -> Dict[str, Any]:
        """Convert UserSession to Cosmos DB document."""
        doc = {
            "id": session.session_id,
            "session_id": session.session_id,
            "user_id": session.user_id,
            "user_email": session.user_email.lower(),
            "provider": session.provider,
            "started_at": session.started_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "source_ip": session.source_ip,
            "is_active": session.is_active,
            "risk_score": session.risk_score,
            "risk_factors": session.risk_factors,
            "ttl": self.ttl_seconds,
        }

        if session.source_geo:
            doc["source_geo"] = session.source_geo.to_dict()
        if session.device_fingerprint:
            doc["device_fingerprint"] = session.device_fingerprint
        if session.user_agent:
            doc["user_agent"] = session.user_agent
        if session.application_name:
            doc["application_name"] = session.application_name
        if session.ended_at:
            doc["ended_at"] = session.ended_at.isoformat()
        if session.end_reason:
            doc["end_reason"] = session.end_reason

        return doc

    def _doc_to_session(self, doc: Dict[str, Any]) -> UserSession:
        """Convert Cosmos DB document to UserSession."""
        from ..models.identity_event import GeoLocation

        source_geo = None
        if "source_geo" in doc and doc["source_geo"]:
            source_geo = GeoLocation.from_dict(doc["source_geo"])

        started_at = datetime.fromisoformat(doc["started_at"].replace("Z", "+00:00"))
        last_activity = datetime.fromisoformat(doc["last_activity"].replace("Z", "+00:00"))

        ended_at = None
        if "ended_at" in doc and doc["ended_at"]:
            ended_at = datetime.fromisoformat(doc["ended_at"].replace("Z", "+00:00"))

        return UserSession(
            session_id=doc["session_id"],
            user_id=doc.get("user_id", ""),
            user_email=doc["user_email"],
            provider=doc["provider"],
            started_at=started_at,
            last_activity=last_activity,
            source_ip=doc.get("source_ip", ""),
            source_geo=source_geo,
            device_fingerprint=doc.get("device_fingerprint"),
            user_agent=doc.get("user_agent"),
            application_name=doc.get("application_name"),
            is_active=doc.get("is_active", True),
            risk_score=float(doc.get("risk_score", 0)),
            risk_factors=doc.get("risk_factors", []),
            ended_at=ended_at,
            end_reason=doc.get("end_reason"),
        )

    def create_session(self, session: UserSession) -> str:
        """Create a new session."""
        try:
            doc = self._session_to_doc(session)
            self._get_container().create_item(body=doc)
            logger.debug(f"Created session {session.session_id} for {session.user_email}")
            return session.session_id
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            raise

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing session."""
        try:
            # First get the session to find partition key
            session = self.get_session(session_id)
            if not session:
                logger.warning(f"Session not found for update: {session_id}")
                return False

            # Read current document
            doc = self._get_container().read_item(
                item=session_id,
                partition_key=session.user_email.lower()
            )

            # Apply updates
            for key, value in updates.items():
                if isinstance(value, datetime):
                    doc[key] = value.isoformat()
                else:
                    doc[key] = value

            # Replace document
            self._get_container().replace_item(
                item=session_id,
                body=doc
            )

            logger.debug(f"Updated session {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            return False

    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get a session by ID."""
        try:
            # Cross-partition query to find by session_id
            query = "SELECT * FROM c WHERE c.session_id = @session_id"
            parameters = [{"name": "@session_id", "value": session_id}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
                max_item_count=1
            ))

            if not items:
                return None

            return self._doc_to_session(items[0])
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None

    def get_active_sessions_for_user(self, user_email: str) -> List[UserSession]:
        """Get all active sessions for a user."""
        try:
            query = "SELECT * FROM c WHERE c.user_email = @email AND c.is_active = true"
            parameters = [{"name": "@email", "value": user_email.lower()}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                partition_key=user_email.lower()
            ))

            return [self._doc_to_session(item) for item in items]
        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []

    def get_recent_sessions_for_user(
        self, user_email: str, hours: int = 24
    ) -> List[UserSession]:
        """Get recent sessions for a user."""
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

            query = """
                SELECT * FROM c
                WHERE c.user_email = @email AND c.started_at >= @cutoff
                ORDER BY c.started_at DESC
            """
            parameters = [
                {"name": "@email", "value": user_email.lower()},
                {"name": "@cutoff", "value": cutoff}
            ]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                partition_key=user_email.lower()
            ))

            return [self._doc_to_session(item) for item in items]
        except Exception as e:
            logger.error(f"Error getting recent sessions: {e}")
            return []

    def get_concurrent_sessions(self, user_email: str) -> List[UserSession]:
        """Get concurrent active sessions (active within last 5 minutes)."""
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

            query = """
                SELECT * FROM c
                WHERE c.user_email = @email
                AND c.is_active = true
                AND c.last_activity >= @cutoff
            """
            parameters = [
                {"name": "@email", "value": user_email.lower()},
                {"name": "@cutoff", "value": cutoff}
            ]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                partition_key=user_email.lower()
            ))

            return [self._doc_to_session(item) for item in items]
        except Exception as e:
            logger.error(f"Error getting concurrent sessions: {e}")
            return []

    def end_session(self, session_id: str, reason: str) -> bool:
        """End/terminate a session."""
        try:
            session = self.get_session(session_id)
            if not session:
                logger.warning(f"Session not found for end: {session_id}")
                return False

            return self.update_session(session_id, {
                "is_active": False,
                "ended_at": datetime.now(timezone.utc),
                "end_reason": reason,
            })
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False

    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions.

        Note: With TTL enabled, Cosmos DB will auto-delete old records.
        This method performs immediate cleanup if needed.
        """
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()

            query = "SELECT c.id, c.user_email FROM c WHERE c.started_at < @cutoff"
            parameters = [{"name": "@cutoff", "value": cutoff}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True
            ))

            deleted = 0
            for item in items:
                self._get_container().delete_item(
                    item=item["id"],
                    partition_key=item["user_email"]
                )
                deleted += 1

            logger.info(f"Cleaned up {deleted} expired sessions")
            return deleted
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
            return 0

    def get_sessions_by_ip(self, source_ip: str) -> List[UserSession]:
        """Get all sessions from a specific IP."""
        try:
            query = "SELECT * FROM c WHERE c.source_ip = @ip"
            parameters = [{"name": "@ip", "value": source_ip}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True
            ))

            return [self._doc_to_session(item) for item in items]
        except Exception as e:
            logger.error(f"Error getting sessions by IP: {e}")
            return []

    def get_sessions_by_provider(
        self, provider: str, active_only: bool = True
    ) -> List[UserSession]:
        """Get all sessions for a specific provider."""
        try:
            if active_only:
                query = "SELECT * FROM c WHERE c.provider = @provider AND c.is_active = true"
            else:
                query = "SELECT * FROM c WHERE c.provider = @provider"

            parameters = [{"name": "@provider", "value": provider.lower()}]

            items = list(self._get_container().query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True
            ))

            return [self._doc_to_session(item) for item in items]
        except Exception as e:
            logger.error(f"Error getting sessions by provider: {e}")
            return []
