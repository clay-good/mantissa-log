"""DynamoDB implementation of session store for AWS deployments."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .session_store import SessionStore, UserSession

logger = logging.getLogger(__name__)


class DynamoDBSessionStore(SessionStore):
    """DynamoDB implementation of session storage.

    Table schema:
    - PK: user_email
    - SK: session_id
    - GSI1: provider-index (PK: provider, SK: started_at)
    - GSI2: ip-index (PK: source_ip, SK: started_at)
    - TTL: ttl_timestamp (for auto-cleanup)
    """

    def __init__(
        self,
        table_name: str = "mantissa-identity-sessions",
        region: str = "us-east-1",
        ttl_hours: int = 24,
    ):
        self.table_name = table_name
        self.region = region
        self.ttl_hours = ttl_hours
        self._table = None

    def _get_table(self):
        """Lazy initialization of DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def _session_to_item(self, session: UserSession) -> Dict[str, Any]:
        """Convert UserSession to DynamoDB item."""
        # Calculate TTL
        ttl_timestamp = int(
            (datetime.now(timezone.utc) + timedelta(hours=self.ttl_hours)).timestamp()
        )

        item = {
            "pk": session.user_email.lower(),
            "sk": f"SESSION#{session.session_id}",
            "session_id": session.session_id,
            "user_id": session.user_id,
            "user_email": session.user_email.lower(),
            "provider": session.provider,
            "started_at": session.started_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "source_ip": session.source_ip,
            "is_active": session.is_active,
            "risk_score": str(session.risk_score),
            "risk_factors": session.risk_factors,
            "ttl_timestamp": ttl_timestamp,
        }

        if session.source_geo:
            item["source_geo"] = session.source_geo.to_dict()
        if session.device_fingerprint:
            item["device_fingerprint"] = session.device_fingerprint
        if session.user_agent:
            item["user_agent"] = session.user_agent
        if session.application_name:
            item["application_name"] = session.application_name
        if session.ended_at:
            item["ended_at"] = session.ended_at.isoformat()
        if session.end_reason:
            item["end_reason"] = session.end_reason

        return item

    def _item_to_session(self, item: Dict[str, Any]) -> UserSession:
        """Convert DynamoDB item to UserSession."""
        from ..models.identity_event import GeoLocation

        source_geo = None
        if "source_geo" in item and item["source_geo"]:
            source_geo = GeoLocation.from_dict(item["source_geo"])

        started_at = datetime.fromisoformat(item["started_at"].replace("Z", "+00:00"))
        last_activity = datetime.fromisoformat(item["last_activity"].replace("Z", "+00:00"))

        ended_at = None
        if "ended_at" in item and item["ended_at"]:
            ended_at = datetime.fromisoformat(item["ended_at"].replace("Z", "+00:00"))

        return UserSession(
            session_id=item["session_id"],
            user_id=item.get("user_id", ""),
            user_email=item["user_email"],
            provider=item["provider"],
            started_at=started_at,
            last_activity=last_activity,
            source_ip=item.get("source_ip", ""),
            source_geo=source_geo,
            device_fingerprint=item.get("device_fingerprint"),
            user_agent=item.get("user_agent"),
            application_name=item.get("application_name"),
            is_active=item.get("is_active", True),
            risk_score=float(item.get("risk_score", 0)),
            risk_factors=item.get("risk_factors", []),
            ended_at=ended_at,
            end_reason=item.get("end_reason"),
        )

    def create_session(self, session: UserSession) -> str:
        """Create a new session."""
        try:
            item = self._session_to_item(session)
            self._get_table().put_item(Item=item)
            logger.debug(f"Created session {session.session_id} for {session.user_email}")
            return session.session_id
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            raise

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing session."""
        try:
            # First get the session to find the user_email (pk)
            session = self.get_session(session_id)
            if not session:
                logger.warning(f"Session not found for update: {session_id}")
                return False

            # Build update expression
            update_expr_parts = []
            expr_attr_values = {}
            expr_attr_names = {}

            for key, value in updates.items():
                attr_name = f"#{key}"
                attr_value = f":{key}"
                update_expr_parts.append(f"{attr_name} = {attr_value}")
                expr_attr_names[attr_name] = key

                if isinstance(value, datetime):
                    expr_attr_values[attr_value] = value.isoformat()
                elif isinstance(value, float):
                    expr_attr_values[attr_value] = str(value)
                else:
                    expr_attr_values[attr_value] = value

            update_expr = "SET " + ", ".join(update_expr_parts)

            self._get_table().update_item(
                Key={
                    "pk": session.user_email.lower(),
                    "sk": f"SESSION#{session_id}",
                },
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values,
            )

            logger.debug(f"Updated session {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            return False

    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get a session by ID."""
        try:
            # Need to scan since we don't know the user_email
            response = self._get_table().scan(
                FilterExpression="session_id = :sid",
                ExpressionAttributeValues={":sid": session_id},
                Limit=1,
            )

            items = response.get("Items", [])
            if not items:
                return None

            return self._item_to_session(items[0])
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None

    def get_active_sessions_for_user(self, user_email: str) -> List[UserSession]:
        """Get all active sessions for a user."""
        try:
            response = self._get_table().query(
                KeyConditionExpression="pk = :email AND begins_with(sk, :prefix)",
                FilterExpression="is_active = :active",
                ExpressionAttributeValues={
                    ":email": user_email.lower(),
                    ":prefix": "SESSION#",
                    ":active": True,
                },
            )

            return [self._item_to_session(item) for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []

    def get_recent_sessions_for_user(
        self, user_email: str, hours: int = 24
    ) -> List[UserSession]:
        """Get recent sessions for a user."""
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

            response = self._get_table().query(
                KeyConditionExpression="pk = :email AND begins_with(sk, :prefix)",
                FilterExpression="started_at >= :cutoff",
                ExpressionAttributeValues={
                    ":email": user_email.lower(),
                    ":prefix": "SESSION#",
                    ":cutoff": cutoff,
                },
            )

            sessions = [self._item_to_session(item) for item in response.get("Items", [])]
            return sorted(sessions, key=lambda s: s.started_at, reverse=True)
        except Exception as e:
            logger.error(f"Error getting recent sessions: {e}")
            return []

    def get_concurrent_sessions(self, user_email: str) -> List[UserSession]:
        """Get concurrent active sessions (active within last 5 minutes)."""
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

            response = self._get_table().query(
                KeyConditionExpression="pk = :email AND begins_with(sk, :prefix)",
                FilterExpression="is_active = :active AND last_activity >= :cutoff",
                ExpressionAttributeValues={
                    ":email": user_email.lower(),
                    ":prefix": "SESSION#",
                    ":active": True,
                    ":cutoff": cutoff,
                },
            )

            return [self._item_to_session(item) for item in response.get("Items", [])]
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

            self._get_table().update_item(
                Key={
                    "pk": session.user_email.lower(),
                    "sk": f"SESSION#{session_id}",
                },
                UpdateExpression="SET is_active = :active, ended_at = :ended, end_reason = :reason",
                ExpressionAttributeValues={
                    ":active": False,
                    ":ended": datetime.now(timezone.utc).isoformat(),
                    ":reason": reason,
                },
            )

            logger.debug(f"Ended session {session_id}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False

    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions.

        Note: With TTL enabled, DynamoDB will auto-delete old records.
        This method performs immediate cleanup if needed.
        """
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()

            # Scan for old sessions
            response = self._get_table().scan(
                FilterExpression="started_at < :cutoff",
                ExpressionAttributeValues={":cutoff": cutoff},
            )

            deleted = 0
            for item in response.get("Items", []):
                self._get_table().delete_item(
                    Key={"pk": item["pk"], "sk": item["sk"]}
                )
                deleted += 1

            logger.info(f"Cleaned up {deleted} expired sessions")
            return deleted
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
            return 0

    def get_sessions_by_ip(self, source_ip: str) -> List[UserSession]:
        """Get all sessions from a specific IP using GSI."""
        try:
            response = self._get_table().query(
                IndexName="ip-index",
                KeyConditionExpression="source_ip = :ip",
                ExpressionAttributeValues={":ip": source_ip},
            )

            return [self._item_to_session(item) for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error getting sessions by IP: {e}")
            return []

    def get_sessions_by_provider(
        self, provider: str, active_only: bool = True
    ) -> List[UserSession]:
        """Get all sessions for a specific provider using GSI."""
        try:
            filter_expr = "is_active = :active" if active_only else None
            expr_values = {":provider": provider.lower()}
            if active_only:
                expr_values[":active"] = True

            response = self._get_table().query(
                IndexName="provider-index",
                KeyConditionExpression="provider = :provider",
                FilterExpression=filter_expr,
                ExpressionAttributeValues=expr_values,
            )

            return [self._item_to_session(item) for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error getting sessions by provider: {e}")
            return []
