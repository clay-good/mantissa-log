"""Firestore implementation of session store for GCP deployments."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .session_store import SessionStore, UserSession

logger = logging.getLogger(__name__)


class FirestoreSessionStore(SessionStore):
    """Firestore implementation of session storage.

    Collection structure:
    - identity_sessions/{session_id}
      - user_email (indexed)
      - provider (indexed)
      - source_ip (indexed)
      - is_active (indexed)
      - started_at (indexed)
    """

    def __init__(
        self,
        collection_name: str = "identity_sessions",
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
        """Get the sessions collection."""
        return self._get_db().collection(self.collection_name)

    def _session_to_doc(self, session: UserSession) -> Dict[str, Any]:
        """Convert UserSession to Firestore document."""
        doc = {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "user_email": session.user_email.lower(),
            "provider": session.provider,
            "started_at": session.started_at,
            "last_activity": session.last_activity,
            "source_ip": session.source_ip,
            "is_active": session.is_active,
            "risk_score": session.risk_score,
            "risk_factors": session.risk_factors,
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
            doc["ended_at"] = session.ended_at
        if session.end_reason:
            doc["end_reason"] = session.end_reason

        return doc

    def _doc_to_session(self, doc: Dict[str, Any]) -> UserSession:
        """Convert Firestore document to UserSession."""
        from ..models.identity_event import GeoLocation

        source_geo = None
        if "source_geo" in doc and doc["source_geo"]:
            source_geo = GeoLocation.from_dict(doc["source_geo"])

        # Handle Firestore Timestamp objects
        started_at = doc.get("started_at")
        if hasattr(started_at, "isoformat"):
            pass  # Already a datetime
        elif hasattr(started_at, "timestamp"):
            started_at = datetime.fromtimestamp(started_at.timestamp(), tz=timezone.utc)
        elif isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))

        last_activity = doc.get("last_activity")
        if hasattr(last_activity, "isoformat"):
            pass
        elif hasattr(last_activity, "timestamp"):
            last_activity = datetime.fromtimestamp(last_activity.timestamp(), tz=timezone.utc)
        elif isinstance(last_activity, str):
            last_activity = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))

        ended_at = doc.get("ended_at")
        if ended_at:
            if hasattr(ended_at, "isoformat"):
                pass
            elif hasattr(ended_at, "timestamp"):
                ended_at = datetime.fromtimestamp(ended_at.timestamp(), tz=timezone.utc)
            elif isinstance(ended_at, str):
                ended_at = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))

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
            doc_ref = self._get_collection().document(session.session_id)
            doc_ref.set(self._session_to_doc(session))
            logger.debug(f"Created session {session.session_id} for {session.user_email}")
            return session.session_id
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            raise

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing session."""
        try:
            doc_ref = self._get_collection().document(session_id)

            # Convert datetime objects
            processed_updates = {}
            for key, value in updates.items():
                if isinstance(value, datetime):
                    processed_updates[key] = value
                else:
                    processed_updates[key] = value

            doc_ref.update(processed_updates)
            logger.debug(f"Updated session {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            return False

    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get a session by ID."""
        try:
            doc_ref = self._get_collection().document(session_id)
            doc = doc_ref.get()

            if not doc.exists:
                return None

            return self._doc_to_session(doc.to_dict())
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None

    def get_active_sessions_for_user(self, user_email: str) -> List[UserSession]:
        """Get all active sessions for a user."""
        try:
            query = (
                self._get_collection()
                .where("user_email", "==", user_email.lower())
                .where("is_active", "==", True)
            )

            return [self._doc_to_session(doc.to_dict()) for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []

    def get_recent_sessions_for_user(
        self, user_email: str, hours: int = 24
    ) -> List[UserSession]:
        """Get recent sessions for a user."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

            query = (
                self._get_collection()
                .where("user_email", "==", user_email.lower())
                .where("started_at", ">=", cutoff)
                .order_by("started_at", direction="DESCENDING")
            )

            return [self._doc_to_session(doc.to_dict()) for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error getting recent sessions: {e}")
            return []

    def get_concurrent_sessions(self, user_email: str) -> List[UserSession]:
        """Get concurrent active sessions (active within last 5 minutes)."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)

            query = (
                self._get_collection()
                .where("user_email", "==", user_email.lower())
                .where("is_active", "==", True)
                .where("last_activity", ">=", cutoff)
            )

            return [self._doc_to_session(doc.to_dict()) for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error getting concurrent sessions: {e}")
            return []

    def end_session(self, session_id: str, reason: str) -> bool:
        """End/terminate a session."""
        try:
            doc_ref = self._get_collection().document(session_id)
            doc_ref.update({
                "is_active": False,
                "ended_at": datetime.now(timezone.utc),
                "end_reason": reason,
            })

            logger.debug(f"Ended session {session_id}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False

    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            query = self._get_collection().where("started_at", "<", cutoff)

            deleted = 0
            for doc in query.stream():
                doc.reference.delete()
                deleted += 1

            logger.info(f"Cleaned up {deleted} expired sessions")
            return deleted
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
            return 0

    def get_sessions_by_ip(self, source_ip: str) -> List[UserSession]:
        """Get all sessions from a specific IP."""
        try:
            query = self._get_collection().where("source_ip", "==", source_ip)
            return [self._doc_to_session(doc.to_dict()) for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error getting sessions by IP: {e}")
            return []

    def get_sessions_by_provider(
        self, provider: str, active_only: bool = True
    ) -> List[UserSession]:
        """Get all sessions for a specific provider."""
        try:
            query = self._get_collection().where("provider", "==", provider.lower())

            if active_only:
                query = query.where("is_active", "==", True)

            return [self._doc_to_session(doc.to_dict()) for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error getting sessions by provider: {e}")
            return []
