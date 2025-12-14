"""
Conversation Session Manager

Manages multi-turn conversation sessions with context preservation.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import uuid
import logging

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """A single message in a conversation"""
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'role': self.role,
            'content': self.content,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create from dictionary"""
        return cls(
            role=data['role'],
            content=data['content'],
            timestamp=data.get('timestamp', datetime.utcnow().isoformat()),
            metadata=data.get('metadata', {})
        )


@dataclass
class ConversationSession:
    """A conversation session with context"""
    session_id: str
    user_id: str
    messages: List[Message] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    expires_at: str = field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=24)).isoformat())

    def add_message(self, role: str, content: str, metadata: Dict[str, Any] = None) -> Message:
        """Add a message to the conversation"""
        message = Message(
            role=role,
            content=content,
            metadata=metadata or {}
        )
        self.messages.append(message)
        self.updated_at = datetime.utcnow().isoformat()
        return message

    def get_recent_messages(self, count: int = 10) -> List[Message]:
        """Get the most recent N messages"""
        return self.messages[-count:] if self.messages else []

    def get_context_for_llm(self, max_messages: int = 10) -> List[Dict[str, str]]:
        """
        Format conversation history for LLM context.

        Returns:
            List of messages in LLM format (role + content)
        """
        recent = self.get_recent_messages(max_messages)
        return [
            {'role': msg.role, 'content': msg.content}
            for msg in recent
        ]

    def update_context(self, key: str, value: Any) -> None:
        """Update session context"""
        self.context[key] = value
        self.updated_at = datetime.utcnow().isoformat()

    def get_context(self, key: str, default: Any = None) -> Any:
        """Get value from session context"""
        return self.context.get(key, default)

    def is_expired(self) -> bool:
        """Check if session has expired"""
        expires = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
        return datetime.utcnow() > expires.replace(tzinfo=None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'messages': [msg.to_dict() for msg in self.messages],
            'context': self.context,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'expires_at': self.expires_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationSession':
        """Create from dictionary"""
        messages = [Message.from_dict(msg) for msg in data.get('messages', [])]
        return cls(
            session_id=data['session_id'],
            user_id=data['user_id'],
            messages=messages,
            context=data.get('context', {}),
            created_at=data.get('created_at', datetime.utcnow().isoformat()),
            updated_at=data.get('updated_at', datetime.utcnow().isoformat()),
            expires_at=data.get('expires_at', (datetime.utcnow() + timedelta(hours=24)).isoformat())
        )


class SessionManager:
    """Manages conversation sessions"""

    def __init__(self, storage_backend=None):
        """
        Initialize session manager.

        Args:
            storage_backend: Optional storage backend (DynamoDB, Redis, etc.)
        """
        self.storage = storage_backend
        self.local_sessions: Dict[str, ConversationSession] = {}

    def create_session(self, user_id: str) -> ConversationSession:
        """
        Create a new conversation session.

        Args:
            user_id: User identifier

        Returns:
            New ConversationSession
        """
        session = ConversationSession(
            session_id=str(uuid.uuid4()),
            user_id=user_id
        )

        # Store locally
        self.local_sessions[session.session_id] = session

        # Store in backend if available
        if self.storage:
            self.storage.save_session(session)

        return session

    def get_session(self, session_id: str) -> Optional[ConversationSession]:
        """
        Get an existing session.

        Args:
            session_id: Session identifier

        Returns:
            ConversationSession or None if not found
        """
        # Check local cache first
        if session_id in self.local_sessions:
            session = self.local_sessions[session_id]
            if not session.is_expired():
                return session

        # Check storage backend
        if self.storage:
            session = self.storage.load_session(session_id)
            if session and not session.is_expired():
                self.local_sessions[session_id] = session
                return session

        return None

    def save_session(self, session: ConversationSession) -> None:
        """
        Save session to storage.

        Args:
            session: ConversationSession to save
        """
        # Update local cache
        self.local_sessions[session.session_id] = session

        # Save to backend
        if self.storage:
            self.storage.save_session(session)

    def add_user_message(
        self,
        session_id: str,
        content: str,
        metadata: Dict[str, Any] = None
    ) -> Message:
        """
        Add a user message to the session.

        Args:
            session_id: Session identifier
            content: Message content
            metadata: Optional message metadata

        Returns:
            Created Message

        Raises:
            ValueError: If session not found
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        message = session.add_message('user', content, metadata)
        self.save_session(session)
        return message

    def add_assistant_message(
        self,
        session_id: str,
        content: str,
        metadata: Dict[str, Any] = None
    ) -> Message:
        """
        Add an assistant message to the session.

        Args:
            session_id: Session identifier
            content: Message content
            metadata: Optional message metadata (e.g., SQL query, execution results)

        Returns:
            Created Message

        Raises:
            ValueError: If session not found
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        message = session.add_message('assistant', content, metadata)
        self.save_session(session)
        return message

    def get_context_for_llm(self, session_id: str, max_messages: int = 10) -> List[Dict[str, str]]:
        """
        Get conversation context formatted for LLM.

        Args:
            session_id: Session identifier
            max_messages: Maximum number of recent messages to include

        Returns:
            List of messages in LLM format

        Raises:
            ValueError: If session not found
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        return session.get_context_for_llm(max_messages)

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions from local cache.

        Returns:
            Number of sessions cleaned up
        """
        expired = [
            sid for sid, session in self.local_sessions.items()
            if session.is_expired()
        ]

        for sid in expired:
            del self.local_sessions[sid]

        return len(expired)


class DynamoDBSessionStorage:
    """DynamoDB storage backend for conversation sessions"""

    def __init__(self, table_name: str, dynamodb_resource=None):
        """
        Initialize DynamoDB storage.

        Args:
            table_name: DynamoDB table name
            dynamodb_resource: Boto3 DynamoDB resource
        """
        import boto3
        self.table_name = table_name
        self.dynamodb = dynamodb_resource or boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(table_name)

    def save_session(self, session: ConversationSession) -> None:
        """Save session to DynamoDB"""
        item = session.to_dict()
        item['messages'] = json.dumps(item['messages'])
        item['context'] = json.dumps(item['context'])

        self.table.put_item(Item=item)

    def load_session(self, session_id: str) -> Optional[ConversationSession]:
        """Load session from DynamoDB"""
        try:
            response = self.table.get_item(Key={'session_id': session_id})

            if 'Item' not in response:
                return None

            item = response['Item']
            item['messages'] = json.loads(item['messages'])
            item['context'] = json.loads(item['context'])

            return ConversationSession.from_dict(item)

        except Exception as e:
            logger.error(f"Error loading session: {str(e)}")
            return None

    def delete_session(self, session_id: str) -> None:
        """Delete session from DynamoDB"""
        self.table.delete_item(Key={'session_id': session_id})
