"""
Conversation Manager

Manages conversational context for multi-turn natural language queries.
Maintains session state, conversation history, and enables follow-up queries
that reference previous questions and results.
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
import boto3
import logging

logger = logging.getLogger(__name__)


class MessageRole(Enum):
    """Role of a message in the conversation."""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


@dataclass
class ConversationMessage:
    """A single message in a conversation."""
    role: MessageRole
    content: str
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'role': self.role.value,
            'content': self.content,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationMessage':
        """Create from dictionary."""
        return cls(
            role=MessageRole(data['role']),
            content=data['content'],
            timestamp=data['timestamp'],
            metadata=data.get('metadata', {})
        )


@dataclass
class QueryContext:
    """Context for a query within a conversation."""
    query_text: str
    generated_sql: Optional[str] = None
    execution_id: Optional[str] = None
    result_count: Optional[int] = None
    data_scanned_mb: Optional[float] = None
    error: Optional[str] = None
    cost_usd: Optional[float] = None


@dataclass
class ConversationSession:
    """A conversation session with context and history."""
    session_id: str
    user_id: str
    created_at: str
    updated_at: str
    messages: List[ConversationMessage] = field(default_factory=list)

    # Contextual state
    current_table: Optional[str] = None
    current_timerange: Optional[Dict[str, str]] = None
    active_filters: List[str] = field(default_factory=list)
    referenced_fields: List[str] = field(default_factory=list)

    # Query history
    query_history: List[QueryContext] = field(default_factory=list)

    # Session metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    ttl: Optional[int] = None

    def add_message(self, role: MessageRole, content: str, metadata: Optional[Dict] = None):
        """Add a message to the conversation."""
        message = ConversationMessage(
            role=role,
            content=content,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            metadata=metadata or {}
        )
        self.messages.append(message)
        self.updated_at = message.timestamp

    def add_query_context(self, context: QueryContext):
        """Add query context to history."""
        self.query_history.append(context)

        # Extract and update contextual state
        if context.generated_sql:
            self._extract_context_from_sql(context.generated_sql)

    def _extract_context_from_sql(self, sql: str):
        """Extract contextual information from SQL query."""
        sql_upper = sql.upper()

        # Extract table name
        if 'FROM' in sql_upper:
            from_idx = sql_upper.index('FROM')
            remainder = sql[from_idx + 4:].strip()
            table_name = remainder.split()[0].strip()
            if table_name and not table_name.upper() in ('SELECT', 'WHERE'):
                self.current_table = table_name

        # Extract time range
        if 'CURRENT_DATE' in sql_upper or 'CURRENT_TIMESTAMP' in sql_upper:
            # Parse interval
            if 'INTERVAL' in sql_upper:
                interval_idx = sql_upper.index('INTERVAL')
                # Extract next few words to get the interval
                interval_part = sql[interval_idx:interval_idx + 50]
                self.current_timerange = {'expression': interval_part}

        # Extract referenced fields
        if 'SELECT' in sql_upper:
            select_idx = sql_upper.index('SELECT')
            from_idx = sql_upper.index('FROM') if 'FROM' in sql_upper else len(sql)
            select_clause = sql[select_idx + 6:from_idx].strip()

            # Parse fields (simple approach - doesn't handle complex expressions perfectly)
            if select_clause != '*':
                fields = [f.strip().split()[-1] for f in select_clause.split(',')]
                self.referenced_fields.extend(fields)
                # Keep unique fields
                self.referenced_fields = list(set(self.referenced_fields))

    def get_last_query(self) -> Optional[QueryContext]:
        """Get the most recent query context."""
        return self.query_history[-1] if self.query_history else None

    def get_conversation_summary(self) -> str:
        """Generate a summary of the conversation for context."""
        summary_parts = []

        if self.current_table:
            summary_parts.append(f"Currently querying table: {self.current_table}")

        if self.current_timerange:
            summary_parts.append(f"Current time range: {self.current_timerange.get('expression', 'last query')}")

        if self.active_filters:
            summary_parts.append(f"Active filters: {', '.join(self.active_filters)}")

        if self.query_history:
            last_query = self.query_history[-1]
            if last_query.result_count is not None:
                summary_parts.append(f"Last query returned {last_query.result_count} rows")

        return "; ".join(summary_parts) if summary_parts else "New conversation"

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for storage."""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'messages': [msg.to_dict() for msg in self.messages],
            'current_table': self.current_table,
            'current_timerange': self.current_timerange,
            'active_filters': self.active_filters,
            'referenced_fields': self.referenced_fields,
            'query_history': [asdict(q) for q in self.query_history],
            'metadata': self.metadata,
            'ttl': self.ttl
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationSession':
        """Create session from dictionary."""
        return cls(
            session_id=data['session_id'],
            user_id=data['user_id'],
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            messages=[ConversationMessage.from_dict(m) for m in data.get('messages', [])],
            current_table=data.get('current_table'),
            current_timerange=data.get('current_timerange'),
            active_filters=data.get('active_filters', []),
            referenced_fields=data.get('referenced_fields', []),
            query_history=[QueryContext(**q) for q in data.get('query_history', [])],
            metadata=data.get('metadata', {}),
            ttl=data.get('ttl')
        )


class ConversationManager:
    """
    Manages conversation sessions for natural language queries.

    Features:
    - Session-based conversation memory
    - Multi-turn query refinement
    - Context extraction from queries
    - Follow-up command recognition
    """

    def __init__(self, table_name: Optional[str] = None):
        """
        Initialize conversation manager.

        Args:
            table_name: DynamoDB table for session storage
        """
        self.table_name = table_name or os.environ.get(
            'CONVERSATION_TABLE',
            'mantissa-log-conversations'
        )

        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

        # Session timeout (24 hours)
        self.session_timeout_hours = 24

    def create_session(self, user_id: str, metadata: Optional[Dict] = None) -> ConversationSession:
        """
        Create a new conversation session.

        Args:
            user_id: User ID
            metadata: Optional session metadata

        Returns:
            New ConversationSession
        """
        session_id = f"session-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.utcnow().isoformat() + 'Z'

        session = ConversationSession(
            session_id=session_id,
            user_id=user_id,
            created_at=timestamp,
            updated_at=timestamp,
            metadata=metadata or {},
            ttl=int((datetime.utcnow() + timedelta(hours=self.session_timeout_hours)).timestamp())
        )

        # Add system message
        session.add_message(
            MessageRole.SYSTEM,
            "You are a helpful assistant for querying security logs. "
            "You help users write SQL queries against their log data in Athena."
        )

        # Save to DynamoDB
        self._save_session(session)

        return session

    def get_session(self, session_id: str, user_id: str) -> Optional[ConversationSession]:
        """
        Retrieve an existing session.

        Args:
            session_id: Session ID
            user_id: User ID

        Returns:
            ConversationSession or None if not found
        """
        try:
            response = self.table.get_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'session#{session_id}'
                }
            )

            if 'Item' not in response:
                return None

            item = response['Item']

            # Convert DynamoDB item to session
            session = ConversationSession.from_dict(item)

            return session

        except Exception as e:
            logger.error(f'Error retrieving session: {e}')
            return None

    def _save_session(self, session: ConversationSession):
        """Save session to DynamoDB."""
        try:
            item = session.to_dict()
            item['pk'] = f'user#{session.user_id}'
            item['sk'] = f'session#{session.session_id}'

            self.table.put_item(Item=item)

        except Exception as e:
            logger.error(f'Error saving session: {e}')
            raise

    def add_user_message(
        self,
        session_id: str,
        user_id: str,
        message: str,
        metadata: Optional[Dict] = None
    ) -> ConversationSession:
        """
        Add a user message to the session.

        Args:
            session_id: Session ID
            user_id: User ID
            message: User's message
            metadata: Optional message metadata

        Returns:
            Updated session
        """
        session = self.get_session(session_id, user_id)

        if not session:
            raise ValueError(f'Session not found: {session_id}')

        session.add_message(MessageRole.USER, message, metadata)
        self._save_session(session)

        return session

    def add_assistant_response(
        self,
        session_id: str,
        user_id: str,
        response: str,
        query_context: Optional[QueryContext] = None,
        metadata: Optional[Dict] = None
    ) -> ConversationSession:
        """
        Add an assistant response to the session.

        Args:
            session_id: Session ID
            user_id: User ID
            response: Assistant's response
            query_context: Optional query execution context
            metadata: Optional message metadata

        Returns:
            Updated session
        """
        session = self.get_session(session_id, user_id)

        if not session:
            raise ValueError(f'Session not found: {session_id}')

        session.add_message(MessageRole.ASSISTANT, response, metadata)

        if query_context:
            session.add_query_context(query_context)

        self._save_session(session)

        return session

    def is_follow_up_query(self, message: str) -> bool:
        """
        Determine if a message is a follow-up query.

        Args:
            message: User's message

        Returns:
            True if this is a follow-up query
        """
        message_lower = message.lower().strip()

        # Follow-up indicators
        follow_up_patterns = [
            # Refinement commands
            'and', 'also', 'but', 'except', 'without',
            'exclude', 'include', 'add', 'remove',

            # Modification commands
            'change', 'modify', 'update', 'filter',
            'limit', 'order by', 'group by',

            # Reference to previous
            'same', 'those', 'these', 'that', 'this',
            'previous', 'last', 'earlier',

            # Aggregation follow-ups
            'count', 'sum', 'average', 'total',
            'show me', 'what about', 'how many'
        ]

        # Check if message starts with or contains follow-up patterns
        for pattern in follow_up_patterns:
            if message_lower.startswith(pattern):
                return True
            # For longer phrases, check if they appear early in the message
            if pattern in message_lower[:50]:
                return True

        # Check for short queries (likely follow-ups)
        word_count = len(message_lower.split())
        if word_count <= 5:
            return True

        # Check for questions without context (likely new queries)
        if message_lower.startswith(('show me all', 'find', 'search for', 'list all')):
            return False

        return False

    def build_context_prompt(self, session: ConversationSession, new_message: str) -> str:
        """
        Build a context-aware prompt for the LLM.

        Args:
            session: Current session
            new_message: New user message

        Returns:
            Prompt with conversation context
        """
        context_parts = []

        # Add conversation summary
        summary = session.get_conversation_summary()
        if summary != "New conversation":
            context_parts.append(f"Conversation context: {summary}")

        # Add recent query history (last 3 queries)
        recent_queries = session.query_history[-3:] if len(session.query_history) > 0 else []
        if recent_queries:
            context_parts.append("\nRecent queries:")
            for i, query in enumerate(recent_queries, 1):
                context_parts.append(f"{i}. User asked: \"{query.query_text}\"")
                if query.generated_sql:
                    # Truncate SQL for brevity
                    sql_preview = query.generated_sql[:150] + "..." if len(query.generated_sql) > 150 else query.generated_sql
                    context_parts.append(f"   Generated SQL: {sql_preview}")
                if query.result_count is not None:
                    context_parts.append(f"   Returned {query.result_count} rows")

        # Indicate if this is a follow-up
        if self.is_follow_up_query(new_message):
            context_parts.append("\nThis appears to be a follow-up query. Refine the previous query based on the new request.")

        # Build final prompt
        if context_parts:
            return "\n".join(context_parts) + f"\n\nNew user request: {new_message}"
        else:
            return new_message

    def get_user_sessions(
        self,
        user_id: str,
        limit: int = 10
    ) -> List[ConversationSession]:
        """
        Get recent sessions for a user.

        Args:
            user_id: User ID
            limit: Maximum number of sessions to return

        Returns:
            List of sessions, most recent first
        """
        from boto3.dynamodb.conditions import Key

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').begins_with('session#'),
                Limit=limit,
                ScanIndexForward=False  # Most recent first
            )

            sessions = []
            for item in response.get('Items', []):
                session = ConversationSession.from_dict(item)
                sessions.append(session)

            return sessions

        except Exception as e:
            logger.error(f'Error retrieving user sessions: {e}')
            return []

    def delete_session(self, session_id: str, user_id: str):
        """
        Delete a conversation session.

        Args:
            session_id: Session ID
            user_id: User ID
        """
        try:
            self.table.delete_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'session#{session_id}'
                }
            )
        except Exception as e:
            logger.error(f'Error deleting session: {e}')


def create_conversation_session(user_id: str) -> str:
    """
    Convenience function to create a new conversation session.

    Args:
        user_id: User ID

    Returns:
        Session ID
    """
    manager = ConversationManager()
    session = manager.create_session(user_id)
    return session.session_id


def get_conversation_context(
    session_id: str,
    user_id: str,
    new_message: str
) -> Dict[str, Any]:
    """
    Convenience function to get conversation context for a new message.

    Args:
        session_id: Session ID
        user_id: User ID
        new_message: New user message

    Returns:
        Dictionary with context information
    """
    manager = ConversationManager()
    session = manager.get_session(session_id, user_id)

    if not session:
        return {
            'is_new_session': True,
            'prompt': new_message,
            'is_follow_up': False
        }

    is_follow_up = manager.is_follow_up_query(new_message)
    prompt = manager.build_context_prompt(session, new_message)

    return {
        'is_new_session': False,
        'session': session,
        'prompt': prompt,
        'is_follow_up': is_follow_up,
        'conversation_summary': session.get_conversation_summary(),
        'last_query': session.get_last_query()
    }
