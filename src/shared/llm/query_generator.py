"""Natural language to SQL query generation."""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Union
import json

from .providers.base import LLMProvider
from .schema_context import SchemaContext
from .sql_validator import SQLValidator, ValidationResult
from .prompt_templates import PromptBuilder
from .cache import QueryPatternCache, InMemoryQueryCache, CachedQuery

logger = logging.getLogger(__name__)


@dataclass
class QueryGenerationResult:
    """Result of query generation."""

    success: bool
    sql: Optional[str] = None
    explanation: Optional[str] = None
    validation_warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    attempts: int = 1
    llm_response: Optional[str] = None
    from_cache: bool = False

    def to_dict(self) -> Dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "success": self.success,
            "sql": self.sql,
            "explanation": self.explanation,
            "validation_warnings": self.validation_warnings,
            "error": self.error,
            "attempts": self.attempts,
            "from_cache": self.from_cache,
        }


@dataclass
class ConversationMessage:
    """Conversation message for session management."""

    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    sql: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "sql": self.sql,
        }


class SessionManager:
    """Manages conversation sessions for follow-up queries."""

    def __init__(self, storage_backend: Optional[str] = None):
        """Initialize session manager.

        Args:
            storage_backend: Storage backend ('dynamodb' or 'memory')
        """
        self.storage_backend = storage_backend or 'memory'
        self.sessions: Dict[str, List[ConversationMessage]] = {}

    def add_message(self, session_id: str, message: ConversationMessage) -> None:
        """Add message to session.

        Args:
            session_id: Session identifier
            message: Message to add
        """
        if session_id not in self.sessions:
            self.sessions[session_id] = []

        self.sessions[session_id].append(message)

        # Keep only last 10 messages
        if len(self.sessions[session_id]) > 10:
            self.sessions[session_id] = self.sessions[session_id][-10:]

    def get_history(self, session_id: str, limit: int = 5) -> List[ConversationMessage]:
        """Get conversation history.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to return

        Returns:
            List of conversation messages
        """
        if session_id not in self.sessions:
            return []

        return self.sessions[session_id][-limit:]

    def clear_session(self, session_id: str) -> None:
        """Clear session history.

        Args:
            session_id: Session identifier
        """
        if session_id in self.sessions:
            del self.sessions[session_id]


class QueryGenerator:
    """Generates SQL queries from natural language questions."""

    def __init__(
        self,
        llm_provider: LLMProvider,
        schema_context: SchemaContext,
        sql_validator: SQLValidator,
        session_manager: Optional[SessionManager] = None,
        query_cache: Optional[Union[QueryPatternCache, InMemoryQueryCache]] = None,
        max_retries: int = 3,
        enable_cache: bool = True
    ):
        """Initialize query generator.

        Args:
            llm_provider: LLM provider for generation
            schema_context: Schema context builder
            sql_validator: SQL validator
            session_manager: Optional session manager for conversations
            query_cache: Optional query cache for reducing LLM calls
            max_retries: Maximum retry attempts for failed queries
            enable_cache: Whether to enable query caching (default True)
        """
        self.llm_provider = llm_provider
        self.schema_context = schema_context
        self.sql_validator = sql_validator
        self.session_manager = session_manager or SessionManager()
        self.max_retries = max_retries
        self.prompt_builder = PromptBuilder()
        self.enable_cache = enable_cache

        # Initialize cache
        if query_cache is not None:
            self.query_cache = query_cache
        elif enable_cache:
            try:
                self.query_cache = QueryPatternCache()
            except Exception as e:
                logger.warning(f"Failed to initialize DynamoDB cache, using in-memory: {e}")
                self.query_cache = InMemoryQueryCache()
        else:
            self.query_cache = None

    def generate_query(
        self,
        user_question: str,
        session_id: Optional[str] = None,
        include_explanation: bool = False,
        skip_cache: bool = False
    ) -> QueryGenerationResult:
        """Generate SQL query from natural language question.

        Args:
            user_question: Natural language question
            session_id: Optional session ID for conversation context
            include_explanation: Whether to generate explanation
            skip_cache: Skip cache lookup (force LLM call)

        Returns:
            QueryGenerationResult
        """
        # Check cache first (only for standalone queries, not conversations)
        if self.query_cache and not skip_cache and not session_id:
            cached = self.query_cache.get(user_question)
            if cached:
                logger.debug(f"Cache hit for query: {user_question[:50]}...")

                # Store in session if provided
                if session_id:
                    self.session_manager.add_message(
                        session_id,
                        ConversationMessage(
                            role="user",
                            content=user_question
                        )
                    )
                    self.session_manager.add_message(
                        session_id,
                        ConversationMessage(
                            role="assistant",
                            content=cached.explanation or "Generated SQL query (from cache)",
                            sql=cached.generated_sql
                        )
                    )

                return QueryGenerationResult(
                    success=True,
                    sql=cached.generated_sql,
                    explanation=cached.explanation,
                    validation_warnings=[],
                    attempts=0,
                    from_cache=True
                )

        # Get conversation history if session provided
        conversation_history = []
        if session_id:
            history = self.session_manager.get_history(session_id)
            conversation_history = [
                {"role": msg.role, "content": msg.content, "sql": msg.sql}
                for msg in history
            ]

        # Build schema context
        schema_context_str = self.schema_context.build_context()

        # Attempt to generate valid SQL
        for attempt in range(1, self.max_retries + 1):
            try:
                # Build prompt
                if attempt == 1:
                    prompt = self.prompt_builder.build_query_prompt(
                        user_query=user_question,
                        schema_context=schema_context_str,
                        conversation_history=conversation_history
                    )
                else:
                    # Retry with error context
                    prompt = self.prompt_builder.build_refinement_prompt(
                        original_query=user_question,
                        generated_sql=previous_sql,
                        error=previous_error
                    )

                # Generate SQL using LLM
                llm_response = self.llm_provider.generate(prompt, max_tokens=1000)

                # Extract SQL from response
                sql = self._extract_sql(llm_response)

                if not sql:
                    return QueryGenerationResult(
                        success=False,
                        error="Failed to extract SQL from LLM response",
                        attempts=attempt,
                        llm_response=llm_response
                    )

                # Validate SQL
                validation = self.sql_validator.validate(
                    sql,
                    allowed_tables=self._get_allowed_tables()
                )

                if validation.valid:
                    # Success
                    result_sql = validation.modified_sql or sql
                    explanation = None

                    if include_explanation:
                        explanation = self._generate_explanation(result_sql)

                    # Store in session if provided
                    if session_id:
                        self.session_manager.add_message(
                            session_id,
                            ConversationMessage(
                                role="user",
                                content=user_question
                            )
                        )
                        self.session_manager.add_message(
                            session_id,
                            ConversationMessage(
                                role="assistant",
                                content=explanation or "Generated SQL query",
                                sql=result_sql
                            )
                        )

                    # Cache successful query (only for standalone queries)
                    if self.query_cache and not session_id:
                        try:
                            self.query_cache.put(
                                query=user_question,
                                sql=result_sql,
                                explanation=explanation
                            )
                            logger.debug(f"Cached query: {user_question[:50]}...")
                        except Exception as e:
                            logger.warning(f"Failed to cache query: {e}")

                    return QueryGenerationResult(
                        success=True,
                        sql=result_sql,
                        explanation=explanation,
                        validation_warnings=validation.warnings,
                        attempts=attempt,
                        llm_response=llm_response,
                        from_cache=False
                    )
                else:
                    # Validation failed, retry
                    previous_sql = sql
                    previous_error = "; ".join(validation.errors)

            except Exception as e:
                return QueryGenerationResult(
                    success=False,
                    error=f"Error generating query: {str(e)}",
                    attempts=attempt
                )

        # All retries exhausted
        return QueryGenerationResult(
            success=False,
            error=f"Failed to generate valid SQL after {self.max_retries} attempts. Last error: {previous_error}",
            sql=previous_sql,
            attempts=self.max_retries
        )

    def refine_query(
        self,
        original_question: str,
        generated_sql: str,
        refinement_request: str,
        session_id: Optional[str] = None
    ) -> QueryGenerationResult:
        """Refine an existing query based on user feedback.

        Args:
            original_question: Original natural language question
            generated_sql: Previously generated SQL
            refinement_request: User's refinement request
            session_id: Optional session ID

        Returns:
            QueryGenerationResult
        """
        # Build refinement prompt
        prompt = self.prompt_builder.build_query_refinement_prompt(
            original_question=original_question,
            original_sql=generated_sql,
            refinement_request=refinement_request,
            schema_context=self.schema_context.build_context()
        )

        try:
            # Generate refined SQL
            llm_response = self.llm_provider.generate(prompt, max_tokens=1000)
            sql = self._extract_sql(llm_response)

            if not sql:
                return QueryGenerationResult(
                    success=False,
                    error="Failed to extract SQL from refinement response",
                    llm_response=llm_response
                )

            # Validate
            validation = self.sql_validator.validate(
                sql,
                allowed_tables=self._get_allowed_tables()
            )

            if validation.valid:
                result_sql = validation.modified_sql or sql

                # Store in session
                if session_id:
                    self.session_manager.add_message(
                        session_id,
                        ConversationMessage(
                            role="user",
                            content=refinement_request
                        )
                    )
                    self.session_manager.add_message(
                        session_id,
                        ConversationMessage(
                            role="assistant",
                            content="Refined SQL query",
                            sql=result_sql
                        )
                    )

                return QueryGenerationResult(
                    success=True,
                    sql=result_sql,
                    validation_warnings=validation.warnings,
                    llm_response=llm_response
                )
            else:
                return QueryGenerationResult(
                    success=False,
                    error="; ".join(validation.errors),
                    sql=sql
                )

        except Exception as e:
            return QueryGenerationResult(
                success=False,
                error=f"Error refining query: {str(e)}"
            )

    def explain_query(self, sql: str) -> str:
        """Generate natural language explanation of SQL query.

        Args:
            sql: SQL query to explain

        Returns:
            Natural language explanation
        """
        return self._generate_explanation(sql)

    def _extract_sql(self, llm_response: str) -> Optional[str]:
        """Extract SQL from LLM response.

        Args:
            llm_response: Raw LLM response

        Returns:
            Extracted SQL or None
        """
        # Try to extract SQL from code blocks
        code_block_pattern = r'```(?:sql)?\s*(SELECT.*?)```'
        match = re.search(code_block_pattern, llm_response, re.IGNORECASE | re.DOTALL)

        if match:
            return match.group(1).strip()

        # Try to find SELECT statement directly
        select_pattern = r'(SELECT\s+.*?)(?:\n\n|$)'
        match = re.search(select_pattern, llm_response, re.IGNORECASE | re.DOTALL)

        if match:
            return match.group(1).strip()

        # If response starts with SELECT, use entire response
        if llm_response.strip().upper().startswith('SELECT'):
            return llm_response.strip()

        return None

    def _generate_explanation(self, sql: str) -> str:
        """Generate explanation for SQL query.

        Args:
            sql: SQL query

        Returns:
            Natural language explanation
        """
        prompt = self.prompt_builder.build_explanation_prompt(sql)

        try:
            explanation = self.llm_provider.generate(prompt, max_tokens=500)
            return explanation.strip()
        except Exception as e:
            return f"Unable to generate explanation: {str(e)}"

    def _get_allowed_tables(self) -> List[str]:
        """Get list of allowed tables from schema context.

        Returns:
            List of table names
        """
        try:
            tables = self.schema_context.schema_source.get_tables()
            return [table.name for table in tables]
        except Exception:
            # Fallback to common tables
            return [
                "cloudtrail_logs",
                "vpc_flow_logs",
                "guardduty_findings",
                "normalized_auth_events",
                "normalized_network_events",
                "application_logs"
            ]


class DynamoDBSessionManager(SessionManager):
    """DynamoDB-backed session manager for production use."""

    def __init__(self, table_name: str, region: str = "us-east-1"):
        """Initialize DynamoDB session manager.

        Args:
            table_name: DynamoDB table name
            region: AWS region
        """
        super().__init__(storage_backend='dynamodb')
        self.table_name = table_name
        self.region = region
        self.table = None

    def _get_table(self):
        """Get or create DynamoDB table resource.

        Returns:
            DynamoDB table resource
        """
        if self.table is None:
            import boto3
            dynamodb = boto3.resource('dynamodb', region_name=self.region)
            self.table = dynamodb.Table(self.table_name)
        return self.table

    def add_message(self, session_id: str, message: ConversationMessage) -> None:
        """Add message to session in DynamoDB.

        Args:
            session_id: Session identifier
            message: Message to add
        """
        table = self._get_table()

        try:
            table.put_item(
                Item={
                    'session_id': session_id,
                    'timestamp': message.timestamp.isoformat(),
                    'role': message.role,
                    'content': message.content,
                    'sql': message.sql,
                    'ttl': int((message.timestamp.timestamp())) + (24 * 60 * 60)  # 24 hour TTL
                }
            )
        except Exception as e:
            print(f"Error storing message in DynamoDB: {e}")

    def get_history(self, session_id: str, limit: int = 5) -> List[ConversationMessage]:
        """Get conversation history from DynamoDB.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages

        Returns:
            List of conversation messages
        """
        table = self._get_table()

        try:
            response = table.query(
                KeyConditionExpression='session_id = :sid',
                ExpressionAttributeValues={':sid': session_id},
                ScanIndexForward=False,  # Most recent first
                Limit=limit
            )

            messages = []
            for item in reversed(response.get('Items', [])):
                messages.append(ConversationMessage(
                    role=item['role'],
                    content=item['content'],
                    timestamp=datetime.fromisoformat(item['timestamp']),
                    sql=item.get('sql')
                ))

            return messages

        except Exception as e:
            print(f"Error retrieving session history: {e}")
            return []

    def clear_session(self, session_id: str) -> None:
        """Clear session from DynamoDB.

        Args:
            session_id: Session identifier
        """
        table = self._get_table()

        try:
            # Query all items for session
            response = table.query(
                KeyConditionExpression='session_id = :sid',
                ExpressionAttributeValues={':sid': session_id}
            )

            # Delete each item
            for item in response.get('Items', []):
                table.delete_item(
                    Key={
                        'session_id': item['session_id'],
                        'timestamp': item['timestamp']
                    }
                )

        except Exception as e:
            print(f"Error clearing session: {e}")
