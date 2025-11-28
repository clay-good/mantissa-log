"""Unit tests for QueryGenerator."""

from datetime import datetime
from unittest.mock import Mock, MagicMock

import pytest

from src.shared.llm.query_generator import (
    QueryGenerator,
    QueryGenerationResult,
    SessionManager,
    ConversationMessage,
)
from src.shared.llm.sql_validator import ValidationResult


@pytest.fixture
def mock_llm_provider():
    """Create mock LLM provider."""
    provider = Mock()
    provider.generate.return_value = "SELECT * FROM cloudtrail_logs WHERE eventTime >= '2025-01-27' LIMIT 1000"
    return provider


@pytest.fixture
def mock_schema_context():
    """Create mock schema context."""
    context = Mock()
    context.build_context.return_value = "Mock schema context"

    # Mock schema source
    mock_table = Mock()
    mock_table.name = "cloudtrail_logs"

    context.schema_source = Mock()
    context.schema_source.get_tables.return_value = [mock_table]

    return context


@pytest.fixture
def mock_sql_validator():
    """Create mock SQL validator."""
    validator = Mock()
    validator.validate.return_value = ValidationResult(
        valid=True,
        errors=[],
        warnings=[],
        modified_sql=None
    )
    return validator


@pytest.fixture
def mock_prompt_builder():
    """Create mock prompt builder."""
    return Mock()


@pytest.fixture
def query_generator(mock_llm_provider, mock_schema_context, mock_sql_validator):
    """Create QueryGenerator instance with mocked dependencies."""
    return QueryGenerator(
        llm_provider=mock_llm_provider,
        schema_context=mock_schema_context,
        sql_validator=mock_sql_validator
    )


class TestQueryGenerator:
    """Tests for QueryGenerator class."""

    def test_generate_query_success(self, query_generator, mock_llm_provider):
        """Test successful query generation."""
        result = query_generator.generate_query("Show me CloudTrail logs from today")

        assert result.success
        assert result.sql is not None
        assert "SELECT" in result.sql.upper()
        assert result.error is None
        assert result.attempts == 1

        # Verify LLM was called
        mock_llm_provider.generate.assert_called_once()

    def test_generate_query_with_explanation(self, query_generator, mock_llm_provider):
        """Test query generation with explanation."""
        # Mock both SQL generation and explanation
        mock_llm_provider.generate.side_effect = [
            "SELECT * FROM cloudtrail_logs LIMIT 1000",
            "This query retrieves CloudTrail logs."
        ]

        result = query_generator.generate_query(
            "Show me CloudTrail logs",
            include_explanation=True
        )

        assert result.success
        assert result.explanation is not None
        assert len(result.explanation) > 0

        # Should be called twice: once for SQL, once for explanation
        assert mock_llm_provider.generate.call_count == 2

    def test_generate_query_extraction_from_code_block(self, query_generator, mock_llm_provider):
        """Test SQL extraction from markdown code block."""
        mock_llm_provider.generate.return_value = """
```sql
SELECT eventName, eventTime
FROM cloudtrail_logs
WHERE year = 2025
LIMIT 100
```
"""

        result = query_generator.generate_query("Show me events")

        assert result.success
        assert "SELECT" in result.sql
        assert "```" not in result.sql

    def test_generate_query_extraction_plain_sql(self, query_generator, mock_llm_provider):
        """Test SQL extraction when LLM returns plain SQL."""
        sql = "SELECT * FROM vpc_flow_logs LIMIT 500"
        mock_llm_provider.generate.return_value = sql

        result = query_generator.generate_query("Show me network traffic")

        assert result.success
        assert result.sql == sql

    def test_generate_query_validation_failure_retry(
        self,
        query_generator,
        mock_llm_provider,
        mock_sql_validator
    ):
        """Test retry logic when validation fails."""
        # First attempt fails validation, second succeeds
        mock_sql_validator.validate.side_effect = [
            ValidationResult(
                valid=False,
                errors=["Invalid syntax"],
                warnings=[],
                modified_sql=None
            ),
            ValidationResult(
                valid=True,
                errors=[],
                warnings=[],
                modified_sql=None
            )
        ]

        mock_llm_provider.generate.return_value = "SELECT * FROM cloudtrail_logs LIMIT 1000"

        result = query_generator.generate_query("Show me logs")

        assert result.success
        assert result.attempts == 2

    def test_generate_query_max_retries_exhausted(
        self,
        query_generator,
        mock_llm_provider,
        mock_sql_validator
    ):
        """Test behavior when max retries are exhausted."""
        # Always fail validation
        mock_sql_validator.validate.return_value = ValidationResult(
            valid=False,
            errors=["Invalid query"],
            warnings=[],
            modified_sql=None
        )

        result = query_generator.generate_query("Invalid question")

        assert not result.success
        assert result.error is not None
        assert result.attempts == query_generator.max_retries

    def test_generate_query_no_sql_extracted(self, query_generator, mock_llm_provider):
        """Test handling when no SQL can be extracted from response."""
        mock_llm_provider.generate.return_value = "I cannot generate a query for this."

        result = query_generator.generate_query("Nonsensical question???")

        assert not result.success
        assert "Failed to extract SQL" in result.error

    def test_generate_query_with_session(self, query_generator):
        """Test query generation with session context."""
        session_id = "test-session-123"

        result = query_generator.generate_query(
            "Show me failed logins",
            session_id=session_id
        )

        assert result.success

        # Check session was updated
        history = query_generator.session_manager.get_history(session_id)
        assert len(history) == 2  # User question + assistant response
        assert history[0].role == "user"
        assert history[1].role == "assistant"
        assert history[1].sql is not None

    def test_refine_query(self, query_generator, mock_llm_provider):
        """Test query refinement."""
        original_sql = "SELECT * FROM cloudtrail_logs LIMIT 100"
        refined_sql = "SELECT * FROM cloudtrail_logs WHERE year = 2025 LIMIT 100"

        mock_llm_provider.generate.return_value = refined_sql

        result = query_generator.refine_query(
            original_question="Show me logs",
            generated_sql=original_sql,
            refinement_request="Only from this year"
        )

        assert result.success
        assert result.sql == refined_sql

    def test_explain_query(self, query_generator, mock_llm_provider):
        """Test query explanation generation."""
        mock_llm_provider.generate.return_value = "This query retrieves all CloudTrail events."

        sql = "SELECT * FROM cloudtrail_logs"
        explanation = query_generator.explain_query(sql)

        assert len(explanation) > 0
        assert "CloudTrail" in explanation

    def test_extract_sql_variations(self, query_generator):
        """Test SQL extraction from various response formats."""
        # Test code block with sql language
        response1 = "```sql\nSELECT 1\n```"
        sql1 = query_generator._extract_sql(response1)
        assert sql1 == "SELECT 1"

        # Test code block without language
        response2 = "```\nSELECT 2\n```"
        sql2 = query_generator._extract_sql(response2)
        assert sql2 == "SELECT 2"

        # Test plain SQL
        response3 = "SELECT 3"
        sql3 = query_generator._extract_sql(response3)
        assert sql3 == "SELECT 3"

        # Test with explanation before SQL
        response4 = "Here is your query:\nSELECT 4 FROM table"
        sql4 = query_generator._extract_sql(response4)
        assert "SELECT 4" in sql4

    def test_get_allowed_tables(self, query_generator, mock_schema_context):
        """Test getting allowed tables from schema context."""
        tables = query_generator._get_allowed_tables()

        assert isinstance(tables, list)
        assert "cloudtrail_logs" in tables

    def test_llm_provider_error(self, query_generator, mock_llm_provider):
        """Test handling of LLM provider errors."""
        mock_llm_provider.generate.side_effect = Exception("API error")

        result = query_generator.generate_query("Show me logs")

        assert not result.success
        assert "Error generating query" in result.error


class TestSessionManager:
    """Tests for SessionManager class."""

    def test_add_message(self):
        """Test adding messages to session."""
        manager = SessionManager()
        session_id = "test-session"

        message = ConversationMessage(
            role="user",
            content="Show me logs"
        )

        manager.add_message(session_id, message)

        history = manager.get_history(session_id)
        assert len(history) == 1
        assert history[0].role == "user"
        assert history[0].content == "Show me logs"

    def test_get_history_limit(self):
        """Test history retrieval with limit."""
        manager = SessionManager()
        session_id = "test-session"

        # Add 10 messages
        for i in range(10):
            manager.add_message(
                session_id,
                ConversationMessage(role="user", content=f"Message {i}")
            )

        # Get last 5
        history = manager.get_history(session_id, limit=5)
        assert len(history) == 5
        assert history[-1].content == "Message 9"

    def test_session_message_limit(self):
        """Test that sessions are limited to 10 messages."""
        manager = SessionManager()
        session_id = "test-session"

        # Add 15 messages
        for i in range(15):
            manager.add_message(
                session_id,
                ConversationMessage(role="user", content=f"Message {i}")
            )

        # Should only keep last 10
        history = manager.get_history(session_id, limit=20)
        assert len(history) == 10
        assert history[0].content == "Message 5"

    def test_clear_session(self):
        """Test clearing session."""
        manager = SessionManager()
        session_id = "test-session"

        manager.add_message(
            session_id,
            ConversationMessage(role="user", content="Test")
        )

        assert len(manager.get_history(session_id)) == 1

        manager.clear_session(session_id)

        assert len(manager.get_history(session_id)) == 0

    def test_nonexistent_session(self):
        """Test getting history for non-existent session."""
        manager = SessionManager()

        history = manager.get_history("nonexistent")
        assert len(history) == 0


class TestQueryGenerationResult:
    """Tests for QueryGenerationResult class."""

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = QueryGenerationResult(
            success=True,
            sql="SELECT * FROM table",
            explanation="Test explanation",
            validation_warnings=["Warning 1"],
            attempts=1
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is True
        assert result_dict["sql"] == "SELECT * FROM table"
        assert result_dict["explanation"] == "Test explanation"
        assert len(result_dict["validation_warnings"]) == 1
        assert result_dict["attempts"] == 1


class TestConversationMessage:
    """Tests for ConversationMessage class."""

    def test_to_dict(self):
        """Test converting message to dictionary."""
        timestamp = datetime(2025, 1, 27, 12, 0, 0)
        message = ConversationMessage(
            role="user",
            content="Show me logs",
            timestamp=timestamp,
            sql="SELECT * FROM logs"
        )

        msg_dict = message.to_dict()

        assert msg_dict["role"] == "user"
        assert msg_dict["content"] == "Show me logs"
        assert msg_dict["timestamp"] == timestamp.isoformat()
        assert msg_dict["sql"] == "SELECT * FROM logs"
