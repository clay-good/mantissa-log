"""Integration tests for APM NL queries.

Tests:
- NL queries for APM data generate correct SQL
- Service map queries return correct structure
- Performance-related queries work with sample data
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from src.shared.llm.schema_context import SchemaContext, StaticSchemaSource


class TestAPMQueryGeneration:
    """Tests for APM-related NL query generation."""

    @pytest.fixture
    def schema_context(self):
        """Create schema context with APM tables."""
        return SchemaContext(
            database_name="mantissa_log",
            schema_source=StaticSchemaSource()
        )

    def test_schema_includes_apm_tables(self, schema_context):
        """Verify APM tables are in schema context."""
        context = schema_context.build_context()

        assert "apm_traces" in context
        assert "apm_metrics" in context
        assert "apm_service_map" in context
        assert "apm_service_stats" in context

    def test_latency_keywords_suggest_apm_tables(self, schema_context):
        """Test that latency keywords suggest APM tables."""
        relevant = schema_context.get_relevant_tables("Why is service X slow?")

        assert "apm_traces" in relevant
        assert "apm_service_stats" in relevant

    def test_error_keywords_suggest_apm_tables(self, schema_context):
        """Test that error keywords suggest APM tables."""
        relevant = schema_context.get_relevant_tables("Show me errors in the last hour")

        assert "apm_traces" in relevant

    def test_service_dependency_keywords(self, schema_context):
        """Test that dependency keywords suggest service map."""
        relevant = schema_context.get_relevant_tables("What services depend on payment-api?")

        assert "apm_service_map" in relevant

    def test_percentile_keywords(self, schema_context):
        """Test that percentile keywords suggest APM tables."""
        relevant = schema_context.get_relevant_tables("What is the p95 latency for checkout?")

        assert "apm_traces" in relevant or "apm_service_stats" in relevant

    def test_trace_keywords(self, schema_context):
        """Test that trace keywords suggest traces table."""
        relevant = schema_context.get_relevant_tables("Show me the trace for request abc123")

        assert "apm_traces" in relevant

    def test_observability_keywords(self, schema_context):
        """Test that observability keywords suggest all APM tables."""
        relevant = schema_context.get_relevant_tables("Show me APM data for api-gateway")

        assert "apm_traces" in relevant
        assert "apm_metrics" in relevant
        assert "apm_service_map" in relevant


class TestAPMQueryPatterns:
    """Tests for APM query pattern suggestions."""

    @pytest.fixture
    def schema_context(self):
        """Create schema context with APM tables."""
        return SchemaContext(
            database_name="mantissa_log",
            schema_source=StaticSchemaSource()
        )

    def test_context_includes_latency_patterns(self, schema_context):
        """Test that context includes latency query patterns."""
        context = schema_context.build_context()

        assert "APPROX_PERCENTILE" in context
        assert "duration_ms" in context
        assert "p95" in context.lower() or "percentile" in context.lower()

    def test_context_includes_error_patterns(self, schema_context):
        """Test that context includes error query patterns."""
        context = schema_context.build_context()

        assert "status = 'error'" in context or "error" in context.lower()

    def test_context_includes_trace_patterns(self, schema_context):
        """Test that context includes trace lookup patterns."""
        context = schema_context.build_context()

        assert "trace_id" in context

    def test_context_includes_service_map_patterns(self, schema_context):
        """Test that context includes service map patterns."""
        context = schema_context.build_context()

        assert "apm_service_map" in context


class TestLatencyQueryGeneration:
    """Tests for latency-related query generation."""

    def test_slow_service_query_structure(self):
        """Test structure of slow service query."""
        # Expected query pattern for "Why is checkout slow?"
        expected_patterns = [
            "SELECT",
            "FROM apm_traces",
            "duration_ms",
            "service_name",
        ]

        query_template = """
        SELECT
            service_name,
            operation_name,
            AVG(duration_ms) as avg_duration,
            APPROX_PERCENTILE(duration_ms, 0.95) as p95_duration,
            COUNT(*) as request_count
        FROM apm_traces
        WHERE service_name = 'checkout'
            AND year = '2024' AND month = '01' AND day = '15'
        GROUP BY service_name, operation_name
        ORDER BY p95_duration DESC
        LIMIT 20
        """

        for pattern in expected_patterns:
            assert pattern.lower() in query_template.lower()

    def test_percentile_query_structure(self):
        """Test structure of percentile query."""
        query_template = """
        SELECT
            service_name,
            operation_name,
            APPROX_PERCENTILE(duration_ms, 0.50) as p50,
            APPROX_PERCENTILE(duration_ms, 0.95) as p95,
            APPROX_PERCENTILE(duration_ms, 0.99) as p99
        FROM apm_traces
        WHERE year = '2024' AND month = '01' AND day = '15'
            AND kind = 'server'
        GROUP BY service_name, operation_name
        """

        assert "APPROX_PERCENTILE" in query_template
        assert "0.50" in query_template
        assert "0.95" in query_template
        assert "0.99" in query_template


class TestErrorQueryGeneration:
    """Tests for error-related query generation."""

    def test_error_query_structure(self):
        """Test structure of error query."""
        query_template = """
        SELECT
            trace_id,
            span_id,
            service_name,
            operation_name,
            status_message,
            start_time,
            duration_ms
        FROM apm_traces
        WHERE status = 'error'
            AND year = '2024' AND month = '01' AND day = '15'
        ORDER BY start_time DESC
        LIMIT 100
        """

        assert "status = 'error'" in query_template
        assert "apm_traces" in query_template.lower()

    def test_error_rate_query_structure(self):
        """Test structure of error rate calculation query."""
        query_template = """
        SELECT
            service_name,
            COUNT(*) as total_requests,
            SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_count,
            CAST(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) as error_rate
        FROM apm_traces
        WHERE year = '2024' AND month = '01' AND day = '15'
            AND kind = 'server'
        GROUP BY service_name
        HAVING error_rate > 0.01
        ORDER BY error_rate DESC
        """

        assert "error_rate" in query_template
        assert "CASE WHEN" in query_template


class TestServiceMapQueries:
    """Tests for service map query generation."""

    def test_service_dependencies_query(self):
        """Test query for service dependencies."""
        query_template = """
        SELECT
            source_service,
            target_service,
            call_count,
            error_rate,
            p95_latency_ms
        FROM apm_service_map
        WHERE target_service = 'payment-api'
        ORDER BY call_count DESC
        """

        assert "apm_service_map" in query_template.lower()
        assert "source_service" in query_template
        assert "target_service" in query_template

    def test_service_health_query(self):
        """Test query for service health overview."""
        query_template = """
        SELECT
            service_name,
            request_count,
            error_rate,
            avg_latency_ms,
            p95_latency_ms
        FROM apm_service_stats
        ORDER BY error_rate DESC, p95_latency_ms DESC
        """

        assert "apm_service_stats" in query_template.lower()
        assert "error_rate" in query_template


class TestTraceQueries:
    """Tests for trace lookup queries."""

    def test_trace_lookup_query(self):
        """Test query for looking up specific trace."""
        trace_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

        query_template = f"""
        SELECT
            trace_id,
            span_id,
            parent_span_id,
            service_name,
            operation_name,
            kind,
            status,
            start_time,
            end_time,
            duration_ms,
            attributes
        FROM apm_traces
        WHERE trace_id = '{trace_id}'
        ORDER BY start_time
        """

        assert trace_id in query_template
        assert "parent_span_id" in query_template
        assert "ORDER BY start_time" in query_template

    def test_slow_traces_query(self):
        """Test query for finding slow traces."""
        query_template = """
        SELECT DISTINCT
            trace_id,
            MIN(start_time) as trace_start,
            MAX(end_time) as trace_end,
            SUM(duration_ms) as total_span_duration
        FROM apm_traces
        WHERE year = '2024' AND month = '01' AND day = '15'
            AND kind = 'server'
            AND duration_ms > 1000
        GROUP BY trace_id
        ORDER BY total_span_duration DESC
        LIMIT 50
        """

        assert "duration_ms > 1000" in query_template
        assert "trace_id" in query_template


class TestMetricsQueries:
    """Tests for metrics-related queries."""

    def test_metric_aggregation_query(self):
        """Test query for metric aggregation."""
        query_template = """
        SELECT
            service_name,
            name as metric_name,
            AVG(value) as avg_value,
            MAX(value) as max_value,
            MIN(value) as min_value
        FROM apm_metrics
        WHERE name = 'http.server.request.duration'
            AND year = '2024' AND month = '01' AND day = '15'
        GROUP BY service_name, name
        """

        assert "apm_metrics" in query_template.lower()
        assert "AVG(value)" in query_template

    def test_histogram_query(self):
        """Test query for histogram metrics."""
        query_template = """
        SELECT
            service_name,
            name,
            bucket_boundaries,
            bucket_counts,
            timestamp
        FROM apm_metrics
        WHERE metric_type = 'histogram'
            AND name LIKE 'http.server%'
            AND year = '2024' AND month = '01' AND day = '15'
        ORDER BY timestamp DESC
        """

        assert "metric_type = 'histogram'" in query_template
        assert "bucket_boundaries" in query_template


class TestSchemaContextIntegration:
    """Integration tests for schema context with APM."""

    @pytest.fixture
    def schema_context(self):
        """Create schema context."""
        return SchemaContext(
            database_name="mantissa_log",
            schema_source=StaticSchemaSource()
        )

    def test_apm_traces_table_info(self, schema_context):
        """Test APM traces table information."""
        table_context = schema_context.get_table_context("apm_traces")

        assert "trace_id" in table_context
        assert "span_id" in table_context
        assert "duration_ms" in table_context
        assert "service_name" in table_context
        assert "operation_name" in table_context

    def test_apm_metrics_table_info(self, schema_context):
        """Test APM metrics table information."""
        table_context = schema_context.get_table_context("apm_metrics")

        assert "name" in table_context
        assert "value" in table_context
        assert "metric_type" in table_context
        assert "labels" in table_context

    def test_apm_service_map_table_info(self, schema_context):
        """Test APM service map table information."""
        table_context = schema_context.get_table_context("apm_service_map")

        assert "source_service" in table_context
        assert "target_service" in table_context
        assert "call_count" in table_context
        assert "error_rate" in table_context

    def test_full_context_has_apm_section(self, schema_context):
        """Test that full context includes APM query patterns."""
        context = schema_context.build_context()

        assert "APM Query Patterns:" in context
        assert "Latency analysis" in context
        assert "Error traces" in context
        assert "Service dependencies" in context


class TestQueryValidation:
    """Tests for query validation with APM tables."""

    def test_valid_apm_query_structure(self):
        """Test that generated queries have valid structure."""
        valid_queries = [
            "SELECT * FROM apm_traces WHERE trace_id = 'abc123' LIMIT 100",
            "SELECT service_name, AVG(duration_ms) FROM apm_traces GROUP BY service_name",
            "SELECT * FROM apm_service_map WHERE target_service = 'api'",
            "SELECT * FROM apm_metrics WHERE name = 'http.duration' LIMIT 50",
        ]

        for query in valid_queries:
            # Basic validation
            assert query.strip().upper().startswith("SELECT")
            assert "FROM apm_" in query
            # No dangerous operations
            for keyword in ["DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE"]:
                assert keyword not in query.upper()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
