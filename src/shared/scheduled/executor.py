"""
Scheduled Query Executor

Executes NL queries on schedule and generates summaries for Slack output.
"""

import os
import time
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any, Optional

from .config import ScheduledQueryConfig
from .manager import ScheduledQuery, ScheduledQueryManager

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of scheduled query execution."""

    success: bool
    query_id: str
    generated_sql: Optional[str] = None
    results: List[Dict[str, Any]] = None
    result_count: int = 0
    duration_ms: int = 0
    summary: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.results is None:
            self.results = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'success': self.success,
            'query_id': self.query_id,
            'generated_sql': self.generated_sql,
            'result_count': self.result_count,
            'duration_ms': self.duration_ms,
            'summary': self.summary,
            'error': self.error
        }


class ScheduledQueryExecutor:
    """
    Executes scheduled NL queries and generates intelligence summaries.

    Flow:
    1. Receive query_id from EventBridge trigger
    2. Load query from DynamoDB
    3. Execute NL query using QueryGenerator
    4. Generate LLM summary of results
    5. Format and send to Slack
    6. Record execution history
    """

    def __init__(
        self,
        config: Optional[ScheduledQueryConfig] = None,
        manager: Optional[ScheduledQueryManager] = None,
        query_generator: Optional[Any] = None,
        athena_executor: Optional[Any] = None,
        llm_provider: Optional[Any] = None
    ):
        """
        Initialize scheduled query executor.

        Args:
            config: Execution configuration
            manager: ScheduledQueryManager instance
            query_generator: QueryGenerator instance for NL-to-SQL
            athena_executor: Query executor for running SQL
            llm_provider: LLM provider for summary generation
        """
        self.config = config or ScheduledQueryConfig.from_environment()
        self.manager = manager or ScheduledQueryManager()
        self._query_generator = query_generator
        self._athena_executor = athena_executor
        self._llm_provider = llm_provider

    @property
    def query_generator(self):
        """Lazy-load query generator."""
        if self._query_generator is None:
            from ..llm.query_generator import QueryGenerator
            from ..llm.providers.anthropic import AnthropicProvider
            from ..llm.schema_context import SchemaContext
            from ..llm.sql_validator import SQLValidator

            provider = AnthropicProvider()
            schema_context = SchemaContext()
            validator = SQLValidator()

            self._query_generator = QueryGenerator(
                llm_provider=provider,
                schema_context=schema_context,
                sql_validator=validator
            )
        return self._query_generator

    @property
    def athena_executor(self):
        """Lazy-load Athena executor."""
        if self._athena_executor is None:
            import boto3
            self._athena_executor = boto3.client('athena')
        return self._athena_executor

    @property
    def llm_provider(self):
        """Lazy-load LLM provider."""
        if self._llm_provider is None:
            from ..llm.providers.anthropic import AnthropicProvider
            self._llm_provider = AnthropicProvider(
                model=self.config.llm_model
            )
        return self._llm_provider

    def execute(self, query_id: str) -> ExecutionResult:
        """
        Execute a scheduled query by ID.

        Args:
            query_id: Query ID to execute

        Returns:
            ExecutionResult with summary
        """
        start_time = time.time()

        # Load query
        query = self.manager.get_query_by_id(query_id)
        if not query:
            logger.error(f"Query not found: {query_id}")
            return ExecutionResult(
                success=False,
                query_id=query_id,
                error="Query not found"
            )

        if not query.enabled:
            logger.info(f"Query disabled, skipping: {query_id}")
            return ExecutionResult(
                success=False,
                query_id=query_id,
                error="Query is disabled"
            )

        try:
            # Step 1: Generate SQL from NL query
            logger.info(f"Generating SQL for query: {query.query_text[:100]}...")
            gen_result = self.query_generator.generate_query(
                user_question=query.query_text,
                include_explanation=True
            )

            if not gen_result.success:
                error_msg = f"Failed to generate SQL: {gen_result.error}"
                logger.error(error_msg)

                self._record_execution(
                    query, 'failed', int((time.time() - start_time) * 1000),
                    0, False, error_msg
                )

                return ExecutionResult(
                    success=False,
                    query_id=query_id,
                    error=error_msg
                )

            generated_sql = gen_result.sql
            logger.info(f"Generated SQL: {generated_sql[:200]}...")

            # Step 2: Execute SQL query
            results = self._execute_sql(generated_sql)
            result_count = len(results)
            logger.info(f"Query returned {result_count} results")

            # Step 3: Generate LLM summary
            summary = None
            if self.config.use_llm_for_summary and results:
                summary = self._generate_summary(query, results, gen_result.explanation)
            elif results:
                summary = self._generate_basic_summary(query, results)
            else:
                summary = self._generate_no_results_summary(query)

            # Step 4: Send to Slack
            slack_sent = self._send_to_slack(query, summary, results, generated_sql)

            # Step 5: Record execution
            duration_ms = int((time.time() - start_time) * 1000)
            self._record_execution(
                query, 'success', duration_ms, result_count, slack_sent,
                generated_sql=generated_sql
            )

            return ExecutionResult(
                success=True,
                query_id=query_id,
                generated_sql=generated_sql,
                results=results[:100],  # Limit results in response
                result_count=result_count,
                duration_ms=duration_ms,
                summary=summary
            )

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error executing scheduled query: {error_msg}")
            import traceback
            traceback.print_exc()

            duration_ms = int((time.time() - start_time) * 1000)
            self._record_execution(query, 'failed', duration_ms, 0, False, error_msg)

            return ExecutionResult(
                success=False,
                query_id=query_id,
                duration_ms=duration_ms,
                error=error_msg
            )

    def _execute_sql(self, sql: str) -> List[Dict[str, Any]]:
        """Execute SQL query via Athena."""
        database = os.environ.get('ATHENA_DATABASE', 'mantissa_log')
        output_location = os.environ.get('ATHENA_OUTPUT', 's3://mantissa-log-query-results/')

        # Start query
        response = self.athena_executor.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={'Database': database},
            ResultConfiguration={'OutputLocation': output_location}
        )

        query_id = response['QueryExecutionId']

        # Wait for completion
        max_wait = self.config.max_execution_time_seconds
        for _ in range(max_wait):
            status = self.athena_executor.get_query_execution(QueryExecutionId=query_id)
            state = status['QueryExecution']['Status']['State']

            if state == 'SUCCEEDED':
                break
            elif state in ['FAILED', 'CANCELLED']:
                error = status['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
                raise Exception(f"Query failed: {error}")

            time.sleep(1)
        else:
            raise Exception(f"Query timed out after {max_wait} seconds")

        # Get results
        results = []
        paginator = self.athena_executor.get_paginator('get_query_results')

        headers = None
        for page in paginator.paginate(QueryExecutionId=query_id):
            rows = page['ResultSet']['Rows']

            if headers is None and rows:
                headers = [col.get('VarCharValue', f'col_{i}') for i, col in enumerate(rows[0]['Data'])]
                rows = rows[1:]

            for row in rows:
                if len(results) >= self.config.max_results_per_query:
                    break

                result = {}
                for i, col in enumerate(row['Data']):
                    if i < len(headers):
                        result[headers[i]] = col.get('VarCharValue')
                results.append(result)

        return results

    def _generate_summary(
        self,
        query: ScheduledQuery,
        results: List[Dict[str, Any]],
        explanation: Optional[str] = None
    ) -> str:
        """Generate LLM-powered summary of query results."""
        # Build prompt for summary generation
        results_sample = results[:50]  # Limit context size
        results_text = self._format_results_for_prompt(results_sample)

        prompt = f"""You are a security analyst providing an intelligence summary.

SCHEDULED QUERY: {query.name}
QUERY TEXT: {query.query_text}

{f"QUERY EXPLANATION: {explanation}" if explanation else ""}

TOTAL RESULTS: {len(results)}

SAMPLE RESULTS:
{results_text}

Generate a concise intelligence summary suitable for a Slack message. Include:
1. Key findings and patterns
2. Notable anomalies or concerns
3. Recommended actions (if any)

Keep the summary under 2000 characters. Use bullet points for clarity.
Do not include any emojis."""

        try:
            summary = self.llm_provider.generate(
                prompt,
                max_tokens=self.config.max_tokens_for_summary
            )
            return summary.strip()
        except Exception as e:
            logger.warning(f"Failed to generate LLM summary: {e}")
            return self._generate_basic_summary(query, results)

    def _generate_basic_summary(
        self,
        query: ScheduledQuery,
        results: List[Dict[str, Any]]
    ) -> str:
        """Generate basic summary without LLM."""
        summary_lines = [
            f"*{query.name}*",
            f"Query: {query.query_text}",
            f"",
            f"*Results: {len(results)} records found*",
        ]

        if results:
            # Show first few results
            summary_lines.append("")
            summary_lines.append("*Sample Results:*")

            for i, result in enumerate(results[:5]):
                # Format each result as key-value pairs
                result_str = " | ".join([f"{k}: {v}" for k, v in list(result.items())[:4]])
                summary_lines.append(f"{i+1}. {result_str[:200]}")

            if len(results) > 5:
                summary_lines.append(f"...and {len(results) - 5} more records")

        return "\n".join(summary_lines)

    def _generate_no_results_summary(self, query: ScheduledQuery) -> str:
        """Generate summary when no results found."""
        return f"""*{query.name}*
Query: {query.query_text}

*No results found*

This may indicate:
- No matching events in the analysis window
- Query criteria too restrictive
- Data not yet available"""

    def _format_results_for_prompt(self, results: List[Dict[str, Any]]) -> str:
        """Format results for LLM prompt."""
        if not results:
            return "No results"

        lines = []
        for i, result in enumerate(results[:20]):
            # Truncate long values
            formatted = {}
            for k, v in result.items():
                if v and len(str(v)) > 100:
                    formatted[k] = str(v)[:100] + "..."
                else:
                    formatted[k] = v
            lines.append(f"{i+1}. {formatted}")

        if len(results) > 20:
            lines.append(f"... ({len(results) - 20} more results)")

        return "\n".join(lines)

    def _send_to_slack(
        self,
        query: ScheduledQuery,
        summary: str,
        results: List[Dict[str, Any]],
        generated_sql: str
    ) -> bool:
        """Send summary to Slack channel."""
        import requests

        webhook_url = query.webhook_url
        if not webhook_url:
            # Try to get from integrations
            webhook_url = self._get_slack_webhook(query.output_channel)

        if not webhook_url:
            logger.warning(f"No Slack webhook configured for channel: {query.output_channel}")
            return False

        try:
            # Build Slack message
            from .formatters import SlackSummaryFormatter
            formatter = SlackSummaryFormatter(self.config)
            payload = formatter.format(query, summary, results, generated_sql)

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=self.config.slack_webhook_timeout
            )
            response.raise_for_status()

            logger.info(f"Sent summary to Slack channel: {query.output_channel}")
            return True

        except Exception as e:
            logger.error(f"Failed to send to Slack: {e}")
            return False

    def _get_slack_webhook(self, channel: str) -> Optional[str]:
        """Get Slack webhook URL from integrations."""
        try:
            import boto3
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(
                os.environ.get('INTEGRATIONS_TABLE', 'mantissa-log-integrations')
            )

            # Look for Slack integration matching channel
            response = table.scan(
                FilterExpression='integration_type = :type AND enabled = :enabled',
                ExpressionAttributeValues={
                    ':type': 'slack',
                    ':enabled': True
                }
            )

            for item in response.get('Items', []):
                config = item.get('config', {})
                if config.get('channel') == channel:
                    return config.get('webhook_url')

            # Return first enabled Slack integration as fallback
            items = response.get('Items', [])
            if items:
                return items[0].get('config', {}).get('webhook_url')

            return None

        except Exception as e:
            logger.warning(f"Failed to get Slack webhook: {e}")
            return None

    def _record_execution(
        self,
        query: ScheduledQuery,
        status: str,
        duration_ms: int,
        result_count: int,
        summary_sent: bool,
        error_message: Optional[str] = None,
        generated_sql: Optional[str] = None
    ) -> None:
        """Record execution in history."""
        try:
            self.manager.record_execution(
                query=query,
                status=status,
                duration_ms=duration_ms,
                result_count=result_count,
                summary_sent=summary_sent,
                error_message=error_message,
                generated_sql=generated_sql
            )
        except Exception as e:
            logger.warning(f"Failed to record execution: {e}")
