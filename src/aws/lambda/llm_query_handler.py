"""AWS Lambda handler for LLM-powered natural language queries."""

import json
import logging
import os
from typing import Any, Dict

from shared.llm import (
    QueryGenerator,
    SchemaContext,
    GlueSchemaSource,
    SQLValidator,
    DynamoDBSessionManager,
)
from shared.llm.providers import get_provider
from shared.detection.engine import AthenaQueryExecutor
from shared.auth import get_authenticated_user_id, AuthenticationError
from shared.auth.cors import get_cors_headers, cors_preflight_response
from shared.auth.rate_limiter import (
    get_rate_limiter,
    RateLimitExceeded,
    RateLimitConfig,
    rate_limit_response,
)

logger = logging.getLogger(__name__)

# Use strict rate limits for LLM queries (expensive operation)
_rate_limiter = None

def _get_rate_limiter():
    """Get or create rate limiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        config = RateLimitConfig.strict()  # 10/min, 100/hour, 1000/day
        _rate_limiter = get_rate_limiter("aws")
        _rate_limiter.config = config
    return _rate_limiter


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for natural language to SQL query generation and execution.

    This function:
    1. Receives natural language question from API Gateway
    2. Generates SQL using LLM
    3. Optionally executes the query against Athena
    4. Returns results

    Args:
        event: API Gateway event
        context: Lambda context

    Returns:
        API Gateway response
    """
    # Handle CORS preflight
    http_method = event.get('httpMethod', 'POST')
    if http_method == 'OPTIONS':
        return cors_preflight_response(event)

    # Authenticate user from JWT
    try:
        user_id = get_authenticated_user_id(event)
    except AuthenticationError:
        return _error_response(event, 'Authentication required', 401)

    # Check rate limit
    try:
        rate_limiter = _get_rate_limiter()
        rate_limiter.check_rate_limit(user_id, "llm_query")
    except RateLimitExceeded as e:
        logger.warning(f"Rate limit exceeded for user {user_id}")
        return rate_limit_response(e.retry_after, get_cors_headers(event))

    # Load configuration
    database_name = os.environ.get("ATHENA_DATABASE", "mantissa_logs")
    athena_output_location = os.environ.get("ATHENA_OUTPUT_LOCATION")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "bedrock")
    session_table = os.environ.get("SESSION_TABLE", "mantissa-log-sessions")
    max_result_rows = int(os.environ.get("MAX_RESULT_ROWS", "1000"))

    # Parse request body
    try:
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        else:
            body = event.get('body', {})

        user_question = body.get('question')
        execute_query = body.get('execute', False)
        session_id = body.get('session_id')
        include_explanation = body.get('explain', True)
        refinement_request = body.get('refinement')
        original_sql = body.get('original_sql')

        if not user_question:
            return _error_response(event, "Missing 'question' field in request", 400)

    except json.JSONDecodeError as e:
        return _error_response(event, f"Invalid JSON in request body: {str(e)}", 400)

    try:
        # Initialize components
        logger.info(f"Initializing query generator with provider: {llm_provider_name}")

        # Get LLM provider
        llm_provider = get_provider(llm_provider_name, region=aws_region)

        # Get schema context
        schema_source = GlueSchemaSource(database_name, region=aws_region)
        schema_context = SchemaContext(database_name, schema_source)

        # Get SQL validator
        sql_validator = SQLValidator(max_result_rows=max_result_rows)

        # Get session manager
        session_manager = DynamoDBSessionManager(
            table_name=session_table,
            region=aws_region
        )

        # Create query generator
        query_generator = QueryGenerator(
            llm_provider=llm_provider,
            schema_context=schema_context,
            sql_validator=sql_validator,
            session_manager=session_manager
        )

        # Generate or refine query
        if refinement_request and original_sql:
            logger.info(f"Refining query: {refinement_request}")
            result = query_generator.refine_query(
                original_question=user_question,
                generated_sql=original_sql,
                refinement_request=refinement_request,
                session_id=session_id
            )
        else:
            logger.info(f"Generating query for: {user_question}")
            result = query_generator.generate_query(
                user_question=user_question,
                session_id=session_id,
                include_explanation=include_explanation
            )

        if not result.success:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json",
                    **get_cors_headers(event)
                },
                "body": json.dumps({
                    "success": False,
                    "error": result.error,
                    "attempts": result.attempts
                })
            }

        # Build response
        response_data = {
            "success": True,
            "sql": result.sql,
            "explanation": result.explanation,
            "warnings": result.validation_warnings,
            "attempts": result.attempts
        }

        # Execute query if requested
        if execute_query and result.sql:
            logger.info("Executing generated SQL query")

            try:
                query_executor = AthenaQueryExecutor(
                    database=database_name,
                    output_location=athena_output_location,
                    region=aws_region
                )

                query_results = query_executor.execute_query(result.sql, timeout=120)

                response_data["results"] = query_results
                response_data["result_count"] = len(query_results)

                logger.info(f"Query executed successfully: {len(query_results)} rows returned")

            except Exception as e:
                logger.error(f"Error executing query: {e}")
                response_data["execution_error"] = str(e)
                response_data["results"] = []

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                **get_cors_headers(event)
            },
            "body": json.dumps(response_data)
        }

    except Exception as e:
        logger.error(f"Fatal error in query handler: {e}")
        import traceback
        traceback.print_exc()

        return _error_response(event, f"Internal server error: {str(e)}", 500)


def explain_query_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for explaining SQL queries.

    Args:
        event: API Gateway event with SQL in body
        context: Lambda context

    Returns:
        API Gateway response with explanation
    """
    # Handle CORS preflight
    http_method = event.get('httpMethod', 'POST')
    if http_method == 'OPTIONS':
        return cors_preflight_response(event)

    # Authenticate user from JWT
    try:
        user_id = get_authenticated_user_id(event)
    except AuthenticationError:
        return _error_response(event, 'Authentication required', 401)

    # Check rate limit
    try:
        rate_limiter = _get_rate_limiter()
        rate_limiter.check_rate_limit(user_id, "llm_explain")
    except RateLimitExceeded as e:
        logger.warning(f"Rate limit exceeded for user {user_id}")
        return rate_limit_response(e.retry_after, get_cors_headers(event))

    # Load configuration
    database_name = os.environ.get("ATHENA_DATABASE", "mantissa_logs")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "bedrock")

    try:
        # Parse request
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        else:
            body = event.get('body', {})

        sql = body.get('sql')

        if not sql:
            return _error_response(event, "Missing 'sql' field in request", 400)

        # Initialize components
        llm_provider = get_provider(llm_provider_name, region=aws_region)
        schema_source = GlueSchemaSource(database_name, region=aws_region)
        schema_context = SchemaContext(database_name, schema_source)
        sql_validator = SQLValidator()

        query_generator = QueryGenerator(
            llm_provider=llm_provider,
            schema_context=schema_context,
            sql_validator=sql_validator
        )

        # Generate explanation
        explanation = query_generator.explain_query(sql)

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                **get_cors_headers(event)
            },
            "body": json.dumps({
                "success": True,
                "sql": sql,
                "explanation": explanation
            })
        }

    except Exception as e:
        logger.error(f"Error explaining query: {e}")
        return _error_response(event, str(e), 500)


def _error_response(event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response with secure CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            **get_cors_headers(event)
        },
        "body": json.dumps({
            "success": False,
            "error": message
        })
    }
