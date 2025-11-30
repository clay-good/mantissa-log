"""AWS Lambda handler for LLM-powered natural language queries."""

import json
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
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Missing 'question' field in request"})
            }

    except json.JSONDecodeError as e:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"Invalid JSON in request body: {str(e)}"})
        }

    try:
        # Initialize components
        print(f"Initializing query generator with provider: {llm_provider_name}")

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
            print(f"Refining query: {refinement_request}")
            result = query_generator.refine_query(
                original_question=user_question,
                generated_sql=original_sql,
                refinement_request=refinement_request,
                session_id=session_id
            )
        else:
            print(f"Generating query for: {user_question}")
            result = query_generator.generate_query(
                user_question=user_question,
                session_id=session_id,
                include_explanation=include_explanation
            )

        if not result.success:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
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
            print("Executing generated SQL query")

            try:
                query_executor = AthenaQueryExecutor(
                    database=database_name,
                    output_location=athena_output_location,
                    region=aws_region
                )

                query_results = query_executor.execute_query(result.sql, timeout=120)

                response_data["results"] = query_results
                response_data["result_count"] = len(query_results)

                print(f"Query executed successfully: {len(query_results)} rows returned")

            except Exception as e:
                print(f"Error executing query: {e}")
                response_data["execution_error"] = str(e)
                response_data["results"] = []

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "POST,OPTIONS"
            },
            "body": json.dumps(response_data)
        }

    except Exception as e:
        print(f"Fatal error in query handler: {e}")
        import traceback
        traceback.print_exc()

        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "success": False,
                "error": f"Internal server error: {str(e)}"
            })
        }


def explain_query_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for explaining SQL queries.

    Args:
        event: API Gateway event with SQL in body
        context: Lambda context

    Returns:
        API Gateway response with explanation
    """
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
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Missing 'sql' field in request"})
            }

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
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({
                "success": True,
                "sql": sql,
                "explanation": explanation
            })
        }

    except Exception as e:
        print(f"Error explaining query: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "success": False,
                "error": str(e)
            })
        }
