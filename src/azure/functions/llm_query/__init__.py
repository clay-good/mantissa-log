"""Azure Function handler for LLM-powered natural language queries."""

import azure.functions as func
import json
import logging
import os
from typing import Any, Dict

from src.shared.llm import (
    QueryGenerator,
    SchemaContext,
    SQLValidator,
)
from src.shared.llm.providers import get_provider
from src.azure.synapse.executor import SynapseExecutor

logger = logging.getLogger(__name__)


class SynapseSchemaSource:
    """Schema source for Azure Synapse Analytics."""

    def __init__(self, database_name: str, workspace_name: str = None):
        self.database_name = database_name
        self.executor = SynapseExecutor(
            workspace_name=workspace_name,
            database_name=database_name,
            use_serverless=True
        )

    def get_tables(self) -> list:
        """Get list of tables in database."""
        return self.executor.list_tables()

    def get_table_schema(self, table_name: str) -> list:
        """Get schema for a specific table."""
        return self.executor.get_table_schema(table_name)


class CosmosDBSessionManager:
    """Session manager using Azure Cosmos DB."""

    def __init__(self, connection_string: str = None, database_name: str = "mantissa", container_name: str = "sessions"):
        from azure.cosmos import CosmosClient, PartitionKey

        self.connection_string = connection_string or os.environ.get("COSMOS_CONNECTION_STRING")
        self.database_name = database_name
        self.container_name = container_name

        self.client = CosmosClient.from_connection_string(self.connection_string)
        self.database = self.client.get_database_client(self.database_name)
        self.container = self.database.get_container_client(self.container_name)

    def get_session(self, session_id: str) -> Dict[str, Any]:
        """Get session data."""
        try:
            item = self.container.read_item(item=session_id, partition_key=session_id)
            return item
        except Exception:
            return {}

    def save_session(self, session_id: str, data: Dict[str, Any]) -> None:
        """Save session data."""
        data["id"] = session_id
        data["session_id"] = session_id
        self.container.upsert_item(data)

    def get_conversation_history(self, session_id: str) -> list:
        """Get conversation history for session."""
        session = self.get_session(session_id)
        return session.get("history", [])

    def add_to_history(self, session_id: str, entry: Dict[str, Any]) -> None:
        """Add entry to conversation history."""
        session = self.get_session(session_id)
        history = session.get("history", [])
        history.append(entry)

        # Keep last 20 entries
        if len(history) > 20:
            history = history[-20:]

        session["history"] = history
        self.save_session(session_id, session)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for natural language to SQL query generation.

    This function:
    1. Receives natural language question via HTTP
    2. Generates SQL using LLM
    3. Optionally executes the query against Synapse
    4. Returns results
    """
    logger.info("Processing LLM query request")

    # Load configuration
    database_name = os.environ.get("SYNAPSE_DATABASE", "mantissa_logs")
    workspace_name = os.environ.get("SYNAPSE_WORKSPACE_NAME")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "openai")
    max_result_rows = int(os.environ.get("MAX_RESULT_ROWS", "1000"))

    # Parse request body
    try:
        body = req.get_json()

        user_question = body.get("question")
        execute_query = body.get("execute", False)
        session_id = body.get("session_id")
        include_explanation = body.get("explain", True)
        refinement_request = body.get("refinement")
        original_sql = body.get("original_sql")

        if not user_question:
            return func.HttpResponse(
                json.dumps({"error": "Missing 'question' field in request"}),
                status_code=400,
                mimetype="application/json"
            )

    except ValueError as e:
        return func.HttpResponse(
            json.dumps({"error": f"Invalid JSON in request body: {str(e)}"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Initialize components
        logger.info(f"Initializing query generator with provider: {llm_provider_name}")

        # Get LLM provider
        llm_provider = get_provider(llm_provider_name)

        # Get schema context
        schema_source = SynapseSchemaSource(database_name, workspace_name)
        schema_context = SchemaContext(database_name, schema_source)

        # Get SQL validator
        sql_validator = SQLValidator(
            max_result_rows=max_result_rows,
            sql_dialect="tsql"  # Use T-SQL for Synapse
        )

        # Get session manager
        session_manager = None
        if os.environ.get("COSMOS_CONNECTION_STRING"):
            session_manager = CosmosDBSessionManager()

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
            return func.HttpResponse(
                json.dumps({
                    "success": False,
                    "error": result.error,
                    "attempts": result.attempts
                }),
                status_code=400,
                mimetype="application/json"
            )

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
                query_executor = SynapseExecutor(
                    workspace_name=workspace_name,
                    database_name=database_name,
                    use_serverless=True
                )

                query_result = query_executor.execute_query(
                    result.sql,
                    max_results=max_result_rows
                )

                response_data["results"] = query_result.get("results", [])
                response_data["result_count"] = query_result.get("row_count", 0)
                response_data["bytes_processed"] = query_result.get("bytes_processed", 0)
                response_data["cost_estimate"] = query_result.get("cost_estimate", 0.0)

                logger.info(f"Query executed successfully: {response_data['result_count']} rows returned")

            except Exception as e:
                logger.error(f"Error executing query: {e}")
                response_data["execution_error"] = str(e)
                response_data["results"] = []

        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "POST,OPTIONS"
            }
        )

    except Exception as e:
        logger.error(f"Fatal error in query handler: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({
                "success": False,
                "error": f"Internal server error: {str(e)}"
            }),
            status_code=500,
            mimetype="application/json"
        )
