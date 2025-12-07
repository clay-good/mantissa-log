"""
Conversation API Handler

Lambda function to handle conversational natural language query API requests.
Manages session state, conversation context, and multi-turn query refinement.
"""

import json
import os
import sys
from typing import Dict, Any

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

from llm.conversation_manager import (
    ConversationManager,
    QueryContext,
    create_conversation_session,
    get_conversation_context
)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle conversation API requests.

    Routes:
    - POST /conversation/create - Create new conversation session
    - POST /conversation/query - Send message and get response
    - GET /conversation/sessions - Get user's conversation sessions
    - GET /conversation/{session_id} - Get specific session
    - DELETE /conversation/{session_id} - Delete session
    """
    try:
        path = event.get('path', '')
        method = event.get('httpMethod', 'GET')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('pathParameters') or {}

        # Route to appropriate handler
        if path == '/conversation/create' and method == 'POST':
            return handle_create_session(body)
        elif path == '/conversation/query' and method == 'POST':
            return handle_query(body)
        elif path == '/conversation/sessions' and method == 'GET':
            return handle_get_sessions(event)
        elif path.startswith('/conversation/') and method == 'GET':
            return handle_get_session(event, params)
        elif path.startswith('/conversation/') and method == 'DELETE':
            return handle_delete_session(body, params)
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        print(f'Error in conversation API handler: {e}')
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': str(e)})
        }


def handle_create_session(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new conversation session.

    Request body:
    {
        "user_id": "user-123",
        "metadata": {"source": "web-ui"}
    }
    """
    user_id = body.get('user_id')
    metadata = body.get('metadata', {})

    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id'})
        }

    manager = ConversationManager()
    session = manager.create_session(user_id, metadata)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'session_id': session.session_id,
            'created_at': session.created_at,
            'message': 'Session created successfully'
        })
    }


def handle_query(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a conversational query.

    Request body:
    {
        "user_id": "user-123",
        "session_id": "session-abc123",
        "message": "Show me failed logins"
    }
    """
    user_id = body.get('user_id')
    session_id = body.get('session_id')
    message = body.get('message')

    if not all([user_id, session_id, message]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing required fields'})
        }

    manager = ConversationManager()

    # Get session
    session = manager.get_session(session_id, user_id)
    if not session:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Session not found'})
        }

    # Add user message
    manager.add_user_message(session_id, user_id, message)

    # Determine if this is a follow-up query
    is_follow_up = manager.is_follow_up_query(message)

    # Build context-aware prompt
    context_prompt = manager.build_context_prompt(session, message)

    # Call LLM to generate SQL using the shared query generator
    from llm.query_generator import generate_sql_from_nlp

    try:
        sql_result = generate_sql_from_nlp(
            context_prompt,
            user_id,
            session_context=session
        )

        sql = sql_result.get('sql', '')
        execution_id = sql_result.get('execution_id')

        # Execute query (using existing query execution logic)
        query_results = execute_athena_query(sql, user_id)

        # Create query context
        query_context = QueryContext(
            query_text=message,
            generated_sql=sql,
            execution_id=execution_id,
            result_count=len(query_results.get('rows', [])),
            data_scanned_mb=query_results.get('data_scanned_mb'),
            cost_usd=query_results.get('cost_usd')
        )

        # Generate assistant response
        if is_follow_up:
            response_text = f"I've refined the previous query. Found {query_context.result_count} results."
        else:
            response_text = f"I've generated a query that found {query_context.result_count} results."

        # Add assistant response
        manager.add_assistant_response(
            session_id,
            user_id,
            response_text,
            query_context=query_context
        )

        # Get updated session for summary
        updated_session = manager.get_session(session_id, user_id)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'response': response_text,
                'sql': sql,
                'results': query_results.get('rows', [])[:100],  # Limit to 100 rows
                'result_count': query_context.result_count,
                'cost': query_context.cost_usd,
                'is_follow_up': is_follow_up,
                'session_summary': updated_session.get_conversation_summary()
            })
        }

    except Exception as e:
        print(f'Error processing query: {e}')

        # Add error message to conversation
        manager.add_assistant_response(
            session_id,
            user_id,
            f"I encountered an error processing your request: {str(e)}"
        )

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e),
                'response': "I'm sorry, I encountered an error processing your request. Please try rephrasing your question."
            })
        }


def handle_get_sessions(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get user's conversation sessions.

    Query parameters:
    - user_id: User ID
    - limit: Maximum sessions to return (default 10)
    """
    params = event.get('queryStringParameters', {}) or {}
    user_id = params.get('user_id')
    limit = int(params.get('limit', 10))

    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id'})
        }

    manager = ConversationManager()
    sessions = manager.get_user_sessions(user_id, limit)

    # Convert sessions to JSON-friendly format
    sessions_data = []
    for session in sessions:
        sessions_data.append({
            'session_id': session.session_id,
            'created_at': session.created_at,
            'updated_at': session.updated_at,
            'message_count': len(session.messages),
            'query_count': len(session.query_history),
            'summary': session.get_conversation_summary()
        })

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'sessions': sessions_data,
            'total': len(sessions_data)
        })
    }


def handle_get_session(event: Dict[str, Any], params: Dict[str, str]) -> Dict[str, Any]:
    """
    Get specific conversation session.

    Path parameters:
    - session_id: Session ID

    Query parameters:
    - user_id: User ID
    """
    query_params = event.get('queryStringParameters', {}) or {}
    session_id = params.get('session_id')
    user_id = query_params.get('user_id')

    if not all([session_id, user_id]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing session_id or user_id'})
        }

    manager = ConversationManager()
    session = manager.get_session(session_id, user_id)

    if not session:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Session not found'})
        }

    # Convert to JSON-friendly format
    session_data = {
        'session_id': session.session_id,
        'user_id': session.user_id,
        'created_at': session.created_at,
        'updated_at': session.updated_at,
        'messages': [
            {
                'role': msg.role.value,
                'content': msg.content,
                'timestamp': msg.timestamp
            }
            for msg in session.messages
        ],
        'summary': session.get_conversation_summary(),
        'query_count': len(session.query_history)
    }

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'session': session_data})
    }


def handle_delete_session(body: Dict[str, Any], params: Dict[str, str]) -> Dict[str, Any]:
    """
    Delete a conversation session.

    Path parameters:
    - session_id: Session ID

    Request body:
    {
        "user_id": "user-123"
    }
    """
    session_id = params.get('session_id')
    user_id = body.get('user_id')

    if not all([session_id, user_id]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing session_id or user_id'})
        }

    manager = ConversationManager()
    manager.delete_session(session_id, user_id)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'message': 'Session deleted successfully'})
    }


# Helper functions integrating with existing modules

def generate_sql_from_nlp(prompt: str, user_id: str, session_context=None) -> Dict[str, Any]:
    """
    Generate SQL from natural language using LLM.

    Integrates with the shared LLM query generation module.
    """
    from shared.llm import QueryGenerator, SchemaContext, GlueSchemaSource
    from shared.llm.providers import get_provider

    database_name = os.environ.get("ATHENA_DATABASE", "mantissa_logs")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "bedrock")

    try:
        # Get LLM provider
        llm_provider = get_provider(llm_provider_name, region=aws_region)

        # Get schema context
        schema_source = GlueSchemaSource(database_name, region=aws_region)
        schema_context = SchemaContext(database_name, schema_source)

        # Initialize query generator
        query_generator = QueryGenerator(
            llm_provider=llm_provider,
            schema_context=schema_context
        )

        # Generate SQL from natural language
        result = query_generator.generate_query(
            question=prompt,
            conversation_history=session_context
        )

        return {
            'sql': result.sql,
            'explanation': result.explanation,
            'execution_id': f'query-{user_id[:8]}'
        }
    except Exception as e:
        print(f"Error generating SQL: {e}")
        raise


def execute_athena_query(sql: str, user_id: str) -> Dict[str, Any]:
    """
    Execute Athena query and return results.

    Integrates with the shared Athena executor module.
    """
    from shared.detection.executors.athena import AthenaQueryExecutor

    database_name = os.environ.get("ATHENA_DATABASE", "mantissa_logs")
    output_location = os.environ.get("ATHENA_OUTPUT_LOCATION")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    max_result_rows = int(os.environ.get("MAX_RESULT_ROWS", "1000"))

    try:
        # Initialize Athena executor
        executor = AthenaQueryExecutor(
            database=database_name,
            output_location=output_location,
            region=aws_region
        )

        # Execute query
        result = executor.execute_query(sql, max_results=max_result_rows)

        return {
            'rows': result.rows,
            'columns': result.columns,
            'row_count': result.row_count,
            'data_scanned_mb': result.bytes_scanned / (1024 * 1024) if result.bytes_scanned else 0,
            'cost_usd': (result.bytes_scanned / (1024 ** 4)) * 5.0 if result.bytes_scanned else 0,
            'execution_time_ms': result.execution_time_ms
        }
    except Exception as e:
        print(f"Error executing Athena query: {e}")
        raise
