"""
Conversational Query Generation API

Generates SQL queries with conversation context for multi-turn interactions.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from conversation import SessionManager, DynamoDBSessionStorage


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for conversational query generation.

    Expected input:
    {
        "question": "Show me failed logins",
        "sessionId": "abc-123" (optional, creates new if not provided),
        "userId": "user-456"
    }

    Returns:
    {
        "sql": "SELECT ...",
        "explanation": "This query...",
        "sessionId": "abc-123",
        "conversationHistory": [...]
    }
    """
    try:
        body = json.loads(event.get('body', '{}'))

        question = body.get('question', '')
        session_id = body.get('sessionId')
        user_id = body.get('userId')

        if not question:
            return error_response('question is required', 400)

        if not user_id:
            return error_response('userId is required', 400)

        # Initialize session manager
        storage = DynamoDBSessionStorage(
            table_name=get_sessions_table_name()
        )
        session_manager = SessionManager(storage_backend=storage)

        # Get or create session
        if session_id:
            session = session_manager.get_session(session_id)
            if not session:
                # Session expired or not found, create new
                session = session_manager.create_session(user_id)
        else:
            session = session_manager.create_session(user_id)

        # Add user message
        session_manager.add_user_message(
            session.session_id,
            question
        )

        # Get conversation context for LLM
        conversation_history = session_manager.get_context_for_llm(
            session.session_id,
            max_messages=10
        )

        # Generate SQL with context
        result = generate_contextual_query(
            question=question,
            conversation_history=conversation_history,
            session_context=session.context
        )

        # Add assistant response
        session_manager.add_assistant_message(
            session.session_id,
            result['explanation'],
            metadata={
                'sql': result['sql'],
                'table_schema': result.get('table_schema'),
                'warnings': result.get('warnings', [])
            }
        )

        # Update session context with last query
        session.update_context('last_query', result['sql'])
        session.update_context('last_table', result.get('primary_table'))
        session_manager.save_session(session)

        return success_response({
            'sql': result['sql'],
            'explanation': result['explanation'],
            'sessionId': session.session_id,
            'conversationHistory': conversation_history,
            'warnings': result.get('warnings', [])
        })

    except Exception as e:
        print(f"Error in conversational query generation: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(str(e), 500)


def generate_contextual_query(
    question: str,
    conversation_history: List[Dict[str, str]],
    session_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate SQL query with conversation context.

    Args:
        question: User's question
        conversation_history: Previous messages
        session_context: Session context (last query, tables, etc.)

    Returns:
        Dictionary with sql, explanation, and metadata
    """
    import os
    import boto3

    # Get LLM configuration
    llm_provider = os.environ.get('LLM_PROVIDER', 'bedrock')

    # Build context-aware prompt
    prompt = build_contextual_prompt(
        question,
        conversation_history,
        session_context
    )

    if llm_provider == 'bedrock':
        return generate_with_bedrock(prompt)
    else:
        # Fallback to external LLM
        return generate_with_external_llm(prompt, llm_provider)


def build_contextual_prompt(
    question: str,
    conversation_history: List[Dict[str, str]],
    session_context: Dict[str, Any]
) -> str:
    """
    Build prompt with conversation context.

    Args:
        question: Current question
        conversation_history: Previous messages
        session_context: Session context

    Returns:
        Formatted prompt string
    """
    # Base prompt
    prompt = """You are a SQL query generator for AWS security log analysis.

Available tables:
- cloudtrail: AWS CloudTrail API events
  Columns: eventname, eventtime, useridentity, sourceipaddress, errorcode, etc.
- vpc_flow_logs: VPC network traffic logs
  Columns: srcaddr, dstaddr, srcport, dstport, protocol, action, etc.
- guardduty_findings: AWS GuardDuty security findings
  Columns: type, severity, resource, service, etc.

"""

    # Add conversation context if available
    if conversation_history and len(conversation_history) > 1:
        prompt += "\nConversation History:\n"
        for msg in conversation_history[:-1]:  # Exclude current question
            role = "User" if msg['role'] == 'user' else "Assistant"
            prompt += f"{role}: {msg['content']}\n"
        prompt += "\n"

    # Add session context if available
    if session_context.get('last_query'):
        prompt += f"\nLast generated query:\n{session_context['last_query']}\n\n"

    # Add current question
    prompt += f"Current question: {question}\n\n"

    # Add instructions
    prompt += """Generate a SQL query to answer the question.

Important:
- If the question references "it", "that", "the same", or similar pronouns, use context from the conversation history
- If the question is a follow-up like "and send to Slack", recognize this is about alert routing, not SQL
- If asking to modify the previous query, build upon the last_query shown above
- Always include WHERE clauses with partitions (year, month, day) for performance
- Return valid Athena (Presto SQL) syntax

Return JSON format:
{
  "sql": "SELECT ...",
  "explanation": "This query...",
  "is_followup": true/false,
  "followup_type": "query_modification|alert_routing|rule_creation|null"
}
"""

    return prompt


def generate_with_bedrock(prompt: str) -> Dict[str, Any]:
    """Generate query using AWS Bedrock"""
    import boto3
    import json

    bedrock = boto3.client('bedrock-runtime')

    # Use Claude 3.5 Sonnet
    model_id = 'anthropic.claude-3-5-sonnet-20241022-v2:0'

    request_body = {
        'anthropic_version': 'bedrock-2023-05-31',
        'max_tokens': 2000,
        'temperature': 0.0,
        'messages': [
            {
                'role': 'user',
                'content': prompt
            }
        ]
    }

    response = bedrock.invoke_model(
        modelId=model_id,
        body=json.dumps(request_body)
    )

    response_body = json.loads(response['body'].read())
    content = response_body['content'][0]['text']

    # Parse JSON response
    try:
        result = json.loads(content)
        return {
            'sql': result['sql'],
            'explanation': result['explanation'],
            'is_followup': result.get('is_followup', False),
            'followup_type': result.get('followup_type')
        }
    except json.JSONDecodeError:
        # Fallback: extract SQL from text
        return {
            'sql': content,
            'explanation': 'Query generated from conversation context',
            'warnings': ['Could not parse structured response']
        }


def generate_with_external_llm(prompt: str, provider: str) -> Dict[str, Any]:
    """Generate query using external LLM (Anthropic, OpenAI, etc.)"""
    import os
    import re

    try:
        # Import the provider factory
        from shared.llm.providers import get_provider

        # Get the configured provider
        llm = get_provider(provider)

        # Generate completion
        response = llm.complete(prompt)

        # Extract SQL from response
        response_text = response.text if hasattr(response, 'text') else str(response)

        # Try to extract SQL from code blocks
        sql_match = re.search(r'```sql\s*(.*?)\s*```', response_text, re.DOTALL | re.IGNORECASE)
        if sql_match:
            sql = sql_match.group(1).strip()
        else:
            # Try to find SELECT statement
            select_match = re.search(r'(SELECT\s+.*?)(;|$)', response_text, re.DOTALL | re.IGNORECASE)
            if select_match:
                sql = select_match.group(1).strip()
            else:
                sql = response_text.strip()

        # Extract explanation (text before or after SQL)
        explanation = response_text.replace(sql, '').strip()
        if not explanation:
            explanation = f'Query generated using {provider}'

        return {
            'sql': sql,
            'explanation': explanation[:500],  # Truncate long explanations
            'warnings': []
        }
    except ImportError as e:
        return {
            'sql': 'SELECT * FROM cloudtrail_logs LIMIT 10',
            'explanation': f'Could not load LLM provider module: {e}',
            'warnings': ['Using fallback query - provider module not available']
        }
    except Exception as e:
        return {
            'sql': 'SELECT * FROM cloudtrail_logs LIMIT 10',
            'explanation': f'Error generating query with {provider}: {str(e)}',
            'warnings': ['Using fallback query due to LLM error']
        }


def get_sessions_table_name() -> str:
    """Get DynamoDB table name for conversation sessions"""
    import os
    return os.environ.get('CONVERSATION_SESSIONS_TABLE', 'mantissa-log-conversation-sessions')


def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return success response"""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data)
    }


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    """Return error response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'error': message})
    }
