"""
Conversation API

REST API endpoints for managing conversational sessions and context.
"""

import json
import logging
from typing import Dict, Any
import sys
from pathlib import Path

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from conversation.session_manager import SessionManager, DynamoDBSessionStorage
from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ConversationAPI:
    """Lambda handler for conversation API endpoints."""

    def __init__(self):
        import os
        table_name = os.environ.get('CONVERSATION_TABLE', 'mantissa-log-conversation-sessions-dev')
        storage = DynamoDBSessionStorage(table_name)
        self.session_manager = SessionManager(storage)

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Lambda handler for conversation API.

        Endpoints:
        - POST /api/conversation/sessions - Create new session
        - GET /api/conversation/sessions/{session_id} - Get session
        - POST /api/conversation/messages - Add message
        - GET /api/conversation/context/{session_id} - Get context for LLM
        - PUT /api/conversation/context/{session_id} - Update context
        - DELETE /api/conversation/sessions/{session_id} - Delete session
        """
        # Handle CORS preflight
        http_method = event.get('httpMethod')
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        try:
            # Authenticate user from Cognito JWT claims
            try:
                user_id = get_authenticated_user_id(event)
            except AuthenticationError:
                return self._error_response(event, 'Authentication required', 401)

            path = event.get('path', '')
            body = json.loads(event.get('body', '{}')) if event.get('body') else {}
            path_params = event.get('pathParameters', {}) or {}
            query_params = event.get('queryStringParameters', {}) or {}

            # POST /api/conversation/sessions - Create new session
            if http_method == 'POST' and path.endswith('/sessions'):
                # user_id comes from authenticated JWT, not request body
                session = self.session_manager.create_session(user_id)

                return self._success_response(event, {
                    'session_id': session.session_id,
                    'user_id': session.user_id,
                    'created_at': session.created_at,
                    'expires_at': session.expires_at
                })

            # GET /api/conversation/sessions/{session_id} - Get session
            elif http_method == 'GET' and '/sessions/' in path:
                session_id = path_params.get('session_id')

                if not session_id:
                    return self._error_response(event, 'session_id is required', 400)

                session = self.session_manager.get_session(session_id)

                if not session:
                    return self._error_response(event, 'Session not found', 404)

                # Verify user owns this session
                if session.user_id != user_id:
                    return self._error_response(event, 'Access denied', 403)

                return self._success_response(event, {
                    'session_id': session.session_id,
                    'user_id': session.user_id,
                    'created_at': session.created_at,
                    'updated_at': session.updated_at,
                    'expires_at': session.expires_at,
                    'message_count': len(session.messages),
                    'context': session.context
                })

            # POST /api/conversation/messages - Add message
            elif http_method == 'POST' and path.endswith('/messages'):
                session_id = body.get('session_id')
                role = body.get('role')  # 'user' or 'assistant'
                content = body.get('content')
                metadata = body.get('metadata', {})

                if not all([session_id, role, content]):
                    return self._error_response(
                        event,
                        'session_id, role, and content are required',
                        400
                    )

                # Verify user owns this session
                session = self.session_manager.get_session(session_id)
                if not session:
                    return self._error_response(event, 'Session not found', 404)
                if session.user_id != user_id:
                    return self._error_response(event, 'Access denied', 403)

                if role not in ['user', 'assistant']:
                    return self._error_response(
                        event,
                        'role must be "user" or "assistant"',
                        400
                    )

                if role == 'user':
                    message = self.session_manager.add_user_message(
                        session_id, content, metadata
                    )
                else:
                    message = self.session_manager.add_assistant_message(
                        session_id, content, metadata
                    )

                return self._success_response(event, {
                    'role': message.role,
                    'content': message.content,
                    'timestamp': message.timestamp,
                    'metadata': message.metadata
                })

            # GET /api/conversation/context/{session_id} - Get context for LLM
            elif http_method == 'GET' and '/context/' in path:
                session_id = path_params.get('session_id')
                max_messages = int(query_params.get('max_messages', 10))

                if not session_id:
                    return self._error_response(event, 'session_id is required', 400)

                # Verify user owns this session
                session = self.session_manager.get_session(session_id)
                if not session:
                    return self._error_response(event, 'Session not found', 404)
                if session.user_id != user_id:
                    return self._error_response(event, 'Access denied', 403)

                context = self.session_manager.get_context_for_llm(
                    session_id,
                    max_messages
                )

                return self._success_response(event, {
                    'session_id': session_id,
                    'messages': context
                })

            # PUT /api/conversation/context/{session_id} - Update context
            elif http_method == 'PUT' and '/context/' in path:
                session_id = path_params.get('session_id')
                context_updates = body.get('context', {})

                if not session_id:
                    return self._error_response(event, 'session_id is required', 400)

                session = self.session_manager.get_session(session_id)

                if not session:
                    return self._error_response(event, 'Session not found', 404)

                # Verify user owns this session
                if session.user_id != user_id:
                    return self._error_response(event, 'Access denied', 403)

                for key, value in context_updates.items():
                    session.update_context(key, value)

                self.session_manager.save_session(session)

                return self._success_response(event, {
                    'session_id': session_id,
                    'context': session.context
                })

            # DELETE /api/conversation/sessions/{session_id} - Delete session
            elif http_method == 'DELETE' and '/sessions/' in path:
                session_id = path_params.get('session_id')

                if not session_id:
                    return self._error_response(event, 'session_id is required', 400)

                session = self.session_manager.get_session(session_id)

                # Verify user owns this session
                if session and session.user_id != user_id:
                    return self._error_response(event, 'Access denied', 403)

                if session and self.session_manager.storage:
                    self.session_manager.storage.delete_session(session_id)

                # Remove from local cache
                if session_id in self.session_manager.local_sessions:
                    del self.session_manager.local_sessions[session_id]

                return self._success_response(event, {'status': 'deleted'})

            # GET /api/conversation/history/{session_id} - Get full conversation history
            elif http_method == 'GET' and '/history/' in path:
                session_id = path_params.get('session_id')

                if not session_id:
                    return self._error_response(event, 'session_id is required', 400)

                session = self.session_manager.get_session(session_id)

                if not session:
                    return self._error_response(event, 'Session not found', 404)

                # Verify user owns this session
                if session.user_id != user_id:
                    return self._error_response(event, 'Access denied', 403)

                return self._success_response(event, {
                    'session_id': session_id,
                    'messages': [msg.to_dict() for msg in session.messages],
                    'context': session.context
                })

            else:
                return self._error_response(event, 'Not found', 404)

        except ValueError as e:
            return self._error_response(event, str(e), 400)
        except Exception as e:
            logger.error(f"Error in conversation API: {str(e)}", exc_info=True)
            return self._error_response(event, 'Internal server error', 500)

    def _success_response(self, event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Return success response with secure CORS headers."""
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps(data)
        }

    def _error_response(self, event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
        """Return error response with secure CORS headers."""
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': message})
        }


# Lambda entry point
def lambda_handler(event, context):
    """Entry point for AWS Lambda."""
    api = ConversationAPI()
    return api.lambda_handler(event, context)
