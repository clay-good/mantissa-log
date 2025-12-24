"""
Playbook API Business Logic

Provides business logic functions for playbook management operations.
Separates business logic from Lambda handler for testability.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from shared.soar import (
    Playbook,
    PlaybookStore,
    PlaybookTriggerType,
    IRPlanParser,
    parse_ir_plan,
    generate_playbook_code,
    validate_playbook_code,
    get_playbook_store,
    get_execution_store,
    ExecutionStatus,
)

logger = logging.getLogger(__name__)


class PlaybookAPI:
    """Business logic for playbook management."""

    def __init__(
        self,
        playbook_store: Optional[PlaybookStore] = None,
        llm_provider=None,
    ):
        """Initialize playbook API.

        Args:
            playbook_store: Playbook storage backend
            llm_provider: LLM provider for generation features
        """
        self.playbook_store = playbook_store or get_playbook_store()
        self.llm_provider = llm_provider

    def list_playbooks(
        self,
        user_id: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """List playbooks with optional filters.

        Args:
            user_id: ID of requesting user
            filters: Optional filter criteria
            page: Page number (1-indexed)
            page_size: Number of results per page

        Returns:
            Dict with playbooks list and pagination info
        """
        playbooks = self.playbook_store.list(filters=filters or {})

        # Sort by modified date descending
        playbooks.sort(key=lambda p: p.modified, reverse=True)

        # Calculate pagination
        total = len(playbooks)
        start = (page - 1) * page_size
        end = start + page_size
        page_playbooks = playbooks[start:end]

        return {
            'playbooks': [p.to_dict() for p in page_playbooks],
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        }

    def get_playbook(
        self,
        user_id: str,
        playbook_id: str,
        include_stats: bool = True,
    ) -> Dict[str, Any]:
        """Get a playbook by ID with optional statistics.

        Args:
            user_id: ID of requesting user
            playbook_id: Playbook ID
            include_stats: Whether to include execution statistics

        Returns:
            Dict with playbook data

        Raises:
            ValueError: If playbook not found
        """
        playbook = self.playbook_store.get(playbook_id)
        if not playbook:
            raise ValueError(f'Playbook not found: {playbook_id}')

        result = {
            'playbook': playbook.to_dict(),
        }

        if include_stats:
            # Get execution statistics
            execution_store = get_execution_store()
            executions = execution_store.list(playbook_id=playbook_id, limit=100)

            total_executions = len(executions)
            successful = len([e for e in executions if e.status == ExecutionStatus.COMPLETED])
            failed = len([e for e in executions if e.status == ExecutionStatus.FAILED])

            result['stats'] = {
                'total_executions': total_executions,
                'successful_executions': successful,
                'failed_executions': failed,
                'success_rate': successful / total_executions if total_executions > 0 else 0,
            }

        return result

    def create_playbook(
        self,
        user_id: str,
        playbook_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a new playbook.

        Args:
            user_id: ID of creating user
            playbook_data: Playbook definition

        Returns:
            Dict with created playbook

        Raises:
            ValueError: If playbook data is invalid
        """
        # Set defaults
        now = datetime.now(timezone.utc)

        if 'id' not in playbook_data:
            playbook_data['id'] = f"pb-{uuid.uuid4().hex[:12]}"

        playbook_data.setdefault('version', '1.0.0')
        playbook_data.setdefault('author', user_id)
        playbook_data.setdefault('created', now.isoformat())
        playbook_data.setdefault('modified', now.isoformat())
        playbook_data.setdefault('enabled', True)
        playbook_data.setdefault('description', '')
        playbook_data.setdefault('tags', [])

        if 'trigger' not in playbook_data:
            playbook_data['trigger'] = {
                'trigger_type': 'manual',
                'conditions': {},
            }

        # Create playbook object
        try:
            playbook = Playbook.from_dict(playbook_data)
        except Exception as e:
            raise ValueError(f'Invalid playbook data: {e}')

        # Validate structure
        is_valid, errors = playbook.validate()
        if not is_valid:
            raise ValueError(f'Invalid playbook: {", ".join(errors)}')

        # Save
        self.playbook_store.save(playbook)
        logger.info(f'Created playbook {playbook.id} by user {user_id}')

        return {
            'playbook': playbook.to_dict(),
            'message': 'Playbook created successfully',
        }

    def update_playbook(
        self,
        user_id: str,
        playbook_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update an existing playbook.

        Args:
            user_id: ID of updating user
            playbook_id: Playbook ID
            updates: Fields to update

        Returns:
            Dict with updated playbook

        Raises:
            ValueError: If playbook not found or updates invalid
        """
        # Get existing playbook
        existing = self.playbook_store.get(playbook_id)
        if not existing:
            raise ValueError(f'Playbook not found: {playbook_id}')

        # Merge updates
        playbook_data = existing.to_dict()
        for key, value in updates.items():
            if key not in ['id', 'created']:
                playbook_data[key] = value

        # Update modified timestamp
        playbook_data['modified'] = datetime.now(timezone.utc).isoformat()

        # Auto-increment version if steps changed
        if 'steps' in updates and updates['steps'] != existing.to_dict().get('steps'):
            parts = playbook_data.get('version', '1.0.0').split('.')
            parts[-1] = str(int(parts[-1]) + 1)
            playbook_data['version'] = '.'.join(parts)

        # Create updated playbook
        try:
            playbook = Playbook.from_dict(playbook_data)
        except Exception as e:
            raise ValueError(f'Invalid playbook data: {e}')

        # Validate
        is_valid, errors = playbook.validate()
        if not is_valid:
            raise ValueError(f'Invalid playbook: {", ".join(errors)}')

        # Save
        self.playbook_store.save(playbook)
        logger.info(f'Updated playbook {playbook_id} by user {user_id}')

        return {
            'playbook': playbook.to_dict(),
            'message': 'Playbook updated successfully',
        }

    def delete_playbook(
        self,
        user_id: str,
        playbook_id: str,
    ) -> bool:
        """Delete (archive) a playbook.

        Args:
            user_id: ID of deleting user
            playbook_id: Playbook ID

        Returns:
            True if deleted successfully

        Raises:
            ValueError: If playbook not found or has running executions
        """
        # Check playbook exists
        playbook = self.playbook_store.get(playbook_id)
        if not playbook:
            raise ValueError(f'Playbook not found: {playbook_id}')

        # Check for running executions
        execution_store = get_execution_store()
        running = execution_store.list(
            playbook_id=playbook_id,
            status=ExecutionStatus.RUNNING,
            limit=1,
        )
        if running:
            raise ValueError('Cannot delete playbook with running executions')

        # Delete (archive)
        success = self.playbook_store.delete(playbook_id)
        if success:
            logger.info(f'Deleted playbook {playbook_id} by user {user_id}')

        return success

    def generate_playbook(
        self,
        user_id: str,
        description: str,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a playbook from natural language description.

        Args:
            user_id: ID of requesting user
            description: Natural language description
            name: Optional playbook name

        Returns:
            Dict with generated playbook (needs review)
        """
        now = datetime.now(timezone.utc)

        # TODO: Implement full LLM-based generation
        # For now, create a template playbook

        playbook_data = {
            'id': f"pb-gen-{uuid.uuid4().hex[:8]}",
            'name': name or 'Generated Playbook',
            'description': description,
            'version': '1.0.0',
            'author': user_id,
            'created': now.isoformat(),
            'modified': now.isoformat(),
            'enabled': False,  # Disabled by default
            'tags': ['generated', 'review-required'],
            'trigger': {
                'trigger_type': 'manual',
                'conditions': {},
            },
            'steps': [
                {
                    'id': 'review_step',
                    'name': 'Review Required',
                    'action_type': 'notify',
                    'provider': 'slack',
                    'parameters': {
                        'channel': '#security-alerts',
                        'message': f'Generated playbook requires review: {description}',
                    },
                },
            ],
        }

        return {
            'playbook': playbook_data,
            'message': 'Playbook generated. Review and modify before enabling.',
            'generated_from': description,
        }

    def parse_ir_plan(
        self,
        user_id: str,
        plan_text: str,
        plan_name: Optional[str] = None,
        plan_format: str = 'markdown',
    ) -> Dict[str, Any]:
        """Parse an IR plan into a playbook.

        Args:
            user_id: ID of requesting user
            plan_text: IR plan text content
            plan_name: Optional name for the playbook
            plan_format: Format of the plan (markdown or text)

        Returns:
            Dict with parsed playbook (needs review)
        """
        # Parse the IR plan
        playbook = parse_ir_plan(
            plan_text,
            plan_name=plan_name or 'Parsed IR Plan',
        )

        # Update metadata
        playbook_dict = playbook.to_dict()
        playbook_dict['author'] = user_id
        playbook_dict['enabled'] = False
        if 'parsed-ir-plan' not in playbook_dict.get('tags', []):
            playbook_dict.setdefault('tags', []).append('parsed-ir-plan')
        if 'review-required' not in playbook_dict.get('tags', []):
            playbook_dict['tags'].append('review-required')

        return {
            'playbook': playbook_dict,
            'message': 'IR plan parsed successfully. Review before enabling.',
            'parsed_from': plan_format,
        }

    def get_playbook_code(
        self,
        user_id: str,
        playbook_id: str,
        regenerate: bool = False,
    ) -> Dict[str, Any]:
        """Get generated Lambda code for a playbook.

        Args:
            user_id: ID of requesting user
            playbook_id: Playbook ID
            regenerate: Whether to regenerate the code

        Returns:
            Dict with generated code

        Raises:
            ValueError: If playbook not found
        """
        playbook = self.playbook_store.get(playbook_id)
        if not playbook:
            raise ValueError(f'Playbook not found: {playbook_id}')

        # Generate or return cached code
        if playbook.lambda_code and not regenerate:
            code = playbook.lambda_code
        else:
            code = generate_playbook_code(playbook)

            # Cache the generated code
            playbook.lambda_code = code
            self.playbook_store.save(playbook)

        return {
            'playbook_id': playbook_id,
            'code': code,
            'regenerated': regenerate,
        }

    def validate_playbook(
        self,
        playbook_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Validate playbook data without saving.

        Args:
            playbook_data: Playbook data to validate

        Returns:
            Dict with validation results
        """
        try:
            playbook = Playbook.from_dict(playbook_data)
            is_valid, errors = playbook.validate()

            return {
                'valid': is_valid,
                'errors': errors,
            }

        except Exception as e:
            return {
                'valid': False,
                'errors': [str(e)],
            }

    def list_versions(
        self,
        user_id: str,
        playbook_id: str,
    ) -> Dict[str, Any]:
        """List all versions of a playbook.

        Args:
            user_id: ID of requesting user
            playbook_id: Playbook ID

        Returns:
            Dict with version list

        Raises:
            ValueError: If playbook not found
        """
        playbook = self.playbook_store.get(playbook_id)
        if not playbook:
            raise ValueError(f'Playbook not found: {playbook_id}')

        versions = self.playbook_store.list_versions(playbook_id)

        return {
            'playbook_id': playbook_id,
            'versions': versions,
            'current_version': playbook.version,
        }

    def get_version(
        self,
        user_id: str,
        playbook_id: str,
        version: str,
    ) -> Dict[str, Any]:
        """Get a specific version of a playbook.

        Args:
            user_id: ID of requesting user
            playbook_id: Playbook ID
            version: Version string

        Returns:
            Dict with playbook at specified version

        Raises:
            ValueError: If version not found
        """
        playbook = self.playbook_store.get_version(playbook_id, version)
        if not playbook:
            raise ValueError(f'Playbook version not found: {playbook_id}@{version}')

        return {
            'playbook': playbook.to_dict(),
        }
