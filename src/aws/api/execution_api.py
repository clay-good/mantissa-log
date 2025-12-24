"""
Execution API Business Logic

Provides business logic functions for playbook execution operations.
Separates business logic from Lambda handler for testability.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.soar import (
    PlaybookExecution,
    PlaybookTriggerType,
    ExecutionStatus,
    get_playbook_store,
    get_execution_store,
    get_execution_engine,
    get_approval_service,
    get_action_log,
)

logger = logging.getLogger(__name__)


class ExecutionAPI:
    """Business logic for playbook execution management."""

    def __init__(
        self,
        playbook_store=None,
        execution_store=None,
        execution_engine=None,
        action_log=None,
    ):
        """Initialize execution API.

        Args:
            playbook_store: Playbook storage backend
            execution_store: Execution storage backend
            execution_engine: Playbook execution engine
            action_log: Action audit log
        """
        self.playbook_store = playbook_store or get_playbook_store()
        self.execution_store = execution_store or get_execution_store()
        self.action_log = action_log or get_action_log()
        self._engine = execution_engine

    @property
    def execution_engine(self):
        """Get lazily-initialized execution engine."""
        if self._engine is None:
            self._engine = get_execution_engine(
                playbook_store=self.playbook_store,
                execution_store=self.execution_store,
                approval_service=get_approval_service(),
                action_log=self.action_log,
            )
        return self._engine

    def execute_playbook(
        self,
        user_id: str,
        playbook_id: str,
        context: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Execute a playbook.

        Args:
            user_id: ID of user triggering execution
            playbook_id: Playbook to execute
            context: Optional trigger context
            dry_run: If True, log actions but don't execute

        Returns:
            Dict with execution ID and initial status

        Raises:
            ValueError: If playbook not found or user not authorized
        """
        # Verify playbook exists
        playbook = self.playbook_store.get(playbook_id)
        if not playbook:
            raise ValueError(f'Playbook not found: {playbook_id}')

        # Check if playbook is enabled (allow execution of disabled for dry_run)
        if not playbook.enabled and not dry_run:
            raise ValueError('Playbook is disabled. Enable it or use dry_run mode.')

        # Build trigger context
        trigger_context = {
            'user_id': user_id,
            'triggered_at': datetime.now(timezone.utc).isoformat(),
            'parameters': context or {},
        }

        # Execute playbook
        execution = self.execution_engine.execute_playbook(
            playbook_id=playbook_id,
            trigger_context=trigger_context,
            dry_run=dry_run,
            trigger_type=PlaybookTriggerType.MANUAL,
        )

        logger.info(
            f'Playbook {playbook_id} executed by {user_id}, '
            f'execution_id: {execution.execution_id}, '
            f'dry_run: {dry_run}'
        )

        return {
            'execution_id': execution.execution_id,
            'playbook_id': playbook_id,
            'status': execution.status.value,
            'dry_run': dry_run,
            'message': f'Playbook execution {"simulated (dry run)" if dry_run else "started"}',
        }

    def get_execution(
        self,
        user_id: str,
        execution_id: str,
    ) -> Dict[str, Any]:
        """Get execution details.

        Args:
            user_id: ID of requesting user
            execution_id: Execution ID

        Returns:
            Dict with execution details

        Raises:
            ValueError: If execution not found
        """
        execution = self.execution_store.get(execution_id)
        if not execution:
            raise ValueError(f'Execution not found: {execution_id}')

        result = execution.to_dict()
        result['is_complete'] = execution.is_complete
        result['duration_ms'] = execution.duration_ms

        return {
            'execution': result,
        }

    def list_executions(
        self,
        user_id: str,
        playbook_id: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """List executions with filters.

        Args:
            user_id: ID of requesting user
            playbook_id: Filter by playbook ID
            status: Filter by status
            page: Page number
            page_size: Results per page

        Returns:
            Dict with execution list and pagination
        """
        # Parse status filter
        status_enum = None
        if status:
            try:
                status_enum = ExecutionStatus(status)
            except ValueError:
                raise ValueError(f'Invalid status: {status}')

        # Get executions
        offset = (page - 1) * page_size
        executions = self.execution_store.list(
            playbook_id=playbook_id,
            status=status_enum,
            limit=page_size,
            offset=offset,
        )

        return {
            'executions': [e.to_dict() for e in executions],
            'page': page,
            'page_size': page_size,
        }

    def cancel_execution(
        self,
        user_id: str,
        execution_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """Cancel a running execution.

        Args:
            user_id: ID of user cancelling
            execution_id: Execution to cancel
            reason: Optional cancellation reason

        Returns:
            True if cancelled successfully

        Raises:
            ValueError: If execution not found or cannot be cancelled
        """
        execution = self.execution_store.get(execution_id)
        if not execution:
            raise ValueError(f'Execution not found: {execution_id}')

        if execution.is_complete:
            raise ValueError(
                f'Execution is already {execution.status.value} '
                'and cannot be cancelled'
            )

        success = self.execution_engine.cancel_execution(execution_id)
        if success:
            logger.info(
                f'Execution {execution_id} cancelled by {user_id}: '
                f'{reason or "No reason given"}'
            )

        return success

    def get_execution_logs(
        self,
        user_id: str,
        execution_id: str,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get action logs for an execution.

        Args:
            user_id: ID of requesting user
            execution_id: Execution ID
            limit: Maximum number of logs

        Returns:
            Dict with log entries

        Raises:
            ValueError: If execution not found
        """
        # Verify execution exists
        execution = self.execution_store.get(execution_id)
        if not execution:
            raise ValueError(f'Execution not found: {execution_id}')

        # Get logs
        logs = self.action_log.get_actions(execution_id, limit=limit)

        return {
            'execution_id': execution_id,
            'logs': [log.to_dict() for log in logs],
            'total': len(logs),
        }

    def get_execution_stats(
        self,
        user_id: str,
        playbook_id: Optional[str] = None,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get execution statistics.

        Args:
            user_id: ID of requesting user
            playbook_id: Optional filter by playbook
            days: Number of days to analyze

        Returns:
            Dict with statistics
        """
        # Get recent executions
        executions = self.execution_store.list(
            playbook_id=playbook_id,
            limit=1000,  # Reasonable limit for stats
        )

        # Calculate stats
        total = len(executions)
        completed = len([e for e in executions if e.status == ExecutionStatus.COMPLETED])
        failed = len([e for e in executions if e.status == ExecutionStatus.FAILED])
        pending = len([e for e in executions if e.status == ExecutionStatus.PENDING_APPROVAL])
        running = len([e for e in executions if e.status == ExecutionStatus.RUNNING])

        # Calculate average duration for completed executions
        durations = [
            e.duration_ms for e in executions
            if e.status == ExecutionStatus.COMPLETED and e.duration_ms
        ]
        avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            'total_executions': total,
            'completed': completed,
            'failed': failed,
            'pending_approval': pending,
            'running': running,
            'success_rate': completed / total if total > 0 else 0,
            'failure_rate': failed / total if total > 0 else 0,
            'average_duration_ms': avg_duration,
        }

    def execute_alert_response(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Execute playbooks matching an alert.

        This is called by the alert router to automatically
        execute playbooks triggered by alerts.

        Args:
            alert_id: Alert ID
            alert_data: Alert data

        Returns:
            List of execution results
        """
        # Find matching playbooks
        playbooks = self.playbook_store.list(filters={'enabled': True})

        # Filter to alert-triggered playbooks that match
        matching = []
        for playbook in playbooks:
            if playbook.trigger.trigger_type != PlaybookTriggerType.ALERT:
                continue

            # Create a mock alert object for matching
            class MockAlert:
                def __init__(self, data):
                    self.severity = data.get('severity', '')
                    self.rule_name = data.get('rule_name', '')
                    self.rule_id = data.get('rule_id', '')
                    self.tags = data.get('tags', [])

                def to_dict(self):
                    return alert_data

            mock = MockAlert(alert_data)
            if playbook.trigger.matches_alert(mock):
                matching.append(playbook)

        # Execute matching playbooks
        results = []
        for playbook in matching:
            try:
                trigger_context = {
                    'alert': alert_data,
                    'alert_id': alert_id,
                }

                execution = self.execution_engine.execute_playbook(
                    playbook_id=playbook.id,
                    trigger_context=trigger_context,
                    dry_run=False,  # Real execution for alert response
                    trigger_type=PlaybookTriggerType.ALERT,
                )

                results.append({
                    'playbook_id': playbook.id,
                    'playbook_name': playbook.name,
                    'execution_id': execution.execution_id,
                    'status': execution.status.value,
                    'success': True,
                })

                logger.info(
                    f'Alert {alert_id} triggered playbook {playbook.id}, '
                    f'execution: {execution.execution_id}'
                )

            except Exception as e:
                logger.error(f'Failed to execute playbook {playbook.id}: {e}')
                results.append({
                    'playbook_id': playbook.id,
                    'playbook_name': playbook.name,
                    'error': str(e),
                    'success': False,
                })

        return results
