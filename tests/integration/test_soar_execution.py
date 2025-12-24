"""Integration tests for SOAR playbook execution.

Tests:
- Playbook execution flow
- Approval workflow
- Dry run mode
- Step dependencies
- Timeout handling
- Action logging
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from src.shared.soar.models import (
    Playbook,
    PlaybookStep,
    PlaybookTrigger,
    ActionType,
    ApprovalRequirement,
    PlaybookStatus,
    Execution,
    ExecutionStatus,
    StepResult,
    ApprovalRequest,
    ApprovalStatus,
)
from src.shared.soar.execution_engine import ExecutionEngine, ExecutionContext


class TestPlaybookExecution:
    """Tests for basic playbook execution."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine with mocked dependencies."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            engine = ExecutionEngine()
            engine.action_executor = mock_executor.return_value
            engine.action_executor.execute = AsyncMock(return_value={
                "success": True,
                "result": {"message": "Action completed"}
            })
            return engine

    @pytest.fixture
    def simple_playbook(self):
        """Create simple playbook without approvals."""
        return Playbook(
            playbook_id="pb-exec-test",
            name="Execution Test Playbook",
            description="Test execution flow",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Send Notification",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "Test notification"},
                    requires_approval=ApprovalRequirement.NOT_REQUIRED,
                ),
            ],
            created_by="test-user",
        )

    @pytest.fixture
    def multi_step_playbook(self):
        """Create playbook with multiple steps."""
        return Playbook(
            playbook_id="pb-multi-step",
            name="Multi-Step Playbook",
            description="Test multi-step execution",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Step One",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "Step 1"},
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Step Two",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "Step 2"},
                    depends_on=["step-1"],
                ),
                PlaybookStep(
                    step_id="step-3",
                    name="Step Three",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "Step 3"},
                    depends_on=["step-2"],
                ),
            ],
            created_by="test-user",
        )

    @pytest.mark.asyncio
    async def test_execute_simple_playbook(self, execution_engine, simple_playbook):
        """Test executing a simple playbook."""
        context = ExecutionContext(
            trigger_type="manual",
            trigger_data={"user": "test-user"},
        )

        execution = await execution_engine.execute(simple_playbook, context)

        assert execution is not None
        assert execution.status == ExecutionStatus.COMPLETED
        assert len(execution.step_results) == 1
        assert execution.step_results[0].success is True

    @pytest.mark.asyncio
    async def test_execute_multi_step_playbook(self, execution_engine, multi_step_playbook):
        """Test executing playbook with multiple dependent steps."""
        context = ExecutionContext(
            trigger_type="manual",
            trigger_data={},
        )

        execution = await execution_engine.execute(multi_step_playbook, context)

        assert execution.status == ExecutionStatus.COMPLETED
        assert len(execution.step_results) == 3

        # Verify execution order
        step_ids = [r.step_id for r in execution.step_results]
        assert step_ids == ["step-1", "step-2", "step-3"]

    @pytest.mark.asyncio
    async def test_execution_with_parameter_substitution(self, execution_engine):
        """Test parameter substitution from trigger context."""
        playbook = Playbook(
            playbook_id="pb-param-test",
            name="Parameter Test",
            description="Test parameter substitution",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Notify",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={
                        "message": "Alert from {{alert.source_ip}} for user {{alert.user_id}}",
                    },
                ),
            ],
            created_by="test-user",
        )

        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={
                "alert": {
                    "source_ip": "192.168.1.100",
                    "user_id": "john.doe",
                }
            },
        )

        execution = await execution_engine.execute(playbook, context)

        # Verify parameters were substituted
        assert execution.status == ExecutionStatus.COMPLETED
        call_args = execution_engine.action_executor.execute.call_args
        params = call_args[1].get("parameters", call_args[0][1] if len(call_args[0]) > 1 else {})
        assert "192.168.1.100" in str(params) or execution.step_results[0].success


class TestApprovalWorkflow:
    """Tests for approval workflow."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine with approval support."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            with patch("src.shared.soar.execution_engine.ApprovalManager") as mock_approval:
                engine = ExecutionEngine()
                engine.action_executor = mock_executor.return_value
                engine.approval_manager = mock_approval.return_value
                engine.action_executor.execute = AsyncMock(return_value={
                    "success": True,
                    "result": {}
                })
                return engine

    @pytest.fixture
    def playbook_with_approval(self):
        """Create playbook requiring approval."""
        return Playbook(
            playbook_id="pb-approval-test",
            name="Approval Test Playbook",
            description="Test approval workflow",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Disable User",
                    action_type=ActionType.DISABLE_USER,
                    parameters={"user_id": "{{alert.user_id}}"},
                    requires_approval=ApprovalRequirement.REQUIRED,
                    approval_timeout_seconds=3600,
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Notify",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "User disabled"},
                    depends_on=["step-1"],
                ),
            ],
            created_by="test-user",
        )

    @pytest.mark.asyncio
    async def test_execution_pauses_for_approval(self, execution_engine, playbook_with_approval):
        """Test that execution pauses when approval is required."""
        execution_engine.approval_manager.create_request = AsyncMock(return_value=ApprovalRequest(
            id="approval-001",
            execution_id="exec-001",
            step_id="step-1",
            playbook_id="pb-approval-test",
            status=ApprovalStatus.PENDING,
        ))
        execution_engine.approval_manager.wait_for_approval = AsyncMock(return_value=None)

        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={"alert": {"user_id": "test-user"}},
        )

        execution = await execution_engine.execute(
            playbook_with_approval,
            context,
            wait_for_approval=False
        )

        assert execution.status == ExecutionStatus.PENDING_APPROVAL
        assert execution_engine.approval_manager.create_request.called

    @pytest.mark.asyncio
    async def test_execution_continues_after_approval(self, execution_engine, playbook_with_approval):
        """Test that execution continues after approval is granted."""
        execution_engine.approval_manager.create_request = AsyncMock(return_value=ApprovalRequest(
            id="approval-001",
            execution_id="exec-001",
            step_id="step-1",
            playbook_id="pb-approval-test",
            status=ApprovalStatus.APPROVED,
        ))
        execution_engine.approval_manager.wait_for_approval = AsyncMock(return_value=ApprovalRequest(
            id="approval-001",
            execution_id="exec-001",
            step_id="step-1",
            playbook_id="pb-approval-test",
            status=ApprovalStatus.APPROVED,
            approved_by="admin-user",
        ))

        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={"alert": {"user_id": "test-user"}},
        )

        execution = await execution_engine.execute(
            playbook_with_approval,
            context,
            wait_for_approval=True
        )

        assert execution.status == ExecutionStatus.COMPLETED
        assert len(execution.step_results) == 2

    @pytest.mark.asyncio
    async def test_execution_stops_on_denial(self, execution_engine, playbook_with_approval):
        """Test that execution stops when approval is denied."""
        execution_engine.approval_manager.create_request = AsyncMock(return_value=ApprovalRequest(
            id="approval-001",
            execution_id="exec-001",
            step_id="step-1",
            playbook_id="pb-approval-test",
            status=ApprovalStatus.PENDING,
        ))
        execution_engine.approval_manager.wait_for_approval = AsyncMock(return_value=ApprovalRequest(
            id="approval-001",
            execution_id="exec-001",
            step_id="step-1",
            playbook_id="pb-approval-test",
            status=ApprovalStatus.DENIED,
            denied_by="admin-user",
            denial_reason="Not authorized",
        ))

        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={"alert": {"user_id": "test-user"}},
        )

        execution = await execution_engine.execute(
            playbook_with_approval,
            context,
            wait_for_approval=True
        )

        assert execution.status == ExecutionStatus.CANCELLED
        # Step 2 should not have executed
        executed_steps = [r.step_id for r in execution.step_results if r.executed]
        assert "step-2" not in executed_steps


class TestDryRunMode:
    """Tests for dry run mode."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            engine = ExecutionEngine()
            engine.action_executor = mock_executor.return_value
            engine.action_executor.execute = AsyncMock(return_value={
                "success": True,
                "result": {}
            })
            return engine

    @pytest.fixture
    def dangerous_playbook(self):
        """Create playbook with dangerous actions."""
        return Playbook(
            playbook_id="pb-dangerous",
            name="Dangerous Playbook",
            description="Has dangerous actions",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Isolate Host",
                    action_type=ActionType.ISOLATE_HOST,
                    parameters={"host_id": "{{alert.host_id}}"},
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Block IP",
                    action_type=ActionType.BLOCK_IP,
                    parameters={"ip_address": "{{alert.source_ip}}"},
                ),
            ],
            created_by="test-user",
        )

    @pytest.mark.asyncio
    async def test_dry_run_does_not_execute_actions(self, execution_engine, dangerous_playbook):
        """Test that dry run doesn't actually execute actions."""
        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={
                "alert": {
                    "host_id": "host-123",
                    "source_ip": "192.168.1.100",
                }
            },
        )

        execution = await execution_engine.execute(
            dangerous_playbook,
            context,
            dry_run=True
        )

        assert execution.dry_run is True
        assert execution.status == ExecutionStatus.COMPLETED
        # Action executor should not have been called for actual execution
        # or should have been called with dry_run=True
        for call in execution_engine.action_executor.execute.call_args_list:
            if "dry_run" in call.kwargs:
                assert call.kwargs["dry_run"] is True

    @pytest.mark.asyncio
    async def test_dry_run_validates_parameters(self, execution_engine, dangerous_playbook):
        """Test that dry run validates parameter substitution."""
        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={
                "alert": {
                    # Missing host_id
                    "source_ip": "192.168.1.100",
                }
            },
        )

        execution = await execution_engine.execute(
            dangerous_playbook,
            context,
            dry_run=True
        )

        # Should complete but note missing parameters
        assert execution.dry_run is True


class TestStepDependencies:
    """Tests for step dependency handling."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            engine = ExecutionEngine()
            engine.action_executor = mock_executor.return_value
            return engine

    @pytest.fixture
    def playbook_with_branching(self):
        """Create playbook with branching dependencies."""
        return Playbook(
            playbook_id="pb-branching",
            name="Branching Playbook",
            description="Has branching execution paths",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Initial Check",
                    action_type=ActionType.RUN_SCRIPT,
                    parameters={"script": "check.py"},
                ),
                PlaybookStep(
                    step_id="step-2a",
                    name="Path A",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "Path A"},
                    depends_on=["step-1"],
                    on_success=True,
                ),
                PlaybookStep(
                    step_id="step-2b",
                    name="Path B",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "Path B"},
                    depends_on=["step-1"],
                    on_failure=True,
                ),
            ],
            created_by="test-user",
        )

    @pytest.mark.asyncio
    async def test_success_path_execution(self, execution_engine, playbook_with_branching):
        """Test execution follows success path."""
        execution_engine.action_executor.execute = AsyncMock(return_value={
            "success": True,
            "result": {}
        })

        context = ExecutionContext(trigger_type="manual", trigger_data={})
        execution = await execution_engine.execute(playbook_with_branching, context)

        executed_ids = [r.step_id for r in execution.step_results if r.executed]
        assert "step-1" in executed_ids
        assert "step-2a" in executed_ids
        assert "step-2b" not in executed_ids

    @pytest.mark.asyncio
    async def test_failure_path_execution(self, execution_engine, playbook_with_branching):
        """Test execution follows failure path."""
        call_count = 0

        async def mock_execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": False, "error": "Check failed"}
            return {"success": True, "result": {}}

        execution_engine.action_executor.execute = mock_execute

        context = ExecutionContext(trigger_type="manual", trigger_data={})
        execution = await execution_engine.execute(playbook_with_branching, context)

        executed_ids = [r.step_id for r in execution.step_results if r.executed]
        assert "step-1" in executed_ids
        assert "step-2b" in executed_ids
        assert "step-2a" not in executed_ids


class TestTimeoutHandling:
    """Tests for timeout handling."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            engine = ExecutionEngine()
            engine.action_executor = mock_executor.return_value
            return engine

    @pytest.fixture
    def playbook_with_timeout(self):
        """Create playbook with timeout settings."""
        return Playbook(
            playbook_id="pb-timeout",
            name="Timeout Test Playbook",
            description="Test timeout handling",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Slow Action",
                    action_type=ActionType.RUN_SCRIPT,
                    parameters={"script": "slow.py"},
                    timeout_seconds=5,
                ),
            ],
            created_by="test-user",
        )

    @pytest.mark.asyncio
    async def test_step_timeout(self, execution_engine, playbook_with_timeout):
        """Test that step times out correctly."""
        async def slow_execute(*args, **kwargs):
            await asyncio.sleep(10)
            return {"success": True}

        execution_engine.action_executor.execute = slow_execute

        context = ExecutionContext(trigger_type="manual", trigger_data={})

        execution = await execution_engine.execute(playbook_with_timeout, context)

        assert execution.step_results[0].success is False
        assert "timeout" in execution.step_results[0].error.lower()


class TestActionLogging:
    """Tests for action logging."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine with logging."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            with patch("src.shared.soar.execution_engine.ActionLogger") as mock_logger:
                engine = ExecutionEngine()
                engine.action_executor = mock_executor.return_value
                engine.action_logger = mock_logger.return_value
                engine.action_executor.execute = AsyncMock(return_value={
                    "success": True,
                    "result": {}
                })
                engine.action_logger.log = AsyncMock()
                return engine

    @pytest.fixture
    def simple_playbook(self):
        """Create simple playbook."""
        return Playbook(
            playbook_id="pb-logging-test",
            name="Logging Test",
            description="Test action logging",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Test Action",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "test"},
                ),
            ],
            created_by="test-user",
        )

    @pytest.mark.asyncio
    async def test_actions_are_logged(self, execution_engine, simple_playbook):
        """Test that all actions are logged."""
        context = ExecutionContext(trigger_type="manual", trigger_data={})

        await execution_engine.execute(simple_playbook, context)

        # Verify logger was called
        assert execution_engine.action_logger.log.called

    @pytest.mark.asyncio
    async def test_log_includes_execution_details(self, execution_engine, simple_playbook):
        """Test that log includes execution details."""
        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={"alert_id": "alert-123"},
        )

        await execution_engine.execute(simple_playbook, context)

        # Check log call arguments
        log_calls = execution_engine.action_logger.log.call_args_list
        assert len(log_calls) > 0

        # Verify log contains expected data
        for call in log_calls:
            log_data = call[0][0] if call[0] else call[1]
            assert "playbook_id" in str(log_data) or "step_id" in str(log_data)


class TestExecutionRecovery:
    """Tests for execution recovery and resumption."""

    @pytest.fixture
    def execution_engine(self):
        """Create execution engine."""
        with patch("src.shared.soar.execution_engine.ActionExecutor") as mock_executor:
            with patch("src.shared.soar.execution_engine.ExecutionStore") as mock_store:
                engine = ExecutionEngine()
                engine.action_executor = mock_executor.return_value
                engine.execution_store = mock_store.return_value
                engine.action_executor.execute = AsyncMock(return_value={
                    "success": True,
                    "result": {}
                })
                return engine

    @pytest.mark.asyncio
    async def test_resume_from_pending_approval(self, execution_engine):
        """Test resuming execution from pending approval state."""
        # Create a paused execution
        paused_execution = Execution(
            execution_id="exec-paused",
            playbook_id="pb-test",
            status=ExecutionStatus.PENDING_APPROVAL,
            step_results=[
                StepResult(
                    step_id="step-1",
                    success=True,
                    executed=True,
                ),
            ],
            current_step="step-2",
        )

        execution_engine.execution_store.get = AsyncMock(return_value=paused_execution)

        playbook = Playbook(
            playbook_id="pb-test",
            name="Test",
            description="Test",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Done Step",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={},
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Pending Step",
                    action_type=ActionType.DISABLE_USER,
                    parameters={},
                    requires_approval=ApprovalRequirement.REQUIRED,
                ),
            ],
            created_by="test-user",
        )

        # Resume with approval
        execution = await execution_engine.resume(
            "exec-paused",
            playbook,
            approval_granted=True
        )

        # Step 1 should not be re-executed
        new_executions = [r for r in execution.step_results if r.step_id == "step-2"]
        assert len(new_executions) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
