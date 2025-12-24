"""Integration tests for SOAR playbook operations.

Tests:
- Playbook CRUD operations
- IR plan parsing
- Playbook code generation
- Playbook validation
- Version management
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
import yaml

from src.shared.soar.models import (
    Playbook,
    PlaybookStep,
    PlaybookTrigger,
    ActionType,
    ApprovalRequirement,
    PlaybookStatus,
)
from src.shared.soar.storage import PlaybookStorage, FilePlaybookStorage
from src.shared.soar.ir_plan_parser import IRPlanParser
from src.shared.soar.code_generator import PlaybookCodeGenerator


class TestPlaybookCRUD:
    """Tests for playbook CRUD operations."""

    @pytest.fixture
    def temp_storage_dir(self, tmp_path):
        """Create temporary directory for playbook storage."""
        return tmp_path / "playbooks"

    @pytest.fixture
    def playbook_storage(self, temp_storage_dir):
        """Create file-based playbook storage."""
        return FilePlaybookStorage(str(temp_storage_dir))

    @pytest.fixture
    def sample_playbook(self):
        """Create sample playbook for testing."""
        return Playbook(
            playbook_id="pb-test-001",
            name="Credential Compromise Response",
            description="Respond to credential compromise alerts",
            version="1.0.0",
            status=PlaybookStatus.DRAFT,
            trigger=PlaybookTrigger(
                trigger_type="alert",
                conditions={"rule_id": "credential_compromise_*"},
            ),
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Disable User Account",
                    action_type=ActionType.DISABLE_USER,
                    parameters={"user_id": "{{alert.user_id}}"},
                    requires_approval=ApprovalRequirement.REQUIRED,
                    timeout_seconds=300,
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Revoke Sessions",
                    action_type=ActionType.REVOKE_SESSIONS,
                    parameters={"user_id": "{{alert.user_id}}"},
                    depends_on=["step-1"],
                ),
                PlaybookStep(
                    step_id="step-3",
                    name="Notify Security Team",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={
                        "channel": "security-alerts",
                        "message": "User {{alert.user_id}} disabled due to credential compromise",
                    },
                ),
            ],
            tags=["credential", "compromise", "identity"],
            created_by="test-user",
        )

    def test_create_playbook(self, playbook_storage, sample_playbook):
        """Test creating a new playbook."""
        result = playbook_storage.save(sample_playbook)

        assert result is True

        # Verify playbook was saved
        retrieved = playbook_storage.get(sample_playbook.playbook_id)
        assert retrieved is not None
        assert retrieved.name == sample_playbook.name
        assert len(retrieved.steps) == 3

    def test_read_playbook(self, playbook_storage, sample_playbook):
        """Test reading a playbook."""
        playbook_storage.save(sample_playbook)

        retrieved = playbook_storage.get(sample_playbook.playbook_id)

        assert retrieved is not None
        assert retrieved.playbook_id == sample_playbook.playbook_id
        assert retrieved.name == sample_playbook.name
        assert retrieved.version == "1.0.0"

    def test_update_playbook(self, playbook_storage, sample_playbook):
        """Test updating a playbook."""
        playbook_storage.save(sample_playbook)

        # Update playbook
        sample_playbook.name = "Updated Playbook Name"
        sample_playbook.description = "Updated description"
        playbook_storage.save(sample_playbook)

        # Verify update
        retrieved = playbook_storage.get(sample_playbook.playbook_id)
        assert retrieved.name == "Updated Playbook Name"
        assert retrieved.description == "Updated description"

    def test_delete_playbook(self, playbook_storage, sample_playbook):
        """Test deleting a playbook."""
        playbook_storage.save(sample_playbook)

        result = playbook_storage.delete(sample_playbook.playbook_id)
        assert result is True

        # Verify deletion
        retrieved = playbook_storage.get(sample_playbook.playbook_id)
        assert retrieved is None

    def test_list_playbooks(self, playbook_storage, sample_playbook):
        """Test listing all playbooks."""
        # Create multiple playbooks
        playbook_storage.save(sample_playbook)

        playbook2 = Playbook(
            playbook_id="pb-test-002",
            name="Malware Response",
            description="Respond to malware alerts",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[],
            created_by="test-user",
        )
        playbook_storage.save(playbook2)

        # List all
        playbooks = playbook_storage.list_all()
        assert len(playbooks) >= 2

    def test_get_nonexistent_playbook(self, playbook_storage):
        """Test getting a playbook that doesn't exist."""
        retrieved = playbook_storage.get("nonexistent-id")
        assert retrieved is None


class TestPlaybookVersioning:
    """Tests for playbook version management."""

    @pytest.fixture
    def playbook_storage(self, tmp_path):
        """Create file-based playbook storage."""
        return FilePlaybookStorage(str(tmp_path / "playbooks"))

    @pytest.fixture
    def sample_playbook(self):
        """Create sample playbook."""
        return Playbook(
            playbook_id="pb-version-test",
            name="Version Test Playbook",
            description="Test versioning",
            version="1.0.0",
            status=PlaybookStatus.DRAFT,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Test Step",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "test"},
                ),
            ],
            created_by="test-user",
        )

    def test_version_increment(self, playbook_storage, sample_playbook):
        """Test incrementing playbook version."""
        playbook_storage.save(sample_playbook)

        # Create new version
        sample_playbook.version = "1.1.0"
        sample_playbook.steps.append(
            PlaybookStep(
                step_id="step-2",
                name="New Step",
                action_type=ActionType.SEND_NOTIFICATION,
                parameters={"message": "new step"},
            )
        )

        playbook_storage.save_version(sample_playbook)

        # Verify both versions exist
        versions = playbook_storage.list_versions(sample_playbook.playbook_id)
        assert "1.0.0" in versions or len(versions) >= 1

    def test_get_specific_version(self, playbook_storage, sample_playbook):
        """Test retrieving specific playbook version."""
        playbook_storage.save(sample_playbook)

        retrieved = playbook_storage.get(
            sample_playbook.playbook_id,
            version=sample_playbook.version
        )

        assert retrieved is not None
        assert retrieved.version == "1.0.0"


class TestIRPlanParsing:
    """Tests for IR plan parsing."""

    @pytest.fixture
    def ir_plan_parser(self):
        """Create IR plan parser with mocked LLM."""
        with patch("src.shared.soar.ir_plan_parser.LLMClient") as mock_llm:
            parser = IRPlanParser()
            parser.llm_client = mock_llm.return_value
            return parser

    @pytest.fixture
    def sample_ir_plan_markdown(self):
        """Sample IR plan in markdown format."""
        return """
# Credential Compromise Response Plan

## Overview
This plan outlines the response procedure when a credential compromise is detected.

## Steps

### 1. Disable User Account
- Action: Disable the compromised user account immediately
- Owner: Security Team
- Priority: Critical
- Requires approval: Yes

### 2. Revoke All Sessions
- Action: Terminate all active sessions for the user
- Owner: Security Team
- Dependencies: Step 1 must complete first

### 3. Reset Credentials
- Action: Force password reset for the user
- Owner: IT Support
- Dependencies: Step 2 must complete first

### 4. Notify User
- Action: Send notification to user about the incident
- Owner: Security Team
- Message template: Your account was temporarily disabled due to suspicious activity

### 5. Document Incident
- Action: Create incident ticket
- Owner: SOC
- Include: Timeline, affected systems, remediation steps
"""

    @pytest.fixture
    def sample_ir_plan_yaml(self):
        """Sample IR plan in YAML format."""
        return """
name: Malware Response Plan
description: Response procedure for malware detection

steps:
  - name: Isolate Host
    action: isolate_host
    priority: critical
    requires_approval: true
    parameters:
      reason: "Malware detected"

  - name: Collect Forensics
    action: collect_forensics
    priority: high
    depends_on:
      - Isolate Host

  - name: Scan Network
    action: run_script
    parameters:
      script: network_scan.py

  - name: Notify Security Team
    action: send_notification
    parameters:
      channel: security-alerts
      message: "Malware incident response initiated"
"""

    def test_parse_markdown_plan(self, ir_plan_parser, sample_ir_plan_markdown):
        """Test parsing markdown IR plan."""
        # Mock LLM response
        mock_playbook_data = {
            "name": "Credential Compromise Response Plan",
            "description": "Response procedure when a credential compromise is detected",
            "steps": [
                {
                    "name": "Disable User Account",
                    "action_type": "disable_user",
                    "requires_approval": True,
                },
                {
                    "name": "Revoke All Sessions",
                    "action_type": "revoke_sessions",
                    "depends_on": ["Disable User Account"],
                },
                {
                    "name": "Reset Credentials",
                    "action_type": "reset_password",
                    "depends_on": ["Revoke All Sessions"],
                },
                {
                    "name": "Notify User",
                    "action_type": "send_notification",
                },
                {
                    "name": "Document Incident",
                    "action_type": "create_ticket",
                },
            ],
        }

        ir_plan_parser.llm_client.parse_ir_plan.return_value = mock_playbook_data

        playbook = ir_plan_parser.parse(sample_ir_plan_markdown, format="markdown")

        assert playbook is not None
        assert "Credential Compromise" in playbook.name
        assert len(playbook.steps) >= 4

    def test_parse_yaml_plan(self, ir_plan_parser, sample_ir_plan_yaml):
        """Test parsing YAML IR plan."""
        # YAML parsing doesn't need LLM
        playbook = ir_plan_parser.parse(sample_ir_plan_yaml, format="yaml")

        assert playbook is not None
        assert playbook.name == "Malware Response Plan"
        assert len(playbook.steps) == 4

    def test_detect_plan_format(self, ir_plan_parser, sample_ir_plan_markdown, sample_ir_plan_yaml):
        """Test automatic format detection."""
        assert ir_plan_parser.detect_format(sample_ir_plan_markdown) == "markdown"
        assert ir_plan_parser.detect_format(sample_ir_plan_yaml) == "yaml"

    def test_parse_invalid_plan(self, ir_plan_parser):
        """Test handling of invalid IR plan."""
        invalid_plan = "This is not a valid IR plan format"

        ir_plan_parser.llm_client.parse_ir_plan.return_value = None

        with pytest.raises((ValueError, Exception)):
            ir_plan_parser.parse(invalid_plan, format="markdown")


class TestPlaybookCodeGeneration:
    """Tests for playbook code generation."""

    @pytest.fixture
    def code_generator(self):
        """Create code generator."""
        return PlaybookCodeGenerator()

    @pytest.fixture
    def sample_playbook(self):
        """Create sample playbook for code generation."""
        return Playbook(
            playbook_id="pb-codegen-test",
            name="Test Playbook",
            description="Playbook for code generation testing",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Isolate Host",
                    action_type=ActionType.ISOLATE_HOST,
                    parameters={
                        "host_id": "{{alert.host_id}}",
                        "reason": "Automated isolation",
                    },
                    requires_approval=ApprovalRequirement.REQUIRED,
                    timeout_seconds=600,
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Block IP",
                    action_type=ActionType.BLOCK_IP,
                    parameters={
                        "ip_address": "{{alert.source_ip}}",
                        "duration": "24h",
                    },
                    depends_on=["step-1"],
                ),
                PlaybookStep(
                    step_id="step-3",
                    name="Send Alert",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={
                        "channel": "security-alerts",
                        "message": "Host isolated: {{alert.host_id}}",
                    },
                ),
            ],
            created_by="test-user",
        )

    def test_generate_lambda_handler(self, code_generator, sample_playbook):
        """Test generating Lambda handler code."""
        code = code_generator.generate_lambda_handler(sample_playbook)

        assert "def lambda_handler" in code or "def handler" in code
        assert sample_playbook.playbook_id in code
        assert "isolate_host" in code.lower() or "ISOLATE_HOST" in code

    def test_generate_step_executor(self, code_generator, sample_playbook):
        """Test generating step executor code."""
        step = sample_playbook.steps[0]
        code = code_generator.generate_step_executor(step)

        assert "def execute" in code or "async def execute" in code
        assert step.step_id in code or step.name in code

    def test_generate_with_approval_workflow(self, code_generator, sample_playbook):
        """Test that approval workflow is included in generated code."""
        code = code_generator.generate_lambda_handler(sample_playbook)

        # Should include approval check for step-1
        assert "approval" in code.lower() or "REQUIRED" in code

    def test_generate_with_dependencies(self, code_generator, sample_playbook):
        """Test that step dependencies are handled."""
        code = code_generator.generate_lambda_handler(sample_playbook)

        # Should handle step dependencies
        assert "depends_on" in code.lower() or "step-1" in code

    def test_generate_with_error_handling(self, code_generator, sample_playbook):
        """Test that error handling is included."""
        code = code_generator.generate_lambda_handler(sample_playbook)

        assert "try:" in code or "except" in code or "error" in code.lower()

    def test_validate_generated_code_syntax(self, code_generator, sample_playbook):
        """Test that generated code has valid Python syntax."""
        code = code_generator.generate_lambda_handler(sample_playbook)

        # Should compile without syntax errors
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            pytest.fail(f"Generated code has syntax error: {e}")


class TestPlaybookValidation:
    """Tests for playbook validation."""

    @pytest.fixture
    def playbook_storage(self, tmp_path):
        """Create playbook storage."""
        return FilePlaybookStorage(str(tmp_path / "playbooks"))

    def test_validate_valid_playbook(self):
        """Test validation of valid playbook."""
        playbook = Playbook(
            playbook_id="pb-valid",
            name="Valid Playbook",
            description="A valid playbook",
            version="1.0.0",
            status=PlaybookStatus.DRAFT,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Test Step",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "test"},
                ),
            ],
            created_by="test-user",
        )

        errors = playbook.validate()
        assert len(errors) == 0

    def test_validate_missing_steps(self):
        """Test validation fails for playbook without steps."""
        playbook = Playbook(
            playbook_id="pb-no-steps",
            name="No Steps Playbook",
            description="Playbook without steps",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            steps=[],
            created_by="test-user",
        )

        errors = playbook.validate()
        assert len(errors) > 0
        assert any("step" in e.lower() for e in errors)

    def test_validate_circular_dependencies(self):
        """Test validation detects circular dependencies."""
        playbook = Playbook(
            playbook_id="pb-circular",
            name="Circular Deps Playbook",
            description="Has circular dependencies",
            version="1.0.0",
            status=PlaybookStatus.DRAFT,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Step 1",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "1"},
                    depends_on=["step-2"],
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Step 2",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "2"},
                    depends_on=["step-1"],
                ),
            ],
            created_by="test-user",
        )

        errors = playbook.validate()
        assert len(errors) > 0
        assert any("circular" in e.lower() or "dependency" in e.lower() for e in errors)

    def test_validate_invalid_dependency_reference(self):
        """Test validation detects invalid dependency references."""
        playbook = Playbook(
            playbook_id="pb-bad-dep",
            name="Bad Dependency Playbook",
            description="References nonexistent step",
            version="1.0.0",
            status=PlaybookStatus.DRAFT,
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Step 1",
                    action_type=ActionType.SEND_NOTIFICATION,
                    parameters={"message": "1"},
                    depends_on=["nonexistent-step"],
                ),
            ],
            created_by="test-user",
        )

        errors = playbook.validate()
        assert len(errors) > 0


class TestPlaybookSerialization:
    """Tests for playbook serialization."""

    @pytest.fixture
    def sample_playbook(self):
        """Create sample playbook."""
        return Playbook(
            playbook_id="pb-serialize",
            name="Serialization Test",
            description="Test serialization",
            version="1.0.0",
            status=PlaybookStatus.ACTIVE,
            trigger=PlaybookTrigger(
                trigger_type="alert",
                conditions={"severity": "critical"},
            ),
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Test Step",
                    action_type=ActionType.DISABLE_USER,
                    parameters={"user_id": "{{user}}"},
                    requires_approval=ApprovalRequirement.REQUIRED,
                ),
            ],
            tags=["test", "serialization"],
            created_by="test-user",
        )

    def test_to_dict(self, sample_playbook):
        """Test playbook to dictionary conversion."""
        data = sample_playbook.to_dict()

        assert data["playbook_id"] == "pb-serialize"
        assert data["name"] == "Serialization Test"
        assert data["version"] == "1.0.0"
        assert len(data["steps"]) == 1
        assert data["tags"] == ["test", "serialization"]

    def test_to_yaml(self, sample_playbook):
        """Test playbook to YAML conversion."""
        yaml_str = sample_playbook.to_yaml()

        parsed = yaml.safe_load(yaml_str)
        assert parsed["name"] == "Serialization Test"
        assert len(parsed["steps"]) == 1

    def test_from_dict(self, sample_playbook):
        """Test playbook from dictionary creation."""
        data = sample_playbook.to_dict()
        restored = Playbook.from_dict(data)

        assert restored.playbook_id == sample_playbook.playbook_id
        assert restored.name == sample_playbook.name
        assert len(restored.steps) == len(sample_playbook.steps)

    def test_from_yaml(self, sample_playbook):
        """Test playbook from YAML creation."""
        yaml_str = sample_playbook.to_yaml()
        restored = Playbook.from_yaml(yaml_str)

        assert restored.name == sample_playbook.name
        assert len(restored.steps) == len(sample_playbook.steps)

    def test_json_serializable(self, sample_playbook):
        """Test that playbook dict is JSON serializable."""
        data = sample_playbook.to_dict()

        # Should not raise
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert parsed["playbook_id"] == sample_playbook.playbook_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
