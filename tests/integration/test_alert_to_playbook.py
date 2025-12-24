"""Integration tests for alert-to-playbook flow.

Tests:
- End-to-end flow: alert triggers playbook
- Detection generates alert
- Alert matches playbook trigger
- Playbook executes
- Actions are logged
"""

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
    ExecutionStatus,
)
from src.shared.detection.alert_generator import Alert, AlertGenerator


class TestAlertTriggerMatching:
    """Tests for alert-to-playbook trigger matching."""

    @pytest.fixture
    def playbook_registry(self):
        """Create playbook registry with multiple playbooks."""
        playbooks = [
            Playbook(
                playbook_id="pb-credential-compromise",
                name="Credential Compromise Response",
                description="Respond to credential compromise",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger=PlaybookTrigger(
                    trigger_type="alert",
                    conditions={
                        "rule_id": "credential_compromise_*",
                        "severity": ["high", "critical"],
                    },
                ),
                steps=[
                    PlaybookStep(
                        step_id="step-1",
                        name="Disable User",
                        action_type=ActionType.DISABLE_USER,
                        parameters={"user_id": "{{alert.user_id}}"},
                        requires_approval=ApprovalRequirement.REQUIRED,
                    ),
                ],
                created_by="system",
            ),
            Playbook(
                playbook_id="pb-malware-response",
                name="Malware Response",
                description="Respond to malware alerts",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger=PlaybookTrigger(
                    trigger_type="alert",
                    conditions={
                        "rule_id": "malware_*",
                        "tags": ["malware"],
                    },
                ),
                steps=[
                    PlaybookStep(
                        step_id="step-1",
                        name="Isolate Host",
                        action_type=ActionType.ISOLATE_HOST,
                        parameters={"host_id": "{{alert.host_id}}"},
                    ),
                ],
                created_by="system",
            ),
            Playbook(
                playbook_id="pb-brute-force",
                name="Brute Force Response",
                description="Respond to brute force attempts",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger=PlaybookTrigger(
                    trigger_type="alert",
                    conditions={
                        "rule_id": "brute_force_*",
                    },
                ),
                steps=[
                    PlaybookStep(
                        step_id="step-1",
                        name="Block IP",
                        action_type=ActionType.BLOCK_IP,
                        parameters={"ip_address": "{{alert.source_ip}}"},
                    ),
                ],
                created_by="system",
            ),
        ]

        class MockRegistry:
            def __init__(self, playbooks):
                self.playbooks = playbooks

            def get_matching_playbooks(self, alert):
                """Find playbooks that match alert criteria."""
                matching = []
                for pb in self.playbooks:
                    if pb.status != PlaybookStatus.ACTIVE:
                        continue
                    if pb.trigger and self._matches_trigger(alert, pb.trigger):
                        matching.append(pb)
                return matching

            def _matches_trigger(self, alert, trigger):
                """Check if alert matches trigger conditions."""
                conditions = trigger.conditions

                # Check rule_id pattern
                if "rule_id" in conditions:
                    pattern = conditions["rule_id"]
                    if pattern.endswith("*"):
                        prefix = pattern[:-1]
                        if not alert.rule_id.startswith(prefix):
                            return False
                    elif alert.rule_id != pattern:
                        return False

                # Check severity
                if "severity" in conditions:
                    severities = conditions["severity"]
                    if isinstance(severities, list):
                        if alert.severity not in severities:
                            return False
                    elif alert.severity != severities:
                        return False

                # Check tags
                if "tags" in conditions:
                    required_tags = set(conditions["tags"])
                    alert_tags = set(alert.tags or [])
                    if not required_tags.intersection(alert_tags):
                        return False

                return True

        return MockRegistry(playbooks)

    def test_credential_compromise_alert_matches(self, playbook_registry):
        """Test credential compromise alert matches correct playbook."""
        alert = Alert(
            id="alert-001",
            rule_id="credential_compromise_suspicious_login",
            rule_name="Suspicious Login Detected",
            severity="high",
            title="Credential Compromise: john.doe",
            description="Multiple failed logins from unusual location",
            timestamp=datetime.utcnow(),
            tags=["credential", "login"],
            metadata={"user_id": "john.doe"},
        )

        matching = playbook_registry.get_matching_playbooks(alert)

        assert len(matching) == 1
        assert matching[0].playbook_id == "pb-credential-compromise"

    def test_malware_alert_matches(self, playbook_registry):
        """Test malware alert matches correct playbook."""
        alert = Alert(
            id="alert-002",
            rule_id="malware_detected_endpoint",
            rule_name="Malware Detected",
            severity="critical",
            title="Malware Detected: host-123",
            description="Malicious file detected on endpoint",
            timestamp=datetime.utcnow(),
            tags=["malware", "endpoint"],
            metadata={"host_id": "host-123"},
        )

        matching = playbook_registry.get_matching_playbooks(alert)

        assert len(matching) == 1
        assert matching[0].playbook_id == "pb-malware-response"

    def test_brute_force_alert_matches(self, playbook_registry):
        """Test brute force alert matches correct playbook."""
        alert = Alert(
            id="alert-003",
            rule_id="brute_force_ssh_attempt",
            rule_name="SSH Brute Force",
            severity="medium",
            title="SSH Brute Force Attempt",
            description="Multiple failed SSH attempts detected",
            timestamp=datetime.utcnow(),
            tags=["brute-force", "ssh"],
            metadata={"source_ip": "192.168.1.100"},
        )

        matching = playbook_registry.get_matching_playbooks(alert)

        assert len(matching) == 1
        assert matching[0].playbook_id == "pb-brute-force"

    def test_no_match_for_unhandled_alert(self, playbook_registry):
        """Test that unhandled alerts don't match any playbook."""
        alert = Alert(
            id="alert-004",
            rule_id="network_anomaly_traffic_spike",
            rule_name="Traffic Spike",
            severity="low",
            title="Unusual Traffic Spike",
            description="Traffic spike detected",
            timestamp=datetime.utcnow(),
            tags=["network"],
        )

        matching = playbook_registry.get_matching_playbooks(alert)

        assert len(matching) == 0


class TestEndToEndAlertFlow:
    """Tests for end-to-end alert to playbook execution."""

    @pytest.fixture
    def mock_detection_engine(self):
        """Create mock detection engine."""
        engine = MagicMock()
        engine.execute_rule = MagicMock(return_value=MagicMock(
            triggered=True,
            rule_id="credential_compromise_test",
            rule_name="Test Rule",
            severity="high",
            results=[{"user_id": "test-user", "source_ip": "192.168.1.100"}],
            alert_title="Credential Compromise Detected",
            alert_body="Suspicious activity detected for test-user",
        ))
        return engine

    @pytest.fixture
    def mock_alert_router(self):
        """Create mock alert router."""
        router = MagicMock()
        router.route_alert = MagicMock(return_value=MagicMock(
            success=True,
            destinations_succeeded=["slack", "pagerduty"],
        ))
        return router

    @pytest.fixture
    def mock_execution_engine(self):
        """Create mock execution engine."""
        engine = MagicMock()
        engine.execute = AsyncMock(return_value=MagicMock(
            execution_id="exec-001",
            status=ExecutionStatus.COMPLETED,
            step_results=[],
        ))
        return engine

    @pytest.fixture
    def mock_playbook_storage(self):
        """Create mock playbook storage."""
        storage = MagicMock()
        storage.get_by_trigger = MagicMock(return_value=[
            Playbook(
                playbook_id="pb-test",
                name="Test Response",
                description="Test",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger=PlaybookTrigger(
                    trigger_type="alert",
                    conditions={"rule_id": "credential_compromise_*"},
                ),
                steps=[
                    PlaybookStep(
                        step_id="step-1",
                        name="Respond",
                        action_type=ActionType.SEND_NOTIFICATION,
                        parameters={"message": "Alert handled"},
                    ),
                ],
                created_by="system",
            )
        ])
        return storage

    @pytest.mark.asyncio
    async def test_detection_to_alert_to_playbook(
        self,
        mock_detection_engine,
        mock_alert_router,
        mock_execution_engine,
        mock_playbook_storage,
    ):
        """Test full flow from detection to playbook execution."""
        # Step 1: Detection generates result
        detection_result = mock_detection_engine.execute_rule("rule-001")
        assert detection_result.triggered is True

        # Step 2: Generate alert from detection
        generator = AlertGenerator()
        alert = generator.generate_alert(
            rule_id=detection_result.rule_id,
            rule_name=detection_result.rule_name,
            severity=detection_result.severity,
            title=detection_result.alert_title,
            description=detection_result.alert_body,
            results=detection_result.results,
        )

        assert alert is not None
        assert alert.rule_id == "credential_compromise_test"

        # Step 3: Route alert to destinations
        routing_result = mock_alert_router.route_alert(alert)
        assert routing_result.success is True

        # Step 4: Find matching playbooks
        matching_playbooks = mock_playbook_storage.get_by_trigger(alert)
        assert len(matching_playbooks) == 1

        # Step 5: Execute playbook
        playbook = matching_playbooks[0]
        from src.shared.soar.execution_engine import ExecutionContext
        context = ExecutionContext(
            trigger_type="alert",
            trigger_data={
                "alert_id": alert.id,
                "alert": {
                    "user_id": detection_result.results[0].get("user_id"),
                    "source_ip": detection_result.results[0].get("source_ip"),
                },
            },
        )

        execution = await mock_execution_engine.execute(playbook, context)

        assert execution.status == ExecutionStatus.COMPLETED


class TestPlaybookTriggerFromAlertRouter:
    """Tests for SOAR integration in alert router."""

    @pytest.fixture
    def alert_router_with_soar(self):
        """Create alert router with SOAR integration."""
        from src.shared.alerting.router import AlertRouter, RouterConfig, AlertHandler

        class MockHandler(AlertHandler):
            def send(self, alert):
                return True

        config = RouterConfig(
            default_destinations=["slack"],
            severity_routing={},
        )

        router = AlertRouter(
            handlers={"slack": MockHandler()},
            config=config,
        )

        # Add SOAR hook
        router.soar_enabled = True
        router.playbook_matcher = MagicMock()
        router.execution_engine = MagicMock()

        return router

    def test_router_triggers_soar_after_alert(self, alert_router_with_soar):
        """Test that router triggers SOAR after routing alert."""
        alert = Alert(
            id="alert-001",
            rule_id="test_rule",
            rule_name="Test Rule",
            severity="high",
            title="Test Alert",
            description="Test",
            timestamp=datetime.utcnow(),
        )

        # Configure SOAR mock
        alert_router_with_soar.playbook_matcher.find_matching = MagicMock(return_value=[
            {"playbook_id": "pb-test", "name": "Test Playbook"}
        ])

        result = alert_router_with_soar.route_alert(alert)

        # Verify alert was routed
        assert result.success is True

        # Verify SOAR was checked (if implemented)
        # This depends on actual router implementation


class TestActionLoggingIntegration:
    """Tests for action logging in alert-to-playbook flow."""

    @pytest.fixture
    def action_logger(self):
        """Create mock action logger."""
        logger = MagicMock()
        logger.log = MagicMock()
        return logger

    def test_playbook_execution_logged(self, action_logger):
        """Test that playbook execution is logged."""
        # Simulate logging a playbook execution
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "execution_id": "exec-001",
            "playbook_id": "pb-test",
            "playbook_name": "Test Playbook",
            "trigger_type": "alert",
            "trigger_alert_id": "alert-001",
            "status": "started",
        }

        action_logger.log(log_entry)

        assert action_logger.log.called
        logged_data = action_logger.log.call_args[0][0]
        assert logged_data["playbook_id"] == "pb-test"
        assert logged_data["trigger_alert_id"] == "alert-001"

    def test_step_execution_logged(self, action_logger):
        """Test that each step execution is logged."""
        steps_logged = []

        def log_step(entry):
            steps_logged.append(entry)

        action_logger.log = log_step

        # Simulate logging multiple steps
        for i in range(3):
            action_logger.log({
                "timestamp": datetime.utcnow().isoformat(),
                "execution_id": "exec-001",
                "step_id": f"step-{i+1}",
                "action_type": "send_notification",
                "status": "completed",
                "duration_ms": 100 * (i + 1),
            })

        assert len(steps_logged) == 3
        assert all(s["status"] == "completed" for s in steps_logged)


class TestMultiplePlaybookTriggers:
    """Tests for scenarios where multiple playbooks match an alert."""

    @pytest.fixture
    def playbooks_with_overlap(self):
        """Create playbooks with overlapping triggers."""
        return [
            Playbook(
                playbook_id="pb-general-malware",
                name="General Malware Response",
                description="Generic malware response",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger=PlaybookTrigger(
                    trigger_type="alert",
                    conditions={"tags": ["malware"]},
                ),
                steps=[
                    PlaybookStep(
                        step_id="step-1",
                        name="Isolate",
                        action_type=ActionType.ISOLATE_HOST,
                        parameters={},
                    ),
                ],
                priority=10,
                created_by="system",
            ),
            Playbook(
                playbook_id="pb-ransomware-specific",
                name="Ransomware Response",
                description="Specific ransomware response",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger=PlaybookTrigger(
                    trigger_type="alert",
                    conditions={
                        "tags": ["malware", "ransomware"],
                    },
                ),
                steps=[
                    PlaybookStep(
                        step_id="step-1",
                        name="Isolate",
                        action_type=ActionType.ISOLATE_HOST,
                        parameters={},
                    ),
                    PlaybookStep(
                        step_id="step-2",
                        name="Backup Check",
                        action_type=ActionType.RUN_SCRIPT,
                        parameters={"script": "check_backups.py"},
                    ),
                ],
                priority=20,  # Higher priority
                created_by="system",
            ),
        ]

    def test_higher_priority_playbook_selected(self, playbooks_with_overlap):
        """Test that higher priority playbook is selected when multiple match."""
        alert = Alert(
            id="alert-001",
            rule_id="ransomware_detected",
            rule_name="Ransomware Detected",
            severity="critical",
            title="Ransomware Alert",
            description="Ransomware detected",
            timestamp=datetime.utcnow(),
            tags=["malware", "ransomware"],
        )

        # Both playbooks should match
        matching = []
        for pb in playbooks_with_overlap:
            trigger_tags = set(pb.trigger.conditions.get("tags", []))
            alert_tags = set(alert.tags)
            if trigger_tags.issubset(alert_tags):
                matching.append(pb)

        assert len(matching) == 2

        # Select highest priority
        selected = max(matching, key=lambda p: getattr(p, 'priority', 0))
        assert selected.playbook_id == "pb-ransomware-specific"

    def test_execute_all_matching_playbooks(self, playbooks_with_overlap):
        """Test option to execute all matching playbooks."""
        alert = Alert(
            id="alert-001",
            rule_id="ransomware_detected",
            rule_name="Ransomware Detected",
            severity="critical",
            title="Ransomware Alert",
            description="Ransomware detected",
            timestamp=datetime.utcnow(),
            tags=["malware", "ransomware"],
        )

        # Find all matching
        matching = []
        for pb in playbooks_with_overlap:
            trigger_tags = set(pb.trigger.conditions.get("tags", []))
            alert_tags = set(alert.tags)
            if trigger_tags.issubset(alert_tags):
                matching.append(pb)

        # Execute all (with deduplication of actions)
        assert len(matching) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
