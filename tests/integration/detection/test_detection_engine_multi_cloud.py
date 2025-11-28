"""Integration tests for DetectionEngine with multi-cloud executors.

Tests that DetectionEngine can use different query executors
(Athena, BigQuery, Synapse) to execute detection rules.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from pathlib import Path

from src.shared.detection.engine import DetectionEngine, DetectionResult
from src.shared.detection.rule import RuleLoader, DetectionRule
from src.shared.detection.executors.athena import AthenaQueryExecutor
from src.shared.detection.executors.bigquery import BigQueryExecutor
from src.shared.detection.executors.synapse import SynapseExecutor


pytestmark = pytest.mark.integration


class TestDetectionEngineWithAthena:
    """Test DetectionEngine with Athena executor."""

    @pytest.fixture
    def mock_athena_executor(self):
        """Create mock Athena executor."""
        executor = Mock(spec=AthenaQueryExecutor)

        # Mock execute_query to return sample results
        executor.execute_query.return_value = [
            {
                'eventname': 'ConsoleLogin',
                'sourceipaddress': '1.2.3.4',
                'eventtime': '2024-01-01T12:00:00Z',
                'count': '5'
            },
            {
                'eventname': 'ConsoleLogin',
                'sourceipaddress': '5.6.7.8',
                'eventtime': '2024-01-01T12:05:00Z',
                'count': '10'
            }
        ]

        return executor

    @pytest.fixture
    def sample_rule(self):
        """Create sample detection rule."""
        from src.shared.detection.rule import (
            DetectionQuery,
            Schedule,
            Threshold,
            AlertConfig
        )

        return DetectionRule(
            id='test-rule-1',
            name='Test Brute Force Detection',
            description='Test rule for brute force detection',
            severity='high',
            query=DetectionQuery(
                sql="SELECT eventname, sourceipaddress, COUNT(*) as count FROM cloudtrail WHERE eventname = 'ConsoleLogin' GROUP BY eventname, sourceipaddress"
            ),
            schedule=Schedule(interval='5m'),
            threshold=Threshold(count=5, time_window='5m'),
            alert=AlertConfig(
                title='Brute Force Detected',
                body_template='Detected {{count}} failed login attempts from {{sourceipaddress}}'
            ),
            enabled=True,
            tags=['attack.credential_access'],
            false_positives=['Legitimate user forgot password'],
            author='Mantissa Security Team',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    def test_execute_rule_with_athena(self, mock_athena_executor, sample_rule):
        """Test executing rule with Athena executor."""
        rule_loader = Mock(spec=RuleLoader)
        rule_loader.get_rule_by_id.return_value = sample_rule

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=mock_athena_executor
        )

        result = engine.execute_rule(sample_rule)

        assert isinstance(result, DetectionResult)
        assert result.rule_id == 'test-rule-1'
        assert result.rule_name == 'Test Brute Force Detection'
        assert result.severity == 'high'
        assert len(result.results) == 2
        assert result.triggered is True  # Should trigger with count > 5

    def test_execute_all_rules_with_athena(self, mock_athena_executor, sample_rule):
        """Test executing all rules with Athena."""
        rule_loader = Mock(spec=RuleLoader)
        rule_loader.get_enabled_rules.return_value = [sample_rule]

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=mock_athena_executor
        )

        results = engine.execute_all_rules()

        assert len(results) == 1
        assert results[0].rule_id == 'test-rule-1'


class TestDetectionEngineWithBigQuery:
    """Test DetectionEngine with BigQuery executor."""

    @pytest.fixture
    def mock_bigquery_executor(self):
        """Create mock BigQuery executor."""
        executor = Mock(spec=BigQueryExecutor)

        executor.execute_query.return_value = [
            {
                'eventname': 'AssumeRole',
                'useridentity_arn': 'arn:aws:iam::123456789012:root',
                'count': '3'
            }
        ]

        return executor

    @pytest.fixture
    def privilege_escalation_rule(self):
        """Create privilege escalation rule."""
        from src.shared.detection.rule import (
            DetectionQuery,
            Schedule,
            Threshold,
            AlertConfig
        )

        return DetectionRule(
            id='test-rule-2',
            name='Privilege Escalation Detection',
            description='Detect privilege escalation attempts',
            severity='critical',
            query=DetectionQuery(
                sql="SELECT eventname, useridentity_arn, COUNT(*) as count FROM cloudtrail WHERE eventname IN ('AttachUserPolicy', 'PutUserPolicy', 'AttachRolePolicy') GROUP BY eventname, useridentity_arn"
            ),
            schedule=Schedule(interval='5m'),
            threshold=Threshold(count=1, time_window='5m'),
            alert=AlertConfig(
                title='Privilege Escalation Detected',
                body_template='User {{useridentity_arn}} performed {{eventname}}'
            ),
            enabled=True,
            tags=['attack.privilege_escalation'],
            false_positives=[],
            author='Mantissa Security Team',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    def test_execute_rule_with_bigquery(self, mock_bigquery_executor, privilege_escalation_rule):
        """Test executing rule with BigQuery executor."""
        rule_loader = Mock(spec=RuleLoader)

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=mock_bigquery_executor
        )

        result = engine.execute_rule(privilege_escalation_rule)

        assert isinstance(result, DetectionResult)
        assert result.rule_id == 'test-rule-2'
        assert result.triggered is True


class TestDetectionEngineWithSynapse:
    """Test DetectionEngine with Synapse executor."""

    @pytest.fixture
    def mock_synapse_executor(self):
        """Create mock Synapse executor."""
        executor = Mock(spec=SynapseExecutor)

        executor.execute_query.return_value = [
            {
                'eventname': 'DeleteTrail',
                'useridentity_arn': 'arn:aws:iam::123456789012:user/attacker',
                'eventtime': '2024-01-01T12:00:00Z'
            }
        ]

        return executor

    @pytest.fixture
    def cloudtrail_disabled_rule(self):
        """Create CloudTrail disabled detection rule."""
        from src.shared.detection.rule import (
            DetectionQuery,
            Schedule,
            Threshold,
            AlertConfig
        )

        return DetectionRule(
            id='test-rule-3',
            name='CloudTrail Disabled',
            description='Detect when CloudTrail logging is disabled',
            severity='critical',
            query=DetectionQuery(
                sql="SELECT eventname, useridentity_arn, eventtime FROM cloudtrail WHERE eventname IN ('StopLogging', 'DeleteTrail')"
            ),
            schedule=Schedule(interval='5m'),
            threshold=Threshold(count=1, time_window='5m'),
            alert=AlertConfig(
                title='CloudTrail Disabled',
                body_template='CloudTrail logging disabled by {{useridentity_arn}}'
            ),
            enabled=True,
            tags=['attack.defense_evasion'],
            false_positives=['Legitimate maintenance'],
            author='Mantissa Security Team',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    def test_execute_rule_with_synapse(self, mock_synapse_executor, cloudtrail_disabled_rule):
        """Test executing rule with Synapse executor."""
        rule_loader = Mock(spec=RuleLoader)

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=mock_synapse_executor
        )

        result = engine.execute_rule(cloudtrail_disabled_rule)

        assert isinstance(result, DetectionResult)
        assert result.rule_id == 'test-rule-3'
        assert result.triggered is True
        assert len(result.results) == 1


class TestDetectionEngineErrorHandling:
    """Test error handling in DetectionEngine with different executors."""

    def test_query_execution_error_athena(self):
        """Test handling of query execution error with Athena."""
        from src.shared.detection.rule import (
            DetectionQuery,
            Schedule,
            Threshold,
            AlertConfig
        )

        executor = Mock(spec=AthenaQueryExecutor)
        executor.execute_query.side_effect = Exception("Athena query failed")

        rule = DetectionRule(
            id='error-rule',
            name='Error Rule',
            description='Rule that will fail',
            severity='high',
            query=DetectionQuery(sql="SELECT * FROM invalid_table"),
            schedule=Schedule(interval='5m'),
            threshold=Threshold(count=1, time_window='5m'),
            alert=AlertConfig(title='Alert', body_template='Body'),
            enabled=True,
            tags=[],
            false_positives=[],
            author='Test',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        rule_loader = Mock(spec=RuleLoader)

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=executor
        )

        result = engine.execute_rule(rule)

        assert result.triggered is False
        assert result.error is not None
        assert "Query execution failed" in result.error

    def test_empty_results_handling(self):
        """Test handling of empty query results."""
        from src.shared.detection.rule import (
            DetectionQuery,
            Schedule,
            Threshold,
            AlertConfig
        )

        executor = Mock(spec=AthenaQueryExecutor)
        executor.execute_query.return_value = []  # No results

        rule = DetectionRule(
            id='no-results-rule',
            name='No Results Rule',
            description='Rule with no results',
            severity='low',
            query=DetectionQuery(sql="SELECT * FROM cloudtrail WHERE 1=0"),
            schedule=Schedule(interval='5m'),
            threshold=Threshold(count=1, time_window='5m'),
            alert=AlertConfig(title='Alert', body_template='Body'),
            enabled=True,
            tags=[],
            false_positives=[],
            author='Test',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        rule_loader = Mock(spec=RuleLoader)

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=executor
        )

        result = engine.execute_rule(rule)

        assert result.triggered is False
        assert result.error is None
        assert len(result.results) == 0


class TestDetectionEngineTimeWindows:
    """Test time window handling with different executors."""

    def test_custom_time_window(self):
        """Test executing rule with custom time window."""
        from src.shared.detection.rule import (
            DetectionQuery,
            Schedule,
            Threshold,
            AlertConfig
        )

        executor = Mock(spec=AthenaQueryExecutor)
        executor.execute_query.return_value = [
            {'eventname': 'ConsoleLogin', 'count': '10'}
        ]

        rule = DetectionRule(
            id='time-window-rule',
            name='Time Window Rule',
            description='Rule with custom time window',
            severity='medium',
            query=DetectionQuery(sql="SELECT eventname, COUNT(*) as count FROM cloudtrail GROUP BY eventname"),
            schedule=Schedule(interval='1h'),
            threshold=Threshold(count=5, time_window='1h'),
            alert=AlertConfig(title='Alert', body_template='Body'),
            enabled=True,
            tags=[],
            false_positives=[],
            author='Test',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        rule_loader = Mock(spec=RuleLoader)

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=executor
        )

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=2)

        result = engine.execute_rule(rule, start_time, end_time)

        assert result is not None
        # Executor should be called with the generated query
        executor.execute_query.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
