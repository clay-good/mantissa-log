"""Tests for health state store implementations.

Covers InMemoryHealthStateStore and DynamoDBHealthStateStore
with mocked DynamoDB using the moto library.
"""

import pytest
import boto3
from datetime import datetime, timezone
from moto import mock_aws
from decimal import Decimal

from shared.health.log_source_health import (
    LogSourceHealthState,
    LogSourceStatus,
)
from shared.health.health_state_store import (
    DynamoDBHealthStateStore,
    InMemoryHealthStateStore,
)


# ======================================================================
# InMemoryHealthStateStore Tests
# ======================================================================


class TestInMemoryHealthStateStore:
    """Test the in-memory store implementation."""

    @pytest.fixture
    def store(self):
        """Create a fresh in-memory store."""
        return InMemoryHealthStateStore()

    def test_save_and_get_state(self, store):
        """Verify state can be saved and retrieved."""
        state = LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=100,
        )
        assert store.save_state("okta", "default", state) is True
        retrieved = store.get_state("okta", "default")
        assert retrieved is not None
        assert retrieved.source_type == "okta"
        assert retrieved.status == LogSourceStatus.HEALTHY
        assert retrieved.event_count_current_window == 100

    def test_get_nonexistent_state(self, store):
        """Verify get_state returns None for missing source."""
        result = store.get_state("nonexistent", "default")
        assert result is None

    def test_save_overwrites_existing(self, store):
        """Verify save_state upserts existing state."""
        state1 = LogSourceHealthState(source_type="okta", status=LogSourceStatus.HEALTHY)
        state2 = LogSourceHealthState(source_type="okta", status=LogSourceStatus.DELAYED)
        store.save_state("okta", "default", state1)
        store.save_state("okta", "default", state2)
        retrieved = store.get_state("okta", "default")
        assert retrieved.status == LogSourceStatus.DELAYED

    def test_get_all_states(self, store):
        """Verify get_all_states returns all states for a tenant."""
        store.save_state("okta", "t1", LogSourceHealthState(source_type="okta"))
        store.save_state("slack", "t1", LogSourceHealthState(source_type="slack"))
        store.save_state("github", "t2", LogSourceHealthState(source_type="github"))

        t1_states = store.get_all_states("t1")
        assert len(t1_states) == 2

        t2_states = store.get_all_states("t2")
        assert len(t2_states) == 1

    def test_get_all_states_empty_tenant(self, store):
        """Verify get_all_states returns empty list for unknown tenant."""
        result = store.get_all_states("nonexistent")
        assert result == []

    def test_update_event_count_new_source(self, store):
        """Verify update_event_count creates state for new source."""
        ts = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert store.update_event_count("okta", "default", 50, ts) is True

        state = store.get_state("okta", "default")
        assert state is not None
        assert state.event_count_current_window == 50
        assert state.last_event_timestamp == ts

    def test_update_event_count_increments(self, store):
        """Verify update_event_count increments existing count."""
        ts1 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2026, 1, 15, 10, 5, 0, tzinfo=timezone.utc)

        store.update_event_count("okta", "default", 50, ts1)
        store.update_event_count("okta", "default", 30, ts2)

        state = store.get_state("okta", "default")
        assert state.event_count_current_window == 80
        assert state.last_event_timestamp == ts2

    def test_update_event_count_keeps_newer_timestamp(self, store):
        """Verify update_event_count keeps the newer timestamp."""
        ts_new = datetime(2026, 1, 15, 10, 5, 0, tzinfo=timezone.utc)
        ts_old = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        store.update_event_count("okta", "default", 50, ts_new)
        store.update_event_count("okta", "default", 30, ts_old)

        state = store.get_state("okta", "default")
        assert state.last_event_timestamp == ts_new

    def test_save_and_get_baseline(self, store):
        """Verify baseline can be saved and retrieved."""
        assert store.save_baseline("okta", "default", 500.0, 50.0) is True
        baseline = store.get_baseline("okta", "default")
        assert baseline is not None
        assert baseline == (500.0, 50.0)

    def test_get_nonexistent_baseline(self, store):
        """Verify get_baseline returns None for missing baseline."""
        result = store.get_baseline("nonexistent", "default")
        assert result is None

    def test_save_baseline_updates_state(self, store):
        """Verify save_baseline also updates the state object."""
        state = LogSourceHealthState(source_type="okta")
        store.save_state("okta", "default", state)
        store.save_baseline("okta", "default", 500.0, 50.0)

        retrieved = store.get_state("okta", "default")
        assert retrieved.baseline_hourly_volume == 500.0
        assert retrieved.baseline_hourly_stddev == 50.0

    def test_clear(self, store):
        """Verify clear removes all state and baselines."""
        store.save_state("okta", "default", LogSourceHealthState(source_type="okta"))
        store.save_baseline("okta", "default", 100.0, 10.0)
        store.clear()
        assert store.get_state("okta", "default") is None
        assert store.get_baseline("okta", "default") is None

    def test_tenant_isolation(self, store):
        """Verify states are isolated by tenant."""
        store.save_state("okta", "t1", LogSourceHealthState(
            source_type="okta", status=LogSourceStatus.HEALTHY,
        ))
        store.save_state("okta", "t2", LogSourceHealthState(
            source_type="okta", status=LogSourceStatus.DELAYED,
        ))

        t1_state = store.get_state("okta", "t1")
        t2_state = store.get_state("okta", "t2")
        assert t1_state.status == LogSourceStatus.HEALTHY
        assert t2_state.status == LogSourceStatus.DELAYED


# ======================================================================
# DynamoDBHealthStateStore Tests
# ======================================================================


class TestDynamoDBHealthStateStore:
    """Test the DynamoDB store with moto mocking."""

    TABLE_NAME = "test-health-state"

    @pytest.fixture
    def mock_dynamodb(self, monkeypatch):
        """Set up mocked AWS environment with DynamoDB table."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        with mock_aws():
            dynamodb = boto3.client("dynamodb", region_name="us-east-1")
            dynamodb.create_table(
                TableName=self.TABLE_NAME,
                KeySchema=[
                    {"AttributeName": "tenant_id", "KeyType": "HASH"},
                    {"AttributeName": "source_type", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "tenant_id", "AttributeType": "S"},
                    {"AttributeName": "source_type", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )
            yield

    @pytest.fixture
    def store(self, mock_dynamodb):
        """Create a DynamoDBHealthStateStore against the mocked table."""
        return DynamoDBHealthStateStore(
            table_name=self.TABLE_NAME,
            region="us-east-1",
        )

    def test_save_and_get_state(self, store):
        """Verify state roundtrip through DynamoDB."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state = LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            last_event_timestamp=now,
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=100,
            consecutive_failures=0,
        )
        assert store.save_state("okta", "default", state) is True
        retrieved = store.get_state("okta", "default")
        assert retrieved is not None
        assert retrieved.source_type == "okta"
        assert retrieved.status == LogSourceStatus.HEALTHY
        assert retrieved.event_count_current_window == 100

    def test_get_nonexistent_state(self, store):
        """Verify get_state returns None for missing item."""
        result = store.get_state("nonexistent", "default")
        assert result is None

    def test_get_all_states(self, store):
        """Verify get_all_states queries by tenant partition key."""
        store.save_state("okta", "t1", LogSourceHealthState(source_type="okta"))
        store.save_state("slack", "t1", LogSourceHealthState(source_type="slack"))
        store.save_state("github", "t2", LogSourceHealthState(source_type="github"))

        t1_states = store.get_all_states("t1")
        assert len(t1_states) == 2
        source_types = {s.source_type for s in t1_states}
        assert source_types == {"okta", "slack"}

    def test_update_event_count(self, store):
        """Verify update_event_count uses atomic increment."""
        ts = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert store.update_event_count("okta", "default", 50, ts) is True

        # Increment again
        ts2 = datetime(2026, 1, 15, 10, 5, 0, tzinfo=timezone.utc)
        assert store.update_event_count("okta", "default", 30, ts2) is True

    def test_save_and_get_baseline(self, store):
        """Verify baseline storage uses Decimal for floats."""
        # First create the item so get_baseline can find it
        store.save_state("okta", "default", LogSourceHealthState(source_type="okta"))
        assert store.save_baseline("okta", "default", 500.5, 50.25) is True

        baseline = store.get_baseline("okta", "default")
        assert baseline is not None
        vol, std = baseline
        assert abs(vol - 500.5) < 0.01
        assert abs(std - 50.25) < 0.01

    def test_get_nonexistent_baseline(self, store):
        """Verify get_baseline returns None for missing baseline."""
        result = store.get_baseline("nonexistent", "default")
        assert result is None

    def test_gap_windows_serialization(self, store):
        """Verify gap_windows are stored as JSON string in DynamoDB."""
        gs = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
        ge = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)
        state = LogSourceHealthState(
            source_type="okta",
            gap_windows=[(gs, ge)],
        )
        store.save_state("okta", "default", state)

        retrieved = store.get_state("okta", "default")
        assert len(retrieved.gap_windows) == 1
        assert retrieved.gap_windows[0][0] == gs
        assert retrieved.gap_windows[0][1] == ge
