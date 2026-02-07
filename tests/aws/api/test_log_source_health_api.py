"""Tests for LogSourceHealthAPI.

Covers all 7 API methods: list_sources, get_source_detail, check_source,
update_config, get_source_history, acknowledge_source, and get_summary.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from shared.health.health_state_store import InMemoryHealthStateStore
from shared.health.log_source_health import (
    DEFAULT_HEALTH_CONFIGS,
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
    list_monitored_sources,
)
from shared.health.health_check_engine import HealthCheckResult


# We need to handle the import path for the API class
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/aws/api"))

from log_source_health_api import LogSourceHealthAPI


# ======================================================================
# list_sources Tests
# ======================================================================


class TestListSources:
    """Test GET /health/sources."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )

    def test_list_all_sources(self, api):
        """List all monitored sources with no filter."""
        result = api.list_sources()
        assert "sources" in result
        assert "total" in result
        assert result["total"] == len(list_monitored_sources())
        assert result["total"] >= 21

    def test_list_sources_with_state(self, api, store):
        """Sources with state reflect correct status."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=100,
        ))

        result = api.list_sources()
        okta = next(s for s in result["sources"] if s["source_type"] == "okta")
        assert okta["status"] == "HEALTHY"
        assert okta["event_count_current_window"] == 100

    def test_list_sources_unknown_when_no_state(self, api):
        """Sources without state show UNKNOWN status."""
        result = api.list_sources()
        okta = next(s for s in result["sources"] if s["source_type"] == "okta")
        assert okta["status"] == "UNKNOWN"
        assert okta["event_count_current_window"] == 0

    def test_list_sources_filter_by_status(self, api, store):
        """Filter sources by status."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
        ))
        store.save_state("slack", "default", LogSourceHealthState(
            source_type="slack",
            status=LogSourceStatus.HEALTHY,
        ))

        result = api.list_sources(status_filter="DELAYED")
        assert result["total"] == 1
        assert result["sources"][0]["source_type"] == "okta"

    def test_list_sources_filter_multiple_statuses(self, api, store):
        """Filter by comma-separated statuses."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
        ))
        store.save_state("slack", "default", LogSourceHealthState(
            source_type="slack",
            status=LogSourceStatus.SILENT,
        ))

        result = api.list_sources(status_filter="DELAYED,SILENT")
        source_types = {s["source_type"] for s in result["sources"]}
        assert "okta" in source_types
        assert "slack" in source_types

    def test_list_sources_includes_config(self, api):
        """Each source entry includes its config."""
        result = api.list_sources()
        okta = next(s for s in result["sources"] if s["source_type"] == "okta")
        assert "config" in okta
        assert "expected_max_latency_seconds" in okta["config"]


# ======================================================================
# get_source_detail Tests
# ======================================================================


class TestGetSourceDetail:
    """Test GET /health/sources/{source_type}."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )

    def test_get_detail_known_source(self, api, store):
        """Get detail for a known source with state."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.HEALTHY,
            last_event_timestamp=now,
        ))
        store.save_baseline("okta", "default", 500.0, 50.0)

        result = api.get_source_detail("okta")

        assert result["source_type"] == "okta"
        assert "state" in result
        assert result["state"]["status"] == "HEALTHY"
        assert "config" in result
        assert result["baseline"] is not None
        assert result["baseline"]["hourly_volume"] == 500.0

    def test_get_detail_no_state(self, api):
        """Get detail for source with no state → default state."""
        result = api.get_source_detail("okta")

        assert result["source_type"] == "okta"
        assert result["state"]["status"] == "UNKNOWN"
        assert result["baseline"] is None

    def test_get_detail_unknown_source_raises(self, api):
        """Unknown source type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown source type"):
            api.get_source_detail("nonexistent_source_xyz")


# ======================================================================
# check_source Tests
# ======================================================================


class TestCheckSource:
    """Test POST /health/sources/{source_type}/check."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            query_executor=None,
            tenant_id="default",
        )

    def test_check_source_on_demand(self, api):
        """On-demand check evaluates the source."""
        result = api.check_source("okta")

        assert result["source_type"] == "okta"
        assert "old_status" in result
        assert "new_status" in result
        assert "detail_message" in result
        assert "gap_windows" in result

    def test_check_source_unknown_raises(self, api):
        """Unknown source raises ValueError."""
        with pytest.raises(ValueError, match="Unknown source type"):
            api.check_source("nonexistent_source_xyz")

    def test_check_source_returns_health_result(self, api, store):
        """Check returns correct health data."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=100,
            last_event_timestamp=now - timedelta(seconds=30),
        ))

        result = api.check_source("okta")
        assert result["new_status"] in [s.value for s in LogSourceStatus]


# ======================================================================
# update_config Tests
# ======================================================================


class TestUpdateConfig:
    """Test PUT /health/sources/{source_type}/config."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )

    def test_update_config_success(self, api):
        """Successful config update returns merged config."""
        result = api.update_config("okta", {
            "expected_max_latency_seconds": 600,
        })

        assert result["source_type"] == "okta"
        assert result["config"]["expected_max_latency_seconds"] == 600
        assert "message" in result

    def test_update_config_persists_in_memory(self, api):
        """Updated config is available for subsequent calls."""
        api.update_config("okta", {
            "expected_max_latency_seconds": 600,
        })

        # Verify it's persisted
        assert "okta" in api.config_map
        assert api.config_map["okta"].expected_max_latency_seconds == 600

    def test_update_config_invalid_raises(self, api):
        """Invalid config raises ValueError."""
        with pytest.raises(ValueError, match="Invalid configuration"):
            api.update_config("okta", {
                "expected_max_latency_seconds": -1,
            })

    def test_update_config_silence_below_latency_raises(self, api):
        """silence < latency raises ValueError."""
        with pytest.raises(ValueError, match="Invalid configuration"):
            api.update_config("okta", {
                "expected_max_latency_seconds": 3600,
                "silence_threshold_seconds": 300,
            })

    def test_update_config_merges_with_existing(self, api):
        """Updates merge with existing config, not replace."""
        result = api.update_config("okta", {
            "expected_max_latency_seconds": 600,
        })

        # Other fields should retain their defaults
        config = result["config"]
        assert config["silence_threshold_seconds"] == 3600  # default for okta
        assert config["gap_detection_enabled"] is True  # default


# ======================================================================
# get_source_history Tests
# ======================================================================


class TestGetSourceHistory:
    """Test GET /health/sources/{source_type}/history."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            query_executor=None,
            tenant_id="default",
        )

    def test_history_no_executor(self, api):
        """History with no executor returns empty history list."""
        result = api.get_source_history("okta")

        assert result["source_type"] == "okta"
        assert result["granularity"] == "hour"
        assert result["history"] == []

    def test_history_unknown_source_raises(self, api):
        """Unknown source raises ValueError."""
        with pytest.raises(ValueError, match="Unknown source type"):
            api.get_source_history("nonexistent_source_xyz")

    def test_history_invalid_granularity_raises(self, api):
        """Invalid granularity raises ValueError."""
        with pytest.raises(ValueError, match="Invalid granularity"):
            api.get_source_history("okta", granularity="minute")

    def test_history_includes_baseline(self, api, store):
        """History includes baseline when available."""
        store.save_baseline("okta", "default", 500.0, 50.0)

        result = api.get_source_history("okta")

        assert result["baseline"] is not None
        assert result["baseline"]["hourly_volume"] == 500.0

    def test_history_includes_current_state(self, api, store):
        """History includes current state."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=100,
            last_event_timestamp=now,
        ))

        result = api.get_source_history("okta")

        assert result["current_state"]["status"] == "HEALTHY"
        assert result["current_state"]["event_count_current_window"] == 100

    def test_history_with_executor(self, store):
        """History with executor queries data lake."""
        mock_executor = MagicMock()
        mock_executor.execute_query.return_value = MagicMock(
            data=[
                {"year": "2026", "month": "01", "day": "15", "hour": "09", "event_count": 100},
                {"year": "2026", "month": "01", "day": "15", "hour": "10", "event_count": 120},
            ]
        )

        api = LogSourceHealthAPI(
            health_state_store=store,
            query_executor=mock_executor,
            tenant_id="default",
        )

        result = api.get_source_history(
            "okta",
            start_time="2026-01-15T00:00:00+00:00",
            end_time="2026-01-15T23:59:59+00:00",
        )

        assert len(result["history"]) == 2
        assert mock_executor.execute_query.called


# ======================================================================
# acknowledge_source Tests
# ======================================================================


class TestAcknowledgeSource:
    """Test POST /health/sources/{source_type}/acknowledge."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )

    def test_acknowledge_success(self, api, store):
        """Successful acknowledgment returns confirmation."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            consecutive_failures=3,
        ))

        result = api.acknowledge_source(
            source_type="okta",
            acknowledged_by="user123",
            suppression_duration_seconds=7200,
            notes="Investigating",
        )

        assert result["source_type"] == "okta"
        assert result["acknowledged_by"] == "user123"
        assert result["notes"] == "Investigating"
        assert "suppression_until" in result
        assert "message" in result

    def test_acknowledge_updates_state(self, api, store):
        """Acknowledgment updates state metadata."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
        ))

        api.acknowledge_source(
            source_type="okta",
            acknowledged_by="user123",
            suppression_duration_seconds=3600,
        )

        state = store.get_state("okta", "default")
        assert state.metadata["acknowledged_by"] == "user123"
        assert "acknowledged_at" in state.metadata
        assert state.last_alert_timestamp is not None

    def test_acknowledge_unknown_source_raises(self, api):
        """Unknown source raises ValueError."""
        with pytest.raises(ValueError, match="Unknown source type"):
            api.acknowledge_source(
                source_type="nonexistent_source_xyz",
                acknowledged_by="user123",
            )

    def test_acknowledge_no_state_raises(self, api):
        """Source with no state raises ValueError."""
        with pytest.raises(ValueError, match="No health state found"):
            api.acknowledge_source(
                source_type="okta",
                acknowledged_by="user123",
            )

    def test_acknowledge_updates_suppression_config(self, api, store):
        """Custom suppression duration updates config_map."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
        ))

        api.acknowledge_source(
            source_type="okta",
            acknowledged_by="user123",
            suppression_duration_seconds=7200,
        )

        # Config map should be updated with new suppression duration
        assert "okta" in api.config_map
        assert api.config_map["okta"].alert_suppression_seconds == 7200


# ======================================================================
# get_summary Tests
# ======================================================================


class TestGetSummary:
    """Test GET /health/summary."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def api(self, store):
        return LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )

    def test_summary_no_state(self, api):
        """Summary with no state → all UNKNOWN."""
        result = api.get_summary()

        assert result["total_sources_monitored"] >= 21
        assert result["status_counts"]["UNKNOWN"] == result["total_sources_monitored"]
        assert result["status_counts"]["HEALTHY"] == 0

    def test_summary_with_mixed_statuses(self, api, store):
        """Summary counts statuses correctly."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.HEALTHY,
        ))
        store.save_state("slack", "default", LogSourceHealthState(
            source_type="slack",
            status=LogSourceStatus.DELAYED,
            consecutive_failures=2,
            last_alert_timestamp=datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
        ))
        store.save_state("github", "default", LogSourceHealthState(
            source_type="github",
            status=LogSourceStatus.SILENT,
            consecutive_failures=5,
            last_alert_timestamp=datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc),
        ))

        result = api.get_summary()

        assert result["status_counts"]["HEALTHY"] == 1
        assert result["status_counts"]["DELAYED"] == 1
        assert result["status_counts"]["SILENT"] == 1

    def test_summary_longest_unhealthy_sorted(self, api, store):
        """Longest unhealthy sources sorted by duration descending."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            last_alert_timestamp=now - timedelta(hours=1),
        ))
        store.save_state("slack", "default", LogSourceHealthState(
            source_type="slack",
            status=LogSourceStatus.SILENT,
            last_alert_timestamp=now - timedelta(hours=5),
        ))

        result = api.get_summary()

        unhealthy = result["longest_unhealthy"]
        assert len(unhealthy) >= 2
        # First should be the longest (slack at 5h)
        assert unhealthy[0]["source_type"] == "slack"

    def test_summary_approaching_silence(self, api, store):
        """Sources approaching silence threshold are flagged."""
        # Use real now since get_summary() calls datetime.now() internally
        now = datetime.now(timezone.utc)

        # okta: latency=300s, silence=3600s
        # 75% of way to silence = age 2850s
        # Remaining = 750s, threshold_margin = 3600*0.25 = 900s
        # 0 < 750 < 900 → approaching silence
        last_event = now - timedelta(seconds=2850)
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            last_event_timestamp=last_event,
        ))

        result = api.get_summary()

        approaching = result["approaching_silence_threshold"]
        assert len(approaching) >= 1
        okta_approaching = next(
            (s for s in approaching if s["source_type"] == "okta"), None
        )
        assert okta_approaching is not None
        assert okta_approaching["seconds_until_silent"] > 0

    def test_summary_healthy_not_in_unhealthy(self, api, store):
        """Healthy sources don't appear in longest_unhealthy."""
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.HEALTHY,
        ))

        result = api.get_summary()

        unhealthy_types = {u["source_type"] for u in result["longest_unhealthy"]}
        assert "okta" not in unhealthy_types


# ======================================================================
# Lazy Engine Initialization Tests
# ======================================================================


class TestEngineInitialization:
    """Test lazy HealthCheckEngine creation."""

    def test_engine_created_lazily(self):
        """Engine not created until accessed."""
        store = InMemoryHealthStateStore()
        api = LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )
        assert api._engine is None

    def test_engine_created_on_check(self):
        """Engine created when check_source is called."""
        store = InMemoryHealthStateStore()
        api = LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )
        api.check_source("okta")
        assert api._engine is not None

    def test_engine_reused(self):
        """Engine instance is reused across calls."""
        store = InMemoryHealthStateStore()
        api = LogSourceHealthAPI(
            health_state_store=store,
            tenant_id="default",
        )
        api.check_source("okta")
        engine1 = api._engine
        api.check_source("slack")
        engine2 = api._engine
        assert engine1 is engine2
