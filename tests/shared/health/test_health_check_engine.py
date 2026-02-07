"""Tests for HealthCheckEngine.

Covers latency evaluation, volume anomaly detection, gap detection,
alert triggering logic, baseline computation, and check_all_sources.
"""

import math
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from shared.health.health_check_engine import (
    HealthCheckEngine,
    HealthCheckResult,
    _mean_stddev,
    _fmt_duration,
)
from shared.health.health_state_store import InMemoryHealthStateStore
from shared.health.log_source_health import (
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
)


# ======================================================================
# HealthCheckResult Tests
# ======================================================================


class TestHealthCheckResult:
    """Test the HealthCheckResult dataclass."""

    def test_default_values(self):
        """Verify defaults for HealthCheckResult."""
        r = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.UNKNOWN,
            new_status=LogSourceStatus.HEALTHY,
        )
        assert r.event_count_current == 0
        assert r.event_count_previous == 0
        assert r.last_event_timestamp is None
        assert r.baseline_volume is None
        assert r.baseline_stddev is None
        assert r.z_score is None
        assert r.consecutive_failures == 0
        assert r.gap_windows == []
        assert r.should_alert is False
        assert r.detail_message == ""

    def test_all_fields(self):
        """Verify all fields can be populated."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        gap_s = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
        gap_e = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)
        r = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            event_count_current=50,
            event_count_previous=100,
            last_event_timestamp=now,
            baseline_volume=200.0,
            baseline_stddev=30.0,
            z_score=-5.0,
            consecutive_failures=2,
            gap_windows=[(gap_s, gap_e)],
            should_alert=True,
            detail_message="Test detail",
        )
        assert r.source_type == "okta"
        assert r.old_status == LogSourceStatus.HEALTHY
        assert r.new_status == LogSourceStatus.DELAYED
        assert r.z_score == -5.0
        assert len(r.gap_windows) == 1


# ======================================================================
# _evaluate_latency Tests
# ======================================================================


class TestEvaluateLatency:
    """Test the static _evaluate_latency method."""

    @pytest.fixture
    def config(self):
        return LogSourceHealthConfig(
            source_type="okta",
            expected_max_latency_seconds=300,
            silence_threshold_seconds=3600,
        )

    def test_no_events_returns_unknown(self, config):
        """No latest timestamp → UNKNOWN."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        status, detail = HealthCheckEngine._evaluate_latency(config, None, now)
        assert status == LogSourceStatus.UNKNOWN
        assert "No events" in detail

    def test_recent_event_returns_healthy(self, config):
        """Event within expected latency → HEALTHY."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        latest = now - timedelta(seconds=60)
        status, detail = HealthCheckEngine._evaluate_latency(config, latest, now)
        assert status == LogSourceStatus.HEALTHY
        assert "within expected latency" in detail

    def test_delayed_event(self, config):
        """Event beyond max latency but within silence → DELAYED."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        latest = now - timedelta(seconds=600)  # 10 min, > 300s max latency
        status, detail = HealthCheckEngine._evaluate_latency(config, latest, now)
        assert status == LogSourceStatus.DELAYED
        assert "Last event" in detail

    def test_silent_event(self, config):
        """Event beyond silence threshold → SILENT."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        latest = now - timedelta(seconds=7200)  # 2h, > 3600s silence
        status, detail = HealthCheckEngine._evaluate_latency(config, latest, now)
        assert status == LogSourceStatus.SILENT
        assert "No events for" in detail

    def test_boundary_at_max_latency(self, config):
        """Exactly at expected_max_latency → still HEALTHY."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        latest = now - timedelta(seconds=300)
        status, _ = HealthCheckEngine._evaluate_latency(config, latest, now)
        assert status == LogSourceStatus.HEALTHY

    def test_boundary_at_silence_threshold(self, config):
        """Exactly at silence_threshold → still DELAYED."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        latest = now - timedelta(seconds=3600)
        status, _ = HealthCheckEngine._evaluate_latency(config, latest, now)
        assert status == LogSourceStatus.DELAYED

    def test_naive_timestamps_handled(self, config):
        """Naive datetimes are treated as UTC."""
        now = datetime(2026, 1, 15, 10, 0, 0)
        latest = datetime(2026, 1, 15, 9, 59, 0)
        status, _ = HealthCheckEngine._evaluate_latency(config, latest, now)
        assert status == LogSourceStatus.HEALTHY


# ======================================================================
# _evaluate_volume Tests
# ======================================================================


class TestEvaluateVolume:
    """Test the static _evaluate_volume method."""

    @pytest.fixture
    def config(self):
        return LogSourceHealthConfig(
            source_type="okta",
            volume_anomaly_stddev_threshold=3.0,
            volume_drop_percentage_threshold=0.5,
            volume_spike_percentage_threshold=3.0,
        )

    def test_normal_volume(self, config):
        """Volume within bounds → None status (normal)."""
        status, detail, z = HealthCheckEngine._evaluate_volume(
            config, current_count=500, baseline_vol=500.0, baseline_std=50.0
        )
        assert status is None
        assert z is not None
        assert abs(z) <= 3.0

    def test_zero_stddev_skipped(self, config):
        """Zero stddev → skip volume check."""
        status, detail, z = HealthCheckEngine._evaluate_volume(
            config, current_count=500, baseline_vol=500.0, baseline_std=0.0
        )
        assert status is None
        assert z is None
        assert "zero" in detail.lower()

    def test_volume_spike_by_zscore(self, config):
        """Very high volume → VOLUME_ANOMALY with spike."""
        status, detail, z = HealthCheckEngine._evaluate_volume(
            config, current_count=700, baseline_vol=500.0, baseline_std=50.0
        )
        assert status == LogSourceStatus.VOLUME_ANOMALY
        assert "spike" in detail.lower()
        assert z > 3.0

    def test_volume_drop_by_zscore(self, config):
        """Very low volume → VOLUME_ANOMALY with drop."""
        status, detail, z = HealthCheckEngine._evaluate_volume(
            config, current_count=300, baseline_vol=500.0, baseline_std=50.0
        )
        assert status == LogSourceStatus.VOLUME_ANOMALY
        assert "drop" in detail.lower()
        assert z < -3.0

    def test_volume_drop_by_percentage(self, config):
        """Volume below percentage threshold → VOLUME_ANOMALY."""
        # z-score = (200 - 500) / 200 = -1.5 (within z-score threshold)
        # But 200 < 500 * 0.5 = 250 → triggers percentage drop
        status, detail, z = HealthCheckEngine._evaluate_volume(
            config, current_count=200, baseline_vol=500.0, baseline_std=200.0
        )
        assert status == LogSourceStatus.VOLUME_ANOMALY
        assert "drop" in detail.lower()

    def test_volume_spike_by_percentage(self, config):
        """Volume above percentage threshold → VOLUME_ANOMALY."""
        # z-score = (1600 - 500) / 500 = 2.2 (within z-score threshold)
        # But 1600 > 500 * 3.0 = 1500 → triggers percentage spike
        status, detail, z = HealthCheckEngine._evaluate_volume(
            config, current_count=1600, baseline_vol=500.0, baseline_std=500.0
        )
        assert status == LogSourceStatus.VOLUME_ANOMALY
        assert "spike" in detail.lower()


# ======================================================================
# _should_alert Tests
# ======================================================================


class TestShouldAlert:
    """Test the static _should_alert method."""

    @pytest.fixture
    def config(self):
        return LogSourceHealthConfig(
            source_type="okta",
            alert_suppression_seconds=3600,
        )

    def test_unknown_status_no_alert(self, config):
        """UNKNOWN status never alerts."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.HEALTHY, LogSourceStatus.UNKNOWN,
            0, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is False

    def test_healthy_to_healthy_no_alert(self, config):
        """Staying HEALTHY → no alert."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.HEALTHY, LogSourceStatus.HEALTHY,
            0, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is False

    def test_healthy_to_delayed_alerts(self, config):
        """Transition HEALTHY → DELAYED → alert."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.HEALTHY, LogSourceStatus.DELAYED,
            1, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is True

    def test_unknown_to_delayed_alerts(self, config):
        """Transition UNKNOWN → DELAYED → alert (new problem)."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.UNKNOWN, LogSourceStatus.DELAYED,
            1, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is True

    def test_delayed_to_silent_escalation_alerts(self, config):
        """Escalation DELAYED → SILENT → alert."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.DELAYED, LogSourceStatus.SILENT,
            3, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is True

    def test_recovery_alerts(self, config):
        """Recovery DELAYED → HEALTHY → alert."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.DELAYED, LogSourceStatus.HEALTHY,
            0, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is True

    def test_silent_recovery_alerts(self, config):
        """Recovery SILENT → HEALTHY → alert."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.SILENT, LogSourceStatus.HEALTHY,
            0, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is True

    def test_volume_anomaly_recovery_alerts(self, config):
        """Recovery VOLUME_ANOMALY → HEALTHY → alert."""
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.VOLUME_ANOMALY, LogSourceStatus.HEALTHY,
            0, None, config,
            datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        ) is True

    def test_same_bad_status_within_suppression_window(self, config):
        """Same bad status within suppression → no alert."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        last_alert = now - timedelta(seconds=1800)  # 30 min ago, < 3600
        existing = LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            last_alert_timestamp=last_alert,
            consecutive_failures=2,
        )
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.DELAYED, LogSourceStatus.DELAYED,
            3, existing, config, now,
        ) is False

    def test_same_bad_status_after_suppression_window(self, config):
        """Same bad status after suppression window → alert."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        last_alert = now - timedelta(seconds=7200)  # 2h ago, > 3600
        existing = LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            last_alert_timestamp=last_alert,
            consecutive_failures=5,
        )
        assert HealthCheckEngine._should_alert(
            LogSourceStatus.DELAYED, LogSourceStatus.DELAYED,
            6, existing, config, now,
        ) is True


# ======================================================================
# HealthCheckEngine Integration Tests
# ======================================================================


class TestHealthCheckEngineIntegration:
    """Integration tests for evaluate_single_source and check_all_sources."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def config_map(self):
        return {
            "okta": LogSourceHealthConfig(
                source_type="okta",
                expected_max_latency_seconds=300,
                silence_threshold_seconds=3600,
                gap_detection_enabled=False,
            ),
        }

    def test_new_source_no_executor(self, store, config_map):
        """Brand-new source with no executor → UNKNOWN."""
        engine = HealthCheckEngine(store, config_map, query_executor=None)
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = engine.evaluate_single_source("okta", "default", now=now)
        assert result.old_status == LogSourceStatus.UNKNOWN
        assert result.new_status == LogSourceStatus.UNKNOWN
        assert result.event_count_current == 0

    def test_healthy_source_from_collector(self, store, config_map):
        """Source with recent collector data → HEALTHY."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        recent_ts = now - timedelta(seconds=60)

        # Simulate collector reporting events
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=100,
            last_event_timestamp=recent_ts,
        ))

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.new_status == LogSourceStatus.HEALTHY
        assert result.event_count_current == 100
        assert result.consecutive_failures == 0

    def test_delayed_source(self, store, config_map):
        """Source with stale data → DELAYED."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        stale_ts = now - timedelta(seconds=600)  # 10 min, > 300s

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=50,
            last_event_timestamp=stale_ts,
        ))

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.old_status == LogSourceStatus.HEALTHY
        assert result.new_status == LogSourceStatus.DELAYED
        assert result.consecutive_failures == 1
        assert result.should_alert is True

    def test_silent_source(self, store, config_map):
        """Source with very old data → SILENT."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        old_ts = now - timedelta(seconds=7200)  # 2h, > 3600s

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            status=LogSourceStatus.DELAYED,
            consecutive_failures=3,
            event_count_current_window=10,
            last_event_timestamp=old_ts,
        ))

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.old_status == LogSourceStatus.DELAYED
        assert result.new_status == LogSourceStatus.SILENT
        assert result.consecutive_failures == 4
        assert result.should_alert is True  # escalation

    def test_volume_anomaly_detected(self, store, config_map):
        """Source with anomalous volume → VOLUME_ANOMALY."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        recent_ts = now - timedelta(seconds=30)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            status=LogSourceStatus.HEALTHY,
            event_count_current_window=10,  # Very low
            last_event_timestamp=recent_ts,
        ))
        store.save_baseline("okta", "default", 500.0, 50.0)

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.new_status == LogSourceStatus.VOLUME_ANOMALY
        assert result.z_score is not None
        assert result.z_score < 0  # drop
        assert result.should_alert is True

    def test_check_all_sources(self, store, config_map):
        """check_all_sources evaluates all enabled sources."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        results = engine.check_all_sources("default", now=now)

        # Should evaluate all sources (21 defaults + any custom)
        assert len(results) >= 21
        source_types = {r.source_type for r in results}
        assert "okta" in source_types

    def test_disabled_source_skipped(self, store):
        """Disabled source is not evaluated."""
        config_map = {
            "okta": LogSourceHealthConfig(
                source_type="okta",
                enabled=False,
            ),
        }
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        results = engine.check_all_sources("default", now=now)

        source_types = {r.source_type for r in results}
        assert "okta" not in source_types

    def test_state_persisted_after_check(self, store, config_map):
        """State is saved to the store after evaluation."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        engine.evaluate_single_source("okta", "default", now=now)

        state = store.get_state("okta", "default")
        assert state is not None
        assert state.last_check_timestamp == now

    def test_consecutive_failures_increment(self, store, config_map):
        """Consecutive failures increment on non-healthy status."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        old_ts = now - timedelta(seconds=7200)

        # First check: failure starts at 1
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            event_count_current_window=0,
            last_event_timestamp=old_ts,
        ))
        engine = HealthCheckEngine(store, config_map, query_executor=None)
        r1 = engine.evaluate_single_source("okta", "default", now=now)
        assert r1.consecutive_failures == 1

        # Second check: failure increments
        r2 = engine.evaluate_single_source("okta", "default", now=now)
        assert r2.consecutive_failures == 2

    def test_consecutive_failures_reset_on_healthy(self, store, config_map):
        """Failures reset to 0 when source becomes healthy."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        recent_ts = now - timedelta(seconds=30)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            consecutive_failures=5,
            event_count_current_window=100,
            last_event_timestamp=recent_ts,
        ))

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.new_status == LogSourceStatus.HEALTHY
        assert result.consecutive_failures == 0


# ======================================================================
# Data Lake Query Tests (with mock executor)
# ======================================================================


class TestDataLakeQueries:
    """Test data lake query paths with mocked executor."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def executor(self):
        mock_exec = MagicMock()
        return mock_exec

    @pytest.fixture
    def config_map(self):
        return {
            "okta": LogSourceHealthConfig(
                source_type="okta",
                expected_max_latency_seconds=300,
                silence_threshold_seconds=3600,
                gap_detection_enabled=False,
            ),
        }

    def test_executor_queried_when_state_stale(self, store, executor, config_map):
        """Executor is used when collector state is stale (>10 min)."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        stale_ts = now - timedelta(seconds=700)  # > 600s freshness

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            event_count_current_window=50,
            last_event_timestamp=stale_ts,
        ))

        # Mock executor returns fresh data
        recent_ts = now - timedelta(seconds=60)
        executor.execute_query.return_value = MagicMock(
            data=[{"event_count": 200, "max_ts": recent_ts.isoformat()}]
        )

        engine = HealthCheckEngine(store, config_map, executor)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert executor.execute_query.called
        assert result.event_count_current == 200
        assert result.new_status == LogSourceStatus.HEALTHY

    def test_executor_not_called_when_state_fresh(self, store, executor, config_map):
        """Executor not queried when collector state is fresh (<10 min)."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        fresh_ts = now - timedelta(seconds=30)  # < 600s

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            event_count_current_window=100,
            last_event_timestamp=fresh_ts,
        ))

        engine = HealthCheckEngine(store, config_map, executor)
        result = engine.evaluate_single_source("okta", "default", now=now)

        # Executor not called for current window metrics
        # (may be called for previous window)
        current_calls = [
            c for c in executor.execute_query.call_args_list
            if "MAX" in str(c)
        ]
        assert len(current_calls) == 0

    def test_executor_failure_falls_back_to_state(self, store, executor, config_map):
        """Executor failure → falls back to existing state."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        stale_ts = now - timedelta(seconds=700)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            event_count_current_window=50,
            last_event_timestamp=stale_ts,
        ))

        executor.execute_query.side_effect = Exception("Query timeout")

        engine = HealthCheckEngine(store, config_map, executor)
        result = engine.evaluate_single_source("okta", "default", now=now)

        # Should still produce a result using stale data
        assert result.event_count_current == 50

    def test_previous_window_query(self, store, executor, config_map):
        """Previous window count queried from data lake."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        fresh_ts = now - timedelta(seconds=30)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            event_count_current_window=100,
            last_event_timestamp=fresh_ts,
        ))

        executor.execute_query.return_value = MagicMock(
            data=[{"event_count": 150}]
        )

        engine = HealthCheckEngine(store, config_map, executor)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.event_count_previous == 150

    def test_no_executor_returns_zero_previous(self, store, config_map):
        """No executor → previous window count is 0."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        fresh_ts = now - timedelta(seconds=30)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            event_count_current_window=100,
            last_event_timestamp=fresh_ts,
        ))

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        result = engine.evaluate_single_source("okta", "default", now=now)

        assert result.event_count_previous == 0


# ======================================================================
# Gap Detection Tests
# ======================================================================


class TestGapDetection:
    """Test the _detect_gaps method."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def executor(self):
        return MagicMock()

    def test_no_executor_returns_empty(self, store):
        """No executor → no gaps detected."""
        config = LogSourceHealthConfig(
            source_type="okta",
            gap_detection_enabled=True,
        )
        engine = HealthCheckEngine(store, {}, query_executor=None)
        now = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        gaps = engine._detect_gaps("okta", "default", config, now)
        assert gaps == []

    def test_gap_detected_between_filled_buckets(self, store, executor):
        """Gap between filled buckets is detected."""
        config = LogSourceHealthConfig(
            source_type="okta",
            gap_detection_enabled=True,
            gap_minimum_duration_seconds=300,  # 5 min minimum
        )

        # Buckets: 0=filled, 1=empty, 2=empty, 3=empty, 4=filled
        # Gap from bucket 1-3 (15 minutes)
        executor.execute_query.return_value = MagicMock(
            data=[
                {"bucket": 0, "cnt": 10},
                {"bucket": 4, "cnt": 5},
            ]
        )

        engine = HealthCheckEngine(store, {}, executor)
        now = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        gaps = engine._detect_gaps("okta", "default", config, now)
        assert len(gaps) == 1
        gap_duration = (gaps[0][1] - gaps[0][0]).total_seconds()
        # gap_start=1, gap_end=4 (first non-empty after gap)
        # duration = (4-1) * 300 = 900s = 15 min
        assert gap_duration == 900

    def test_gap_below_minimum_ignored(self, store, executor):
        """Gaps shorter than minimum duration are ignored."""
        config = LogSourceHealthConfig(
            source_type="okta",
            gap_detection_enabled=True,
            gap_minimum_duration_seconds=900,  # 15 min minimum
        )

        # Only one empty bucket between filled ones → 5 min gap (< 15 min)
        executor.execute_query.return_value = MagicMock(
            data=[
                {"bucket": 0, "cnt": 10},
                {"bucket": 2, "cnt": 5},
            ]
        )

        engine = HealthCheckEngine(store, {}, executor)
        now = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        gaps = engine._detect_gaps("okta", "default", config, now)
        assert len(gaps) == 0

    def test_no_filled_buckets_returns_empty(self, store, executor):
        """No filled buckets → no gaps."""
        config = LogSourceHealthConfig(
            source_type="okta",
            gap_detection_enabled=True,
        )

        executor.execute_query.return_value = MagicMock(data=[])

        engine = HealthCheckEngine(store, {}, executor)
        now = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        gaps = engine._detect_gaps("okta", "default", config, now)
        assert gaps == []

    def test_query_failure_returns_empty(self, store, executor):
        """Query failure → empty gaps."""
        config = LogSourceHealthConfig(
            source_type="okta",
            gap_detection_enabled=True,
        )

        executor.execute_query.side_effect = Exception("Query failed")

        engine = HealthCheckEngine(store, {}, executor)
        now = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        gaps = engine._detect_gaps("okta", "default", config, now)
        assert gaps == []


# ======================================================================
# Baseline Computation Tests
# ======================================================================


class TestBaselineComputation:
    """Test compute_baselines and _compute_baseline_for_source."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def executor(self):
        return MagicMock()

    def test_compute_baselines_success(self, store, executor):
        """Baselines computed and persisted for all sources."""
        config_map = {
            "okta": LogSourceHealthConfig(
                source_type="okta",
                baseline_learning_period_days=7,
            ),
        }

        executor.execute_query.return_value = MagicMock(
            data=[
                {"event_count": 100},
                {"event_count": 110},
                {"event_count": 90},
                {"event_count": 105},
                {"event_count": 95},
            ]
        )

        engine = HealthCheckEngine(store, config_map, executor)
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        baselines = engine.compute_baselines("default", now=now)

        # At least okta should have a baseline
        assert "okta" in baselines
        mean, stddev = baselines["okta"]
        assert mean == 100.0
        assert stddev > 0

        # Baseline persisted in store
        stored = store.get_baseline("okta", "default")
        assert stored is not None
        assert abs(stored[0] - mean) < 0.01

    def test_compute_baselines_no_executor(self, store):
        """No executor → no baselines computed."""
        config_map = {
            "okta": LogSourceHealthConfig(source_type="okta"),
        }

        engine = HealthCheckEngine(store, config_map, query_executor=None)
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        baselines = engine.compute_baselines("default", now=now)
        # okta won't have a baseline without executor
        assert "okta" not in baselines

    def test_compute_baselines_empty_data(self, store, executor):
        """Empty data lake → no baseline computed."""
        config_map = {
            "okta": LogSourceHealthConfig(source_type="okta"),
        }

        executor.execute_query.return_value = MagicMock(data=[])

        engine = HealthCheckEngine(store, config_map, executor)
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        baselines = engine.compute_baselines("default", now=now)
        assert "okta" not in baselines

    def test_compute_baselines_query_failure(self, store, executor):
        """Query failure → source skipped, others still computed."""
        config_map = {
            "okta": LogSourceHealthConfig(source_type="okta"),
        }

        executor.execute_query.side_effect = Exception("Query failed")

        engine = HealthCheckEngine(store, config_map, executor)
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        baselines = engine.compute_baselines("default", now=now)
        assert "okta" not in baselines


# ======================================================================
# Module-Level Helpers
# ======================================================================


class TestModuleHelpers:
    """Test _mean_stddev and _fmt_duration."""

    def test_mean_stddev_empty(self):
        assert _mean_stddev([]) == (0.0, 0.0)

    def test_mean_stddev_single(self):
        mean, std = _mean_stddev([42])
        assert mean == 42.0
        assert std == 0.0

    def test_mean_stddev_multiple(self):
        mean, std = _mean_stddev([10, 20, 30])
        assert mean == 20.0
        # Population stddev of [10,20,30] = sqrt(200/3) ≈ 8.165
        assert abs(std - math.sqrt(200 / 3)) < 0.01

    def test_mean_stddev_uniform(self):
        mean, std = _mean_stddev([5, 5, 5, 5])
        assert mean == 5.0
        assert std == 0.0

    def test_fmt_duration_seconds(self):
        assert _fmt_duration(30) == "30s"

    def test_fmt_duration_minutes(self):
        assert _fmt_duration(300) == "5m"

    def test_fmt_duration_hours(self):
        assert _fmt_duration(7200) == "2.0h"

    def test_fmt_duration_days(self):
        assert _fmt_duration(172800) == "2.0d"

    def test_fmt_duration_negative(self):
        """Negative values produce positive durations."""
        assert _fmt_duration(-300) == "5m"
