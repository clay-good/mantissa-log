"""Tests for HealthAlertGenerator.

Covers alert generation per status transition, severity mapping,
suppression, recovery alerts, and gap reports.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from shared.health.health_alerting import (
    HealthAlertGenerator,
    HealthAlertOutcome,
    _fmt_duration,
)
from shared.health.health_check_engine import HealthCheckResult
from shared.health.health_state_store import InMemoryHealthStateStore
from shared.health.log_source_health import (
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
)


# ======================================================================
# HealthAlertOutcome Tests
# ======================================================================


class TestHealthAlertOutcome:
    """Test the HealthAlertOutcome dataclass."""

    def test_default_values(self):
        outcome = HealthAlertOutcome()
        assert outcome.alert is None
        assert outcome.suppressed is False
        assert outcome.suppression_reason == ""
        assert outcome.routing_result is None


# ======================================================================
# _determine_severity Tests
# ======================================================================


class TestDetermineSeverity:
    """Test severity mapping logic."""

    def test_delayed_low_failures_is_low(self):
        """DELAYED with < 3 failures → low."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
        )
        assert HealthAlertGenerator._determine_severity(result) == "low"

    def test_delayed_high_failures_is_medium(self):
        """DELAYED with >= 3 failures → medium."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=3,
        )
        assert HealthAlertGenerator._determine_severity(result) == "medium"

    def test_silent_low_failures_is_high(self):
        """SILENT with < 3 failures → high."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.DELAYED,
            new_status=LogSourceStatus.SILENT,
            consecutive_failures=2,
        )
        assert HealthAlertGenerator._determine_severity(result) == "high"

    def test_silent_high_failures_is_critical(self):
        """SILENT with >= 3 failures → critical."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.DELAYED,
            new_status=LogSourceStatus.SILENT,
            consecutive_failures=5,
        )
        assert HealthAlertGenerator._determine_severity(result) == "critical"

    def test_volume_anomaly_drop_is_medium(self):
        """VOLUME_ANOMALY with z < 0 (drop) → medium."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.VOLUME_ANOMALY,
            z_score=-4.0,
        )
        assert HealthAlertGenerator._determine_severity(result) == "medium"

    def test_volume_anomaly_spike_is_low(self):
        """VOLUME_ANOMALY with z >= 0 (spike) → low."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.VOLUME_ANOMALY,
            z_score=4.0,
        )
        assert HealthAlertGenerator._determine_severity(result) == "low"

    def test_volume_anomaly_no_zscore_is_low(self):
        """VOLUME_ANOMALY with no z_score → low (fallback)."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.VOLUME_ANOMALY,
            z_score=None,
        )
        assert HealthAlertGenerator._determine_severity(result) == "low"

    def test_gap_windows_is_medium(self):
        """Result with gap_windows → medium."""
        gs = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
        ge = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.HEALTHY,  # Not typically, but testing fallback
            gap_windows=[(gs, ge)],
        )
        assert HealthAlertGenerator._determine_severity(result) == "medium"


# ======================================================================
# generate_health_alert Tests
# ======================================================================


class TestGenerateHealthAlert:
    """Test the generate_health_alert method."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def gen(self, store):
        """Create a HealthAlertGenerator with no router."""
        return HealthAlertGenerator(
            health_state_store=store,
            config_map={},
            alert_router=None,
            default_destinations=["slack"],
        )

    def test_suppressed_when_not_flagged(self, gen):
        """Result with should_alert=False → suppressed."""
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.HEALTHY,
            should_alert=False,
        )
        outcome = gen.generate_health_alert(result)

        assert outcome.suppressed is True
        assert outcome.alert is None
        assert "did not flag" in outcome.suppression_reason.lower()

    def test_alert_generated_for_delayed(self, gen):
        """HEALTHY → DELAYED with should_alert → generates alert."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Last event 10m ago",
            last_event_timestamp=now - timedelta(minutes=10),
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert outcome.suppressed is False
        assert outcome.alert is not None
        assert "okta" in outcome.alert.title
        assert outcome.alert.severity == "low"
        assert "DELAYED" in outcome.alert.title
        assert outcome.alert.metadata["source_type"] == "okta"
        assert outcome.alert.metadata["alert_category"] == "log_source_health"

    def test_alert_generated_for_silent(self, gen):
        """DELAYED → SILENT with should_alert → generates critical alert."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.DELAYED,
            new_status=LogSourceStatus.SILENT,
            consecutive_failures=5,
            should_alert=True,
            detail_message="No events for 2h",
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert outcome.suppressed is False
        assert outcome.alert is not None
        assert outcome.alert.severity == "critical"

    def test_alert_metadata_populated(self, gen):
        """Alert metadata includes health-specific fields."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts = now - timedelta(minutes=10)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.VOLUME_ANOMALY,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Volume drop",
            event_count_current=50,
            event_count_previous=200,
            last_event_timestamp=ts,
            baseline_volume=200.0,
            baseline_stddev=20.0,
            z_score=-7.5,
        )
        outcome = gen.generate_health_alert(result, now=now)

        meta = outcome.alert.metadata
        assert meta["source_type"] == "okta"
        assert meta["old_status"] == "HEALTHY"
        assert meta["new_status"] == "VOLUME_ANOMALY"
        assert meta["consecutive_failures"] == 1
        assert meta["event_count_current"] == 50
        assert meta["z_score"] == -7.5
        assert meta["baseline_volume"] == 200.0
        assert "last_event_timestamp" in meta

    def test_recovery_delegates_to_recovery_alert(self, gen, store):
        """DELAYED → HEALTHY with should_alert → generates recovery alert."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Pre-populate state so recovery can compute duration
        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            last_alert_timestamp=now - timedelta(hours=1),
        ))

        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.DELAYED,
            new_status=LogSourceStatus.HEALTHY,
            consecutive_failures=0,
            should_alert=True,
            detail_message="Back to normal",
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert outcome.suppressed is False
        assert outcome.alert is not None
        assert outcome.alert.severity == "info"
        assert "recovered" in outcome.alert.title.lower()

    def test_gap_metadata_included(self, gen):
        """Gap windows are included in alert metadata."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        gs = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
        ge = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)

        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Delayed with gaps",
            gap_windows=[(gs, ge)],
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert outcome.alert.metadata["gap_count"] == 1
        assert len(outcome.alert.metadata["gaps"]) == 1

    def test_custom_destinations_used(self, store):
        """Source-specific destinations override defaults."""
        config_map = {
            "okta": LogSourceHealthConfig(
                source_type="okta",
                alert_destinations=["pagerduty", "email"],
            ),
        }
        gen = HealthAlertGenerator(
            health_state_store=store,
            config_map=config_map,
            default_destinations=["slack"],
        )

        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Delayed",
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert "pagerduty" in outcome.alert.destinations
        assert "email" in outcome.alert.destinations
        assert "slack" not in outcome.alert.destinations


# ======================================================================
# generate_recovery_alert Tests
# ======================================================================


class TestGenerateRecoveryAlert:
    """Test the generate_recovery_alert method."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def gen(self, store):
        return HealthAlertGenerator(
            health_state_store=store,
            default_destinations=["slack"],
        )

    def test_recovery_alert_generated(self, gen, store):
        """Recovery alert has info severity and recovery tags."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.SILENT,
            last_alert_timestamp=now - timedelta(hours=2),
        ))

        outcome = gen.generate_recovery_alert(
            source_type="okta",
            tenant_id="default",
            old_status=LogSourceStatus.SILENT,
            now=now,
        )

        assert outcome.suppressed is False
        assert outcome.alert is not None
        assert outcome.alert.severity == "info"
        assert "recovery" in outcome.alert.tags
        assert outcome.alert.metadata["old_status"] == "SILENT"
        assert outcome.alert.metadata["new_status"] == "HEALTHY"

    def test_recovery_alert_includes_duration(self, gen, store):
        """Recovery alert includes unhealthy duration."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        store.save_state("okta", "default", LogSourceHealthState(
            source_type="okta",
            status=LogSourceStatus.DELAYED,
            last_alert_timestamp=now - timedelta(hours=3),
        ))

        outcome = gen.generate_recovery_alert(
            source_type="okta",
            tenant_id="default",
            old_status=LogSourceStatus.DELAYED,
            now=now,
        )

        assert "unhealthy_duration_seconds" in outcome.alert.metadata
        assert outcome.alert.metadata["unhealthy_duration_seconds"] == 10800.0

    def test_recovery_alert_no_prior_state(self, gen):
        """Recovery alert works even with no prior state."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        outcome = gen.generate_recovery_alert(
            source_type="okta",
            tenant_id="default",
            old_status=LogSourceStatus.DELAYED,
            now=now,
        )

        assert outcome.alert is not None
        assert outcome.alert.severity == "info"
        # No unhealthy_duration_seconds since no prior state
        assert "unhealthy_duration_seconds" not in outcome.alert.metadata


# ======================================================================
# generate_gap_report Tests
# ======================================================================


class TestGenerateGapReport:
    """Test the generate_gap_report method."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    @pytest.fixture
    def gen(self, store):
        return HealthAlertGenerator(
            health_state_store=store,
            default_destinations=["slack"],
        )

    def test_gap_report_generated(self, gen):
        """Gap report generated with correct severity and metadata."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        gaps = [
            (
                datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 1, 15, 9, 15, 0, tzinfo=timezone.utc),
            ),
            (
                datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc),
                datetime(2026, 1, 15, 9, 45, 0, tzinfo=timezone.utc),
            ),
        ]

        outcome = gen.generate_gap_report(
            source_type="okta",
            tenant_id="default",
            gaps=gaps,
            event_count_before=100,
            event_count_after=80,
            now=now,
        )

        assert outcome.suppressed is False
        assert outcome.alert is not None
        assert outcome.alert.severity == "medium"
        assert "gap_report" in outcome.alert.tags
        assert outcome.alert.metadata["gap_count"] == 2
        assert outcome.alert.metadata["total_gap_duration_seconds"] == 1800.0
        assert outcome.alert.metadata["event_count_before"] == 100
        assert outcome.alert.metadata["event_count_after"] == 80

    def test_gap_report_suppressed_when_no_gaps(self, gen):
        """Empty gaps list → suppressed."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        outcome = gen.generate_gap_report(
            source_type="okta",
            tenant_id="default",
            gaps=[],
            now=now,
        )

        assert outcome.suppressed is True
        assert "No gaps" in outcome.suppression_reason

    def test_gap_report_description_has_details(self, gen):
        """Gap report description includes individual gap details."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        gaps = [
            (
                datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc),
            ),
        ]

        outcome = gen.generate_gap_report(
            source_type="okta",
            tenant_id="default",
            gaps=gaps,
            now=now,
        )

        desc = outcome.alert.description
        assert "09:00:00" in desc
        assert "09:30:00" in desc
        assert "Data gap report" in desc


# ======================================================================
# Alert Routing Tests
# ======================================================================


class TestAlertRouting:
    """Test alert routing integration."""

    @pytest.fixture
    def store(self):
        return InMemoryHealthStateStore()

    def test_alert_routed_when_router_configured(self, store):
        """Alert is routed through AlertRouter."""
        mock_router = MagicMock()
        mock_routing_result = MagicMock(success=True, destinations_succeeded=["slack"])
        mock_router.route_alert.return_value = mock_routing_result

        gen = HealthAlertGenerator(
            health_state_store=store,
            alert_router=mock_router,
            default_destinations=["slack"],
        )

        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Delayed",
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert mock_router.route_alert.called
        assert outcome.routing_result is not None

    def test_no_routing_when_no_router(self, store):
        """No router → routing_result is None."""
        gen = HealthAlertGenerator(
            health_state_store=store,
            alert_router=None,
            default_destinations=["slack"],
        )

        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Delayed",
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert outcome.routing_result is None

    def test_routing_failure_handled_gracefully(self, store):
        """Router exception → routing_result is None, alert still generated."""
        mock_router = MagicMock()
        mock_router.route_alert.side_effect = Exception("Routing failed")

        gen = HealthAlertGenerator(
            health_state_store=store,
            alert_router=mock_router,
            default_destinations=["slack"],
        )

        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = HealthCheckResult(
            source_type="okta",
            old_status=LogSourceStatus.HEALTHY,
            new_status=LogSourceStatus.DELAYED,
            consecutive_failures=1,
            should_alert=True,
            detail_message="Delayed",
        )
        outcome = gen.generate_health_alert(result, now=now)

        assert outcome.alert is not None
        assert outcome.routing_result is None
