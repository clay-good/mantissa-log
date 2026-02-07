"""Tests for log source health data models and configuration.

Covers LogSourceStatus enum, LogSourceHealthState dataclass,
LogSourceHealthConfig dataclass, validation, serialization,
and helper functions.
"""

import json
import pytest
from datetime import datetime, timezone

from shared.health.log_source_health import (
    DEFAULT_HEALTH_CONFIGS,
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
    get_config_for_source,
    list_enabled_sources,
    list_monitored_sources,
)


class TestLogSourceStatus:
    """Test the LogSourceStatus enum values."""

    def test_enum_values(self):
        """Verify all expected enum values exist."""
        assert LogSourceStatus.HEALTHY.value == "HEALTHY"
        assert LogSourceStatus.DELAYED.value == "DELAYED"
        assert LogSourceStatus.SILENT.value == "SILENT"
        assert LogSourceStatus.VOLUME_ANOMALY.value == "VOLUME_ANOMALY"
        assert LogSourceStatus.UNKNOWN.value == "UNKNOWN"

    def test_enum_count(self):
        """Verify exactly 5 status values exist."""
        assert len(LogSourceStatus) == 5

    def test_enum_from_value(self):
        """Verify enum can be constructed from string value."""
        assert LogSourceStatus("HEALTHY") == LogSourceStatus.HEALTHY
        assert LogSourceStatus("VOLUME_ANOMALY") == LogSourceStatus.VOLUME_ANOMALY

    def test_enum_invalid_value(self):
        """Verify invalid status value raises ValueError."""
        with pytest.raises(ValueError):
            LogSourceStatus("INVALID")


class TestLogSourceHealthState:
    """Test the LogSourceHealthState dataclass."""

    def test_default_creation(self):
        """Verify a state can be created with just source_type."""
        state = LogSourceHealthState(source_type="okta")
        assert state.source_type == "okta"
        assert state.tenant_id == "default"
        assert state.status == LogSourceStatus.UNKNOWN
        assert state.consecutive_failures == 0
        assert state.event_count_current_window == 0
        assert state.event_count_previous_window == 0
        assert state.last_event_timestamp is None
        assert state.last_check_timestamp is None
        assert state.last_alert_timestamp is None
        assert state.baseline_hourly_volume is None
        assert state.baseline_hourly_stddev is None
        assert state.gap_windows == []
        assert state.metadata == {}

    def test_full_creation(self):
        """Verify a state can be created with all fields."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        gap_start = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
        gap_end = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)

        state = LogSourceHealthState(
            source_type="cloudtrail",
            tenant_id="tenant-1",
            last_event_timestamp=now,
            last_check_timestamp=now,
            event_count_current_window=500,
            event_count_previous_window=450,
            baseline_hourly_volume=480.0,
            baseline_hourly_stddev=50.0,
            status=LogSourceStatus.HEALTHY,
            consecutive_failures=0,
            last_alert_timestamp=now,
            gap_windows=[(gap_start, gap_end)],
            metadata={"region": "us-east-1"},
        )

        assert state.source_type == "cloudtrail"
        assert state.tenant_id == "tenant-1"
        assert state.event_count_current_window == 500
        assert state.baseline_hourly_volume == 480.0
        assert state.status == LogSourceStatus.HEALTHY
        assert len(state.gap_windows) == 1
        assert state.metadata["region"] == "us-east-1"

    def test_to_dict(self):
        """Verify to_dict serializes all fields correctly."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state = LogSourceHealthState(
            source_type="okta",
            tenant_id="default",
            last_event_timestamp=now,
            status=LogSourceStatus.DELAYED,
            consecutive_failures=2,
        )
        d = state.to_dict()

        assert d["source_type"] == "okta"
        assert d["tenant_id"] == "default"
        assert d["last_event_timestamp"] == "2026-01-15T10:00:00+00:00"
        assert d["status"] == "DELAYED"
        assert d["consecutive_failures"] == 2
        assert d["gap_windows"] == []
        assert d["last_check_timestamp"] is None

    def test_to_dict_with_gap_windows(self):
        """Verify gap_windows are serialized as ISO format pairs."""
        gs = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
        ge = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)
        state = LogSourceHealthState(
            source_type="okta",
            gap_windows=[(gs, ge)],
        )
        d = state.to_dict()
        assert len(d["gap_windows"]) == 1
        assert d["gap_windows"][0][0] == gs.isoformat()
        assert d["gap_windows"][0][1] == ge.isoformat()

    def test_from_dict(self):
        """Verify from_dict deserializes correctly."""
        data = {
            "source_type": "cloudtrail",
            "tenant_id": "tenant-2",
            "last_event_timestamp": "2026-01-15T10:00:00+00:00",
            "status": "SILENT",
            "consecutive_failures": 5,
            "event_count_current_window": 0,
            "gap_windows": [
                ["2026-01-15T09:00:00+00:00", "2026-01-15T09:30:00+00:00"]
            ],
        }
        state = LogSourceHealthState.from_dict(data)

        assert state.source_type == "cloudtrail"
        assert state.tenant_id == "tenant-2"
        assert state.status == LogSourceStatus.SILENT
        assert state.consecutive_failures == 5
        assert state.last_event_timestamp == datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert len(state.gap_windows) == 1

    def test_from_dict_minimal(self):
        """Verify from_dict handles minimal data with defaults."""
        data = {"source_type": "okta"}
        state = LogSourceHealthState.from_dict(data)

        assert state.source_type == "okta"
        assert state.tenant_id == "default"
        assert state.status == LogSourceStatus.UNKNOWN
        assert state.consecutive_failures == 0
        assert state.gap_windows == []

    def test_from_dict_ignores_invalid_gap_windows(self):
        """Verify from_dict skips malformed gap_windows entries."""
        data = {
            "source_type": "okta",
            "gap_windows": [
                ["2026-01-15T09:00:00+00:00", "2026-01-15T09:30:00+00:00"],
                "invalid",
                [1, 2, 3],
            ],
        }
        state = LogSourceHealthState.from_dict(data)
        assert len(state.gap_windows) == 1

    def test_roundtrip_dict(self):
        """Verify to_dict -> from_dict roundtrip preserves state."""
        now = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        original = LogSourceHealthState(
            source_type="okta",
            tenant_id="test",
            last_event_timestamp=now,
            status=LogSourceStatus.HEALTHY,
            consecutive_failures=0,
            baseline_hourly_volume=100.5,
            baseline_hourly_stddev=10.2,
            event_count_current_window=105,
        )
        restored = LogSourceHealthState.from_dict(original.to_dict())

        assert restored.source_type == original.source_type
        assert restored.tenant_id == original.tenant_id
        assert restored.status == original.status
        assert restored.baseline_hourly_volume == original.baseline_hourly_volume
        assert restored.event_count_current_window == original.event_count_current_window

    def test_to_json(self):
        """Verify to_json produces valid JSON."""
        state = LogSourceHealthState(source_type="okta")
        json_str = state.to_json()
        parsed = json.loads(json_str)
        assert parsed["source_type"] == "okta"

    def test_from_json(self):
        """Verify from_json parses JSON string correctly."""
        json_str = '{"source_type": "okta", "status": "HEALTHY"}'
        state = LogSourceHealthState.from_json(json_str)
        assert state.source_type == "okta"
        assert state.status == LogSourceStatus.HEALTHY

    def test_roundtrip_json(self):
        """Verify to_json -> from_json roundtrip."""
        original = LogSourceHealthState(
            source_type="slack",
            status=LogSourceStatus.DELAYED,
            consecutive_failures=3,
        )
        restored = LogSourceHealthState.from_json(original.to_json())
        assert restored.source_type == original.source_type
        assert restored.status == original.status
        assert restored.consecutive_failures == original.consecutive_failures


class TestLogSourceHealthConfig:
    """Test the LogSourceHealthConfig dataclass."""

    def test_default_creation(self):
        """Verify default config values."""
        config = LogSourceHealthConfig(source_type="okta")
        assert config.source_type == "okta"
        assert config.enabled is True
        assert config.expected_max_latency_seconds == 300
        assert config.silence_threshold_seconds == 3600
        assert config.volume_anomaly_stddev_threshold == 3.0
        assert config.volume_drop_percentage_threshold == 0.5
        assert config.volume_spike_percentage_threshold == 3.0
        assert config.baseline_learning_period_days == 7
        assert config.check_interval_seconds == 300
        assert config.alert_suppression_seconds == 3600
        assert config.alert_destinations == []
        assert config.gap_detection_enabled is True
        assert config.gap_minimum_duration_seconds == 900

    def test_validate_valid_config(self):
        """Verify a valid config produces no errors."""
        config = LogSourceHealthConfig(source_type="okta")
        errors = config.validate()
        assert errors == []

    def test_validate_latency_must_be_positive(self):
        """Verify expected_max_latency_seconds must be > 0."""
        config = LogSourceHealthConfig(
            source_type="okta",
            expected_max_latency_seconds=0,
        )
        errors = config.validate()
        assert any("expected_max_latency_seconds" in e for e in errors)

    def test_validate_silence_must_be_positive(self):
        """Verify silence_threshold_seconds must be > 0."""
        config = LogSourceHealthConfig(
            source_type="okta",
            silence_threshold_seconds=0,
        )
        errors = config.validate()
        assert any("silence_threshold_seconds must be positive" in e for e in errors)

    def test_validate_silence_must_exceed_latency(self):
        """Verify silence_threshold must be > expected_max_latency."""
        config = LogSourceHealthConfig(
            source_type="okta",
            expected_max_latency_seconds=3600,
            silence_threshold_seconds=3600,
        )
        errors = config.validate()
        assert any("silence_threshold_seconds must be greater" in e for e in errors)

    def test_validate_stddev_threshold_positive(self):
        """Verify volume_anomaly_stddev_threshold must be > 0."""
        config = LogSourceHealthConfig(
            source_type="okta",
            volume_anomaly_stddev_threshold=0,
        )
        errors = config.validate()
        assert any("volume_anomaly_stddev_threshold" in e for e in errors)

    def test_validate_drop_threshold_range(self):
        """Verify volume_drop_percentage_threshold must be between 0 and 1."""
        for bad_val in [0.0, 1.0, -0.1, 1.5]:
            config = LogSourceHealthConfig(
                source_type="okta",
                volume_drop_percentage_threshold=bad_val,
            )
            errors = config.validate()
            assert any("volume_drop_percentage_threshold" in e for e in errors)

    def test_validate_spike_threshold_must_exceed_one(self):
        """Verify volume_spike_percentage_threshold must be > 1.0."""
        config = LogSourceHealthConfig(
            source_type="okta",
            volume_spike_percentage_threshold=1.0,
        )
        errors = config.validate()
        assert any("volume_spike_percentage_threshold" in e for e in errors)

    def test_validate_baseline_days_minimum(self):
        """Verify baseline_learning_period_days must be >= 1."""
        config = LogSourceHealthConfig(
            source_type="okta",
            baseline_learning_period_days=0,
        )
        errors = config.validate()
        assert any("baseline_learning_period_days" in e for e in errors)

    def test_validate_check_interval_minimum(self):
        """Verify check_interval_seconds must be >= 60."""
        config = LogSourceHealthConfig(
            source_type="okta",
            check_interval_seconds=30,
        )
        errors = config.validate()
        assert any("check_interval_seconds" in e for e in errors)

    def test_validate_suppression_nonnegative(self):
        """Verify alert_suppression_seconds must be >= 0."""
        config = LogSourceHealthConfig(
            source_type="okta",
            alert_suppression_seconds=-1,
        )
        errors = config.validate()
        assert any("alert_suppression_seconds" in e for e in errors)

    def test_validate_gap_duration_minimum(self):
        """Verify gap_minimum_duration_seconds must be >= 60."""
        config = LogSourceHealthConfig(
            source_type="okta",
            gap_minimum_duration_seconds=30,
        )
        errors = config.validate()
        assert any("gap_minimum_duration_seconds" in e for e in errors)

    def test_validate_multiple_errors(self):
        """Verify multiple validation errors are all reported."""
        config = LogSourceHealthConfig(
            source_type="okta",
            expected_max_latency_seconds=-1,
            silence_threshold_seconds=-1,
            volume_anomaly_stddev_threshold=0,
        )
        errors = config.validate()
        assert len(errors) >= 3

    def test_to_dict(self):
        """Verify to_dict serialization."""
        config = LogSourceHealthConfig(source_type="okta")
        d = config.to_dict()
        assert d["source_type"] == "okta"
        assert d["enabled"] is True
        assert d["expected_max_latency_seconds"] == 300

    def test_from_dict(self):
        """Verify from_dict deserialization."""
        data = {
            "source_type": "cloudtrail",
            "expected_max_latency_seconds": 900,
            "silence_threshold_seconds": 7200,
        }
        config = LogSourceHealthConfig.from_dict(data)
        assert config.source_type == "cloudtrail"
        assert config.expected_max_latency_seconds == 900
        assert config.silence_threshold_seconds == 7200
        assert config.enabled is True  # default

    def test_roundtrip_dict(self):
        """Verify to_dict -> from_dict roundtrip."""
        original = LogSourceHealthConfig(
            source_type="syslog",
            expected_max_latency_seconds=60,
            silence_threshold_seconds=600,
            gap_detection_enabled=False,
        )
        restored = LogSourceHealthConfig.from_dict(original.to_dict())
        assert restored.source_type == original.source_type
        assert restored.expected_max_latency_seconds == original.expected_max_latency_seconds
        assert restored.gap_detection_enabled == original.gap_detection_enabled

    def test_merge_with_overrides(self):
        """Verify merge_with applies partial overrides."""
        base = LogSourceHealthConfig(
            source_type="okta",
            expected_max_latency_seconds=300,
            silence_threshold_seconds=3600,
        )
        merged = base.merge_with({"silence_threshold_seconds": 7200})
        assert merged.source_type == "okta"
        assert merged.expected_max_latency_seconds == 300  # unchanged
        assert merged.silence_threshold_seconds == 7200  # overridden

    def test_merge_with_ignores_none_values(self):
        """Verify merge_with ignores None values in overrides."""
        base = LogSourceHealthConfig(
            source_type="okta",
            expected_max_latency_seconds=300,
        )
        merged = base.merge_with({"expected_max_latency_seconds": None})
        assert merged.expected_max_latency_seconds == 300


class TestDefaultHealthConfigs:
    """Test the DEFAULT_HEALTH_CONFIGS dictionary."""

    def test_all_21_sources_present(self):
        """Verify all 21 expected parser source types have configs."""
        expected = {
            "okta", "google_workspace", "microsoft365", "duo",
            "cloudtrail", "vpc_flow_logs", "guardduty",
            "gcp_logging", "azure_monitor",
            "crowdstrike", "jamf",
            "snowflake", "salesforce", "slack", "onepassword",
            "github", "kubernetes", "docker",
            "syslog", "json_generic", "otlp",
        }
        assert set(DEFAULT_HEALTH_CONFIGS.keys()) == expected

    def test_all_configs_valid(self):
        """Verify all default configs pass validation."""
        for source_type, config in DEFAULT_HEALTH_CONFIGS.items():
            errors = config.validate()
            assert errors == [], f"Config for {source_type} has errors: {errors}"

    def test_source_type_matches_key(self):
        """Verify each config's source_type matches its key."""
        for key, config in DEFAULT_HEALTH_CONFIGS.items():
            assert config.source_type == key

    def test_syslog_has_shortest_thresholds(self):
        """Verify syslog has the tightest latency settings."""
        config = DEFAULT_HEALTH_CONFIGS["syslog"]
        assert config.expected_max_latency_seconds == 60
        assert config.silence_threshold_seconds == 600

    def test_guardduty_has_extended_silence(self):
        """Verify guardduty has extended silence threshold."""
        config = DEFAULT_HEALTH_CONFIGS["guardduty"]
        assert config.silence_threshold_seconds == 7200


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_get_config_for_known_source(self):
        """Verify get_config_for_source returns the default config."""
        config = get_config_for_source("okta")
        assert config.source_type == "okta"
        assert config.expected_max_latency_seconds == 300

    def test_get_config_for_custom_source(self):
        """Verify custom config overrides default."""
        custom = {
            "okta": LogSourceHealthConfig(
                source_type="okta",
                expected_max_latency_seconds=600,
            )
        }
        config = get_config_for_source("okta", custom)
        assert config.expected_max_latency_seconds == 600

    def test_get_config_for_unknown_source(self):
        """Verify unknown source returns generic defaults."""
        config = get_config_for_source("nonexistent_source")
        assert config.source_type == "nonexistent_source"
        assert config.expected_max_latency_seconds == 300  # generic default

    def test_list_monitored_sources(self):
        """Verify list_monitored_sources returns sorted list."""
        sources = list_monitored_sources()
        assert len(sources) == 21
        assert sources == sorted(sources)

    def test_list_monitored_sources_with_custom(self):
        """Verify custom sources extend the monitored list."""
        custom = {
            "custom_source": LogSourceHealthConfig(source_type="custom_source"),
        }
        sources = list_monitored_sources(custom)
        assert "custom_source" in sources
        assert len(sources) == 22

    def test_list_enabled_sources(self):
        """Verify list_enabled_sources returns only enabled sources."""
        sources = list_enabled_sources()
        assert len(sources) == 21  # All defaults are enabled

    def test_list_enabled_sources_excludes_disabled(self):
        """Verify disabled sources are excluded."""
        custom = {
            "okta": LogSourceHealthConfig(source_type="okta", enabled=False),
        }
        sources = list_enabled_sources(custom)
        assert "okta" not in sources
