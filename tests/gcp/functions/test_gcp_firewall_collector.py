"""Unit tests for the GCP Cloud Firewall Log Collector Cloud Function."""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure the GCP functions directory is on the path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/gcp/functions")
)
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/shared")
)

import gcp_firewall_collector as collector_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_GCP_FW_ALLOWED = {
    "insertId": "abc123",
    "jsonPayload": {
        "connection": {
            "src_ip": "10.0.0.4",
            "src_port": 54321,
            "dest_ip": "172.217.14.206",
            "dest_port": 443,
            "protocol": 6,
        },
        "disposition": "ALLOWED",
        "rule_details": {
            "reference": "network:default/allow-https",
            "direction": "EGRESS",
            "priority": 1000,
            "action": "ALLOW",
        },
        "instance": {
            "vm_name": "web-server-1",
            "zone": "us-east1-b",
            "project_id": "my-project",
            "region": "us-east1",
        },
        "vpc": {
            "vpc_name": "default",
            "project_id": "my-project",
            "subnetwork_name": "default",
        },
    },
    "resource": {
        "type": "gce_firewall_rule",
        "labels": {"project_id": "my-project"},
    },
    "timestamp": "2025-06-15T10:00:00Z",
}

_SAMPLE_GCP_FW_DENIED = {
    "insertId": "def456",
    "jsonPayload": {
        "connection": {
            "src_ip": "203.0.113.50",
            "src_port": 12345,
            "dest_ip": "10.0.0.10",
            "dest_port": 22,
            "protocol": 6,
        },
        "disposition": "DENIED",
        "rule_details": {
            "reference": "network:default/deny-ssh",
            "direction": "INGRESS",
            "priority": 500,
            "action": "DENY",
        },
    },
    "resource": {
        "type": "gce_firewall_rule",
        "labels": {"project_id": "my-project"},
    },
    "timestamp": "2025-06-15T10:00:01Z",
}


def _make_cloud_event(entries):
    """Create a simulated CloudEvent with base64-encoded Pub/Sub data."""
    encoded = base64.b64encode(
        json.dumps(entries).encode("utf-8")
    ).decode("utf-8")
    return SimpleNamespace(data={"message": {"data": encoded}})


# ===========================================================================
# Test: _decode_pubsub_batch
# ===========================================================================

class TestDecodePubSubBatch:
    """Tests for Pub/Sub message decoding."""

    def test_single_entry(self):
        event = _make_cloud_event(_SAMPLE_GCP_FW_ALLOWED)
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 1

    def test_batch_entries(self):
        event = _make_cloud_event(
            [_SAMPLE_GCP_FW_ALLOWED, _SAMPLE_GCP_FW_DENIED]
        )
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 2

    def test_empty_data(self):
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module._decode_pubsub_batch(event)
        assert result == []

    def test_non_dict_entries_filtered(self):
        event = _make_cloud_event(
            [_SAMPLE_GCP_FW_ALLOWED, "not a dict", 42]
        )
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 1


# ===========================================================================
# Test: _decode_http_request
# ===========================================================================

class TestDecodeHttpRequest:
    """Tests for HTTP request decoding."""

    def test_pubsub_push_format(self):
        encoded = base64.b64encode(
            json.dumps(_SAMPLE_GCP_FW_ALLOWED).encode("utf-8")
        ).decode("utf-8")
        result = collector_module._decode_http_request(
            {"message": {"data": encoded}}
        )
        assert len(result) == 1

    def test_direct_entries(self):
        result = collector_module._decode_http_request(
            {"entries": [_SAMPLE_GCP_FW_ALLOWED, _SAMPLE_GCP_FW_DENIED]}
        )
        assert len(result) == 2

    def test_single_entry_body(self):
        result = collector_module._decode_http_request(
            _SAMPLE_GCP_FW_ALLOWED
        )
        assert len(result) == 1

    def test_empty_request(self):
        result = collector_module._decode_http_request({})
        assert result == []


# ===========================================================================
# Test: _parse_firewall_events
# ===========================================================================

class TestParseFirewallEvents:
    """Tests for firewall event parsing."""

    def test_parse_allowed(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_GCP_FW_ALLOWED]
        )
        assert len(result) == 1
        event = result[0]
        assert event["source_ip"] == "10.0.0.4"
        assert "firewall" in event["metadata"]["tags"]

    def test_parse_denied(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_GCP_FW_DENIED]
        )
        assert len(result) == 1
        assert result[0]["metadata"]["action"] == "deny"

    def test_parse_multiple(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_GCP_FW_ALLOWED, _SAMPLE_GCP_FW_DENIED]
        )
        assert len(result) == 2

    def test_invalid_events_skipped(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_GCP_FW_ALLOWED, {"not": "firewall"}]
        )
        assert len(result) >= 1

    def test_empty_input(self):
        assert collector_module._parse_firewall_events([]) == []


# ===========================================================================
# Test: _write_to_gcs
# ===========================================================================

class TestWriteToGCS:
    """Tests for GCS writes."""

    @patch("gcp_firewall_collector._gcs_storage")
    def test_writes_ndjson(self, mock_storage):
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        events = collector_module._parse_firewall_events(
            [_SAMPLE_GCP_FW_ALLOWED]
        )
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_gcs(events, "my-bucket", ts, "part01")
        assert path == "gcp_firewall/raw/2025/06/15/10/fw_part01.json"
        mock_blob.upload_from_string.assert_called_once()

    @patch("gcp_firewall_collector._gcs_storage")
    def test_empty_events_returns_none(self, mock_storage):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_gcs([], "my-bucket", ts) is None

    @patch("gcp_firewall_collector._gcs_storage")
    def test_gcs_failure_returns_none(self, mock_storage):
        mock_storage.Client.side_effect = Exception("GCS error")
        events = collector_module._parse_firewall_events(
            [_SAMPLE_GCP_FW_ALLOWED]
        )
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_gcs(events, "bucket", ts) is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting."""

    @patch.object(collector_module, "_write_to_gcs")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        paths = collector_module._batch_and_write([{"a": 1}], "bucket", 10)
        assert paths == ["path1"]

    @patch.object(collector_module, "_write_to_gcs")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["p1", "p2", "p3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(events, "bucket", 10)
        assert len(paths) == 3


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch("src.shared.health.health_state_store.FirestoreHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        collector_module.HEALTH_STATE_COLLECTION = "health"
        collector_module.TENANT_ID = "t1"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(50)
        mock_store.update_event_count.assert_called_once()
        assert (
            mock_store.update_event_count.call_args[1]["source_type"]
            == "gcp_firewall"
        )

    def test_no_health_collection(self):
        collector_module.HEALTH_STATE_COLLECTION = ""
        collector_module._report_health(100)  # No crash


# ===========================================================================
# Test: firewall_pubsub entry point
# ===========================================================================

class TestFirewallPubSub:
    """Tests for the Pub/Sub Cloud Function entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_entry(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event(_SAMPLE_GCP_FW_ALLOWED)
        result = collector_module.firewall_pubsub(event)

        assert result["status"] == "success"
        assert result["total_events"] == 1
        mock_health.assert_called_once_with(1)

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_batch(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event(
            [_SAMPLE_GCP_FW_ALLOWED, _SAMPLE_GCP_FW_DENIED]
        )
        result = collector_module.firewall_pubsub(event)
        assert result["total_events"] == 2

    @patch.object(collector_module, "_report_health")
    def test_empty_message(self, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module.firewall_pubsub(event)
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    def test_missing_gcs_bucket(self):
        collector_module.GCS_BUCKET = None
        event = _make_cloud_event(_SAMPLE_GCP_FW_ALLOWED)
        result = collector_module.firewall_pubsub(event)
        assert result["status"] == "error"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("gcp_firewall_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_pubsub_full_pipeline(self, mock_health, mock_storage):
        collector_module.GCS_BUCKET = "test-lake"
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event(
            [_SAMPLE_GCP_FW_ALLOWED, _SAMPLE_GCP_FW_DENIED]
        )
        result = collector_module.firewall_pubsub(event)

        assert result["total_events"] == 2
        assert result["files_written"] == 1
        mock_blob.upload_from_string.assert_called_once()

        content = mock_blob.upload_from_string.call_args[0][0]
        lines = content.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "firewall" in parsed["metadata"]["tags"]

    @patch("gcp_firewall_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_storage):
        collector_module.GCS_BUCKET = "test-lake"
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event(_SAMPLE_GCP_FW_ALLOWED)
        collector_module.firewall_pubsub(event)

        blob_path = mock_bucket.blob.call_args[0][0]
        assert blob_path.startswith("gcp_firewall/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "gcp_firewall"
        assert parts[1] == "raw"
